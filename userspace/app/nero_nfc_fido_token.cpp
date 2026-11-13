// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2026 Nero Duality, LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "nero_nfc_fido_token.hpp"

#include "nero_nfc_ctap_pin.hpp"
#include "nero_nfc_hex.hpp"
#include "nero_nfc_io.hpp"
#include "nero_nfc_pcsc_internal.hpp"

#include <format>
#include <optional>
#include <ranges>
#include <vector>

#ifdef NERO_USERSPACE_HAVE_PCSC
#include <PCSC/winscard.h>
#endif

namespace nero_nfc {

namespace {

inline constexpr int kExitFailure = 1;

std::string JoinStrings(const std::vector<std::string>& items) {
  std::string out;
  for (const std::string& item : items) {
    if (!out.empty()) {
      out += ", ";
    }
    out += item;
  }
  return out;
}

FidoTokenResult Fail(std::string_view message) {
  NeroNfcStderrLine("error: {}", message);
  return FidoTokenResult::kFailed;
}

FidoTokenResult RunReset(ctap::Client& client) {
  std::uint8_t status = 0u;
  std::string err;
  NeroNfcStderrLine("fido_token: resetting security key...");
  if (!client.Reset(status, err)) {
    return Fail("reset failed: " + err);
  }
  switch (status) {
    case ctap::kStatusSuccess:
      NeroNfcStdoutLine(
          "fido_token: security key reset; all credentials and the PIN were "
          "erased");
      return FidoTokenResult::kOk;
    case ctap::kErrNotAllowed:
      NeroNfcStderrLine(
          "error: the key refused the reset ({}); most keys only accept a "
          "reset within a few seconds of being tapped",
          ctap::StatusName(status));
      return FidoTokenResult::kRetryReset;
    case ctap::kErrOperationDenied:
    case ctap::kErrUserActionTimeout:
      return Fail("reset was not confirmed on the key (" +
                  ctap::StatusName(status) + ")");
    default:
      return Fail("reset failed: " + ctap::StatusName(status));
  }
}

void ReportPinRetries(ctap::Client& client, std::uint8_t protocol) {
  ctap::PinRetries retries;
  std::uint8_t status = 0u;
  std::string err;
  if (client.GetPinRetries(protocol, retries, status, err) &&
      status == ctap::kStatusSuccess) {
    NeroNfcStderrLine("fido_token: {} PIN retries left", retries.retries_);
  }
}

FidoTokenResult PinStatusFailure(ctap::Client& client, std::uint8_t protocol,
                                 std::uint8_t status) {
  switch (status) {
    case ctap::kErrPinInvalid:
      NeroNfcStderrLine("error: wrong current PIN");
      ReportPinRetries(client, protocol);
      return FidoTokenResult::kFailed;
    case ctap::kErrPinBlocked:
      return Fail("the PIN is blocked; the key must be reset (--reset)");
    case ctap::kErrPinAuthBlocked:
      return Fail(
          "too many wrong PIN attempts; remove and tap the key again before "
          "retrying");
    case ctap::kErrPinPolicyViolation:
      return Fail("the key rejected the new PIN (PIN policy violation)");
    case ctap::kErrNotAllowed:
      return Fail("a PIN is already set; use --change-pin");
    case ctap::kErrPinNotSet:
      return Fail("no PIN is set; use --set-pin");
    default:
      return Fail("PIN operation failed: " + ctap::StatusName(status));
  }
}

FidoTokenResult RunPinChange(ctap::Client& client,
                             const ctap::AuthenticatorInfo& info,
                             const FidoTokenRequest& request) {
  const std::optional<bool> client_pin = info.Option("clientPin");
  if (!client_pin.has_value()) {
    return Fail("this security key does not support a PIN");
  }
  if (request.set_pin_ && *client_pin) {
    return Fail(
        "a PIN is already set; use --change-pin, or --reset --set-pin to "
        "erase the key first");
  }
  if (request.change_pin_ && !*client_pin) {
    return Fail("no PIN is set; use --set-pin");
  }
  const std::uint8_t protocol = ctap::ChoosePinProtocol(info);
  if (protocol == 0u) {
    return Fail("the key offers no supported PIN/UV auth protocol");
  }
  std::string err;
  if (!ctap::ValidateNewPin(
          request.new_pin_,
          info.min_pin_length_.value_or(ctap::kPinDefaultMinLength), err)) {
    return Fail(err);
  }
  std::uint8_t status = 0u;
  const bool ok =
      request.set_pin_
          ? ctap::SetPin(client, protocol, request.new_pin_, status, err)
          : ctap::ChangePin(client, protocol, request.current_pin_,
                            request.new_pin_, status, err);
  if (!ok) {
    return Fail(err);
  }
  if (status != ctap::kStatusSuccess) {
    return PinStatusFailure(client, protocol, status);
  }
  NeroNfcStdoutLine(request.set_pin_ ? "fido_token: PIN set"
                                     : "fido_token: PIN changed");
  return FidoTokenResult::kOk;
}

}  // namespace

std::string FormatAuthenticatorInfo(const ctap::AuthenticatorInfo& info) {
  std::string out;
  out += std::format("versions: {}\n", JoinStrings(info.versions_));
  if (!info.extensions_.empty()) {
    out += std::format("extensions: {}\n", JoinStrings(info.extensions_));
  }
  if (!info.aaguid_.empty()) {
    out += std::format("aaguid: {}\n", HexBytes(info.aaguid_, '\0'));
  }
  if (!info.options_.empty()) {
    std::vector<std::string> options;
    options.reserve(info.options_.size());
    for (const auto& [name, value] : info.options_) {
      options.push_back(value ? name : "no" + name);
    }
    out += std::format("options: {}\n", JoinStrings(options));
  }
  if (info.max_msg_size_.has_value()) {
    out += std::format("max message size: {}\n", *info.max_msg_size_);
  }
  if (!info.pin_protocols_.empty()) {
    std::vector<std::string> protocols;
    protocols.reserve(info.pin_protocols_.size());
    for (const std::uint64_t p : info.pin_protocols_) {
      protocols.push_back(std::to_string(p));
    }
    out += std::format("pin protocols: {}\n", JoinStrings(protocols));
  }
  if (info.min_pin_length_.has_value()) {
    out += std::format("min pin length: {}\n", *info.min_pin_length_);
  }
  if (info.force_pin_change_.has_value()) {
    out += std::format("force pin change: {}\n", *info.force_pin_change_);
  }
  if (!out.empty() && out.back() == '\n') {
    out.pop_back();
  }
  return out;
}

FidoTokenResult RunFidoTokenOperations(ctap::Client& client,
                                       const FidoTokenRequest& request) {
  std::string err;
  std::string applet_version;
  if (!client.Select(applet_version, err)) {
    return Fail(err);
  }
  if (request.reset_) {
    const FidoTokenResult reset = RunReset(client);
    if (reset != FidoTokenResult::kOk) {
      return reset;
    }
  }
  if (!request.info_ && !request.set_pin_ && !request.change_pin_) {
    return FidoTokenResult::kOk;
  }
  ctap::AuthenticatorInfo info;
  if (!client.GetInfo(info, err)) {
    return Fail(err);
  }
  if (request.info_) {
    NeroNfcStdoutLine("applet: {}", applet_version);
    NeroNfcStdoutLine(FormatAuthenticatorInfo(info));
    if (info.Option("clientPin") == true) {
      ctap::PinRetries retries;
      std::uint8_t status = 0u;
      const std::uint8_t protocol = ctap::ChoosePinProtocol(info);
      if (protocol != 0u &&
          client.GetPinRetries(protocol, retries, status, err) &&
          status == ctap::kStatusSuccess) {
        NeroNfcStdoutLine("pin retries: {}", retries.retries_);
      }
    }
  }
  if (request.set_pin_ || request.change_pin_) {
    return RunPinChange(client, info, request);
  }
  return FidoTokenResult::kOk;
}

#ifdef NERO_USERSPACE_HAVE_PCSC

namespace {

/* Blocks until a card is present; reader is resolved by name or presence. */
bool WaitForKey(const pcsc_internal::PcscCard& card,
                std::string_view reader_substring, std::string& reader,
                std::string& err) {
  const std::string requested = reader_substring.empty()
                                    ? PcscReaderSubstringFromEnv()
                                    : std::string(reader_substring);
  if (requested.empty()) {
    NeroNfcStderrLine(
        "fido_token: tap your security key on the reader (Ctrl+C to stop)");
    return pcsc_internal::ResolvePcscReaderForOperation(card, "", reader, err);
  }
  if (!ResolvePcscReader(requested, reader, err)) {
    return false;
  }
  NeroNfcStderrLine(
      "fido_token: tap your security key on \"{}\" (Ctrl+C to stop)", reader);
  return pcsc_internal::WaitForCardPresent(card.Context(), reader, std::nullopt,
                                           err);
}

FidoTokenResult RunOnReader(pcsc_internal::PcscCard& card,
                            const std::string& reader,
                            const FidoTokenRequest& request) {
  std::string err;
  if (!card.Connect(reader, request.share_mode_, err) ||
      !card.BeginTransaction(err)) {
    return Fail(err);
  }
  ctap::Client client([&card](const std::vector<std::uint8_t>& capdu,
                              std::vector<std::uint8_t>& rapdu,
                              std::string& transmit_err) {
    return card.Transmit(capdu, rapdu, transmit_err);
  });
  const FidoTokenResult result = RunFidoTokenOperations(client, request);
  std::string end_err;
  (void)card.EndTransaction(end_err);
  return result;
}

}  // namespace

#endif  // NERO_USERSPACE_HAVE_PCSC

int RunFidoTokenList() {
  std::vector<std::string> readers;
  std::string err;
  if (!ListPcscReaders(readers, err)) {
    NeroNfcStderrLine("error: {}", err);
    return kExitFailure;
  }
  for (const std::string& reader : readers) {
    NeroNfcStdoutLine(reader);
  }
  return 0;
}

int RunFidoToken(std::string_view reader_substring, FidoTokenRequest& request) {
#ifndef NERO_USERSPACE_HAVE_PCSC
  (void)reader_substring;
  ctap::SecureWipe(request.current_pin_);
  ctap::SecureWipe(request.new_pin_);
  NeroNfcStderrLine(
      "error: PC/SC support was not compiled in (install "
      "libpcsclite-dev/pcsc-lite-devel and rebuild)");
  return kExitFailure;
#else
  constexpr int kMaxResetAttempts = 3;
  pcsc_internal::PcscCard card;
  std::string err;
  FidoTokenResult result = FidoTokenResult::kFailed;
  if (!card.EnsureContext(err)) {
    NeroNfcStderrLine("error: {}", err);
  } else {
    for (int attempt = 1; attempt <= kMaxResetAttempts; ++attempt) {
      std::string reader;
      if (!WaitForKey(card, reader_substring, reader, err)) {
        NeroNfcStderrLine("error: {}", err);
        result = FidoTokenResult::kFailed;
        break;
      }
      result = RunOnReader(card, reader, request);
      card.Disconnect();
      if (result != FidoTokenResult::kRetryReset ||
          attempt == kMaxResetAttempts) {
        break;
      }
      NeroNfcStderrLine(
          "fido_token: remove the security key from the reader, then tap it "
          "again to retry");
      if (!pcsc_internal::WaitForCardAbsentStable(card.Context(), reader,
                                                  err)) {
        NeroNfcStderrLine("error: {}", err);
        result = FidoTokenResult::kFailed;
        break;
      }
    }
  }
  ctap::SecureWipe(request.current_pin_);
  ctap::SecureWipe(request.new_pin_);
  return result == FidoTokenResult::kOk ? 0 : kExitFailure;
#endif
}

}  // namespace nero_nfc
