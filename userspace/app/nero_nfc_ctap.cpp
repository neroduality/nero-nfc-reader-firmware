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

#include "nero_nfc_ctap.hpp"

#include "nero_nfc_null.h"
#include "nfc_ctap_codec.h"
#include "nfc_pcsc_contactless.h"
#include "nfc_tag_geometry_limits.h"

#include <algorithm>
#include <array>
#include <format>
#include <iterator>
#include <limits>
#include <ranges>
#include <span>
#include <thread>

namespace nero_nfc::ctap {

namespace {

enum : std::uint8_t {
  kSw1MoreData = 0x61u,
  kIsoGetResponseIns = 0xC0u,
  kByteBits = 8u,
};

inline constexpr std::uint16_t kSwSuccess = 0x9000u;
/* [CTAP2.3] section 11.3.7.2 -- status update; poll NFCCTAP_GETRESPONSE. */
inline constexpr std::uint16_t kSwCtapStatusUpdate = 0x9100u;
/* Bound 61xx chaining so a misbehaving card cannot loop forever. */
inline constexpr std::size_t kMaxGetResponseRounds = 64u;
inline constexpr auto kDefaultCommandTimeout = std::chrono::seconds(10);
/* Reset may wait on flash erase or a user-presence check. */
inline constexpr auto kResetTimeout = std::chrono::seconds(30);

/* [CTAP2.3] section 6.4 authenticatorGetInfo response keys. */
inline constexpr std::int64_t kInfoVersions = 0x01;
inline constexpr std::int64_t kInfoExtensions = 0x02;
inline constexpr std::int64_t kInfoAaguid = 0x03;
inline constexpr std::int64_t kInfoOptions = 0x04;
inline constexpr std::int64_t kInfoMaxMsgSize = 0x05;
inline constexpr std::int64_t kInfoPinProtocols = 0x06;
inline constexpr std::int64_t kInfoForcePinChange = 0x0C;
inline constexpr std::int64_t kInfoMinPinLength = 0x0D;

void AppendTextArray(const cbor::Value* v, std::vector<std::string>& out) {
  if (v == NERO_NFC_NULL || !v->IsArray()) {
    return;
  }
  for (const cbor::Value& item : v->AsArray()) {
    if (item.IsText()) {
      out.push_back(item.AsText());
    }
  }
}

cbor::Value PinParams(std::uint8_t protocol, std::uint8_t sub_command) {
  return cbor::Value::Map({
      {.key_ = cbor::Value::Int(kPinKeyProtocol),
       .value_ = cbor::Value::Int(protocol)},
      {.key_ = cbor::Value::Int(kPinKeySubCommand),
       .value_ = cbor::Value::Int(sub_command)},
  });
}

}  // namespace

std::optional<bool> AuthenticatorInfo::Option(std::string_view name) const {
  const auto it = std::ranges::find_if(
      options_, [&](const auto& option) { return option.first == name; });
  if (it == options_.end()) {
    return std::nullopt;
  }
  return it->second;
}

Client::Client(ApduTransceiver transceive,
               std::chrono::milliseconds poll_interval)
    : transceive_(std::move(transceive)), poll_interval_(poll_interval) {}

bool Client::Exchange(const std::vector<std::uint8_t>& capdu,
                      std::vector<std::uint8_t>& data, std::uint16_t& sw,
                      std::string& err) {
  data.clear();
  sw = 0u;
  std::vector<std::uint8_t> command = capdu;
  for (std::size_t round = 0u; round < kMaxGetResponseRounds; ++round) {
    std::vector<std::uint8_t> rapdu;
    if (!transceive_(command, rapdu, err)) {
      return false;
    }
    if (rapdu.size() < static_cast<std::size_t>(NFC_ISO7816_SW_LEN)) {
      err = "authenticator response missing status word";
      return false;
    }
    const auto sw_len = static_cast<std::size_t>(NFC_ISO7816_SW_LEN);
    const std::uint8_t sw1 = rapdu.at(rapdu.size() - sw_len);
    const std::uint8_t sw2 = rapdu.back();
    std::ranges::copy(std::span(rapdu).first(rapdu.size() - sw_len),
                      std::back_inserter(data));
    if (sw1 != kSw1MoreData) {
      sw = static_cast<std::uint16_t>(
          (static_cast<std::uint32_t>(sw1) << kByteBits) | sw2);
      err.clear();
      return true;
    }
    command = {static_cast<std::uint8_t>(NFC_ISO7816_CLA_ISO),
               kIsoGetResponseIns, 0x00u, 0x00u, sw2};
  }
  err = "authenticator response chaining exceeded limit";
  return false;
}

bool Client::Select(std::string& version, std::string& err) {
  std::array<std::uint8_t,
             NFC_ISO7816_SHORT_APDU_HDR_LEN + NFC_CTAP_FIDO_AID_LEN + 1u>
      apdu{};
  std::uint16_t apdu_len = 0u;
  version.clear();
  if (!nfc_ctap_pack_select_fido_apdu(true, apdu.data(),
                                      static_cast<std::uint16_t>(apdu.size()),
                                      &apdu_len)) {
    err = "failed to build FIDO SELECT APDU";
    return false;
  }
  std::vector<std::uint8_t> data;
  std::uint16_t sw = 0u;
  if (!Exchange({apdu.begin(), std::next(apdu.begin(), apdu_len)}, data, sw,
                err)) {
    return false;
  }
  if (sw != kSwSuccess) {
    err = std::format(
        "card did not accept the FIDO application SELECT (SW={:04X}); is this "
        "a FIDO security key?",
        sw);
    return false;
  }
  version.assign(data.begin(), data.end());
  return true;
}

bool Client::Command(std::uint8_t cmd, const std::optional<cbor::Value>& params,
                     std::chrono::milliseconds timeout, std::uint8_t& status,
                     std::vector<std::uint8_t>& body, std::string& err) {
  status = 0u;
  body.clear();
  const std::vector<std::uint8_t> cbor_bytes =
      params.has_value() ? cbor::Encode(*params) : std::vector<std::uint8_t>{};
  if (cbor_bytes.size() >= std::numeric_limits<std::uint16_t>::max()) {
    err = "CTAP request too large";
    return false;
  }
  std::vector<std::uint8_t> apdu(cbor_bytes.size() +
                                 NFC_CTAP_APDU_PAYLOAD_HDR_EXTENDED);
  std::uint16_t apdu_len = 0u;
  if (!nfc_ctap_pack_cbor_apdu(
          cmd, cbor_bytes.empty() ? NERO_NFC_NULL : cbor_bytes.data(),
          static_cast<std::uint16_t>(cbor_bytes.size()), false, apdu.data(),
          static_cast<std::uint16_t>(apdu.size()), &apdu_len)) {
    err = "failed to build CTAP APDU";
    return false;
  }
  apdu.resize(apdu_len);

  const auto deadline = std::chrono::steady_clock::now() + timeout;
  std::vector<std::uint8_t> data;
  std::uint16_t sw = 0u;
  if (!Exchange(apdu, data, sw, err)) {
    return false;
  }
  while (sw == kSwCtapStatusUpdate) {
    if (std::chrono::steady_clock::now() >= deadline) {
      err = "timed out waiting for the authenticator to finish";
      return false;
    }
    std::this_thread::sleep_for(poll_interval_);
    const std::vector<std::uint8_t> poll = {
        static_cast<std::uint8_t>(NFC_CTAP_CLA),
        static_cast<std::uint8_t>(NFC_CTAP_INS_GETRESPONSE), 0x00u, 0x00u,
        0x00u};
    if (!Exchange(poll, data, sw, err)) {
      return false;
    }
  }
  if (sw != kSwSuccess) {
    err = std::format("authenticator returned SW={:04X}", sw);
    return false;
  }
  if (data.empty()) {
    err = "authenticator returned an empty CTAP response";
    return false;
  }
  status = data.front();
  if (status == kStatusSuccess) {
    body.assign(data.begin() + 1, data.end());
  }
  err.clear();
  return true;
}

bool Client::GetInfo(AuthenticatorInfo& info, std::string& err) {
  std::uint8_t status = 0u;
  std::vector<std::uint8_t> body;
  info = {};
  if (!Command(static_cast<std::uint8_t>(NFC_CTAP_CMD_GET_INFO), std::nullopt,
               kDefaultCommandTimeout, status, body, err)) {
    return false;
  }
  if (status != kStatusSuccess) {
    err = "authenticatorGetInfo failed: " + StatusName(status);
    return false;
  }
  cbor::Value map;
  if (!cbor::Decode(body, map, err)) {
    err = "authenticatorGetInfo: " + err;
    return false;
  }
  return ParseGetInfo(map, info, err);
}

bool Client::Reset(std::uint8_t& status, std::string& err) {
  std::vector<std::uint8_t> body;
  return Command(static_cast<std::uint8_t>(NFC_CTAP_CMD_RESET), std::nullopt,
                 kResetTimeout, status, body, err);
}

bool Client::ClientPin(const cbor::Value& params, std::uint8_t& status,
                       cbor::Value& response, std::string& err) {
  std::vector<std::uint8_t> body;
  response = cbor::Value::Null();
  if (!Command(static_cast<std::uint8_t>(NFC_CTAP_CMD_CLIENT_PIN), params,
               kDefaultCommandTimeout, status, body, err)) {
    return false;
  }
  if (status != kStatusSuccess || body.empty()) {
    return true;
  }
  if (!cbor::Decode(body, response, err)) {
    err = "authenticatorClientPIN: " + err;
    return false;
  }
  return true;
}

bool Client::GetPinRetries(std::uint8_t protocol, PinRetries& out,
                           std::uint8_t& status, std::string& err) {
  cbor::Value response;
  out = {};
  if (!ClientPin(PinParams(protocol, kPinSubGetRetries), status, response,
                 err)) {
    return false;
  }
  if (status != kStatusSuccess) {
    return true;
  }
  const cbor::Value* retries = response.Find(kPinRespRetries);
  if (retries == NERO_NFC_NULL || !retries->IsUnsigned()) {
    err = "getPINRetries response missing pinRetries";
    return false;
  }
  out.retries_ = retries->Raw();
  const cbor::Value* power_cycle = response.Find(kPinRespPowerCycleState);
  if (power_cycle != NERO_NFC_NULL && power_cycle->IsBool()) {
    out.power_cycle_state_ = power_cycle->AsBool();
  }
  return true;
}

bool Client::GetKeyAgreement(std::uint8_t protocol, cbor::Value& cose_key,
                             std::uint8_t& status, std::string& err) {
  cbor::Value response;
  if (!ClientPin(PinParams(protocol, kPinSubGetKeyAgreement), status, response,
                 err)) {
    return false;
  }
  if (status != kStatusSuccess) {
    return true;
  }
  const cbor::Value* key = response.Find(kPinRespKeyAgreement);
  if (key == NERO_NFC_NULL || !key->IsMap()) {
    err = "getKeyAgreement response missing keyAgreement";
    return false;
  }
  cose_key = *key;
  return true;
}

std::string StatusName(std::uint8_t status) {
  struct Entry {
    std::uint8_t code_{};
    std::string_view name_;
  };
  static constexpr std::array kNames = {
      Entry{.code_ = 0x00u, .name_ = "CTAP2_OK"},
      Entry{.code_ = 0x01u, .name_ = "CTAP1_ERR_INVALID_COMMAND"},
      Entry{.code_ = 0x02u, .name_ = "CTAP1_ERR_INVALID_PARAMETER"},
      Entry{.code_ = 0x03u, .name_ = "CTAP1_ERR_INVALID_LENGTH"},
      Entry{.code_ = 0x11u, .name_ = "CTAP2_ERR_CBOR_UNEXPECTED_TYPE"},
      Entry{.code_ = 0x12u, .name_ = "CTAP2_ERR_INVALID_CBOR"},
      Entry{.code_ = 0x14u, .name_ = "CTAP2_ERR_MISSING_PARAMETER"},
      Entry{.code_ = 0x26u, .name_ = "CTAP2_ERR_UNSUPPORTED_OPTION"},
      Entry{.code_ = 0x27u, .name_ = "CTAP2_ERR_OPERATION_DENIED"},
      Entry{.code_ = 0x2Du, .name_ = "CTAP2_ERR_KEEPALIVE_CANCEL"},
      Entry{.code_ = 0x2Fu, .name_ = "CTAP2_ERR_USER_ACTION_TIMEOUT"},
      Entry{.code_ = 0x30u, .name_ = "CTAP2_ERR_NOT_ALLOWED"},
      Entry{.code_ = 0x31u, .name_ = "CTAP2_ERR_PIN_INVALID"},
      Entry{.code_ = 0x32u, .name_ = "CTAP2_ERR_PIN_BLOCKED"},
      Entry{.code_ = 0x33u, .name_ = "CTAP2_ERR_PIN_AUTH_INVALID"},
      Entry{.code_ = 0x34u, .name_ = "CTAP2_ERR_PIN_AUTH_BLOCKED"},
      Entry{.code_ = 0x35u, .name_ = "CTAP2_ERR_PIN_NOT_SET"},
      Entry{.code_ = 0x36u, .name_ = "CTAP2_ERR_PUAT_REQUIRED"},
      Entry{.code_ = 0x37u, .name_ = "CTAP2_ERR_PIN_POLICY_VIOLATION"},
      Entry{.code_ = 0x7Fu, .name_ = "CTAP1_ERR_OTHER"},
  };
  const auto* it = std::ranges::find_if(
      kNames, [&](const Entry& e) { return e.code_ == status; });
  if (it != kNames.end()) {
    return std::format("{} (0x{:02X})", it->name_, status);
  }
  return std::format("CTAP status 0x{:02X}", status);
}

bool ParseGetInfo(const cbor::Value& map, AuthenticatorInfo& out,
                  std::string& err) {
  out = {};
  if (!map.IsMap()) {
    err = "authenticatorGetInfo response is not a CBOR map";
    return false;
  }
  AppendTextArray(map.Find(kInfoVersions), out.versions_);
  if (out.versions_.empty()) {
    err = "authenticatorGetInfo response missing versions";
    return false;
  }
  AppendTextArray(map.Find(kInfoExtensions), out.extensions_);
  if (const cbor::Value* aaguid = map.Find(kInfoAaguid);
      aaguid != NERO_NFC_NULL && aaguid->IsBytes()) {
    out.aaguid_ = aaguid->AsBytes();
  }
  if (const cbor::Value* options = map.Find(kInfoOptions);
      options != NERO_NFC_NULL && options->IsMap()) {
    for (const cbor::MapEntry& entry : options->AsMap()) {
      if (entry.key_.IsText() && entry.value_.IsBool()) {
        out.options_.emplace_back(entry.key_.AsText(), entry.value_.AsBool());
      }
    }
  }
  if (const cbor::Value* size = map.Find(kInfoMaxMsgSize);
      size != NERO_NFC_NULL && size->IsUnsigned()) {
    out.max_msg_size_ = size->Raw();
  }
  if (const cbor::Value* protocols = map.Find(kInfoPinProtocols);
      protocols != NERO_NFC_NULL && protocols->IsArray()) {
    for (const cbor::Value& p : protocols->AsArray()) {
      if (p.IsUnsigned()) {
        out.pin_protocols_.push_back(p.Raw());
      }
    }
  }
  if (const cbor::Value* force = map.Find(kInfoForcePinChange);
      force != NERO_NFC_NULL && force->IsBool()) {
    out.force_pin_change_ = force->AsBool();
  }
  if (const cbor::Value* min_len = map.Find(kInfoMinPinLength);
      min_len != NERO_NFC_NULL && min_len->IsUnsigned()) {
    out.min_pin_length_ = min_len->Raw();
  }
  err.clear();
  return true;
}

std::uint8_t ChoosePinProtocol(const AuthenticatorInfo& info) {
  /* [CTAP2.3] section 6.4 -- CTAP 2.0 authenticators may omit
   * pinUvAuthProtocols; they implement protocol 1. */
  if (info.pin_protocols_.empty()) {
    return kPinProtocolOne;
  }
  if (std::ranges::contains(info.pin_protocols_, kPinProtocolTwo)) {
    return kPinProtocolTwo;
  }
  if (std::ranges::contains(info.pin_protocols_, kPinProtocolOne)) {
    return kPinProtocolOne;
  }
  return 0u;
}

}  // namespace nero_nfc::ctap
