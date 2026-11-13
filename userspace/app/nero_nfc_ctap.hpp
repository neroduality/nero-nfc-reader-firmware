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

// CTAP2 client over the NFC APDU transport ([CTAP2.3] section 11.3). The APDU
// transceiver is injected so the same client runs over PC/SC or a test fake.

#pragma once

#include "nero_nfc_attrs.h"
#include "nero_nfc_cbor.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace nero_nfc::ctap {

using ApduTransceiver =
    std::function<bool(const std::vector<std::uint8_t>& capdu,
                       std::vector<std::uint8_t>& rapdu, std::string& err)>;

/* [CTAP2.3] section 8.2 status codes the CLI reacts to. */
inline constexpr std::uint8_t kStatusSuccess = 0x00u;
inline constexpr std::uint8_t kErrInvalidCommand = 0x01u;
inline constexpr std::uint8_t kErrOperationDenied = 0x27u;
inline constexpr std::uint8_t kErrUserActionTimeout = 0x2Fu;
inline constexpr std::uint8_t kErrNotAllowed = 0x30u;
inline constexpr std::uint8_t kErrPinInvalid = 0x31u;
inline constexpr std::uint8_t kErrPinBlocked = 0x32u;
inline constexpr std::uint8_t kErrPinAuthInvalid = 0x33u;
inline constexpr std::uint8_t kErrPinAuthBlocked = 0x34u;
inline constexpr std::uint8_t kErrPinNotSet = 0x35u;
inline constexpr std::uint8_t kErrPinPolicyViolation = 0x37u;

/* [CTAP2.3] section 6.5.5 authenticatorClientPIN subcommands and keys. */
inline constexpr std::uint8_t kPinSubGetRetries = 0x01u;
inline constexpr std::uint8_t kPinSubGetKeyAgreement = 0x02u;
inline constexpr std::uint8_t kPinSubSetPin = 0x03u;
inline constexpr std::uint8_t kPinSubChangePin = 0x04u;
inline constexpr std::int64_t kPinKeyProtocol = 0x01;
inline constexpr std::int64_t kPinKeySubCommand = 0x02;
inline constexpr std::int64_t kPinKeyKeyAgreement = 0x03;
inline constexpr std::int64_t kPinKeyAuthParam = 0x04;
inline constexpr std::int64_t kPinKeyNewPinEnc = 0x05;
inline constexpr std::int64_t kPinKeyPinHashEnc = 0x06;
inline constexpr std::int64_t kPinRespKeyAgreement = 0x01;
inline constexpr std::int64_t kPinRespRetries = 0x03;
inline constexpr std::int64_t kPinRespPowerCycleState = 0x04;

/* [CTAP2.3] sections 6.5.6 and 6.5.7 -- PIN/UV auth protocol versions. */
inline constexpr std::uint8_t kPinProtocolOne = 1u;
inline constexpr std::uint8_t kPinProtocolTwo = 2u;

/* Delay between polls while the authenticator reports CTAP status updates. */
inline constexpr std::chrono::milliseconds kDefaultPollInterval{100};

struct AuthenticatorInfo {
  std::vector<std::string> versions_;
  std::vector<std::string> extensions_;
  std::vector<std::uint8_t> aaguid_;
  std::vector<std::pair<std::string, bool>> options_;
  std::optional<std::uint64_t> max_msg_size_;
  std::vector<std::uint64_t> pin_protocols_;
  std::optional<std::uint64_t> min_pin_length_;
  std::optional<bool> force_pin_change_;

  [[nodiscard]] std::optional<bool> Option(std::string_view name) const;
};

struct PinRetries {
  std::uint64_t retries_{};
  std::optional<bool> power_cycle_state_;
};

class Client {
 public:
  explicit Client(
      ApduTransceiver transceive,
      std::chrono::milliseconds poll_interval = kDefaultPollInterval);

  /* SELECT the FIDO AID; version is the applet's response (e.g. FIDO_2_0). */
  NERO_NFC_NODISCARD bool Select(std::string& version, std::string& err);

  /* Send one CTAP2 command. Returns false on transport failure; a CTAP error
   * is reported through status with body empty. */
  NERO_NFC_NODISCARD bool Command(std::uint8_t cmd,
                                  const std::optional<cbor::Value>& params,
                                  std::chrono::milliseconds timeout,
                                  std::uint8_t& status,
                                  std::vector<std::uint8_t>& body,
                                  std::string& err);

  NERO_NFC_NODISCARD bool GetInfo(AuthenticatorInfo& info, std::string& err);
  NERO_NFC_NODISCARD bool Reset(std::uint8_t& status, std::string& err);
  NERO_NFC_NODISCARD bool ClientPin(const cbor::Value& params,
                                    std::uint8_t& status, cbor::Value& response,
                                    std::string& err);
  NERO_NFC_NODISCARD bool GetPinRetries(std::uint8_t protocol, PinRetries& out,
                                        std::uint8_t& status, std::string& err);
  NERO_NFC_NODISCARD bool GetKeyAgreement(std::uint8_t protocol,
                                          cbor::Value& cose_key,
                                          std::uint8_t& status,
                                          std::string& err);

 private:
  /* One APDU round trip, following ISO7816 61xx GET RESPONSE chaining. */
  NERO_NFC_NODISCARD bool Exchange(const std::vector<std::uint8_t>& capdu,
                                   std::vector<std::uint8_t>& data,
                                   std::uint16_t& sw, std::string& err);

  ApduTransceiver transceive_;
  std::chrono::milliseconds poll_interval_;
};

std::string StatusName(std::uint8_t status);
NERO_NFC_NODISCARD bool ParseGetInfo(const cbor::Value& map,
                                     AuthenticatorInfo& out, std::string& err);
/* Preferred PIN/UV auth protocol (2, then 1); 0 when none is supported. */
std::uint8_t ChoosePinProtocol(const AuthenticatorInfo& info);

}  // namespace nero_nfc::ctap
