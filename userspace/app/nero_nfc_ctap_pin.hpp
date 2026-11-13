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

// PIN/UV auth protocols one and two ([CTAP2.3] section 6.5) and the ClientPIN
// setPIN / changePIN flows, backed by OpenSSL 3.

#pragma once

#include "nero_nfc_attrs.h"
#include "nero_nfc_cbor.hpp"
#include "nero_nfc_ctap.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace nero_nfc::ctap {

/* [CTAP2.3] section 6.5.5.5 -- newPin is at most 63 bytes, padded to 64. */
inline constexpr std::size_t kPinMaxBytes = 63u;
inline constexpr std::size_t kPinPaddedLen = 64u;
inline constexpr std::uint64_t kPinDefaultMinLength = 4u;

/* Count of Unicode code points (minPINLength is measured in code points). */
std::size_t PinCodePointCount(std::string_view pin);
NERO_NFC_NODISCARD bool ValidateNewPin(std::string_view pin,
                                       std::uint64_t min_length,
                                       std::string& err);
void SecureWipe(std::string& s);
void SecureWipe(std::vector<std::uint8_t>& v);

/* Ephemeral P-256 key pair for the ClientPIN key agreement. */
class EcdhKeyPair {
 public:
  EcdhKeyPair();
  ~EcdhKeyPair();
  EcdhKeyPair(const EcdhKeyPair&) = delete;
  EcdhKeyPair& operator=(const EcdhKeyPair&) = delete;
  EcdhKeyPair(EcdhKeyPair&&) noexcept;
  EcdhKeyPair& operator=(EcdhKeyPair&&) noexcept;

  NERO_NFC_NODISCARD bool Generate(std::string& err);
  /* COSE_Key {1: 2, 3: -25, -1: 1, -2: x, -3: y}. */
  NERO_NFC_NODISCARD bool CoseKey(cbor::Value& out, std::string& err) const;
  /* ECDH with the peer COSE_Key; z is the 32-byte shared x-coordinate. */
  NERO_NFC_NODISCARD bool Agree(const cbor::Value& peer_cose_key,
                                std::vector<std::uint8_t>& z,
                                std::string& err) const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

class PinUvAuthProtocol {
 public:
  explicit PinUvAuthProtocol(std::uint8_t version) : version_(version) {}

  [[nodiscard]] std::uint8_t Version() const { return version_; }
  NERO_NFC_NODISCARD bool Kdf(std::span<const std::uint8_t> z,
                              std::vector<std::uint8_t>& shared,
                              std::string& err) const;
  NERO_NFC_NODISCARD bool Encrypt(std::span<const std::uint8_t> shared,
                                  std::span<const std::uint8_t> plaintext,
                                  std::vector<std::uint8_t>& out,
                                  std::string& err) const;
  NERO_NFC_NODISCARD bool Decrypt(std::span<const std::uint8_t> shared,
                                  std::span<const std::uint8_t> ciphertext,
                                  std::vector<std::uint8_t>& out,
                                  std::string& err) const;
  NERO_NFC_NODISCARD bool Authenticate(std::span<const std::uint8_t> shared,
                                       std::span<const std::uint8_t> message,
                                       std::vector<std::uint8_t>& out,
                                       std::string& err) const;

 private:
  std::uint8_t version_;
};

/* status carries the authenticator's CTAP status when the call returns true. */
NERO_NFC_NODISCARD bool SetPin(Client& client, std::uint8_t protocol,
                               std::string_view new_pin, std::uint8_t& status,
                               std::string& err);
NERO_NFC_NODISCARD bool ChangePin(Client& client, std::uint8_t protocol,
                                  std::string_view current_pin,
                                  std::string_view new_pin,
                                  std::uint8_t& status, std::string& err);

}  // namespace nero_nfc::ctap
