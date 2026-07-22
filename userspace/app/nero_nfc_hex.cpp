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

#include "nero_nfc_hex.hpp"
#include "nero_nfc_bounds.hpp"

#include "nero_nfc_limits.h"

#include <cctype>

namespace nero_nfc {

namespace {

enum {
  kHexNibbleShift = 4u,
  kHexNibbleMask = 0x0Fu,
  kHexDigitsPerByte = 2u,
  kHexRadix = 16u,
  kHexAlphaBase = 10,
  kMaxByteValue = 0xFFu,
};

}  // namespace

std::string HexBytes(const std::vector<std::uint8_t>& bytes, char separator) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string out;
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    if (i != 0u && separator != '\0') {
      out.push_back(separator);
    }
    out.push_back(
        At(kHex, static_cast<std::size_t>(bytes[i] >> kHexNibbleShift)));
    out.push_back(
        At(kHex, static_cast<std::size_t>(bytes[i] & kHexNibbleMask)));
  }
  return out;
}

bool ParseHexBytes(std::string_view text, std::vector<std::uint8_t>& out) {
  std::string compact;
  compact.reserve(text.size());
  for (char c : text) {
    if (std::isxdigit(static_cast<unsigned char>(c)) != 0) {
      compact.push_back(c);
    } else if (std::isspace(static_cast<unsigned char>(c)) == 0 && c != ':' &&
               c != '-') {
      return false;
    }
  }
  if ((compact.size() % kHexDigitsPerByte) != 0u) {
    return false;
  }
  const std::size_t kByteLen = compact.size() / kHexDigitsPerByte;
  if (kByteLen > NERO_NFC_NDEF_MAX_TOTAL_BYTES) {
    return false;
  }
  out.clear();
  out.reserve(kByteLen);
  for (std::size_t i = 0; i < compact.size(); i += kHexDigitsPerByte) {
    auto nibble = [](char c) -> int {
      if (c >= '0' && c <= '9') {
        return static_cast<int>(c - '0');
      }
      if (c >= 'a' && c <= 'f') {
        return kHexAlphaBase + static_cast<int>(c - 'a');
      }
      if (c >= 'A' && c <= 'F') {
        return kHexAlphaBase + static_cast<int>(c - 'A');
      }
      return -1;
    };
    const int kHi = nibble(compact[i]);
    const int kLo = nibble(compact[i + 1u]);
    if (kHi < 0 || kLo < 0) {
      return false;
    }
    const unsigned kValue = (static_cast<unsigned>(kHi) << kHexNibbleShift) |
                            static_cast<unsigned>(kLo);
    if (kValue > kMaxByteValue) {
      return false;
    }
    out.push_back(static_cast<std::uint8_t>(kValue));
  }
  return true;
}

}  // namespace nero_nfc
