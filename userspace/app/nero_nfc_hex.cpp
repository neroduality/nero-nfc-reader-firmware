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

#include "nero_nfc_hex.h"

#include "nero_nfc_limits.h"

#include <cctype>
#include <charconv>

namespace nero_nfc {

namespace {

enum {
  kHexNibbleShift = 4u,
  kHexNibbleMask = 0x0Fu,
  kHexDigitsPerByte = 2u,
  kHexRadix = 16u,
  kMaxByteValue = 0xFFu,
};

} // namespace

std::string hex_bytes(const std::vector<std::uint8_t> &bytes, char separator) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string out;
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    if (i != 0u && separator != '\0') {
      out.push_back(separator);
    }
    out.push_back(kHex[bytes[i] >> kHexNibbleShift]);
    out.push_back(kHex[bytes[i] & kHexNibbleMask]);
  }
  return out;
}

bool parse_hex_bytes(std::string_view text, std::vector<std::uint8_t> &out) {
  std::string compact;
  compact.reserve(text.size());
  for (char c : text) {
    if (std::isxdigit(static_cast<unsigned char>(c)) != 0) {
      compact.push_back(c);
    } else if (std::isspace(static_cast<unsigned char>(c)) == 0 && c != ':' && c != '-') {
      return false;
    }
  }
  if ((compact.size() % kHexDigitsPerByte) != 0u) {
    return false;
  }
  const std::size_t byte_len = compact.size() / kHexDigitsPerByte;
  if (byte_len > NERO_NFC_NDEF_MAX_TOTAL_BYTES) {
    return false;
  }
  out.clear();
  out.reserve(byte_len);
  for (std::size_t i = 0; i < compact.size(); i += kHexDigitsPerByte) {
    unsigned value = 0;
    auto *first = compact.data() + i;
    auto *last = first + kHexDigitsPerByte;
    auto [ptr, ec] = std::from_chars(first, last, value, kHexRadix);
    if (ec != std::errc{} || ptr != last || value > kMaxByteValue) {
      return false;
    }
    out.push_back(static_cast<std::uint8_t>(value));
  }
  return true;
}

} // namespace nero_nfc
