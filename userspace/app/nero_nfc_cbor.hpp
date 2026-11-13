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

// Minimal CTAP2 canonical CBOR ([RFC8949-CBOR-CTAP2]) for host CLIs: definite
// lengths only, integer/bytes/text/array/map/bool/null. Encoding sorts map
// keys into CTAP2 canonical order.

#pragma once

#include "nero_nfc_attrs.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace nero_nfc::cbor {

struct MapEntry;

class Value {
 public:
  enum class Kind : std::uint8_t {
    kUnsigned,
    kNegative,
    kBytes,
    kText,
    kArray,
    kMap,
    kBool,
    kNull,
  };

  Value();
  static Value Int(std::int64_t v);
  /* Full CBOR integer range: value is raw, or -1 - raw when negative. */
  static Value RawInt(bool negative, std::uint64_t raw);
  static Value Bytes(std::span<const std::uint8_t> v);
  static Value Text(std::string_view v);
  static Value Array(std::vector<Value> items);
  static Value Map(std::vector<MapEntry> entries);
  static Value Bool(bool v);
  static Value Null();

  [[nodiscard]] Kind GetKind() const { return kind_; }
  [[nodiscard]] bool IsUnsigned() const { return kind_ == Kind::kUnsigned; }
  [[nodiscard]] bool IsInt() const {
    return kind_ == Kind::kUnsigned || kind_ == Kind::kNegative;
  }
  [[nodiscard]] bool IsBytes() const { return kind_ == Kind::kBytes; }
  [[nodiscard]] bool IsText() const { return kind_ == Kind::kText; }
  [[nodiscard]] bool IsArray() const { return kind_ == Kind::kArray; }
  [[nodiscard]] bool IsMap() const { return kind_ == Kind::kMap; }
  [[nodiscard]] bool IsBool() const { return kind_ == Kind::kBool; }

  /* Raw head argument: the value for kUnsigned, n for kNegative (-1 - n). */
  [[nodiscard]] std::uint64_t Raw() const { return raw_; }
  /* False when the integer does not fit int64_t. */
  NERO_NFC_NODISCARD bool AsInt(std::int64_t& out) const;
  [[nodiscard]] bool AsBool() const { return raw_ != 0u; }
  [[nodiscard]] const std::vector<std::uint8_t>& AsBytes() const {
    return bytes_;
  }
  [[nodiscard]] const std::string& AsText() const { return text_; }
  [[nodiscard]] const std::vector<Value>& AsArray() const { return array_; }
  [[nodiscard]] const std::vector<MapEntry>& AsMap() const { return map_; }

  /* Map lookup by integer or text key; nullptr when absent or not a map. */
  [[nodiscard]] const Value* Find(std::int64_t key) const;
  [[nodiscard]] const Value* Find(std::string_view key) const;

 private:
  Kind kind_{Kind::kNull};
  std::uint64_t raw_{};
  std::vector<std::uint8_t> bytes_;
  std::string text_;
  std::vector<Value> array_;
  std::vector<MapEntry> map_;
};

struct MapEntry {
  Value key_;
  Value value_;
};

std::vector<std::uint8_t> Encode(const Value& value);
NERO_NFC_NODISCARD bool Decode(std::span<const std::uint8_t> in, Value& out,
                               std::string& err);

}  // namespace nero_nfc::cbor
