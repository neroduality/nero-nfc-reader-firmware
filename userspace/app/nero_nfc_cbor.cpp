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

#include "nero_nfc_cbor.hpp"
#include "nero_nfc_null.h"

#include <algorithm>
#include <iterator>
#include <limits>
#include <utility>

namespace nero_nfc::cbor {

namespace {

enum : std::uint8_t {
  kMajorUnsigned = 0u,
  kMajorNegative = 1u,
  kMajorBytes = 2u,
  kMajorText = 3u,
  kMajorArray = 4u,
  kMajorMap = 5u,
  kMajorTag = 6u,
  kMajorSimple = 7u,
  kMajorShift = 5u,
  kInfoMask = 0x1Fu,
  kInfoInlineMax = 23u,
  kInfoUint8 = 24u,
  kInfoUint16 = 25u,
  kInfoUint32 = 26u,
  kInfoUint64 = 27u,
  kSimpleFalse = 20u,
  kSimpleTrue = 21u,
  kSimpleNull = 22u,
  kByteBits = 8u,
  /* A map entry is a key and a value, each at least one byte. */
  kMinMapEntryBytes = 2u,
};

/* CTAP2 messages nest at most a few levels (getInfo -> algorithms -> map). */
inline constexpr std::size_t kMaxDecodeDepth = 8u;

void EncodeHead(std::uint8_t major, std::uint64_t arg,
                std::vector<std::uint8_t>& out) {
  const auto major_bits = static_cast<std::uint8_t>(major << kMajorShift);
  std::size_t width = 0u;
  if (arg <= kInfoInlineMax) {
    out.push_back(static_cast<std::uint8_t>(major_bits | arg));
    return;
  }
  if (arg <= std::numeric_limits<std::uint8_t>::max()) {
    out.push_back(static_cast<std::uint8_t>(major_bits | kInfoUint8));
    width = 1u;
  } else if (arg <= std::numeric_limits<std::uint16_t>::max()) {
    out.push_back(static_cast<std::uint8_t>(major_bits | kInfoUint16));
    width = sizeof(std::uint16_t);
  } else if (arg <= std::numeric_limits<std::uint32_t>::max()) {
    out.push_back(static_cast<std::uint8_t>(major_bits | kInfoUint32));
    width = sizeof(std::uint32_t);
  } else {
    out.push_back(static_cast<std::uint8_t>(major_bits | kInfoUint64));
    width = sizeof(std::uint64_t);
  }
  for (std::size_t i = width; i > 0u; --i) {
    out.push_back(static_cast<std::uint8_t>(arg >> ((i - 1u) * kByteBits)));
  }
}

void EncodeInto(const Value& value, std::vector<std::uint8_t>& out) {
  /* NERO_NFC_BOUNDED_RECURSION max depth: kMaxDecodeDepth (CLI-built requests
   * nest at most three levels; decoded values are capped on input). */
  switch (value.GetKind()) {
    case Value::Kind::kUnsigned:
      EncodeHead(kMajorUnsigned, value.Raw(), out);
      break;
    case Value::Kind::kNegative:
      EncodeHead(kMajorNegative, value.Raw(), out);
      break;
    case Value::Kind::kBytes:
      EncodeHead(kMajorBytes, value.AsBytes().size(), out);
      out.insert(out.end(), value.AsBytes().begin(), value.AsBytes().end());
      break;
    case Value::Kind::kText:
      EncodeHead(kMajorText, value.AsText().size(), out);
      out.insert(out.end(), value.AsText().begin(), value.AsText().end());
      break;
    case Value::Kind::kArray:
      EncodeHead(kMajorArray, value.AsArray().size(), out);
      for (const Value& item : value.AsArray()) {
        EncodeInto(item, out);
      }
      break;
    case Value::Kind::kMap: {
      /* [RFC8949-CBOR-CTAP2] CTAP2 canonical form: keys sorted by encoded
       * length, then bytewise. */
      std::vector<std::pair<std::vector<std::uint8_t>, const Value*>> entries;
      entries.reserve(value.AsMap().size());
      for (const MapEntry& entry : value.AsMap()) {
        entries.emplace_back(Encode(entry.key_), &entry.value_);
      }
      std::ranges::sort(entries, [](const auto& a, const auto& b) {
        if (a.first.size() != b.first.size()) {
          return a.first.size() < b.first.size();
        }
        return a.first < b.first;
      });
      EncodeHead(kMajorMap, entries.size(), out);
      for (const auto& [key_bytes, item] : entries) {
        out.insert(out.end(), key_bytes.begin(), key_bytes.end());
        EncodeInto(*item, out);
      }
      break;
    }
    case Value::Kind::kBool:
      out.push_back(static_cast<std::uint8_t>(
          (static_cast<std::uint32_t>(kMajorSimple) << kMajorShift) |
          (value.AsBool() ? kSimpleTrue : kSimpleFalse)));
      break;
    case Value::Kind::kNull:
      out.push_back(static_cast<std::uint8_t>(
          (static_cast<std::uint32_t>(kMajorSimple) << kMajorShift) |
          kSimpleNull));
      break;
  }
}

class Decoder {
 public:
  explicit Decoder(std::span<const std::uint8_t> in) : in_(in) {}

  bool DecodeValue(Value& out, std::size_t depth, std::string& err) {
    /* NERO_NFC_BOUNDED_RECURSION max depth: kMaxDecodeDepth. */
    if (depth > kMaxDecodeDepth) {
      err = "CBOR nesting too deep";
      return false;
    }
    std::uint8_t initial = 0u;
    if (!Byte(initial, err)) {
      return false;
    }
    const auto major = static_cast<std::uint8_t>(initial >> kMajorShift);
    const auto info = static_cast<std::uint8_t>(initial & kInfoMask);
    if (major == kMajorSimple) {
      return DecodeSimple(info, out, err);
    }
    std::uint64_t arg = 0u;
    if (!Argument(info, arg, err)) {
      return false;
    }
    switch (major) {
      case kMajorUnsigned:
        out = Value::RawInt(false, arg);
        return true;
      case kMajorNegative:
        out = Value::RawInt(true, arg);
        return true;
      case kMajorBytes: {
        std::span<const std::uint8_t> body;
        if (!Take(arg, body, err)) {
          return false;
        }
        out = Value::Bytes(body);
        return true;
      }
      case kMajorText: {
        std::span<const std::uint8_t> body;
        if (!Take(arg, body, err)) {
          return false;
        }
        out = Value::Text(std::string_view(
            reinterpret_cast<const char*>(body.data()), body.size()));
        return true;
      }
      case kMajorArray: {
        if (arg > Remaining()) {
          err = "CBOR array length exceeds input";
          return false;
        }
        std::vector<Value> items(static_cast<std::size_t>(arg));
        for (Value& item : items) {
          if (!DecodeValue(item, depth + 1u, err)) {
            return false;
          }
        }
        out = Value::Array(std::move(items));
        return true;
      }
      case kMajorMap: {
        if (arg > Remaining() / kMinMapEntryBytes) {
          err = "CBOR map length exceeds input";
          return false;
        }
        std::vector<MapEntry> entries(static_cast<std::size_t>(arg));
        for (MapEntry& entry : entries) {
          if (!DecodeValue(entry.key_, depth + 1u, err) ||
              !DecodeValue(entry.value_, depth + 1u, err)) {
            return false;
          }
        }
        out = Value::Map(std::move(entries));
        return true;
      }
      case kMajorTag:
      default:
        err = "CBOR tags are not used by CTAP2";
        return false;
    }
  }

  [[nodiscard]] std::size_t Remaining() const { return in_.size() - pos_; }

 private:
  bool Byte(std::uint8_t& out, std::string& err) {
    if (pos_ >= in_.size()) {
      err = "truncated CBOR";
      return false;
    }
    out = *std::next(in_.begin(), static_cast<std::ptrdiff_t>(pos_));
    ++pos_;
    return true;
  }

  bool Take(std::uint64_t len, std::span<const std::uint8_t>& out,
            std::string& err) {
    if (len > Remaining()) {
      err = "truncated CBOR string";
      return false;
    }
    out = in_.subspan(pos_, static_cast<std::size_t>(len));
    pos_ += static_cast<std::size_t>(len);
    return true;
  }

  bool Argument(std::uint8_t info, std::uint64_t& out, std::string& err) {
    std::size_t width = 0u;
    if (info <= kInfoInlineMax) {
      out = info;
      return true;
    }
    switch (info) {
      case kInfoUint8:
        width = 1u;
        break;
      case kInfoUint16:
        width = sizeof(std::uint16_t);
        break;
      case kInfoUint32:
        width = sizeof(std::uint32_t);
        break;
      case kInfoUint64:
        width = sizeof(std::uint64_t);
        break;
      default:
        err = "indefinite or reserved CBOR length";
        return false;
    }
    out = 0u;
    for (std::size_t i = 0u; i < width; ++i) {
      std::uint8_t b = 0u;
      if (!Byte(b, err)) {
        return false;
      }
      out = (out << kByteBits) | b;
    }
    return true;
  }

  static bool DecodeSimple(std::uint8_t info, Value& out, std::string& err) {
    switch (info) {
      case kSimpleFalse:
        out = Value::Bool(false);
        return true;
      case kSimpleTrue:
        out = Value::Bool(true);
        return true;
      case kSimpleNull:
        out = Value::Null();
        return true;
      default:
        err = "unsupported CBOR simple/float value";
        return false;
    }
  }

  std::span<const std::uint8_t> in_;
  std::size_t pos_{};
};

}  // namespace

Value::Value() = default;

Value Value::Int(std::int64_t v) {
  return v >= 0 ? RawInt(false, static_cast<std::uint64_t>(v))
                : RawInt(true, static_cast<std::uint64_t>(-(v + 1)));
}

Value Value::RawInt(bool negative, std::uint64_t raw) {
  Value out;
  out.kind_ = negative ? Kind::kNegative : Kind::kUnsigned;
  out.raw_ = raw;
  return out;
}

Value Value::Bytes(std::span<const std::uint8_t> v) {
  Value out;
  out.kind_ = Kind::kBytes;
  out.bytes_.assign(v.begin(), v.end());
  return out;
}

Value Value::Text(std::string_view v) {
  Value out;
  out.kind_ = Kind::kText;
  out.text_ = v;
  return out;
}

Value Value::Array(std::vector<Value> items) {
  Value out;
  out.kind_ = Kind::kArray;
  out.array_ = std::move(items);
  return out;
}

Value Value::Map(std::vector<MapEntry> entries) {
  Value out;
  out.kind_ = Kind::kMap;
  out.map_ = std::move(entries);
  return out;
}

Value Value::Bool(bool v) {
  Value out;
  out.kind_ = Kind::kBool;
  out.raw_ = v ? 1u : 0u;
  return out;
}

Value Value::Null() { return Value{}; }

bool Value::AsInt(std::int64_t& out) const {
  constexpr auto kMax =
      static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
  if (!IsInt() || raw_ > kMax) {
    return false;
  }
  out = kind_ == Kind::kUnsigned ? static_cast<std::int64_t>(raw_)
                                 : -1 - static_cast<std::int64_t>(raw_);
  return true;
}

const Value* Value::Find(std::int64_t key) const {
  if (!IsMap()) {
    return NERO_NFC_NULL;
  }
  for (const MapEntry& entry : map_) {
    std::int64_t k = 0;
    if (entry.key_.AsInt(k) && k == key) {
      return &entry.value_;
    }
  }
  return NERO_NFC_NULL;
}

const Value* Value::Find(std::string_view key) const {
  if (!IsMap()) {
    return NERO_NFC_NULL;
  }
  for (const MapEntry& entry : map_) {
    if (entry.key_.IsText() && entry.key_.AsText() == key) {
      return &entry.value_;
    }
  }
  return NERO_NFC_NULL;
}

std::vector<std::uint8_t> Encode(const Value& value) {
  std::vector<std::uint8_t> out;
  EncodeInto(value, out);
  return out;
}

bool Decode(std::span<const std::uint8_t> in, Value& out, std::string& err) {
  Decoder decoder(in);
  if (!decoder.DecodeValue(out, 0u, err)) {
    return false;
  }
  if (decoder.Remaining() != 0u) {
    err = "trailing bytes after CBOR item";
    return false;
  }
  err.clear();
  return true;
}

}  // namespace nero_nfc::cbor
