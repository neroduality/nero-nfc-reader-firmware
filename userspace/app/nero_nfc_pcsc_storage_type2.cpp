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
#include "nero_nfc_limits.h"
#include "nero_nfc_ndef.hpp"
#include "nero_nfc_pcsc_internal.hpp"
#include "nfc_pcsc_contactless.h"
#include "nfc_storage_ndef.h"
#include "nfc_tag_geometry_limits.h"
#include "nfc_tag_info.h"

#include <algorithm>
#include <iterator>
#include <limits>
#include <optional>
#include <ranges>
#include <sstream>
#include <utility>

namespace nero_nfc::pcsc_internal {

namespace {

constexpr std::uint8_t kType2StorageBulkReadBytes = static_cast<std::uint8_t>(
    (static_cast<unsigned>(NFC_ISO7816_SHORT_LC_MAX) /
     static_cast<unsigned>(NFC_STORAGE_TYPE2_UNIT_SIZE)) *
    static_cast<unsigned>(NFC_STORAGE_TYPE2_UNIT_SIZE));

}  // namespace

std::uint8_t Type2StorageBulkReadLen(std::uint16_t data_area_size) {
  const auto kCapped = static_cast<std::uint16_t>(
      std::min<std::uint16_t>(data_area_size, kType2StorageBulkReadBytes));
  return static_cast<std::uint8_t>((kCapped / NFC_STORAGE_TYPE2_UNIT_SIZE) *
                                   NFC_STORAGE_TYPE2_UNIT_SIZE);
}

#ifdef NERO_USERSPACE_HAVE_PCSC

bool ParseType2Cc(const std::vector<std::uint8_t>& cc,
                  nfc_tag_type2_info_t& info, std::string& err) {
  info = {};
  if (cc.size() < static_cast<std::size_t>(NFC_TAG_T2T_PAGE_SIZE_BYTES)) {
    err = "Type 2 CC read returned fewer than 4 bytes";
    return false;
  }
  nfc_tag_type2_apply_cc(
      &info, cc.data(), static_cast<std::uint8_t>(NFC_TAG_T2T_PAGE_SIZE_BYTES));
  if (!info.cc_valid || info.data_area_size_bytes == 0u) {
    err = "invalid Type 2 capability container";
    return false;
  }
  err.clear();
  return true;
}

bool ReadType2CcStorage(PcscCard& card, std::vector<std::uint8_t>& cc,
                        std::string& err) {
  if (cc.size() >= static_cast<std::size_t>(NFC_TAG_T2T_PAGE_SIZE_BYTES)) {
    cc.resize(static_cast<std::size_t>(NFC_TAG_T2T_PAGE_SIZE_BYTES));
    err.clear();
    return true;
  }
  if (!StorageReadBinary(
          card, static_cast<std::uint16_t>(NFC_STORAGE_TYPE2_CC_PAGE),
          static_cast<std::uint8_t>(NFC_STORAGE_TYPE2_UNIT_SIZE), cc, err)) {
    return false;
  }
  if (cc.size() < static_cast<std::size_t>(NFC_TAG_T2T_PAGE_SIZE_BYTES)) {
    err = "short Type 2 CC READ BINARY response";
    return false;
  }
  cc.resize(static_cast<std::size_t>(NFC_TAG_T2T_PAGE_SIZE_BYTES));
  err.clear();
  return true;
}

bool ReadType2Cc(PcscCard& card, std::vector<std::uint8_t>& cc,
                 std::string& err) {
  if (cc.size() < static_cast<std::size_t>(NFC_TAG_T2T_PAGE_SIZE_BYTES)) {
    std::vector<std::uint8_t> cached = TryGetDataBytes(
        card, NFC_PCSC_GET_DATA_TYPE2_CC, NFC_ISO7816_GET_DATA_P2_DEFAULT);
    if (!cached.empty()) {
      cc = std::move(cached);
    }
  }
  return ReadType2CcStorage(card, cc, err);
}

static bool ReadStorageNdefTlv(PcscCard& card, std::uint16_t first_unit,
                               std::uint8_t unit_size,
                               std::uint16_t tlv_start_offset,
                               std::uint16_t data_area_size,
                               const std::vector<std::uint8_t>& initial_raw,
                               PcscTagSnapshot& tag, std::string& err) {
  if (static_cast<std::uint32_t>(tlv_start_offset) +
          static_cast<std::uint32_t>(data_area_size) >
      std::numeric_limits<std::uint16_t>::max()) {
    err = "storage TLV area exceeds host address range";
    return false;
  }
  const auto kTotalLen =
      static_cast<std::uint16_t>(tlv_start_offset + data_area_size);
  auto units =
      static_cast<std::uint16_t>((static_cast<unsigned>(kTotalLen) +
                                  static_cast<unsigned>(unit_size) - 1u) /
                                 unit_size);
  if (first_unit == static_cast<std::uint16_t>(NFC_STORAGE_TYPE2_CC_PAGE) &&
      unit_size == static_cast<std::uint8_t>(NFC_STORAGE_TYPE2_UNIT_SIZE)) {
    const auto kCappedUnits = StorageType2ReadUnitLimit(
        first_unit, unit_size, tlv_start_offset, data_area_size);
    if (kCappedUnits != 0u && kCappedUnits < units) {
      units = kCappedUnits;
    }
  }
  const bool kType2StorageUnits =
      (first_unit == static_cast<std::uint16_t>(NFC_STORAGE_TYPE2_CC_PAGE)) &&
      (unit_size == static_cast<std::uint8_t>(NFC_STORAGE_TYPE2_UNIT_SIZE));
  std::vector<std::uint8_t> raw;
  raw.reserve(
      std::min<std::uint16_t>(kTotalLen, NFC_PCSC_ISO_DEP_APDU_RESP_MAX));
  if (!initial_raw.empty()) {
    const auto kSeedLen = static_cast<std::uint16_t>(
        std::min<std::size_t>(initial_raw.size(), kTotalLen));
    raw.insert(raw.end(), initial_raw.begin(),
               initial_raw.begin() + static_cast<std::ptrdiff_t>(kSeedLen));
  }

  uint16_t unit_index = 0u;
  if (!raw.empty() &&
      !nfc_storage_ceil_units_u16(static_cast<std::uint16_t>(raw.size()),
                                  unit_size, &unit_index)) {
    err = "invalid seeded storage READ BINARY geometry";
    return false;
  }
  auto scan_raw = [&]() -> std::optional<bool> {
    if (raw.size() <= tlv_start_offset) {
      return std::nullopt;
    }
    nfc_ndef_tlv_t tlv{};
    nfc_ndef_tlv_status_t const kStatus = nfc_ndef_find_message_tlv(
        raw.data(), static_cast<std::uint16_t>(raw.size()), tlv_start_offset,
        &tlv);
    if (kStatus == NFC_NDEF_TLV_OK) {
      tag.ndef_message_.assign(
          raw.begin() + static_cast<std::ptrdiff_t>(tlv.value_offset),
          raw.begin() +
              static_cast<std::ptrdiff_t>(tlv.value_offset + tlv.value_len));
      tag.records_ = ParseNdefRecords(tag.ndef_message_);
      err.clear();
      return true;
    }
    if (kStatus == NFC_NDEF_TLV_NOT_FOUND) {
      if (TlvAreaHasTerminator(raw, tlv_start_offset) ||
          raw.size() >= kTotalLen) {
        tag.ndef_message_.clear();
        tag.records_.clear();
        err.clear();
        return true;
      }
      return std::nullopt;
    }
    if (kStatus == NFC_NDEF_TLV_TRUNCATED) {
      return std::nullopt;
    }
    err = std::string("NDEF TLV ") + TlvStatusName(kStatus);
    return false;
  };
  if (auto seeded = scan_raw(); seeded.has_value()) {
    return *seeded;
  }
  for (; unit_index < units;) {
    const auto kCopied = static_cast<std::uint16_t>(raw.size());
    const auto kRemaining = static_cast<std::uint16_t>(kTotalLen - kCopied);
    const std::uint8_t kWant =
        static_cast<std::uint8_t>(std::min<std::uint16_t>(
            kType2StorageUnits ? NFC_TAG_T2T_READ_RESP_BYTES : unit_size,
            kRemaining));
    std::vector<std::uint8_t> chunk;
    std::uint16_t units_read = 0u;
    if (!StorageReadBinary(card,
                           static_cast<std::uint16_t>(first_unit + unit_index),
                           kWant, chunk, err)) {
      return false;
    }
    const auto kCopiedFromChunk =
        static_cast<std::uint16_t>(std::min<std::size_t>(chunk.size(), kWant));
    if ((kCopiedFromChunk == 0u) ||
        (!kType2StorageUnits && kCopiedFromChunk < kWant)) {
      err = "short storage READ BINARY response";
      return false;
    }
    raw.insert(raw.end(), chunk.begin(),
               chunk.begin() + static_cast<std::ptrdiff_t>(kCopiedFromChunk));
    if (!nfc_storage_ceil_units_u16(kCopiedFromChunk, unit_size, &units_read) ||
        (units_read == 0u)) {
      err = "invalid storage READ BINARY response geometry";
      return false;
    }
    unit_index = static_cast<std::uint16_t>(unit_index + units_read);
    if (raw.size() <= tlv_start_offset) {
      continue;
    }

    if (auto scanned = scan_raw(); scanned.has_value()) {
      return *scanned;
    }
  }

  tag.ndef_message_.clear();
  tag.records_.clear();
  err = "NDEF TLV truncated";
  return false;
}

bool ReadType2StorageNdef(PcscCard& card, PcscTagSnapshot& tag,
                          std::vector<std::uint8_t>& type2_cc,
                          std::string& err) {
  nfc_tag_type2_info_t info{};
  if (!ReadType2Cc(card, type2_cc, err) || !ParseType2Cc(type2_cc, info, err)) {
    return false;
  }
  tag.max_ndef_size_ = StorageTlvPayloadCap(info.data_area_size_bytes);
  tag.read_access_open_ = info.read_access_open;
  tag.write_access_open_ = info.write_access_open;
  if (!info.read_access_open) {
    err = "tag reports read access restricted";
    return false;
  }
  std::vector<std::uint8_t> initial_raw = type2_cc;
  return ReadStorageNdefTlv(
      card, static_cast<std::uint16_t>(NFC_STORAGE_TYPE2_CC_PAGE),
      static_cast<std::uint8_t>(NFC_STORAGE_TYPE2_UNIT_SIZE),
      static_cast<std::uint16_t>(NFC_STORAGE_TYPE2_FIRST_DATA_PAGE),
      info.data_area_size_bytes, initial_raw, tag, err);
}

bool WriteType2StorageNdef(PcscCard& card,
                           const std::vector<std::uint8_t>& ndef,
                           std::string& err) {
  std::vector<std::uint8_t> cc;
  std::vector<std::uint8_t> tlv_area;
  nfc_tag_type2_info_t info{};
  if (!ReadType2CcStorage(card, cc, err) || !ParseType2Cc(cc, info, err)) {
    return false;
  }
  if (!info.write_access_open) {
    err = "tag reports write access restricted";
    return false;
  }
  if (!BuildStorageNdefTlv(ndef, info.data_area_size_bytes, tlv_area, err)) {
    return false;
  }
  uint16_t pages = 0u;
  if ((tlv_area.size() > std::numeric_limits<std::uint16_t>::max()) ||
      !nfc_storage_ceil_units_u16(static_cast<std::uint16_t>(tlv_area.size()),
                                  NFC_STORAGE_TYPE2_UNIT_SIZE, &pages) ||
      ((pages != 0u) &&
       ((static_cast<uint32_t>(NFC_STORAGE_TYPE2_FIRST_DATA_PAGE) + pages -
         1u) > static_cast<uint32_t>(NERO_NFC_TYPE2_STORAGE_MAX_PAGE)))) {
    err = "Type 2 NDEF payload exceeds supported storage page range";
    return false;
  }
  return StorageWriteUnits(card, NFC_STORAGE_TYPE2_FIRST_DATA_PAGE,
                           NFC_STORAGE_TYPE2_UNIT_SIZE, tlv_area, err);
}

#endif  // NERO_USERSPACE_HAVE_PCSC

}  // namespace nero_nfc::pcsc_internal
