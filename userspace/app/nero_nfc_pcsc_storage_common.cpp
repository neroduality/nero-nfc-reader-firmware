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
#include "nero_nfc_ndef.h"
#include "nero_nfc_null.h"
#include "nero_nfc_pcsc_internal.h"
#include "nfc_pcsc_contactless.h"
#include "nfc_storage_ndef.h"
#include "nfc_tag_geometry_limits.h"
#include "nfc_tag_info.h"

#include <algorithm>
#include <iterator>
#include <limits>
#include <ranges>
#include <sstream>
#include <utility>

namespace nero_nfc::pcsc_internal {

const char *tlv_status_name(nfc_ndef_tlv_status_t status) {
  switch (status) {
  case NFC_NDEF_TLV_OK:
    return "ok";
  case NFC_NDEF_TLV_NOT_FOUND:
    return "not found";
  case NFC_NDEF_TLV_TRUNCATED:
    return "truncated";
  case NFC_NDEF_TLV_INVALID_ARG:
    return "invalid argument";
  case NFC_NDEF_TLV_TOO_LARGE:
    return "too large";
  default:
    return "unknown";
  }
}

bool extract_ndef_from_tlv_area(const std::vector<std::uint8_t> &tlv_area,
                                std::uint16_t start_offset, PcscTagSnapshot &tag,
                                std::string &err) {
  nfc_ndef_tlv_t tlv{};
  nfc_ndef_tlv_status_t const status = nfc_ndef_find_message_tlv(
    tlv_area.data(), static_cast<std::uint16_t>(tlv_area.size()), start_offset, &tlv);
  if (status == NFC_NDEF_TLV_NOT_FOUND) {
    tag.ndef_message.clear();
    tag.records.clear();
    err.clear();
    return true;
  }
  if (status != NFC_NDEF_TLV_OK) {
    err = std::string("NDEF TLV ") + tlv_status_name(status);
    return false;
  }
  tag.ndef_message.assign(tlv_area.begin() + static_cast<std::ptrdiff_t>(tlv.value_offset),
                          tlv_area.begin() +
                            static_cast<std::ptrdiff_t>(tlv.value_offset + tlv.value_len));
  tag.records = parse_ndef_records(tag.ndef_message);
  err.clear();
  return true;
}

bool build_storage_ndef_tlv(const std::vector<std::uint8_t> &ndef, std::uint16_t data_area_size,
                            std::vector<std::uint8_t> &tlv_area, std::string &err) {
  std::uint16_t tlv_len = 0u;
  if (ndef.size() > NERO_NFC_NDEF_MAX_TOTAL_BYTES) {
    err = "NDEF payload exceeds host parse limit";
    tlv_area.clear();
    return false;
  }
  if (ndef.size() > static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max())) {
    err = "NDEF payload exceeds host storage TLV limit";
    tlv_area.clear();
    return false;
  }
  tlv_area.assign(data_area_size, 0u);
  if (!nfc_ndef_build_message_tlv(ndef.data(), static_cast<std::uint16_t>(ndef.size()),
                                  tlv_area.data(), data_area_size, &tlv_len)) {
    err = "NDEF payload exceeds tag data area";
    tlv_area.clear();
    return false;
  }
  tlv_area.resize(tlv_len);
  err.clear();
  return true;
}

std::uint16_t storage_tlv_payload_cap(std::uint16_t data_area_size) {
  return nfc_ndef_tlv_max_payload_for_data_area(data_area_size);
}

std::vector<std::uint8_t> normalize_type5_uid(std::vector<std::uint8_t> uid) {
  if (uid.size() == NFC_TAG_T5T_ISO15693_SYS_INFO_UID_FIELD_LEN &&
      uid[NFC_TAG_T5T_ISO15693_UID_MSB_BYTE_INDEX] ==
        static_cast<std::uint8_t>(NFC_TAG_T4T_RATS_START_BYTE) &&
      uid[0] != static_cast<std::uint8_t>(NFC_TAG_T4T_RATS_START_BYTE)) {
    std::ranges::reverse(uid);
  }
  return uid;
}

bool build_select_apdu(std::uint8_t p1, std::uint8_t p2, const std::vector<std::uint8_t> &data,
                       std::vector<std::uint8_t> &capdu, std::string &err) {
  if (data.empty() || data.size() > static_cast<std::size_t>(NFC_BYTE_VALUE_MAX)) {
    err = "SELECT data length is invalid";
    capdu.clear();
    return false;
  }
  capdu = {static_cast<std::uint8_t>(NFC_ISO7816_CLA_ISO),
           static_cast<std::uint8_t>(NFC_ISO7816_INS_SELECT), p1, p2,
           static_cast<std::uint8_t>(data.size())};
  capdu.insert(capdu.end(), data.begin(), data.end());
  capdu.push_back(static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS));
  err.clear();
  return true;
}

std::uint16_t storage_cap_data_area_scan(std::uint16_t data_area_size, std::uint16_t scan_max) {
  return nfc_storage_cap_scan_bytes(data_area_size, scan_max);
}

std::uint16_t storage_type2_read_unit_limit(std::uint16_t first_unit, std::uint8_t unit_size,
                                            std::uint16_t tlv_start_offset,
                                            std::uint16_t data_area_size) {
  return nfc_storage_type2_read_unit_limit(
    first_unit, unit_size, tlv_start_offset, data_area_size,
    static_cast<std::uint16_t>(NERO_NFC_TYPE2_STORAGE_NDEF_SCAN_MAX));
}

std::uint16_t storage_type5_read_block_limit(std::uint16_t tlv_start_offset,
                                             std::uint16_t data_area_size) {
  return nfc_storage_type5_read_block_limit(
    tlv_start_offset, data_area_size, static_cast<std::uint16_t>(NERO_NFC_TYPE5_STORAGE_READ_MAX));
}

bool tlv_area_has_terminator(const std::vector<std::uint8_t> &raw, std::uint16_t start_offset) {
  if (start_offset >= raw.size()) {
    return false;
  }
  return std::ranges::find(raw.begin() + static_cast<std::ptrdiff_t>(start_offset), raw.end(),
                           NFC_NDEF_TLV_TERMINATOR) != raw.end();
}

#ifdef NERO_USERSPACE_HAVE_PCSC

bool storage_read_binary_apdu(PcscCard &card, std::uint8_t p1, std::uint8_t p2, std::uint8_t len,
                              std::vector<std::uint8_t> &data, std::string &err) {
  auto read_with_len = [&](std::uint8_t le, std::uint8_t &sw1, std::uint8_t &sw2) {
    std::vector<std::uint8_t> rapdu;
    if (!card.transmit({static_cast<std::uint8_t>(NFC_ISO7816_CLA_PROPRIETARY),
                        static_cast<std::uint8_t>(NFC_ISO7816_INS_READ_BINARY), p1, p2, le},
                       rapdu, err)) {
      return false;
    }
    if (status_ok(rapdu)) {
      data = without_status(rapdu);
      err.clear();
      return true;
    }
    if (rapdu.size() >= static_cast<std::size_t>(NFC_PCSC_T4_NLEN_LEN)) {
      sw1 = rapdu[rapdu.size() - static_cast<std::size_t>(NFC_PCSC_T4_NLEN_LEN)];
      sw2 = rapdu.back();
      std::ostringstream msg;
      msg << "APDU SW=" << hex_bytes({sw1, sw2}, '\0');
      err = msg.str();
    } else {
      sw1 = 0u;
      sw2 = 0u;
      err = "APDU response missing status word";
    }
    return false;
  };

  std::uint8_t sw1 = 0u;
  std::uint8_t sw2 = 0u;
  data.clear();
  if (read_with_len(len, sw1, sw2)) {
    return true;
  }
  if (sw1 == static_cast<std::uint8_t>(NFC_ISO7816_SW1_WRONG_LENGTH) && sw2 != len) {
    if (read_with_len(sw2, sw1, sw2)) {
      return true;
    }
  }
  if (sw1 == static_cast<std::uint8_t>(NFC_ISO7816_SW1_WRONG_LENGTH_ALT) &&
      sw2 == static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS) &&
      len != static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS)) {
    if (read_with_len(static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS), sw1, sw2)) {
      return true;
    }
  }
  return false;
}

bool storage_read_binary(PcscCard &card, std::uint16_t unit, std::uint8_t len,
                         std::vector<std::uint8_t> &data, std::string &err) {
  return storage_read_binary_apdu(
    card,
    static_cast<std::uint8_t>(unit >> static_cast<unsigned>(NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES)),
    static_cast<std::uint8_t>(unit & static_cast<unsigned>(NFC_BYTE_VALUE_MAX)), len, data, err);
}

static bool type5_block_byte_offset(std::uint16_t block, std::uint16_t &offset) {
  if (block > (std::numeric_limits<std::uint16_t>::max() / NFC_STORAGE_TYPE5_BLOCK_SIZE)) {
    offset = 0u;
    return false;
  }
  offset = static_cast<std::uint16_t>(block * NFC_STORAGE_TYPE5_BLOCK_SIZE);
  return true;
}

bool type5_storage_read_binary(PcscCard &card, std::uint16_t block, std::uint8_t len,
                               std::vector<std::uint8_t> &data, std::string &err) {
  std::string block_address_err;
  std::uint16_t byte_offset = 0u;
  if (block <= static_cast<std::uint16_t>(NFC_TAG_T5T_ISO15693_BLOCK_ADDR_1BYTE_MAX)) {
    if (storage_read_binary_apdu(card, static_cast<std::uint8_t>(NFC_ISO7816_CLA_PROPRIETARY),
                                 static_cast<std::uint8_t>(block), len, data, err)) {
      return true;
    }
    block_address_err = err;
  }
  if (!type5_block_byte_offset(block, byte_offset)) {
    err = "Type 5 block offset exceeds host READ BINARY range";
    return false;
  }
  if (storage_read_binary(card, byte_offset, len, data, err)) {
    return true;
  }
  if (!block_address_err.empty() && block_address_err != err) {
    err = block_address_err + "; generic offset: " + err;
  }
  return false;
}

bool type5_storage_read_binary(PcscCard &card, std::uint16_t block, std::vector<std::uint8_t> &data,
                               std::string &err) {
  return type5_storage_read_binary(
    card, block, static_cast<std::uint8_t>(NFC_STORAGE_TYPE5_BLOCK_SIZE), data, err);
}

bool storage_update_binary_apdu(PcscCard &card, std::uint8_t p1, std::uint8_t p2,
                                const std::vector<std::uint8_t> &bytes, std::string &err) {
  if (bytes.empty() || bytes.size() > static_cast<std::size_t>(NFC_BYTE_VALUE_MAX)) {
    err = "storage UPDATE BINARY chunk size is invalid";
    return false;
  }
  std::vector<std::uint8_t> capdu;
  capdu.reserve(static_cast<std::size_t>(NFC_ISO7816_SHORT_APDU_HDR_LEN) + bytes.size());
  capdu.push_back(static_cast<std::uint8_t>(NFC_ISO7816_CLA_PROPRIETARY));
  capdu.push_back(static_cast<std::uint8_t>(NFC_ISO7816_INS_UPDATE_BINARY));
  capdu.push_back(p1);
  capdu.push_back(p2);
  capdu.push_back(static_cast<std::uint8_t>(bytes.size()));
  capdu.insert(capdu.end(), bytes.begin(), bytes.end());
  std::vector<std::uint8_t> response;
  return transmit_ok(card, capdu, response, err);
}

bool storage_update_binary(PcscCard &card, std::uint16_t unit,
                           const std::vector<std::uint8_t> &bytes, std::string &err) {
  return storage_update_binary_apdu(
    card,
    static_cast<std::uint8_t>(unit >> static_cast<unsigned>(NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES)),
    static_cast<std::uint8_t>(unit & static_cast<unsigned>(NFC_BYTE_VALUE_MAX)), bytes, err);
}

bool type5_storage_update_binary(PcscCard &card, std::uint16_t block,
                                 const std::vector<std::uint8_t> &bytes, std::string &err) {
  std::string block_address_err;
  std::uint16_t byte_offset = 0u;
  if (block <= static_cast<std::uint16_t>(NFC_TAG_T5T_ISO15693_BLOCK_ADDR_1BYTE_MAX)) {
    if (storage_update_binary_apdu(card, static_cast<std::uint8_t>(NFC_ISO7816_CLA_PROPRIETARY),
                                   static_cast<std::uint8_t>(block), bytes, err)) {
      return true;
    }
    block_address_err = err;
  }
  if (!type5_block_byte_offset(block, byte_offset)) {
    err = "Type 5 block offset exceeds host UPDATE BINARY range";
    return false;
  }
  if (storage_update_binary(card, byte_offset, bytes, err)) {
    return true;
  }
  if (!block_address_err.empty() && block_address_err != err) {
    err = block_address_err + "; generic offset: " + err;
  }
  return false;
}

bool storage_write_units(PcscCard &card, std::uint16_t first_unit, std::uint8_t unit_size,
                         const std::vector<std::uint8_t> &bytes, std::string &err) {
  return storage_write_units_with_io(card, {}, first_unit, unit_size, bytes,
                                     type2_storage_write_unit, err);
}

bool storage_write_units_with_io(PcscCard &card, const std::vector<std::uint8_t> &uid,
                                 std::uint16_t first_unit, std::uint8_t unit_size,
                                 const std::vector<std::uint8_t> &bytes,
                                 StorageWriteUnitFn write_unit, std::string &err) {
  constexpr std::uint16_t kStorageShortLcMax = static_cast<std::uint16_t>(NFC_ISO7816_SHORT_LC_MAX);
  constexpr std::uint16_t kStorageWriteUnitAlignment =
    static_cast<std::uint16_t>(NFC_STORAGE_TYPE2_UNIT_SIZE);
  constexpr std::uint16_t kStorageWriteApduDataMax = static_cast<std::uint16_t>(
    kStorageShortLcMax - (kStorageShortLcMax % kStorageWriteUnitAlignment));

  if (unit_size == 0u) {
    err = "invalid storage write geometry";
    return false;
  }
  if (write_unit == NERO_NFC_NULL) {
    err = "invalid storage write callbacks";
    return false;
  }
  if (bytes.size() > std::numeric_limits<std::uint16_t>::max()) {
    err = "storage write image exceeds addressable unit range";
    return false;
  }
  const auto units =
    static_cast<std::uint16_t>((bytes.size() + static_cast<std::size_t>(unit_size) - 1u) /
                               static_cast<std::size_t>(unit_size));
  if (units != 0u &&
      (static_cast<std::uint32_t>(first_unit) + static_cast<std::uint32_t>(units) >
       (static_cast<std::uint32_t>(std::numeric_limits<std::uint16_t>::max()) + 1u))) {
    err = "storage write crosses addressable unit range";
    return false;
  }
  const std::uint16_t max_units_per_apdu =
    std::max<std::uint16_t>(1u, static_cast<std::uint16_t>(kStorageWriteApduDataMax / unit_size));
  for (std::uint16_t unit_index = 0u; unit_index < units;) {
    const auto off = static_cast<std::size_t>(unit_index) * static_cast<std::size_t>(unit_size);
    const auto remaining_units = static_cast<std::uint16_t>(units - unit_index);
    std::uint16_t chunk_units = std::min<std::uint16_t>(remaining_units, max_units_per_apdu);
    const auto unit = static_cast<std::uint16_t>(first_unit + unit_index);
    auto make_chunk = [&](std::uint16_t chunk_unit_count) {
      std::vector<std::uint8_t> chunk(static_cast<std::size_t>(chunk_unit_count) * unit_size, 0u);
      const auto left = static_cast<std::uint16_t>(bytes.size() - off);
      const auto chunk_len =
        std::min<std::uint16_t>(static_cast<std::uint16_t>(chunk.size()), left);
      std::ranges::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(off), chunk_len,
                          chunk.begin());
      return chunk;
    };

    if (chunk_units > 1u) {
      std::vector<std::uint8_t> chunk = make_chunk(chunk_units);
      if (write_unit(card, uid, unit, chunk, err)) {
        unit_index = static_cast<std::uint16_t>(unit_index + chunk_units);
        continue;
      }
    }
    chunk_units = 1u;
    std::vector<std::uint8_t> chunk = make_chunk(chunk_units);
    if (!write_unit(card, uid, unit, chunk, err)) {
      return false;
    }
    unit_index = static_cast<std::uint16_t>(unit_index + chunk_units);
  }
  err.clear();
  return true;
}

bool type2_storage_write_unit(PcscCard &card, const std::vector<std::uint8_t> &uid,
                              std::uint16_t unit, const std::vector<std::uint8_t> &bytes,
                              std::string &err) {
  (void)uid;
  return storage_update_binary(card, unit, bytes, err);
}

#endif // NERO_USERSPACE_HAVE_PCSC

} // namespace nero_nfc::pcsc_internal
