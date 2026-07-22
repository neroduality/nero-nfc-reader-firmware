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

#include "nero_nfc_null.h"
#include <span>
#include "nero_nfc_pcsc_tag_details.hpp"

#include "nfc_pcsc_contactless.h"
#include "nfc_ndef_tlv.h"
#include "nfc_tag_geometry_limits.h"
#include "nfc_tag_info.h"
#include "nero_nfc_mem_util.h"

#include <algorithm>
#include <cstddef>
#include <numeric>
#include <optional>
#include <ranges>
#include <sstream>
#include <string_view>
#include <vector>

namespace nero_nfc {
namespace {

/* Standard Get System Info optional one-byte fields: DSFID, AFI, and IC
 * reference. */
constexpr std::size_t kType5StandardSystemInfoOneByteOptionalFields = 3u;
constexpr std::size_t kType5StandardSystemInfoMaxLen =
    static_cast<std::size_t>(NFC_TAG_T5T_ISO15693_SYS_INFO_PREAMBLE_LEN) +
    static_cast<std::size_t>(NFC_TAG_T5T_ISO15693_SYS_INFO_UID_FIELD_LEN) +
    static_cast<std::size_t>(NFC_TAG_T5T_ISO15693_MEMORY_SIZE_FIELD_LEN) +
    kType5StandardSystemInfoOneByteOptionalFields;

/* The PC/SC storage ATR places the standard byte (SS) immediately after the
 * RID, followed by a 2-byte card name; require all three (plus the TCK) to be
 * present. */
enum : std::size_t {
  kStorageAtrSsByteLen = 1u,
  kStorageAtrCardNameLen = 2u,
  kStorageAtrSsAndNameLen = kStorageAtrSsByteLen + kStorageAtrCardNameLen,
};

bool FirstHexByte(std::string_view text, std::uint8_t& value_out) {
  std::vector<std::uint8_t> bytes;
  if (!ParseHexBytes(text, bytes) || bytes.empty()) {
    return false;
  }
  value_out = bytes.front();
  return true;
}

std::string HexU8(std::uint8_t value) { return HexBytes({value}, '\0'); }

}  // namespace

void ApplyStorageAtrHint(PcscTagSnapshot& tag) {
  std::vector<std::uint8_t> atr;
  if (!ParseHexBytes(tag.atr_hex_, atr) ||
      atr.size() < static_cast<std::size_t>(NFC_ISO7816_HISTORICAL_BYTES_MAX)) {
    return;
  }
  /* [PCSC-P3] §3.1.3 / [ISO7816-3] §8 — validate the contactless storage ATR
   * before trusting its contents: TS must be 0x3B (direct convention), and the
   * trailing TCK must make the XOR of T0..TCK zero. Fail closed (no hint) on a
   * malformed ATR rather than scanning arbitrary bytes for the RID. */
  if (atr[0] != static_cast<std::uint8_t>(NFC_ISO7816_ATR_TS)) {
    return;
  }
  std::uint8_t tck =
      std::accumulate(atr.begin() + 1, atr.end(), static_cast<std::uint8_t>(0u),
                      [](std::uint8_t acc, std::uint8_t b) {
                        return static_cast<std::uint8_t>(acc ^ b);
                      });
  if (tck != 0u) {
    return;
  }
  auto match = std::ranges::search(atr, NFC_PCSC_STORAGE_RID);
  if (match.empty()) {
    return;
  }
  std::size_t pos = static_cast<std::size_t>(match.begin() - atr.begin()) +
                    NFC_PCSC_STORAGE_RID_LEN;
  if (pos + kStorageAtrSsAndNameLen >= atr.size()) {
    return;
  }
  switch (atr[pos]) {
    case static_cast<std::uint8_t>(NFC_PCSC_STORAGE_STANDARD_ISO14443A):
      tag.tag_type_ = "PC/SC storage: ISO 14443-3A / NFC Forum Type 2";
      break;
    case static_cast<std::uint8_t>(NFC_PCSC_STORAGE_STANDARD_ISO15693):
      tag.tag_type_ = "PC/SC storage: ISO 15693 / NFC Forum Type 5";
      break;
    default:
      break;
  }
}

void ApplyType4ContactlessHint(PcscTagSnapshot& tag) {
  std::uint8_t sak = 0u;
  if (!tag.tag_type_.empty()) {
    return;
  }
  if (!tag.ats_hex_.empty()) {
    tag.tag_type_ =
        "ISO 14443-4 / NFC Forum Type 4-compatible contactless smartcard";
    return;
  }
  if (FirstHexByte(tag.sak_hex_, sak) &&
      ((sak & static_cast<std::uint8_t>(NFC_TAG_T4T_SAK_ISO14443_4_BIT)) !=
       0u)) {
    tag.tag_type_ =
        "ISO 14443-4 / NFC Forum Type 4-compatible contactless smartcard";
  }
}

bool HasPcscStorageHint(const PcscTagSnapshot& tag) {
  return tag.tag_type_.starts_with("PC/SC storage:");
}

bool IsPcscStorageType2(const PcscTagSnapshot& tag) {
  return tag.tag_type_ == "PC/SC storage: ISO 14443-3A / NFC Forum Type 2";
}

bool IsPcscStorageType5(const PcscTagSnapshot& tag) {
  return tag.tag_type_ == "PC/SC storage: ISO 15693 / NFC Forum Type 5";
}

bool LooksLikeNtag21xVersion(const std::vector<std::uint8_t>& version) {
  nfc_tag_type2_info_t info{};
  if (version.size() > static_cast<std::size_t>(NFC_BYTE_VALUE_MAX)) {
    return false;
  }
  nfc_tag_type2_apply_version(&info, version.data(),
                              static_cast<std::uint8_t>(version.size()));
  return info.family == NFC_TAG_TYPE2_FAMILY_NTAG21X;
}

void AppendDetailLine(PcscTagSnapshot& tag, std::string line) {
  if (!line.empty()) {
    tag.detail_lines_.push_back(std::move(line));
  }
}

void ApplyType2Details(PcscTagSnapshot& tag,
                       const std::vector<std::uint8_t>& uid,
                       const std::vector<std::uint8_t>& version,
                       const std::vector<std::uint8_t>& cc,
                       const std::vector<std::uint8_t>& signature,
                       const std::optional<std::uint8_t>& auth0) {
  nfc_tag_type2_info_t info{};
  const char* manufacturer = NERO_NFC_NULL;
  const char* family = NERO_NFC_NULL;

  if (!version.empty()) {
    nfc_tag_type2_apply_version(&info, version.data(),
                                static_cast<std::uint8_t>(version.size()));
  }
  if (!cc.empty()) {
    nfc_tag_type2_apply_cc(&info, cc.data(),
                           static_cast<std::uint8_t>(cc.size()));
  }
  if (!signature.empty()) {
    nfc_tag_type2_apply_signature(&info, signature.data(),
                                  static_cast<std::uint8_t>(signature.size()));
  }
  if (auth0.has_value()) {
    nfc_tag_type2_apply_auth0(&info, *auth0);
  }
  if ((info.family == NFC_TAG_TYPE2_FAMILY_UNKNOWN) && !uid.empty() &&
      uid[0] == static_cast<std::uint8_t>(NFC_TAG_MFR_CODE_ST) &&
      info.cc_valid &&
      info.cc[0] == static_cast<std::uint8_t>(NFC_FORUM_CC_MAGIC)) {
    nfc_tag_type2_apply_family_hint(&info, NFC_TAG_TYPE2_FAMILY_ST25TN);
  }

  if (tag.tech_list_.empty()) {
    tag.tech_list_ = "NfcA, MifareUltralight, Ndef";
  }
  manufacturer = uid.empty()
                     ? NERO_NFC_NULL
                     : nfc_tag_iso14443a_manufacturer_name(
                           uid.data(), static_cast<std::uint8_t>(uid.size()));
  if (manufacturer != NERO_NFC_NULL && tag.manufacturer_.empty()) {
    tag.manufacturer_ = manufacturer;
  } else if (info.vendor_name != NERO_NFC_NULL && tag.manufacturer_.empty()) {
    tag.manufacturer_ = info.vendor_name;
  }
  if (info.product_name != NERO_NFC_NULL) {
    tag.product_name_ = info.product_name;
  }
  family = nfc_tag_type2_family_name(info.family);
  if (family != NERO_NFC_NULL && tag.product_name_.empty()) {
    tag.family_name_ = family;
  }
  if (info.version_valid &&
      info.version_len >=
          static_cast<std::uint8_t>(NFC_TAG_NTAG_VER_REPLY_LEN)) {
    std::ostringstream code;
    code << "Product code: vendor=0x" << HexU8(info.vendor_id) << " product=0x"
         << HexU8(info.product_id) << " subtype=0x" << HexU8(info.subtype_id)
         << " size=0x" << HexU8(info.size_id);
    AppendDetailLine(tag, code.str());

    std::ostringstream version_line;
    version_line << "Product version: "
                 << static_cast<unsigned>(
                        info.version[NFC_TAG_NTAG_VER_PRODUCT_MAJOR_INDEX])
                 << '.'
                 << static_cast<unsigned>(
                        info.version[NFC_TAG_NTAG_VER_PRODUCT_MINOR_INDEX]);
    AppendDetailLine(tag, version_line.str());
  }
  if (info.cc_valid) {
    if (nero_nfc_span_ok(NFC_TAG_T2T_CC_ACCESS_INDEX, 1u,
                         NFC_TAG_T2T_PAGE_SIZE_BYTES)) {
      AppendDetailLine(
          tag, "CC: " + HexBytes(std::vector<std::uint8_t>(std::begin(info.cc),
                                                           std::end(info.cc))));
      AppendDetailLine(tag, std::string("CC file: E1 ") +
                                HexU8(info.cc[NFC_TAG_T2T_CC_VER_INDEX]) + ' ' +
                                HexU8(info.cc[NFC_TAG_T2T_CC_MLEN_INDEX]) +
                                ' ' +
                                HexU8(info.cc[NFC_TAG_T2T_CC_ACCESS_INDEX]));
      AppendDetailLine(tag, "Data format: NFC Forum Type 2 Tag / NDEF TLV");

      std::ostringstream mapping;
      mapping << "NDEF mapping: " << static_cast<unsigned>(info.mapping_major)
              << '.' << static_cast<unsigned>(info.mapping_minor)
              << "  Data area: " << info.data_area_size_bytes << " bytes";
      AppendDetailLine(tag, mapping.str());

      std::ostringstream area;
      area << "T2T area size: " << info.data_area_size_bytes
           << " bytes  TLV area size: " << info.data_area_size_bytes
           << " bytes";
      AppendDetailLine(tag, area.str());

      tag.max_ndef_size_ =
          nfc_ndef_tlv_max_payload_for_data_area(info.data_area_size_bytes);
      tag.read_access_open_ = info.read_access_open;
      tag.write_access_open_ = info.write_access_open;
      AppendDetailLine(tag,
                       std::string("Read access: ") +
                           (info.read_access_open ? "open" : "restricted") +
                           "  Write access: " +
                           (info.write_access_open ? "open" : "restricted"));
      AppendDetailLine(
          tag,
          std::string("Writable: ") + (info.write_access_open ? "yes" : "no") +
              "  Can be made read-only: " +
              (info.write_access_open ? "yes" : "already restricted/unknown"));
    }
  }
  if (info.auth0_valid) {
    AppendDetailLine(tag, std::string("Protected by password: ") +
                              (info.password_protected ? "yes" : "no") +
                              " (AUTH0=0x" + HexU8(info.auth0_page) + ')');
  }
}

void ApplyType4Details(PcscTagSnapshot& tag,
                       const std::vector<std::uint8_t>& uid,
                       const std::vector<std::uint8_t>& cc) {
  nfc_tag_type4_info_t info{};
  const char* manufacturer = NERO_NFC_NULL;

  if (tag.tech_list_.empty()) {
    tag.tech_list_ = "NfcA, IsoDep";
  }
  manufacturer = uid.empty()
                     ? NERO_NFC_NULL
                     : nfc_tag_iso14443a_manufacturer_name(
                           uid.data(), static_cast<std::uint8_t>(uid.size()));
  if (manufacturer != NERO_NFC_NULL && tag.manufacturer_.empty()) {
    tag.manufacturer_ = manufacturer;
  }
  if (cc.empty() ||
      !nfc_tag_type4_apply_cc(&info, cc.data(),
                              static_cast<std::uint8_t>(cc.size()))) {
    return;
  }
  if (tag.tech_list_.find("Ndef") == std::string::npos) {
    tag.tech_list_ += ", Ndef";
  }
  AppendDetailLine(tag, "CC: " + HexBytes(cc));
  AppendDetailLine(tag, "Data format: NFC Forum Type 4 Tag / NDEF file");

  std::ostringstream mapping;
  mapping << "NDEF mapping: " << static_cast<unsigned>(info.mapping_major)
          << '.' << static_cast<unsigned>(info.mapping_minor)
          << "  MLe=" << info.mle << "  MLc=" << info.mlc;
  AppendDetailLine(tag, mapping.str());

  std::ostringstream ndef_file;
  ndef_file << "NDEF file ID: 0x" << HexU8(info.ndef_file_id[0])
            << HexU8(info.ndef_file_id[1])
            << "  Max NDEF file: " << info.max_ndef_size << " bytes";
  AppendDetailLine(tag, ndef_file.str());

  (void)nfc_pcsc_type4_max_message_size(info.max_ndef_size,
                                        &tag.max_ndef_size_);
  tag.read_access_open_ = info.read_access_open;
  tag.write_access_open_ = info.write_access_open;
  AppendDetailLine(tag, std::string("Read access: ") +
                            (info.read_access_open ? "open" : "restricted") +
                            "  Write access: " +
                            (info.write_access_open ? "open" : "restricted"));
  AppendDetailLine(
      tag,
      std::string("Writable: ") + (info.write_access_open ? "yes" : "no") +
          "  Can be made read-only: " +
          (info.write_access_open ? "yes (if tag supports locking)" : "no"));
}

void ApplyType5Details(PcscTagSnapshot& tag,
                       const std::vector<std::uint8_t>& uid,
                       const std::vector<std::uint8_t>& system_info,
                       const std::vector<std::uint8_t>& cc) {
  nfc_tag_type5_info_t info{};
  const char* manufacturer = NERO_NFC_NULL;
  const char* family = NERO_NFC_NULL;

  if (!cc.empty()) {
    nfc_tag_type5_apply_cc(&info, cc.data(),
                           static_cast<std::uint8_t>(cc.size()));
  }
  if (!system_info.empty()) {
    const bool kExtendedSystemInfo =
        system_info.size() > kType5StandardSystemInfoMaxLen &&
        nfc_tag_type5_cc_signals_mlen_overflow(&info);
    if (kExtendedSystemInfo) {
      nfc_tag_type5_apply_system_info_ext(
          &info, system_info.data(),
          static_cast<std::uint8_t>(system_info.size()));
    } else {
      nfc_tag_type5_apply_system_info(
          &info, system_info.data(),
          static_cast<std::uint8_t>(system_info.size()));
    }
    nfc_tag_type5_resolve_mlen_overflow(&info);
  }
  if (tag.tech_list_.empty()) {
    tag.tech_list_ = "NfcV, Ndef";
  }
  manufacturer = uid.size() < static_cast<std::size_t>(
                                  NFC_TAG_T5T_ISO15693_UID_MFR_MIN_LEN)
                     ? NERO_NFC_NULL
                     : nfc_tag_iso15693_manufacturer_name(
                           uid.data(), static_cast<std::uint8_t>(uid.size()));
  if (manufacturer != NERO_NFC_NULL && tag.manufacturer_.empty()) {
    tag.manufacturer_ = manufacturer;
  }
  if (info.dsfid_valid) {
    std::string line = "DSFID: 0x" + HexU8(info.dsfid);
    if (info.afi_valid) {
      line += "  AFI: 0x" + HexU8(info.afi);
    }
    AppendDetailLine(tag, line);
  } else if (info.afi_valid) {
    AppendDetailLine(tag, "AFI: 0x" + HexU8(info.afi));
  }
  if (info.block_count != 0u && info.block_size != 0u) {
    std::ostringstream geometry;
    geometry << "Geometry: " << info.block_count << " blocks x "
             << static_cast<unsigned>(info.block_size) << "B";
    AppendDetailLine(tag, geometry.str());
  }
  if (info.ic_ref_valid) {
    AppendDetailLine(tag, "IC reference: 0x" + HexU8(info.ic_ref));
  }
  family = uid.empty()
               ? NERO_NFC_NULL
               : nfc_tag_type5_family_name(
                     uid.data(), static_cast<std::uint8_t>(uid.size()), &info);
  if (family != NERO_NFC_NULL) {
    if (tag.product_name_.empty()) {
      tag.product_name_ = family;
    }
    if (tag.family_name_.empty()) {
      tag.family_name_ = family;
    }
    AppendDetailLine(tag, std::string("Product family: ") + family);
  }
  if (info.cc_valid) {
    {
      const auto kCc = std::span{info.cc}.first(info.cc_len);
      AppendDetailLine(tag, "CC: " + HexBytes(std::vector<std::uint8_t>(
                                         kCc.begin(), kCc.end())));
    }
    AppendDetailLine(tag, "Data format: NFC Forum Type 5 Tag / NDEF TLV");

    std::ostringstream mapping;
    mapping << "NDEF mapping: " << static_cast<unsigned>(info.mapping_major)
            << '.' << static_cast<unsigned>(info.mapping_minor)
            << "  Data area: " << info.data_area_size_bytes << " bytes";
    AppendDetailLine(tag, mapping.str());

    tag.max_ndef_size_ =
        nfc_ndef_tlv_max_payload_for_data_area(info.data_area_size_bytes);
    tag.read_access_open_ = info.read_access_open;
    tag.write_access_open_ = info.write_access_open;
    AppendDetailLine(tag, std::string("Read access: ") +
                              (info.read_access_open ? "open" : "restricted") +
                              "  Write access: " +
                              (info.write_access_open ? "open" : "restricted"));
    AppendDetailLine(
        tag,
        std::string("Writable: ") + (info.write_access_open ? "yes" : "no") +
            "  Can be made read-only: " +
            (info.write_access_open ? "yes (if tag supports locking)" : "no"));
  }
}

}  // namespace nero_nfc
