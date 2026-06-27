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

#include "nero_nfc_pcsc_tag_details.h"

#include "nfc_pcsc_contactless.h"
#include "nfc_tag_info.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <vector>

namespace {

std::string storage_atr_hex(nfc_tag_kind_t kind) {
  std::array<std::uint8_t, NFC_PCSC_STORAGE_ATR_LEN> atr{};
  std::uint16_t len = 0u;
  if (!nfc_pcsc_copy_storage_card_atr(kind, atr.data(), static_cast<std::uint16_t>(atr.size()),
                                        &len)) {
    return {};
  }
  return nero_nfc::hex_bytes(
    std::vector<std::uint8_t>(atr.begin(), atr.begin() + static_cast<std::ptrdiff_t>(len)));
}

bool contains_text(const std::string &text, std::string_view needle) {
  return text.find(needle) != std::string::npos;
}

void expect_presented_metadata(const nero_nfc::PcscTagSnapshot &tag,
                               std::initializer_list<std::string_view> expected) {
  const std::string formatted = nero_nfc::format_pcsc_tag_snapshot(tag);
  for (std::string_view needle : expected) {
    EXPECT_TRUE(contains_text(formatted, needle)) << "missing: " << needle << "\n" << formatted;
  }
}

} // namespace

TEST(UserspacePcscTagDetails, ParsesStorageAtrForType2) {
  nero_nfc::PcscTagSnapshot tag;
  tag.atr_hex = storage_atr_hex(NFC_TAG_KIND_TYPE2);
  ASSERT_FALSE(tag.atr_hex.empty());

  nero_nfc::apply_storage_atr_hint(tag);

  EXPECT_TRUE(nero_nfc::is_pcsc_storage_type2(tag));
  EXPECT_TRUE(nero_nfc::has_pcsc_storage_hint(tag));
  EXPECT_FALSE(nero_nfc::is_pcsc_storage_type5(tag));
}

TEST(UserspacePcscTagDetails, ParsesStorageAtrForType5) {
  nero_nfc::PcscTagSnapshot tag;
  tag.atr_hex = storage_atr_hex(NFC_TAG_KIND_TYPE5);
  ASSERT_FALSE(tag.atr_hex.empty());

  nero_nfc::apply_storage_atr_hint(tag);

  EXPECT_TRUE(nero_nfc::is_pcsc_storage_type5(tag));
  EXPECT_TRUE(nero_nfc::has_pcsc_storage_hint(tag));
  EXPECT_FALSE(nero_nfc::is_pcsc_storage_type2(tag));
}

TEST(UserspacePcscTagDetails, RejectsStorageAtrWithBadTck) {
  /* [ISO7816-3] §8 — a storage ATR with a corrupted TCK must be rejected (no hint). */
  nero_nfc::PcscTagSnapshot tag;
  std::string atr = storage_atr_hex(NFC_TAG_KIND_TYPE2);
  ASSERT_FALSE(atr.empty());
  /* Flip the last hex nibble of the TCK byte to corrupt the checksum. */
  atr.back() = (atr.back() == 'F') ? 'E' : 'F';
  tag.atr_hex = atr;

  nero_nfc::apply_storage_atr_hint(tag);

  EXPECT_FALSE(nero_nfc::has_pcsc_storage_hint(tag));
}

TEST(UserspacePcscTagDetails, RejectsStorageAtrWithWrongTs) {
  /* [ISO7816-3] — TS must be 0x3B (direct convention); a wrong TS yields no hint. */
  nero_nfc::PcscTagSnapshot tag;
  tag.atr_hex = "3F 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 00 00 00 00 00 B0";

  nero_nfc::apply_storage_atr_hint(tag);

  EXPECT_FALSE(nero_nfc::has_pcsc_storage_hint(tag));
}

TEST(UserspacePcscTagDetails, AppliesType4ContactlessHintFromAts) {
  nero_nfc::PcscTagSnapshot tag;
  tag.ats_hex = "06 77 77 71 02 80 BE 6A";

  nero_nfc::apply_type4_contactless_hint(tag);

  EXPECT_NE(tag.tag_type.find("Type 4-compatible contactless smartcard"), std::string::npos);
}

TEST(UserspacePcscTagDetails, AppliesType4ContactlessHintFromSakBit6) {
  nero_nfc::PcscTagSnapshot tag;
  tag.sak_hex = "20";

  nero_nfc::apply_type4_contactless_hint(tag);

  EXPECT_NE(tag.tag_type.find("Type 4-compatible contactless smartcard"), std::string::npos);
}

TEST(UserspacePcscTagDetails, RecognizesNtag21xVersionBytes) {
  const std::vector<std::uint8_t> version = {0x00u, 0x04u, 0x04u, 0x02u,
                                             0x01u, 0x00u, 0x0Fu, 0x03u};
  EXPECT_TRUE(nero_nfc::looks_like_ntag21x_version(version));
  EXPECT_FALSE(nero_nfc::looks_like_ntag21x_version({0x00u, 0x04u, 0x03u}));
}

TEST(UserspacePcscTagDetails, AppliesType2DetailLinesFromCcAndVersion) {
  nero_nfc::PcscTagSnapshot tag;
  const std::vector<std::uint8_t> uid = {0x04u, 0xA1u, 0xB2u, 0xC3u, 0xD4u, 0xE5u, 0xF6u};
  const std::vector<std::uint8_t> version = {0x00u, 0x04u, 0x04u, 0x02u,
                                             0x01u, 0x00u, 0x0Fu, 0x03u};
  const std::vector<std::uint8_t> cc = {0xE1u, 0x10u, 0x12u, 0x00u};

  nero_nfc::apply_type2_details(tag, uid, version, cc, {}, std::nullopt);

  EXPECT_EQ(tag.tech_list, "NfcA, MifareUltralight, Ndef");
  EXPECT_EQ(tag.manufacturer, "NXP");
  EXPECT_FALSE(tag.product_name.empty());
  ASSERT_FALSE(tag.detail_lines.empty());
  EXPECT_NE(tag.detail_lines[0].find("Product code: vendor=0x04"), std::string::npos);
  EXPECT_NE(
      std::ranges::find_if(tag.detail_lines,
                           [](const std::string &line) { return line.starts_with("CC: "); }),
      tag.detail_lines.end());
  EXPECT_NE(
      std::ranges::find_if(tag.detail_lines, [](const std::string &line) {
        return line.find("Data format: NFC Forum Type 2 Tag / NDEF TLV") != std::string::npos;
      }),
      tag.detail_lines.end());
}

TEST(UserspacePcscTagDetails, AppliesNtagProductFromVersionWhenUidManufacturerIsUnknown) {
  nero_nfc::PcscTagSnapshot tag;
  const std::vector<std::uint8_t> uid = {0x53u, 0x84u, 0x8Fu, 0xE5u, 0x52u, 0x00u, 0x01u};
  const std::vector<std::uint8_t> version = {0x00u, 0x04u, 0x04u, 0x02u,
                                             0x01u, 0x00u, 0x13u, 0x03u};
  const std::vector<std::uint8_t> cc = {0xE1u, 0x10u, 0x7Fu, 0x00u};

  nero_nfc::apply_type2_details(tag, uid, version, cc, {}, std::nullopt);

  EXPECT_EQ(tag.manufacturer, "NXP");
  EXPECT_EQ(tag.product_name, "NTAG216");
}

TEST(UserspacePcscTagDetails, AppliesAndPresentsSharedMetadataForStorageAndType4Tags) {
  {
    nero_nfc::PcscTagSnapshot tag;
    const std::vector<std::uint8_t> uid = {0x53u, 0x84u, 0x8Fu, 0xE5u, 0x52u, 0x00u, 0x01u};
    const std::vector<std::uint8_t> version = {0x00u, 0x04u, 0x04u, 0x02u,
                                               0x01u, 0x00u, 0x13u, 0x03u};
    const std::vector<std::uint8_t> cc = {0xE1u, 0x10u, 0x7Fu, 0x00u};
    tag.reader_name = "unit-test reader";
    tag.tag_type = "PC/SC storage: ISO 14443-3A / NFC Forum Type 2";
    tag.uid_hex = nero_nfc::hex_bytes(uid);

    nero_nfc::apply_type2_details(tag, uid, version, cc, {}, std::nullopt);

    EXPECT_EQ(tag.tech_list, "NfcA, MifareUltralight, Ndef");
    EXPECT_EQ(tag.manufacturer, "NXP");
    EXPECT_EQ(tag.product_name, "NTAG216");
    EXPECT_EQ(tag.max_ndef_size, 1011u);
    EXPECT_TRUE(tag.read_access_open);
    EXPECT_TRUE(tag.write_access_open);
    expect_presented_metadata(
      tag, {"Tag type: PC/SC storage: ISO 14443-3A / NFC Forum Type 2",
            "Tech list: NfcA, MifareUltralight, Ndef",
            "Serial number / UID: 53 84 8F E5 52 00 01", "Manufacturer: NXP",
            "Product: NTAG216", "Data format: NFC Forum Type 2 Tag / NDEF TLV",
            "NDEF mapping: 1.0  Data area: 1016 bytes", "NDEF max size: 1011 bytes",
            "Read access: open  Write access: open"});
  }

  {
    nero_nfc::PcscTagSnapshot tag;
    const std::vector<std::uint8_t> uid = {0x04u, 0x25u, 0x85u, 0x93u, 0x12u, 0x34u, 0x56u};
    const std::vector<std::uint8_t> cc = {0x00u, 0x0Fu, 0x20u, 0x00u, 0xFFu, 0x00u, 0xF6u,
                                          0x04u, 0x06u, 0xE1u, 0x04u, 0x01u, 0xF4u, 0x00u,
                                          0x00u};
    tag.reader_name = "unit-test reader";
    tag.tag_type = "NFC Forum Type 4-compatible NDEF file";
    tag.uid_hex = nero_nfc::hex_bytes(uid);

    nero_nfc::apply_type4_details(tag, uid, cc);

    EXPECT_EQ(tag.tech_list, "NfcA, IsoDep, Ndef");
    EXPECT_EQ(tag.manufacturer, "NXP");
    EXPECT_EQ(tag.max_ndef_size, 498u);
    EXPECT_TRUE(tag.read_access_open);
    EXPECT_TRUE(tag.write_access_open);
    expect_presented_metadata(
      tag, {"Tag type: NFC Forum Type 4-compatible NDEF file", "Tech list: NfcA, IsoDep, Ndef",
            "Serial number / UID: 04 25 85 93 12 34 56", "Manufacturer: NXP",
            "Data format: NFC Forum Type 4 Tag / NDEF file",
            "NDEF mapping: 2.0  MLe=255  MLc=246", "NDEF file ID: 0xE104",
            "NDEF max size: 498 bytes", "Read access: open  Write access: open"});
  }

  {
    nero_nfc::PcscTagSnapshot tag;
    const std::vector<std::uint8_t> uid = {0xE0u, 0x02u, 0x01u, 0x02u,
                                           0x03u, 0x04u, 0x05u, 0x06u};
    const std::vector<std::uint8_t> system_info = {
      0x00u, 0x0Fu, 0x06u, 0x05u, 0x04u, 0x03u, 0x02u, 0x01u,
      0x02u, 0xE0u, 0x00u, 0x00u, 0xFFu, 0x07u, 0x03u, 0x51u};
    const std::vector<std::uint8_t> cc = {0xE1u, 0x40u, 0xFFu, 0x04u};
    tag.reader_name = "unit-test reader";
    tag.tag_type = "PC/SC storage: ISO 15693 / NFC Forum Type 5";
    tag.uid_hex = nero_nfc::hex_bytes(uid);
    tag.type5_system_info_hex = nero_nfc::hex_bytes(system_info);

    nero_nfc::apply_type5_details(tag, uid, system_info, cc);

    EXPECT_EQ(tag.tech_list, "NfcV, Ndef");
    EXPECT_EQ(tag.manufacturer, "STMicroelectronics");
    EXPECT_FALSE(tag.product_name.empty());
    EXPECT_EQ(tag.max_ndef_size, 8183u);
    EXPECT_TRUE(tag.read_access_open);
    EXPECT_TRUE(tag.write_access_open);
    expect_presented_metadata(
      tag, {"Tag type: PC/SC storage: ISO 15693 / NFC Forum Type 5", "Tech list: NfcV, Ndef",
            "Serial number / UID: E0 02 01 02 03 04 05 06", "Manufacturer: STMicroelectronics",
            "Product: ", "System Info: 00 0F 06 05 04 03 02 01 02 E0 00 00 FF 07 03 51",
            "Geometry: 2048 blocks x 4B", "Data format: NFC Forum Type 5 Tag / NDEF TLV",
            "NDEF mapping: 1.0  Data area: 8188 bytes", "NDEF max size: 8183 bytes",
            "Read access: open  Write access: open"});
  }
}

TEST(UserspacePcscTagDetails, AppliesType4DetailLinesFromCc) {
  nero_nfc::PcscTagSnapshot tag;
  const std::vector<std::uint8_t> uid = {0x04u, 0x25u, 0x85u, 0x93u, 0x12u, 0x34u, 0x56u};
  const std::vector<std::uint8_t> cc = {0x00u, 0x0Fu, 0x20u, 0x00u, 0xFFu, 0x00u, 0xF6u,
                                        0x04u, 0x06u, 0xE1u, 0x04u, 0x01u, 0xF4u, 0x00u, 0x00u};

  nero_nfc::apply_type4_details(tag, uid, cc);

  EXPECT_EQ(tag.tech_list, "NfcA, IsoDep, Ndef");
  EXPECT_NE(
      std::ranges::find_if(tag.detail_lines, [](const std::string &line) {
        return line.find("NDEF file ID: 0xE104") != std::string::npos;
      }),
      tag.detail_lines.end());
  EXPECT_EQ(tag.max_ndef_size, 498u);
  EXPECT_TRUE(tag.read_access_open);
  EXPECT_TRUE(tag.write_access_open);
}

TEST(UserspacePcscTagDetails, AppendDetailLineSkipsEmptyLines) {
  nero_nfc::PcscTagSnapshot tag;
  nero_nfc::append_detail_line(tag, "");
  nero_nfc::append_detail_line(tag, "probe line");

  ASSERT_EQ(tag.detail_lines.size(), 1u);
  EXPECT_EQ(tag.detail_lines.front(), "probe line");
}
