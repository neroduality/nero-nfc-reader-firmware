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

#include "nero_nfc_pcsc.hpp"
#include "nero_nfc_pcsc_tag_details.hpp"

namespace {
enum {
  kTestLit0x10u = 0x10u,
  kTestLit0x20u = 0x20u,
  kTestLit0x40u = 0x40u,
  kTestLit0xAAu = 0xAAu,
  kTestLit0xD1u = 0xD1u,
  kTestLit0xE1u = 0xE1u,
  kTestLit0xE2u = 0xE2u,
  kTestLit128 = 128,
  kTestLit256u = 256u,
  kTestLit2u = 2u,
  kTestLit500u = 500u,
};
}  // namespace

#include "nero_nfc_limits.h"

#include <gtest/gtest.h>

TEST(UserspacePcsc, BuildsAndParsesUriRecord) {
  auto ndef = nero_nfc::BuildNdefUriRecord("https://example.test/demo");
  ASSERT_FALSE(ndef.empty());

  auto records = nero_nfc::ParseNdefRecords(ndef);

  ASSERT_EQ(records.size(), 1u);
  EXPECT_EQ(records[0].tnf_, 1u);
  EXPECT_EQ(records[0].type_, "U");
  ASSERT_TRUE(records[0].decoded_.has_value());
  EXPECT_EQ(records[0].decoded_,
            std::optional<std::string>("https://example.test/demo"));
}

TEST(UserspacePcsc, RejectsUnsafeUriWhenBuildingRecord) {
  EXPECT_TRUE(nero_nfc::BuildNdefUriRecord("https://bad .test").empty());
  std::string uri_with_nul = "http://ok";
  uri_with_nul.push_back('\0');
  uri_with_nul += "bad";
  EXPECT_TRUE(nero_nfc::BuildNdefUriRecord(uri_with_nul).empty());
}

TEST(UserspacePcsc, RejectsUnsafeTextWhenBuildingRecord) {
  EXPECT_TRUE(nero_nfc::BuildNdefTextRecord(std::string("hi\x00", 3)).empty());
}

TEST(UserspacePcsc, BuildsAndParsesTextRecord) {
  auto ndef = nero_nfc::BuildNdefTextRecord("hello NFC", "en");
  ASSERT_FALSE(ndef.empty());

  auto records = nero_nfc::ParseNdefRecords(ndef);

  ASSERT_EQ(records.size(), 1u);
  EXPECT_EQ(records[0].tnf_, 1u);
  EXPECT_EQ(records[0].type_, "T");
  ASSERT_TRUE(records[0].decoded_.has_value());
  EXPECT_EQ(records[0].decoded_, std::optional<std::string>("hello NFC"));
}

TEST(UserspacePcsc, ParseNdefRejectsReservedUriPrefixCode) {
  const std::vector<std::uint8_t> kPayload = {0x24u, 'e', 'x', 'a',
                                              'm',   'p', 'l', 'e'};
  std::vector<std::uint8_t> ndef = {
      kTestLit0xD1u, 0x01u, static_cast<std::uint8_t>(kPayload.size()), 'U'};
  ndef.insert(ndef.end(), kPayload.begin(), kPayload.end());
  auto records = nero_nfc::ParseNdefRecords(ndef);
  ASSERT_EQ(records.size(), 1u);
  EXPECT_FALSE(records[0].decoded_.has_value());
}

TEST(UserspacePcsc, ParseNdefRejectsUriPayloadWithEmbeddedNul) {
  const std::vector<std::uint8_t> kPayload = {0x00u, 'o', 'k', '\0', 'x'};
  std::vector<std::uint8_t> ndef = {
      kTestLit0xD1u, 0x01u, static_cast<std::uint8_t>(kPayload.size()), 'U'};
  ndef.insert(ndef.end(), kPayload.begin(), kPayload.end());
  auto records = nero_nfc::ParseNdefRecords(ndef);
  ASSERT_EQ(records.size(), 1u);
  EXPECT_FALSE(records[0].decoded_.has_value());
}

TEST(UserspacePcsc, ParseNdefStopsOnUnsupportedChunkedRecord) {
  const std::vector<std::uint8_t> kChunked = {0xB1u, 0x01u, 0x02u,
                                              'U',   0x04u, 'a'};
  auto records = nero_nfc::ParseNdefRecords(kChunked);
  EXPECT_TRUE(records.empty());
}

TEST(UserspacePcsc, BuildsMimeRecord) {
  auto ndef =
      nero_nfc::BuildNdefMimeRecord("text/vcard", {'B', 'E', 'G', 'I', 'N'});
  ASSERT_FALSE(ndef.empty());

  auto records = nero_nfc::ParseNdefRecords(ndef);

  ASSERT_EQ(records.size(), 1u);
  EXPECT_EQ(records[0].tnf_, 2u);
  EXPECT_EQ(records[0].type_, "text/vcard");
  EXPECT_EQ(records[0].payload_,
            (std::vector<std::uint8_t>{'B', 'E', 'G', 'I', 'N'}));
}

TEST(UserspacePcsc, BuildsAndParsesMultiRecordMessage) {
  std::vector<std::vector<std::uint8_t>> records = {
      nero_nfc::BuildNdefUriRecord("https://example.test/one"),
      nero_nfc::BuildNdefUriRecord("https://example.test/two"),
  };

  auto ndef = nero_nfc::BuildNdefMessage(records);
  ASSERT_FALSE(ndef.empty());
  auto parsed = nero_nfc::ParseNdefRecords(ndef);

  ASSERT_EQ(parsed.size(), 2u);
  ASSERT_TRUE(parsed[0].decoded_.has_value());
  ASSERT_TRUE(parsed[1].decoded_.has_value());
  EXPECT_EQ(parsed[0].decoded_,
            std::optional<std::string>("https://example.test/one"));
  EXPECT_EQ(parsed[1].decoded_,
            std::optional<std::string>("https://example.test/two"));
}

TEST(UserspacePcsc, ParsesHexWithCommonSeparators) {
  std::vector<std::uint8_t> out;

  ASSERT_TRUE(nero_nfc::ParseHexBytes("04:A1 b2-C3", out));

  ASSERT_EQ(out.size(), 4u);
  EXPECT_EQ(out[0], 0x04u);
  EXPECT_EQ(out[1], 0xA1u);
  EXPECT_EQ(out[2], 0xB2u);
  EXPECT_EQ(out[3], 0xC3u);
  EXPECT_EQ(nero_nfc::HexBytes(out, ':'), "04:A1:B2:C3");
}

TEST(UserspacePcsc, FormatsStandardTagFields) {
  nero_nfc::PcscTagSnapshot tag;
  tag.reader_name_ = "Nero NFC Arduino UNO R4 WiFi CCID 00 00";
  tag.tag_type_ = "PC/SC storage: ISO 14443-3A / NFC Forum Type 2";
  tag.tech_list_ = "NfcA, MifareUltralight, Ndef";
  tag.manufacturer_ = "NXP";
  tag.product_name_ = "NTAG216";
  tag.uid_hex_ = "04 A1 B2 C3 D4 E5 F6";
  tag.atqa_hex_ = "44 00";
  tag.sak_hex_ = "00";
  tag.type2_version_hex_ = "00 04 04 02 01 00 0F 03";
  tag.type2_signature_hex_ = "AA BB CC DD";
  tag.detail_lines_ = {
      "Product code: vendor=0x04 product=0x04 subtype=0x02 size=0x0F",
      "CC: E1 10 12 00",
      "Data format: NFC Forum Type 2 Tag / NDEF TLV",
      "Protected by password: no (AUTH0=0xFF)",
  };
  tag.max_ndef_size_ = kTestLit128;
  tag.read_access_open_ = true;
  tag.write_access_open_ = true;
  tag.ndef_message_ = nero_nfc::BuildNdefUriRecord("https://example.test");
  tag.records_ = nero_nfc::ParseNdefRecords(tag.ndef_message_);

  std::string formatted = nero_nfc::FormatPcscTagSnapshot(tag);

  EXPECT_NE(formatted.find("PC/SC reader: Nero NFC"), std::string::npos);
  EXPECT_NE(formatted.find("Tech list: NfcA, MifareUltralight, Ndef"),
            std::string::npos);
  EXPECT_NE(formatted.find("Manufacturer: NXP"), std::string::npos);
  EXPECT_NE(formatted.find("Product: NTAG216"), std::string::npos);
  EXPECT_NE(formatted.find("Serial number / UID: 04 A1 B2 C3 D4 E5 F6"),
            std::string::npos);
  EXPECT_LT(formatted.find("Serial number / UID: 04 A1 B2 C3 D4 E5 F6"),
            formatted.find("Manufacturer: NXP"));
  EXPECT_NE(
      formatted.find(
          "Product code: vendor=0x04 product=0x04 subtype=0x02 size=0x0F"),
      std::string::npos);
  EXPECT_NE(formatted.find("CC: E1 10 12 00"), std::string::npos);
  EXPECT_NE(formatted.find("Signature: AA BB CC DD"), std::string::npos);
  EXPECT_NE(formatted.find("Protected by password: no (AUTH0=0xFF)"),
            std::string::npos);
  EXPECT_NE(formatted.find("NDEF max size: 128 bytes"), std::string::npos);
  EXPECT_NE(formatted.find("Decoded=\"https://example.test\""),
            std::string::npos);
}

TEST(UserspacePcsc, FormatsPassiveType4SmartcardWithoutNdefProbe) {
  nero_nfc::PcscTagSnapshot tag;
  tag.reader_name_ = "Nero NFC Arduino UNO R4 WiFi CCID 00 00";
  tag.tag_type_ =
      "ISO 14443-4 / NFC Forum Type 4-compatible contactless smartcard";
  tag.tech_list_ = "NfcA, IsoDep";
  tag.uid_hex_ = "04 43 9D 82 4F 23 90";
  tag.sak_hex_ = "20";
  tag.ats_hex_ = "06 77 77 71 02 80 BE 6A";
  tag.detail_lines_ = {
      "Application probing: no NFC Forum Type 4 NDEF app/file found",
  };

  std::string formatted = nero_nfc::FormatPcscTagSnapshot(tag);

  EXPECT_NE(formatted.find("Type 4-compatible contactless smartcard"),
            std::string::npos);
  EXPECT_NE(formatted.find("Tech list: NfcA, IsoDep"), std::string::npos);
  EXPECT_NE(formatted.find(
                "Application probing: no NFC Forum Type 4 NDEF app/file found"),
            std::string::npos);
  EXPECT_EQ(formatted.find("NDEF message:"), std::string::npos);
}

TEST(UserspacePcsc, FormatsCommercialType4NdefTag) {
  nero_nfc::PcscTagSnapshot tag;
  tag.reader_name_ = "HID Global OMNIKEY 5422 Smartcard Reader 00 00";
  tag.tag_type_ = "NFC Forum Type 4-compatible NDEF file";
  tag.tech_list_ = "NfcA, IsoDep, Ndef";
  tag.uid_hex_ = "04 25 85 93 12 34 56";
  tag.ats_hex_ = "06 75 77 81 02";
  tag.detail_lines_ = {
      "CC: 00 0F 20 00 FF 00 F6 04 06 E1 04 01 F4 00 00",
      "Data format: NFC Forum Type 4 Tag / NDEF file",
      "NDEF file ID: 0xE104  Max NDEF file: 500 bytes",
  };
  tag.max_ndef_size_ = kTestLit500u;
  tag.read_access_open_ = true;
  tag.write_access_open_ = true;
  tag.ndef_message_ = nero_nfc::BuildNdefTextRecord("type4 hello");
  tag.records_ = nero_nfc::ParseNdefRecords(tag.ndef_message_);

  std::string formatted = nero_nfc::FormatPcscTagSnapshot(tag);

  EXPECT_NE(formatted.find("OMNIKEY"), std::string::npos);
  EXPECT_NE(formatted.find("NFC Forum Type 4-compatible NDEF file"),
            std::string::npos);
  EXPECT_NE(formatted.find("Tech list: NfcA, IsoDep, Ndef"), std::string::npos);
  EXPECT_NE(formatted.find("NDEF file ID: 0xE104"), std::string::npos);
  EXPECT_NE(formatted.find("NDEF max size: 500 bytes"), std::string::npos);
  EXPECT_NE(formatted.find("Decoded=\"type4 hello\""), std::string::npos);
}

TEST(UserspacePcsc, BuildsAndExtractsType2StorageTlv) {
  std::vector<std::uint8_t> tlv_area;
  std::string err;
  auto ndef = nero_nfc::BuildNdefUriRecord("https://example.test/type2");

  ASSERT_TRUE(
      nero_nfc::NeroNfcUtestBuildStorageNdefTlv(ndef, 128u, tlv_area, err))
      << err;
  std::vector<std::uint8_t> raw = {kTestLit0xE1u, kTestLit0x10u, kTestLit0x10u,
                                   0x00u};
  raw.insert(raw.end(), tlv_area.begin(), tlv_area.end());
  nero_nfc::PcscTagSnapshot tag;
  ASSERT_TRUE(nero_nfc::NeroNfcUtestExtractStorageNdef(raw, 4u, tag, err))
      << err;

  EXPECT_EQ(tag.ndef_message_, ndef);
  ASSERT_EQ(tag.records_.size(), 1u);
  ASSERT_TRUE(tag.records_[0].decoded_.has_value());
  EXPECT_EQ(tag.records_[0].decoded_,
            std::optional<std::string>("https://example.test/type2"));
}

TEST(UserspacePcsc, BuildsAndExtractsType5StorageTlvAfterExtendedCc) {
  std::vector<std::uint8_t> tlv_area;
  std::string err;
  auto ndef = nero_nfc::BuildNdefTextRecord("type5 hello");

  ASSERT_TRUE(
      nero_nfc::NeroNfcUtestBuildStorageNdefTlv(ndef, 256u, tlv_area, err))
      << err;
  std::vector<std::uint8_t> raw = {kTestLit0xE2u, kTestLit0x40u, kTestLit0x20u,
                                   0x00u,         0x00u,         0x00u,
                                   0x00u,         0x00u};
  raw.insert(raw.end(), tlv_area.begin(), tlv_area.end());
  nero_nfc::PcscTagSnapshot tag;
  ASSERT_TRUE(nero_nfc::NeroNfcUtestExtractStorageNdef(raw, 8u, tag, err))
      << err;

  EXPECT_EQ(tag.ndef_message_, ndef);
  ASSERT_EQ(tag.records_.size(), 1u);
  ASSERT_TRUE(tag.records_[0].decoded_.has_value());
  EXPECT_EQ(tag.records_[0].decoded_,
            std::optional<std::string>("type5 hello"));
}

TEST(UserspacePcsc, FormatsType5MlenOverflowFromExtendedSystemInfo) {
  nero_nfc::PcscTagSnapshot tag;
  tag.reader_name_ = "Nero NFC Arduino UNO R4 WiFi CCID 00 00";
  tag.tag_type_ = "PC/SC storage: ISO 15693 / NFC Forum Type 5";
  const std::vector<std::uint8_t> kUid = {0xE0u, 0x02u, 0x01u, 0x02u,
                                          0x03u, 0x04u, 0x05u, 0x06u};
  const std::vector<std::uint8_t> kSystemInfo = {
      0x00u, 0x0Fu, 0x06u, 0x05u, 0x04u, 0x03u, 0x02u, 0x01u,
      0x02u, 0xE0u, 0x00u, 0x00u, 0xFFu, 0x07u, 0x03u, 0x51u};
  const std::vector<std::uint8_t> kCc = {0xE1u, 0x40u, 0xFFu, 0x04u};

  nero_nfc::ApplyType5Details(tag, kUid, kSystemInfo, kCc);

  std::string formatted = nero_nfc::FormatPcscTagSnapshot(tag);

  EXPECT_NE(formatted.find("Geometry: 2048 blocks x 4B"), std::string::npos);
  EXPECT_NE(formatted.find("Data area: 8188 bytes"), std::string::npos);
}

TEST(UserspacePcsc, ReportsStorageNdefPayloadCapacityNotRawDataArea) {
  EXPECT_EQ(nero_nfc::NeroNfcUtestStorageTlvPayloadCap(64u), 61u);
  EXPECT_EQ(nero_nfc::NeroNfcUtestStorageTlvPayloadCap(160u), 157u);
  EXPECT_EQ(nero_nfc::NeroNfcUtestStorageTlvPayloadCap(256u), 251u);
  EXPECT_EQ(nero_nfc::NeroNfcUtestStorageTlvPayloadCap(2048u), 2043u);
}

TEST(UserspacePcsc, BuildsType4SelectApduWithLeZero) {
  std::vector<std::uint8_t> capdu;
  std::string err;
  const std::vector<std::uint8_t> kAid = {0xD2u, 0x76u, 0x00u, 0x00u,
                                          0x85u, 0x01u, 0x01u};

  ASSERT_TRUE(
      nero_nfc::NeroNfcUtestBuildSelectApdu(0x04u, 0x00u, kAid, capdu, err))
      << err;

  const std::vector<std::uint8_t> kExpected = {
      0x00u, 0xA4u, 0x04u, 0x00u, 0x07u, 0xD2u, 0x76u,
      0x00u, 0x00u, 0x85u, 0x01u, 0x01u, 0x00u};
  EXPECT_EQ(capdu, kExpected);
}

TEST(UserspacePcsc, RejectsOversizedSelectApduData) {
  std::vector<std::uint8_t> capdu;
  std::string err;
  std::vector<std::uint8_t> oversized(kTestLit256u, kTestLit0xAAu);

  EXPECT_FALSE(nero_nfc::NeroNfcUtestBuildSelectApdu(0x04u, 0x00u, oversized,
                                                     capdu, err));
  EXPECT_TRUE(capdu.empty());
  EXPECT_FALSE(err.empty());
}

TEST(UserspacePcsc, BoundsType4NdefForShortBinaryAddressing) {
  EXPECT_TRUE(nero_nfc::NeroNfcUtestType4NdefLenFitsShortBinary(65534u));
  EXPECT_FALSE(nero_nfc::NeroNfcUtestType4NdefLenFitsShortBinary(65535u));
}

TEST(UserspacePcsc, CapsType2StorageNdefScanUnitsForLargeTags) {
  constexpr std::uint16_t kNtag216DataArea = 1016u;
  const auto kUncappedUnits =
      static_cast<std::uint16_t>((4u + kNtag216DataArea + 3u) / 4u);
  const std::uint16_t kCappedUnits =
      nero_nfc::NeroNfcUtestStorageType2ReadUnitLimit(3u, 4u, 4u,
                                                      kNtag216DataArea);
  EXPECT_LT(kCappedUnits, kUncappedUnits);
  EXPECT_EQ(kCappedUnits, 223u);
}

TEST(UserspacePcsc, CapsType2BulkReadToDeclaredDataArea) {
  EXPECT_EQ(nero_nfc::NeroNfcUtestType2StorageBulkReadLen(3u), 0u);
  EXPECT_EQ(nero_nfc::NeroNfcUtestType2StorageBulkReadLen(5u), 4u);
  EXPECT_EQ(nero_nfc::NeroNfcUtestType2StorageBulkReadLen(64u), 64u);
  EXPECT_EQ(nero_nfc::NeroNfcUtestType2StorageBulkReadLen(144u), 144u);
  EXPECT_EQ(nero_nfc::NeroNfcUtestType2StorageBulkReadLen(872u), 252u);
}

TEST(UserspacePcsc, ScansExtendedType5StorageNdefArea) {
  constexpr std::uint16_t kLargeDataArea = 2048u;
  const auto kUncappedBlocks =
      static_cast<std::uint16_t>((8u + kLargeDataArea + 3u) / 4u);
  const std::uint16_t kBlocks =
      nero_nfc::NeroNfcUtestStorageType5ReadBlockLimit(8u, kLargeDataArea);
  EXPECT_EQ(kBlocks, kUncappedBlocks);
}

TEST(UserspacePcsc, Type5TransparentFallbackBuildsExtendedBlockCommands) {
  const std::vector<std::uint8_t> kUidLsb = {0x01u, 0x02u, 0x03u, 0x04u,
                                             0x05u, 0x06u, 0x07u, 0x08u};

  EXPECT_EQ(nero_nfc::NeroNfcUtestType5TransparentBlockCommand(false, kUidLsb,
                                                               0x00FFu),
            (std::vector<std::uint8_t>{0x22u, 0x20u, 0x01u, 0x02u, 0x03u, 0x04u,
                                       0x05u, 0x06u, 0x07u, 0x08u, 0xFFu}));
  EXPECT_EQ(
      nero_nfc::NeroNfcUtestType5TransparentBlockCommand(false, kUidLsb,
                                                         0x0100u),
      (std::vector<std::uint8_t>{0x2Au, 0x30u, 0x01u, 0x02u, 0x03u, 0x04u,
                                 0x05u, 0x06u, 0x07u, 0x08u, 0x00u, 0x01u}));
  EXPECT_EQ(
      nero_nfc::NeroNfcUtestType5TransparentBlockCommand(true, kUidLsb,
                                                         0x0100u),
      (std::vector<std::uint8_t>{0x2Au, 0x31u, 0x01u, 0x02u, 0x03u, 0x04u,
                                 0x05u, 0x06u, 0x07u, 0x08u, 0x00u, 0x01u}));
  EXPECT_EQ(
      nero_nfc::NeroNfcUtestType5TransparentReadMultipleCommand(kUidLsb,
                                                                0x0004u, 3u),
      (std::vector<std::uint8_t>{0x22u, 0x23u, 0x01u, 0x02u, 0x03u, 0x04u,
                                 0x05u, 0x06u, 0x07u, 0x08u, 0x04u, 0x02u}));
  EXPECT_EQ(nero_nfc::NeroNfcUtestType5TransparentReadMultipleCommand(
                kUidLsb, 0x0100u, 3u),
            (std::vector<std::uint8_t>{0x2Au, 0x33u, 0x01u, 0x02u, 0x03u, 0x04u,
                                       0x05u, 0x06u, 0x07u, 0x08u, 0x00u, 0x01u,
                                       0x02u, 0x00u}));
  EXPECT_EQ(nero_nfc::NeroNfcUtestType5TransparentSystemInfoExtCommand(kUidLsb),
            (std::vector<std::uint8_t>{0x2Au, 0x3Bu, 0x0Fu, 0x01u, 0x02u, 0x03u,
                                       0x04u, 0x05u, 0x06u, 0x07u, 0x08u}));
}

class UserspacePcscReaderTest : public ::testing::Test {
 protected:
  void TearDown() override {
    nero_nfc::NeroNfcUtestClearListPcscReadersOverride();
  }
};

TEST_F(UserspacePcscReaderTest,
       ResolvePcscReaderUsesOnlyReaderWhenNeedleEmpty) {
  std::vector<std::string> readers = {
      "HID Global OMNIKEY 5422 Smartcard Reader 00 00"};
  nero_nfc::NeroNfcUtestSetListPcscReadersOverride(&readers);

  std::string reader;
  std::string err;
  ASSERT_TRUE(nero_nfc::ResolvePcscReader("", reader, err));
  EXPECT_EQ(reader, "HID Global OMNIKEY 5422 Smartcard Reader 00 00");
}

TEST_F(UserspacePcscReaderTest, ResolvePcscReaderAutoSelectsUniqueNeroReader) {
  std::vector<std::string> readers = {
      "ACS ACR1252 Dual Reader SAM 01 00",
      "Nero NFC Arduino UNO R4 WiFi CCID 00 00"};
  nero_nfc::NeroNfcUtestSetListPcscReadersOverride(&readers);

  std::string reader;
  std::string err;
  ASSERT_TRUE(nero_nfc::ResolvePcscReader("", reader, err));
  EXPECT_EQ(reader, "Nero NFC Arduino UNO R4 WiFi CCID 00 00");
}

TEST_F(UserspacePcscReaderTest,
       ResolvePcscReaderKeepsMultipleSelectableReadersAmbiguous) {
  std::vector<std::string> readers = {
      "HID Global OMNIKEY 5422 Smartcard Reader 00 00",
      "Nero NFC Arduino UNO R4 WiFi CCID 00 00"};
  nero_nfc::NeroNfcUtestSetListPcscReadersOverride(&readers);

  std::string reader;
  std::string err;
  EXPECT_FALSE(nero_nfc::ResolvePcscReader("", reader, err));
  EXPECT_NE(err.find("multiple Nero-compatible PC/SC readers detected"),
            std::string::npos);
  EXPECT_NE(err.find("NFC_PCSC_READER"), std::string::npos);
  EXPECT_NE(err.find("OMNIKEY"), std::string::npos);
  EXPECT_NE(err.find("Nero NFC"), std::string::npos);
}

TEST_F(UserspacePcscReaderTest, ResolvePcscReaderRejectsAmbiguousDefault) {
  std::vector<std::string> readers = {
      "HID Global OMNIKEY 5422 Smartcard Reader 00 00",
      "Yubico YubiKey OTP+FIDO+CCID 00 00"};
  nero_nfc::NeroNfcUtestSetListPcscReadersOverride(&readers);

  std::string reader;
  std::string err;
  EXPECT_FALSE(nero_nfc::ResolvePcscReader("", reader, err));
  EXPECT_NE(err.find("multiple PC/SC readers detected"), std::string::npos);
  EXPECT_NE(err.find("NFC_PCSC_READER"), std::string::npos);
  EXPECT_NE(err.find("OMNIKEY"), std::string::npos);
  EXPECT_NE(err.find("YubiKey"), std::string::npos);
}

TEST_F(UserspacePcscReaderTest,
       ResolvePcscReaderMatchesCaseInsensitiveSubstring) {
  std::vector<std::string> readers = {
      "Nero NFC Arduino UNO R4 WiFi CCID 00 00"};
  nero_nfc::NeroNfcUtestSetListPcscReadersOverride(&readers);

  std::string reader;
  std::string err;
  ASSERT_TRUE(nero_nfc::ResolvePcscReader("arduino", reader, err));
  EXPECT_EQ(reader, readers.front());
}

TEST_F(UserspacePcscReaderTest,
       ResolvePcscReaderPrefersExactMatchOverSubstringAmbiguity) {
  std::vector<std::string> readers = {"Nero NFC CCID 00 00",
                                      "Nero NFC CCID 01 00"};
  nero_nfc::NeroNfcUtestSetListPcscReadersOverride(&readers);

  std::string reader;
  std::string err;
  ASSERT_TRUE(nero_nfc::ResolvePcscReader("Nero NFC CCID 01 00", reader, err));
  EXPECT_EQ(reader, "Nero NFC CCID 01 00");
}

TEST_F(UserspacePcscReaderTest, ResolvePcscReaderRejectsAmbiguousSubstring) {
  std::vector<std::string> readers = {"Nero NFC CCID 00 00",
                                      "Nero NFC CCID 01 00"};
  nero_nfc::NeroNfcUtestSetListPcscReadersOverride(&readers);

  std::string reader;
  std::string err;
  EXPECT_FALSE(nero_nfc::ResolvePcscReader("nero", reader, err));
  EXPECT_NE(err.find("ambiguous PC/SC reader substring"), std::string::npos);
  EXPECT_NE(err.find("Nero NFC CCID 00 00"), std::string::npos);
  EXPECT_NE(err.find("Nero NFC CCID 01 00"), std::string::npos);
}

TEST_F(UserspacePcscReaderTest, ResolvePcscReaderFailsWhenNoMatch) {
  std::vector<std::string> readers = {"Nero NFC CCID 00 00"};
  nero_nfc::NeroNfcUtestSetListPcscReadersOverride(&readers);

  std::string reader;
  std::string err;
  EXPECT_FALSE(nero_nfc::ResolvePcscReader("omnikey", reader, err));
  EXPECT_NE(err.find("no PC/SC reader matched"), std::string::npos);
  EXPECT_NE(err.find("Nero NFC CCID 00 00"), std::string::npos);
}

TEST(UserspacePcsc, ParsesShareModeAliases) {
  ASSERT_TRUE(nero_nfc::ParsePcscShareMode("shared").has_value());
  EXPECT_EQ(nero_nfc::ParsePcscShareMode("shared"),
            std::optional{nero_nfc::PcscShareMode::kShared});
  EXPECT_EQ(nero_nfc::ParsePcscShareMode("SCARD_SHARE_SHARED"),
            std::optional{nero_nfc::PcscShareMode::kShared});
  EXPECT_EQ(nero_nfc::ParsePcscShareMode("exclusive"),
            std::optional{nero_nfc::PcscShareMode::kExclusive});
  EXPECT_EQ(nero_nfc::ParsePcscShareMode("SCARD_SHARE_EXCLUSIVE"),
            std::optional{nero_nfc::PcscShareMode::kExclusive});
  EXPECT_FALSE(nero_nfc::ParsePcscShareMode("auto").has_value());
  EXPECT_EQ(nero_nfc::PcscShareModeName(nero_nfc::PcscShareMode::kShared),
            "shared");
  EXPECT_EQ(nero_nfc::PcscShareModeName(nero_nfc::PcscShareMode::kExclusive),
            "exclusive");
}

TEST(UserspacePcsc, ParsesUriWithHttpsPrefixCode) {
  auto ndef = nero_nfc::BuildNdefUriRecord("https://webauthn.io/demo");
  auto records = nero_nfc::ParseNdefRecords(ndef);

  ASSERT_EQ(records.size(), 1u);
  ASSERT_TRUE(records[0].decoded_.has_value());
  EXPECT_EQ(records[0].decoded_,
            std::optional<std::string>("https://webauthn.io/demo"));
  EXPECT_EQ(records[0].payload_.front(),
            0x04u); /* NFC Forum URI prefix for https:// */
}

TEST(UserspacePcsc, RejectsInvalidHexInput) {
  std::vector<std::uint8_t> out;
  EXPECT_FALSE(nero_nfc::ParseHexBytes("04:GG", out));
  EXPECT_FALSE(nero_nfc::ParseHexBytes("0", out));
  EXPECT_TRUE(out.empty());
  std::string oversized_hex;
  oversized_hex.reserve(
      (static_cast<std::size_t>(NERO_NFC_NDEF_MAX_TOTAL_BYTES) * kTestLit2u) +
      kTestLit2u);
  oversized_hex.assign(
      (static_cast<std::size_t>(NERO_NFC_NDEF_MAX_TOTAL_BYTES) * kTestLit2u) +
          kTestLit2u,
      '0');
  EXPECT_FALSE(nero_nfc::ParseHexBytes(oversized_hex, out));
  EXPECT_TRUE(out.empty());
}

TEST(UserspacePcsc, BuildNdefMessageProducesTwoRecords) {
  auto rec1 = nero_nfc::BuildNdefUriRecord("https://one.test");
  auto rec2 = nero_nfc::BuildNdefUriRecord("https://two.test");
  auto msg = nero_nfc::BuildNdefMessage({rec1, rec2});
  auto parsed = nero_nfc::ParseNdefRecords(msg);

  ASSERT_EQ(parsed.size(), 2u);
  ASSERT_TRUE(parsed[0].decoded_.has_value());
  ASSERT_TRUE(parsed[1].decoded_.has_value());
  EXPECT_EQ(parsed[0].decoded_, std::optional<std::string>("https://one.test"));
  EXPECT_EQ(parsed[1].decoded_, std::optional<std::string>("https://two.test"));
}
