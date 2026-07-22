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

#include "nero_nfc_ndef.hpp"
#include "nero_nfc_writer_payload.hpp"
#include "nfc_ndef_tlv.h"

namespace {
enum {
  kTestLit0x03u = 0x03u,
  kTestLit0x0Du = 0x0Du,
  kTestLit0x11u = 0x11u,
  kTestLit0x2Eu = 0x2Eu,
  kTestLit0x55u = 0x55u,
  kTestLit0x61u = 0x61u,
  kTestLit0x65u = 0x65u,
  kTestLit0x6Cu = 0x6Cu,
  kTestLit0x6Du = 0x6Du,
  kTestLit0x70u = 0x70u,
  kTestLit0x73u = 0x73u,
  kTestLit0x74u = 0x74u,
  kTestLit0x78u = 0x78u,
  kTestLit0xD1u = 0xD1u,
  kTestLit0xFEu = 0xFEu,
};
}  // namespace

#include <gtest/gtest.h>

namespace {

enum {
  kType5NdefTlvScratchCap = 320u,
};

std::vector<nero_nfc::NdefRecordSummary> ParseOne(
    const std::vector<std::uint8_t>& record) {
  return nero_nfc::ParseNdefRecords(nero_nfc::BuildNdefMessage({record}));
}

void ExpectFitsType5Storage(const std::vector<std::uint8_t>& ndef) {
  uint8_t tlv[kType5NdefTlvScratchCap];
  uint16_t tlv_len = 0u;

  ASSERT_FALSE(ndef.empty());
  ASSERT_TRUE(nfc_ndef_build_message_tlv(
      ndef.data(), static_cast<uint16_t>(ndef.size()), &tlv[0],
      static_cast<uint16_t>(sizeof(tlv)), &tlv_len));
  EXPECT_GT(tlv_len, 0u);
  EXPECT_LE(tlv_len, sizeof(tlv));
}

}  // namespace

TEST(UserspaceWriterPayload, UrlComponentEncodeEscapesOnlyRequiredBytes) {
  EXPECT_EQ(nero_nfc::WriterUrlComponentEncode("A z-_.~&?"), "A%20z-_.~%26%3F");
}

TEST(UserspaceWriterPayload, BuildsVcardRecordWithOptionalFields) {
  auto records = ParseOne(
      nero_nfc::BuildWriterVcardRecord("Ada Lovelace|+44123|ada@example.test"));

  ASSERT_EQ(records.size(), 1u);
  EXPECT_EQ(records[0].tnf_, 2u);
  EXPECT_EQ(records[0].type_, "text/vcard");
  ASSERT_TRUE(records[0].decoded_.has_value());
  EXPECT_EQ(
      records[0].decoded_,
      std::optional<std::string>(
          "Contact: name=Ada Lovelace tel=+44123 email=ada@example.test"));
  std::string body(records[0].payload_.begin(), records[0].payload_.end());
  EXPECT_NE(body.find("VERSION:4.0"), std::string::npos);
  EXPECT_NE(body.find("FN:Ada Lovelace"), std::string::npos);
  EXPECT_NE(body.find("TEL:+44123"), std::string::npos);
  EXPECT_NE(body.find("EMAIL:ada@example.test"), std::string::npos);
}

TEST(UserspaceWriterPayload, RejectsEmptyVcard) {
  EXPECT_TRUE(nero_nfc::BuildWriterVcardRecord("").empty());
}

TEST(UserspaceWriterPayload, RejectsVcardWithControlChars) {
  /* [RFC6350] reject CR/LF in field values to prevent property injection. */
  EXPECT_TRUE(nero_nfc::BuildWriterVcardRecord("Ada\r\nFN:Eve|+100").empty());
  EXPECT_TRUE(nero_nfc::BuildWriterVcardRecord("Ada|+1\n00").empty());
}

TEST(UserspaceWriterPayload, BuildsMailAndSmsUriRecords) {
  auto mail = ParseOne(
      nero_nfc::BuildWriterMailRecord("dev@example.test|Hello NFC|body text"));
  ASSERT_EQ(mail.size(), 1u);
  ASSERT_TRUE(mail[0].decoded_.has_value());
  EXPECT_EQ(
      mail[0].decoded_,
      std::optional<std::string>(
          "mailto:dev@example.test?subject=Hello%20NFC&body=body%20text"));
  auto sms = ParseOne(nero_nfc::BuildWriterSmsRecord("+15551234567|tap me"));
  ASSERT_EQ(sms.size(), 1u);
  ASSERT_TRUE(sms[0].decoded_.has_value());
  EXPECT_EQ(sms[0].decoded_,
            std::optional<std::string>("sms:+15551234567?body=tap%20me"));
}

TEST(UserspaceWriterPayload, RejectsEmptyMailAndSms) {
  EXPECT_TRUE(nero_nfc::BuildWriterMailRecord("").empty());
  EXPECT_TRUE(nero_nfc::BuildWriterSmsRecord("").empty());
}

TEST(UserspaceWriterPayload, BuildsBluetoothRecordAndRejectsMalformedMac) {
  auto records =
      ParseOne(nero_nfc::BuildWriterBluetoothRecord("01:23:45:67:89:AB"));

  ASSERT_EQ(records.size(), 1u);
  EXPECT_EQ(records[0].type_, "application/vnd.bluetooth.ep.oob");
  ASSERT_TRUE(records[0].decoded_.has_value());
  EXPECT_EQ(
      records[0].decoded_,
      std::optional<std::string>("Bluetooth OOB: address=01:23:45:67:89:AB"));
  ASSERT_GE(records[0].payload_.size(), 8u);
  /* [BT-OOB] 2-byte OOB Data Length (LSB first) then BD_ADDR LSB first. */
  EXPECT_EQ(records[0].payload_[0], 0x08u);
  EXPECT_EQ(records[0].payload_[1], 0x00u);
  EXPECT_EQ(records[0].payload_[2], 0xABu);
  EXPECT_EQ(records[0].payload_[7], 0x01u);
  EXPECT_TRUE(nero_nfc::BuildWriterBluetoothRecord("01:23:bad").empty());
  EXPECT_TRUE(
      nero_nfc::BuildWriterBluetoothRecord("01:23:45:67:89:AZ").empty());
}

TEST(UserspaceWriterPayload, BuildsWifiWpsRecordAndRejectsInvalidSpecs) {
  auto records =
      ParseOne(nero_nfc::BuildWriterWifiRecord("LabSSID|supersecret"));

  ASSERT_EQ(records.size(), 1u);
  EXPECT_EQ(records[0].type_, "application/vnd.wfa.wsc");
  ASSERT_TRUE(records[0].decoded_.has_value());
  EXPECT_EQ(records[0].decoded_,
            std::optional<std::string>("Wi-Fi: ssid=LabSSID auth=WPA2-Personal "
                                       "encryption=AES key=supersecret"));
  ASSERT_GE(records[0].payload_.size(), 16u);
  EXPECT_EQ(records[0].payload_[0], 0x10u);
  EXPECT_EQ(records[0].payload_[1], 0x4Au);
  EXPECT_TRUE(nero_nfc::BuildWriterWifiRecord("LabSSID|short").empty());
  EXPECT_TRUE(nero_nfc::BuildWriterWifiRecord("|supersecret").empty());
}

TEST(UserspaceWriterPayload, SupportedWriterFlagsFitOrdinaryType5Storage) {
  ExpectFitsType5Storage(
      nero_nfc::BuildNdefMessage({nero_nfc::BuildNdefTextRecord("hello NFC")}));
  ExpectFitsType5Storage(nero_nfc::BuildNdefMessage(
      {nero_nfc::BuildNdefUriRecord("https://example.test/one"),
       nero_nfc::BuildNdefUriRecord("https://example.test/two")}));
  ExpectFitsType5Storage(nero_nfc::BuildNdefMessage(
      {nero_nfc::BuildWriterWifiRecord("SSID|passphrase")}));
  ExpectFitsType5Storage(
      nero_nfc::BuildNdefMessage({nero_nfc::BuildWriterVcardRecord(
          "Ada Lovelace|+15551234567|ada@example.test")}));
}

TEST(UserspaceWriterPayload,
     NormalizesCompleteType2Type5TlvHexPayloadToRawNdef) {
  std::vector<std::uint8_t> tlv = {
      kTestLit0x03u, kTestLit0x11u, kTestLit0xD1u, 0x01u,
      kTestLit0x0Du, kTestLit0x55u, kTestLit0x03u, kTestLit0x65u,
      kTestLit0x78u, kTestLit0x61u, kTestLit0x6Du, kTestLit0x70u,
      kTestLit0x6Cu, kTestLit0x65u, kTestLit0x2Eu, kTestLit0x74u,
      kTestLit0x65u, kTestLit0x73u, kTestLit0x74u, kTestLit0xFEu};

  nero_nfc::NormalizeWriterNdefHexPayload(tlv);

  ASSERT_EQ(tlv.size(), 17u);
  EXPECT_EQ(tlv[0], 0xD1u);
  EXPECT_EQ(tlv[3], 0x55u);
}
