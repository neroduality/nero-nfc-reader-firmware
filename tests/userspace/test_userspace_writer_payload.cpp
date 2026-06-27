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

#include "nero_nfc_ndef.h"
#include "nero_nfc_writer_payload.h"
#include "nfc_ndef_tlv.h"

#include <gtest/gtest.h>

namespace {

std::vector<nero_nfc::NdefRecordSummary> parse_one(const std::vector<std::uint8_t> &record) {
  return nero_nfc::parse_ndef_records(nero_nfc::build_ndef_message({record}));
}

void ExpectFitsType5Storage(const std::vector<std::uint8_t> &ndef) {
  uint8_t tlv[320];
  uint16_t tlv_len = 0u;

  ASSERT_FALSE(ndef.empty());
  ASSERT_TRUE(nfc_ndef_build_message_tlv(ndef.data(), static_cast<uint16_t>(ndef.size()), tlv,
                                         static_cast<uint16_t>(sizeof(tlv)), &tlv_len));
  EXPECT_GT(tlv_len, 0u);
  EXPECT_LE(tlv_len, sizeof(tlv));
}

} // namespace

TEST(UserspaceWriterPayload, UrlComponentEncodeEscapesOnlyRequiredBytes) {
  EXPECT_EQ(nero_nfc::writer_url_component_encode("A z-_.~&?"), "A%20z-_.~%26%3F");
}

TEST(UserspaceWriterPayload, BuildsVcardRecordWithOptionalFields) {
  auto records = parse_one(nero_nfc::build_writer_vcard_record("Ada Lovelace|+44123|ada@example.test"));

  ASSERT_EQ(records.size(), 1u);
  EXPECT_EQ(records[0].tnf, 2u);
  EXPECT_EQ(records[0].type, "text/vcard");
  ASSERT_TRUE(records[0].decoded.has_value());
  EXPECT_EQ(*records[0].decoded, "Contact: name=Ada Lovelace tel=+44123 email=ada@example.test");
  std::string body(records[0].payload.begin(), records[0].payload.end());
  EXPECT_NE(body.find("VERSION:4.0"), std::string::npos);
  EXPECT_NE(body.find("FN:Ada Lovelace"), std::string::npos);
  EXPECT_NE(body.find("TEL:+44123"), std::string::npos);
  EXPECT_NE(body.find("EMAIL:ada@example.test"), std::string::npos);
}

TEST(UserspaceWriterPayload, RejectsEmptyVcard) {
  EXPECT_TRUE(nero_nfc::build_writer_vcard_record("").empty());
}

TEST(UserspaceWriterPayload, RejectsVcardWithControlChars) {
  /* [RFC6350] reject CR/LF in field values to prevent property injection. */
  EXPECT_TRUE(nero_nfc::build_writer_vcard_record("Ada\r\nFN:Eve|+100").empty());
  EXPECT_TRUE(nero_nfc::build_writer_vcard_record("Ada|+1\n00").empty());
}

TEST(UserspaceWriterPayload, BuildsMailAndSmsUriRecords) {
  auto mail = parse_one(nero_nfc::build_writer_mail_record("dev@example.test|Hello NFC|body text"));
  ASSERT_EQ(mail.size(), 1u);
  ASSERT_TRUE(mail[0].decoded.has_value());
  EXPECT_EQ(*mail[0].decoded, "mailto:dev@example.test?subject=Hello%20NFC&body=body%20text");

  auto sms = parse_one(nero_nfc::build_writer_sms_record("+15551234567|tap me"));
  ASSERT_EQ(sms.size(), 1u);
  ASSERT_TRUE(sms[0].decoded.has_value());
  EXPECT_EQ(*sms[0].decoded, "sms:+15551234567?body=tap%20me");
}

TEST(UserspaceWriterPayload, RejectsEmptyMailAndSms) {
  EXPECT_TRUE(nero_nfc::build_writer_mail_record("").empty());
  EXPECT_TRUE(nero_nfc::build_writer_sms_record("").empty());
}

TEST(UserspaceWriterPayload, BuildsBluetoothRecordAndRejectsMalformedMac) {
  auto records = parse_one(nero_nfc::build_writer_bluetooth_record("01:23:45:67:89:AB"));

  ASSERT_EQ(records.size(), 1u);
  EXPECT_EQ(records[0].type, "application/vnd.bluetooth.ep.oob");
  ASSERT_TRUE(records[0].decoded.has_value());
  EXPECT_EQ(*records[0].decoded, "Bluetooth OOB: address=01:23:45:67:89:AB");
  ASSERT_GE(records[0].payload.size(), 8u);
  /* [BT-OOB] 2-byte OOB Data Length (LSB first) then BD_ADDR LSB first. */
  EXPECT_EQ(records[0].payload[0], 0x08u);
  EXPECT_EQ(records[0].payload[1], 0x00u);
  EXPECT_EQ(records[0].payload[2], 0xABu);
  EXPECT_EQ(records[0].payload[7], 0x01u);
  EXPECT_TRUE(nero_nfc::build_writer_bluetooth_record("01:23:bad").empty());
  EXPECT_TRUE(nero_nfc::build_writer_bluetooth_record("01:23:45:67:89:AZ").empty());
}

TEST(UserspaceWriterPayload, BuildsWifiWpsRecordAndRejectsInvalidSpecs) {
  auto records = parse_one(nero_nfc::build_writer_wifi_record("LabSSID|supersecret"));

  ASSERT_EQ(records.size(), 1u);
  EXPECT_EQ(records[0].type, "application/vnd.wfa.wsc");
  ASSERT_TRUE(records[0].decoded.has_value());
  EXPECT_EQ(*records[0].decoded,
            "Wi-Fi: ssid=LabSSID auth=WPA2-Personal encryption=AES key=supersecret");
  ASSERT_GE(records[0].payload.size(), 16u);
  EXPECT_EQ(records[0].payload[0], 0x10u);
  EXPECT_EQ(records[0].payload[1], 0x4Au);
  EXPECT_TRUE(nero_nfc::build_writer_wifi_record("LabSSID|short").empty());
  EXPECT_TRUE(nero_nfc::build_writer_wifi_record("|supersecret").empty());
}

TEST(UserspaceWriterPayload, SupportedWriterFlagsFitOrdinaryType5Storage) {
  ExpectFitsType5Storage(nero_nfc::build_ndef_message({nero_nfc::build_ndef_text_record("hello NFC")}));
  ExpectFitsType5Storage(nero_nfc::build_ndef_message(
    {nero_nfc::build_ndef_uri_record("https://example.test/one"),
     nero_nfc::build_ndef_uri_record("https://example.test/two")}));
  ExpectFitsType5Storage(
    nero_nfc::build_ndef_message({nero_nfc::build_writer_wifi_record("SSID|passphrase")}));
  ExpectFitsType5Storage(nero_nfc::build_ndef_message(
    {nero_nfc::build_writer_vcard_record("Ada Lovelace|+15551234567|ada@example.test")}));
}

TEST(UserspaceWriterPayload, NormalizesCompleteType2Type5TlvHexPayloadToRawNdef) {
  std::vector<std::uint8_t> tlv = {0x03u, 0x11u, 0xD1u, 0x01u, 0x0Du, 0x55u, 0x03u,
                                  0x65u, 0x78u, 0x61u, 0x6Du, 0x70u, 0x6Cu, 0x65u,
                                  0x2Eu, 0x74u, 0x65u, 0x73u, 0x74u, 0xFEu};

  nero_nfc::normalize_writer_ndef_hex_payload(tlv);

  ASSERT_EQ(tlv.size(), 17u);
  EXPECT_EQ(tlv[0], 0xD1u);
  EXPECT_EQ(tlv[3], 0x55u);
}
