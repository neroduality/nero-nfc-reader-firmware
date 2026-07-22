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

#include "reader_tags_internal.h"
#include "writer_hal_utest_stub.hpp"

#include "nero_nfc_null.h"
#include "nfc_ndef_record_decode.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace {

void AppendBytes(std::vector<std::uint8_t>& out, const char* text) {
  const std::string_view kText{text == NERO_NFC_NULL ? "" : text};
  for (char ch : kText) {
    out.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(ch)));
  }
}

std::vector<std::uint8_t> MakeShortMimeRecord(
    const char* mime, const std::vector<std::uint8_t>& payload) {
  std::vector<std::uint8_t> record;
  record.push_back(static_cast<std::uint8_t>(
      NFC_NDEF_HDR_MB | NFC_NDEF_HDR_ME | NFC_NDEF_HDR_SR | NFC_NDEF_TNF_MIME));
  record.push_back(0u);
  record.push_back(static_cast<std::uint8_t>(payload.size()));
  const auto kTypeLenIndex = static_cast<std::size_t>(1u);
  const std::string_view kMime{mime == NERO_NFC_NULL ? "" : mime};
  for (char ch : kMime) {
    record.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(ch)));
    record[kTypeLenIndex]++;
  }
  record.insert(record.end(), payload.begin(), payload.end());
  return record;
}

}  // namespace

TEST(ReaderTagsNdefPrint, DecodesWifiWscMimeRecord) {
  const std::vector<std::uint8_t> kPayload = {
      0x10u, 0x4Au, 0x00u, 0x01u, 0x10u, 0x10u, 0x0Eu, 0x00u, 0x31u, 0x10u,
      0x26u, 0x00u, 0x01u, 0x01u, 0x10u, 0x45u, 0x00u, 0x04u, 'S',   'S',
      'I',   'D',   0x10u, 0x03u, 0x00u, 0x02u, 0x00u, 0x20u, 0x10u, 0x0Fu,
      0x00u, 0x02u, 0x00u, 0x08u, 0x10u, 0x27u, 0x00u, 0x0Au, 'p',   'a',
      's',   's',   'p',   'h',   'r',   'a',   's',   'e',   0x10u, 0x20u,
      0x00u, 0x06u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
  };
  const auto kRecord = MakeShortMimeRecord("application/vnd.wfa.wsc", kPayload);
  WriterHalUtestReset();

  reader_tags_print_ndef_records(kRecord.data(),
                                 static_cast<uint16_t>(kRecord.size()));

  const std::string kOutput = WriterHalUtestOutput();
  EXPECT_NE(kOutput.find("Type=application/vnd.wfa.wsc"), std::string::npos);
  EXPECT_NE(kOutput.find("Decoded=\"Wi-Fi: ssid=SSID auth=WPA2-Personal "
                         "encryption=AES key=passphrase\""),
            std::string::npos);
}

TEST(ReaderTagsNdefPrint, DecodesVcardMimeRecord) {
  std::vector<std::uint8_t> payload;
  AppendBytes(
      payload,
      "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Ada Lovelace\r\nTEL:+15551234567\r\n"
      "EMAIL:ada@example.test\r\nEND:VCARD\r\n");
  const auto kRecord = MakeShortMimeRecord("text/vcard", payload);
  WriterHalUtestReset();

  reader_tags_print_ndef_records(kRecord.data(),
                                 static_cast<uint16_t>(kRecord.size()));

  const std::string kOutput = WriterHalUtestOutput();
  EXPECT_NE(kOutput.find("Type=text/vcard"), std::string::npos);
  EXPECT_NE(
      kOutput.find("Decoded=\"Contact: name=Ada Lovelace tel=+15551234567 "
                   "email=ada@example.test\""),
      std::string::npos);
}
