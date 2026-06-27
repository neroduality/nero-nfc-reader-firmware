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
#include "writer_hal_utest_stub.h"

#include "nfc_ndef_record_decode.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

namespace {

void append_bytes(std::vector<std::uint8_t> &out, const char *text) {
  while (*text != '\0') {
    out.push_back(static_cast<std::uint8_t>(*text++));
  }
}

std::vector<std::uint8_t> make_short_mime_record(const char *mime,
                                                 const std::vector<std::uint8_t> &payload) {
  std::vector<std::uint8_t> record;
  record.push_back(static_cast<std::uint8_t>(NFC_NDEF_HDR_MB | NFC_NDEF_HDR_ME |
                                             NFC_NDEF_HDR_SR | NFC_NDEF_TNF_MIME));
  record.push_back(0u);
  record.push_back(static_cast<std::uint8_t>(payload.size()));
  const auto type_len_index = static_cast<std::size_t>(1u);
  while (*mime != '\0') {
    record.push_back(static_cast<std::uint8_t>(*mime++));
    record[type_len_index]++;
  }
  record.insert(record.end(), payload.begin(), payload.end());
  return record;
}

} // namespace

TEST(ReaderTagsNdefPrint, DecodesWifiWscMimeRecord) {
  const std::vector<std::uint8_t> payload = {
    0x10u, 0x4Au, 0x00u, 0x01u, 0x10u, 0x10u, 0x0Eu, 0x00u, 0x31u, 0x10u, 0x26u, 0x00u,
    0x01u, 0x01u, 0x10u, 0x45u, 0x00u, 0x04u, 'S',   'S',   'I',   'D',   0x10u, 0x03u,
    0x00u, 0x02u, 0x00u, 0x20u, 0x10u, 0x0Fu, 0x00u, 0x02u, 0x00u, 0x08u, 0x10u, 0x27u,
    0x00u, 0x0Au, 'p',   'a',   's',   's',   'p',   'h',   'r',   'a',   's',   'e',
    0x10u, 0x20u, 0x00u, 0x06u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
  };
  const auto record = make_short_mime_record("application/vnd.wfa.wsc", payload);
  writer_hal_utest_reset();

  reader_tags_print_ndef_records(record.data(), static_cast<uint16_t>(record.size()));

  const std::string output = writer_hal_utest_output();
  EXPECT_NE(output.find("Type=application/vnd.wfa.wsc"), std::string::npos);
  EXPECT_NE(output.find("Decoded=\"Wi-Fi: ssid=SSID auth=WPA2-Personal encryption=AES key=passphrase\""),
            std::string::npos);
}

TEST(ReaderTagsNdefPrint, DecodesVcardMimeRecord) {
  std::vector<std::uint8_t> payload;
  append_bytes(payload,
               "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Ada Lovelace\r\nTEL:+15551234567\r\n"
               "EMAIL:ada@example.test\r\nEND:VCARD\r\n");
  const auto record = make_short_mime_record("text/vcard", payload);
  writer_hal_utest_reset();

  reader_tags_print_ndef_records(record.data(), static_cast<uint16_t>(record.size()));

  const std::string output = writer_hal_utest_output();
  EXPECT_NE(output.find("Type=text/vcard"), std::string::npos);
  EXPECT_NE(output.find("Decoded=\"Contact: name=Ada Lovelace tel=+15551234567 email=ada@example.test\""),
            std::string::npos);
}
