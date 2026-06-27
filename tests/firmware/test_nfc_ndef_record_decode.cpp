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

#include "nfc_ndef_record_decode.h"

#include <gtest/gtest.h>

#include <vector>

TEST(NfcNdefRecordDecode, WalksShortUriRecord) {
  static const uint8_t kMsg[] = {0xD1u, 0x01u, 0x0Cu, 'U', 0x04u, 'e', 'x', 'a', 'm',
                                'p',   'l',   'e',   '.',   'c',   'o',   'm'};
  nfc_ndef_record_t rec{};
  uint16_t next = 0u;

  ASSERT_EQ(nfc_ndef_record_next(kMsg, sizeof(kMsg), 0u, &rec, &next), NFC_NDEF_RECORD_OK);
  EXPECT_EQ(rec.tnf, 0x01u);
  EXPECT_EQ(rec.type_len, 1u);
  EXPECT_EQ(rec.payload_len, 12u);
  EXPECT_EQ(rec.type_offset, 3u);
  EXPECT_EQ(rec.payload_offset, 4u);
  EXPECT_EQ(rec.record_len, sizeof(kMsg));
  EXPECT_TRUE(rec.message_end);
  EXPECT_EQ(next, sizeof(kMsg));
}

TEST(NfcNdefRecordDecode, RejectsChunkedRecord) {
  /* [NDEF] CF (0x20) set marks a chunked record; reassembly is unsupported. */
  static const uint8_t kMsg[] = {0xB1u, 0x01u, 0x02u, 'U', 0x04u, 'a'};
  nfc_ndef_record_t rec{};
  uint16_t next = 0u;

  EXPECT_EQ(nfc_ndef_record_next(kMsg, sizeof(kMsg), 0u, &rec, &next), NFC_NDEF_RECORD_UNSUPPORTED);
}

TEST(NfcNdefRecordDecode, SkipsEmptyBytesBetweenRecords) {
  static const uint8_t kMsg[] = {0x00u, 0x00u, 0xD1u, 0x01u, 0x01u, 'U', 0x00u, 'a'};
  nfc_ndef_record_t rec{};
  uint16_t kPos = 0u;
  uint16_t next = 0u;

  ASSERT_EQ(nfc_ndef_record_next(kMsg, sizeof(kMsg), kPos, &rec, &next), NFC_NDEF_RECORD_EMPTY);
  kPos = next;
  ASSERT_EQ(nfc_ndef_record_next(kMsg, sizeof(kMsg), kPos, &rec, &next), NFC_NDEF_RECORD_EMPTY);
  kPos = next;
  ASSERT_EQ(nfc_ndef_record_next(kMsg, sizeof(kMsg), kPos, &rec, &next), NFC_NDEF_RECORD_OK);
  EXPECT_EQ(rec.payload_len, 1u);
  EXPECT_EQ(next, 7u);
  EXPECT_TRUE(rec.message_end);
}

TEST(NfcNdefRecordDecode, RejectsTruncatedRecord) {
  static const uint8_t kMsg[] = {0xD1u, 0x01u, 0x05u, 'U'};
  nfc_ndef_record_t rec{};
  uint16_t next = 0u;

  EXPECT_EQ(nfc_ndef_record_next(kMsg, sizeof(kMsg), 0u, &rec, &next), NFC_NDEF_RECORD_TRUNCATED);
}

TEST(NfcNdefRecordDecode, WalksShortRecordWithIdLength) {
  static const uint8_t kMsg[] = {0xD9u, 0x01u, 0x01u, 0x02u, 'T', 'i', 'd', 'x'};
  nfc_ndef_record_t rec{};
  uint16_t next = 0u;

  ASSERT_EQ(nfc_ndef_record_next(kMsg, sizeof(kMsg), 0u, &rec, &next), NFC_NDEF_RECORD_OK);
  EXPECT_EQ(rec.type_len, 1u);
  EXPECT_EQ(rec.payload_len, 1u);
  EXPECT_EQ(rec.type_offset, 4u);
  EXPECT_EQ(rec.payload_offset, 7u);
  EXPECT_EQ(rec.record_len, sizeof(kMsg));
  EXPECT_EQ(next, sizeof(kMsg));
}

TEST(NfcNdefRecordDecode, WalksNormalRecordLength) {
  std::vector<uint8_t> kMsg(6u + 1u + 256u, 0xAAu);
  nfc_ndef_record_t rec{};
  uint16_t next = 0u;

  kMsg[0] = 0xC1u; /* MB | ME | TNF=well-known, SR=0 */
  kMsg[1] = 0x01u;
  kMsg[2] = 0x00u;
  kMsg[3] = 0x00u;
  kMsg[4] = 0x01u;
  kMsg[5] = 0x00u;
  kMsg[6] = 'U';

  ASSERT_EQ(nfc_ndef_record_next(kMsg.data(), (uint16_t)kMsg.size(), 0u, &rec, &next),
            NFC_NDEF_RECORD_OK);
  EXPECT_EQ(rec.type_len, 1u);
  EXPECT_EQ(rec.payload_len, 256u);
  EXPECT_EQ(rec.type_offset, 6u);
  EXPECT_EQ(rec.payload_offset, 7u);
  EXPECT_EQ(rec.record_len, kMsg.size());
  EXPECT_EQ(next, kMsg.size());
}

TEST(NfcNdefRecordDecode, WalksNormalRecordWithIdLength) {
  static const uint8_t kMsg[] = {0xC9u, 0x01u, 0x00u, 0x00u, 0x00u,
                                0x01u, 0x01u, 'T',  'i',  'x'};
  nfc_ndef_record_t rec{};
  uint16_t next = 0u;

  ASSERT_EQ(nfc_ndef_record_next(kMsg, sizeof(kMsg), 0u, &rec, &next), NFC_NDEF_RECORD_OK);
  EXPECT_EQ(rec.type_len, 1u);
  EXPECT_EQ(rec.payload_len, 1u);
  EXPECT_EQ(rec.type_offset, 7u);
  EXPECT_EQ(rec.payload_offset, 9u);
  EXPECT_EQ(rec.record_len, sizeof(kMsg));
  EXPECT_EQ(next, sizeof(kMsg));
}

TEST(NfcNdefRecordDecode, RejectsWrappedIdLengthOffset) {
  std::vector<uint8_t> kMsg(UINT16_MAX, 0x00u);
  nfc_ndef_record_t rec{};
  uint16_t next = 0u;
  constexpr uint16_t kPos = UINT16_MAX - 3u;

  kMsg[kPos] = 0xD9u; /* MB | ME | SR | IL | TNF=well-known */
  kMsg[kPos + 1u] = 0x01u;
  kMsg[kPos + 2u] = 0x00u;

  EXPECT_EQ(nfc_ndef_record_next(kMsg.data(), (uint16_t)kMsg.size(), kPos, &rec, &next),
            NFC_NDEF_RECORD_TRUNCATED);
}

TEST(NfcNdefRecordDecode, InvalidInputClearsPreviousOutput) {
  static const uint8_t kValid[] = {0xD1u, 0x01u, 0x01u, 'U', 0x00u};
  static const uint8_t kTruncated[] = {0xD1u, 0x01u, 0x05u, 'U'};
  nfc_ndef_record_t rec{};
  uint16_t next = 0u;

  ASSERT_EQ(nfc_ndef_record_next(kValid, sizeof(kValid), 0u, &rec, &next), NFC_NDEF_RECORD_OK);
  ASSERT_NE(rec.record_len, 0u);
  ASSERT_NE(next, 0u);

  EXPECT_EQ(nfc_ndef_record_next(kTruncated, sizeof(kTruncated), 0u, &rec, &next),
            NFC_NDEF_RECORD_TRUNCATED);
  EXPECT_EQ(rec.header, 0u);
  EXPECT_EQ(rec.record_len, 0u);
  EXPECT_EQ(rec.payload_len, 0u);
  EXPECT_EQ(next, 0u);
}
