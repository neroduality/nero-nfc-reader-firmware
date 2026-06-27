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

#include <gtest/gtest.h>

#include <array>
#include <vector>

extern "C" {
#include "nero_nfc_null.h"
#include "nfc_ndef_tlv.h"
}

TEST(NfcNdefTlv, EnvelopeLenShortAndExtended) {
  EXPECT_EQ(nfc_ndef_tlv_envelope_len(10u), 13u);
  EXPECT_EQ(nfc_ndef_tlv_envelope_len(254u), 257u);
  EXPECT_EQ(nfc_ndef_tlv_envelope_len(255u), 260u);
  EXPECT_EQ(nfc_ndef_tlv_envelope_len(256u), 261u);
}

TEST(NfcNdefTlv, NextSkipsNullTlv) {
  static const uint8_t kArea[] = {0x00u, 0x00u, 0x00u, 0x03u, 0x01u, 0xAAu, 0xFEu};
  nfc_ndef_tlv_t tlv{};
  uint16_t next = 0u;
  EXPECT_EQ(nfc_ndef_tlv_next(kArea, sizeof(kArea), 0u, &tlv, &next), NFC_NDEF_TLV_OK);
  EXPECT_EQ(tlv.type, NFC_NDEF_TLV_MESSAGE);
  EXPECT_EQ(tlv.value_len, 1u);
  EXPECT_EQ(kArea[tlv.value_offset], 0xAAu);
}

TEST(NfcNdefTlv, FindMessageSkipsUnknownTlv) {
  static const uint8_t kArea[] = {0x01u, 0x01u, 0x00u, 0x03u, 0x02u, 0xBBu, 0xCCu, 0xFEu};
  nfc_ndef_tlv_t tlv{};
  EXPECT_EQ(nfc_ndef_find_message_tlv(kArea, sizeof(kArea), 0u, &tlv), NFC_NDEF_TLV_OK);
  EXPECT_EQ(tlv.value_len, 2u);
}

TEST(NfcNdefTlv, BuildMessageTlvRoundTrip) {
  static const uint8_t kNdef[] = {0xD1u, 0x01u, 0x03u, 'U', 'R', 'I'};
  std::array<uint8_t, 32> out{};
  uint16_t out_len = 0u;
  ASSERT_TRUE(nfc_ndef_build_message_tlv(kNdef, (uint16_t)sizeof(kNdef), out.data(),
                                         (uint16_t)out.size(), &out_len));
  nfc_ndef_tlv_t tlv{};
  uint16_t next = 0u;
  ASSERT_EQ(nfc_ndef_tlv_next(out.data(), out_len, 0u, &tlv, &next), NFC_NDEF_TLV_OK);
  EXPECT_EQ(tlv.type, NFC_NDEF_TLV_MESSAGE);
  EXPECT_EQ(tlv.value_len, sizeof(kNdef));
}

TEST(NfcNdefTlv, BuildRejectsUndersizedBuffer) {
  static const uint8_t kNdef[] = {0x01u, 0x02u, 0x03u};
  std::array<uint8_t, 4> tiny{};
  uint16_t need = 0u;
  EXPECT_FALSE(nfc_ndef_build_message_tlv(kNdef, (uint16_t)sizeof(kNdef), tiny.data(),
                                           (uint16_t)tiny.size(), &need));
  EXPECT_GT(need, (uint16_t)tiny.size());
}

TEST(NfcNdefTlv, BuildClearsLengthOnInvalidArgument) {
  std::array<uint8_t, 4> out{};
  uint16_t out_len = 0xBEEFu;

  EXPECT_FALSE(nfc_ndef_build_message_tlv(NERO_NFC_NULL, 1u, out.data(), (uint16_t)out.size(),
                                          &out_len));
  EXPECT_EQ(out_len, 0u);
}

TEST(NfcNdefTlv, RejectsWrappedExtendedLengthHeader) {
  std::vector<uint8_t> kArea(UINT16_MAX, 0x00u);
  nfc_ndef_tlv_t tlv{};
  uint16_t next = 0u;

  kArea[UINT16_MAX - 2u] = NFC_NDEF_TLV_MESSAGE;
  kArea[UINT16_MAX - 1u] = NFC_NDEF_TLV_EXTENDED_LEN;

  EXPECT_EQ(nfc_ndef_tlv_next(kArea.data(), (uint16_t)kArea.size(), UINT16_MAX - 2u, &tlv, &next),
            NFC_NDEF_TLV_TRUNCATED);
}

TEST(NfcNdefTlv, RejectsTruncatedExtendedLengthHeaderFixture) {
  static const uint8_t kArea[] = {NFC_NDEF_TLV_MESSAGE, NFC_NDEF_TLV_EXTENDED_LEN, 0x01u};
  nfc_ndef_tlv_t tlv{};
  uint16_t next = 0u;

  EXPECT_EQ(nfc_ndef_tlv_next(kArea, sizeof(kArea), 0u, &tlv, &next), NFC_NDEF_TLV_TRUNCATED);
}

TEST(NfcNdefTlv, InvalidInputClearsPreviousOutput) {
  static const uint8_t kValid[] = {NFC_NDEF_TLV_MESSAGE, 0x01u, 0xAAu};
  static const uint8_t kTruncated[] = {NFC_NDEF_TLV_MESSAGE};
  nfc_ndef_tlv_t tlv{};
  uint16_t next = 0u;

  ASSERT_EQ(nfc_ndef_tlv_next(kValid, sizeof(kValid), 0u, &tlv, &next), NFC_NDEF_TLV_OK);
  ASSERT_EQ(tlv.type, NFC_NDEF_TLV_MESSAGE);
  ASSERT_NE(next, 0u);

  EXPECT_EQ(nfc_ndef_tlv_next(kTruncated, sizeof(kTruncated), 0u, &tlv, &next),
            NFC_NDEF_TLV_TRUNCATED);
  EXPECT_EQ(tlv.type, 0u);
  EXPECT_EQ(tlv.value_offset, 0u);
  EXPECT_EQ(tlv.value_len, 0u);
  EXPECT_EQ(next, 0u);
}

TEST(NfcNdefTlv, AcceptsLargestExtendedTlvThatFitsUint16Buffer) {
  std::vector<uint8_t> kArea(UINT16_MAX, 0x00u);
  nfc_ndef_tlv_t tlv{};
  uint16_t next = 0u;

  kArea[0] = NFC_NDEF_TLV_MESSAGE;
  kArea[1] = NFC_NDEF_TLV_EXTENDED_LEN;
  kArea[2] = 0xFFu;
  kArea[3] = 0xFBu;

  ASSERT_EQ(nfc_ndef_tlv_next(kArea.data(), (uint16_t)kArea.size(), 0u, &tlv, &next),
            NFC_NDEF_TLV_OK);
  EXPECT_EQ(tlv.value_offset, 4u);
  EXPECT_EQ(tlv.value_len, 65531u);
  EXPECT_EQ(next, UINT16_MAX);
}

TEST(NfcNdefTlv, MaxPayloadForDataAreaUsesShortAndExtendedOverhead) {
  EXPECT_EQ(nfc_ndef_tlv_max_payload_for_data_area(64u), 61u);
  EXPECT_EQ(nfc_ndef_tlv_max_payload_for_data_area(160u), 157u);
  EXPECT_EQ(nfc_ndef_tlv_max_payload_for_data_area(256u), 251u);
  EXPECT_EQ(nfc_ndef_tlv_max_payload_for_data_area(2048u), 2043u);
  EXPECT_EQ(nfc_ndef_tlv_max_payload_for_data_area(3u), 0u);
}
