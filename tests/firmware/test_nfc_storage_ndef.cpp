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

extern "C" {
#include "nero_nfc_null.h"
#include "nfc_storage_ndef.h"
}

TEST(NfcStorageNdef, Type2GeometryCoversNtagAndSt25tnCcSizes) {
  uint16_t last_page = 0u;

  ASSERT_TRUE(nfc_storage_type2_last_page(64u, &last_page));
  EXPECT_EQ(last_page, 19u);
  ASSERT_TRUE(nfc_storage_type2_last_page(144u, &last_page));
  EXPECT_EQ(last_page, 39u);
  ASSERT_TRUE(nfc_storage_type2_last_page(496u, &last_page));
  EXPECT_EQ(last_page, 127u);
  ASSERT_TRUE(nfc_storage_type2_last_page(872u, &last_page));
  EXPECT_EQ(last_page, 221u);
  ASSERT_TRUE(nfc_storage_type2_last_page(1016u, &last_page));
  EXPECT_EQ(last_page, 225u);
}

TEST(NfcStorageNdef, Type2ReadAndWriteSpansUseSamePageCaps) {
  EXPECT_TRUE(nfc_storage_type2_read_span_ok(144u, 3u, 4u));
  EXPECT_TRUE(nfc_storage_type2_read_span_ok(144u, 4u, 16u));
  EXPECT_FALSE(nfc_storage_type2_read_span_ok(144u, 2u, 4u));
  EXPECT_FALSE(nfc_storage_type2_read_span_ok(144u, 40u, 4u));

  EXPECT_TRUE(nfc_storage_type2_update_page_ok(4u, 4u));
  EXPECT_TRUE(nfc_storage_type2_update_page_ok(225u, 4u));
  EXPECT_FALSE(nfc_storage_type2_update_page_ok(3u, 4u));
  EXPECT_FALSE(nfc_storage_type2_update_page_ok(4u, 3u));
  EXPECT_FALSE(nfc_storage_type2_update_page_ok(226u, 4u));

  EXPECT_TRUE(nfc_storage_type2_write_span_ok(144u, 4u, 8u));
  EXPECT_FALSE(nfc_storage_type2_write_span_ok(144u, 3u, 4u));
  EXPECT_FALSE(nfc_storage_type2_write_span_ok(144u, 4u, 6u));
  EXPECT_FALSE(nfc_storage_type2_write_span_ok(144u, 39u, 8u));
}

TEST(NfcStorageNdef, Type2ScanLimitCapsLargeTags) {
  const uint16_t kCapped = nfc_storage_type2_read_unit_limit(
      3u, NFC_STORAGE_TYPE2_UNIT_SIZE, 4u, 1016u,
      NERO_NFC_TYPE2_STORAGE_NDEF_SCAN_MAX);

  EXPECT_EQ(kCapped, 223u);
}

TEST(NfcStorageNdef, Type5CcLengthAndDataBlocksCoverFourAndEightByteCc) {
  const uint8_t kShortCc[] = {0xE1u, 0x40u, 0x08u, 0x00u};
  const uint8_t kExtendedCc[] = {0xE2u, 0x40u, 0x00u, 0x00u,
                                 0x00u, 0x00u, 0x20u, 0x00u};
  uint16_t first = 0u;
  uint16_t last = 0u;

  EXPECT_EQ(
      nfc_storage_type5_cc_len_or_default(0u, &kShortCc[0], sizeof(kShortCc)),
      4u);
  EXPECT_EQ(nfc_storage_type5_cc_len_or_default(0u, &kExtendedCc[0],
                                                sizeof(kExtendedCc)),
            8u);
  EXPECT_EQ(
      nfc_storage_type5_cc_len_or_default(8u, &kShortCc[0], sizeof(kShortCc)),
      8u);
  EXPECT_EQ(nfc_storage_type5_declared_cc_len_from_first_block(
                &kShortCc[0], sizeof(kShortCc)),
            4u);
  EXPECT_EQ(
      nfc_storage_type5_declared_cc_len_from_first_block(&kExtendedCc[0], 4u),
      8u);
  EXPECT_EQ(
      nfc_storage_type5_declared_cc_len_from_first_block(NERO_NFC_NULL, 4u),
      0u);

  ASSERT_TRUE(nfc_storage_type5_data_blocks(4u, 320u, 4u, 80u, &first, &last));
  EXPECT_EQ(first, 1u);
  EXPECT_EQ(last, 79u);
  ASSERT_TRUE(nfc_storage_type5_data_blocks(8u, 2048u, 4u, 0u, &first, &last));
  EXPECT_EQ(first, 2u);
  EXPECT_EQ(last, 513u);
}

TEST(NfcStorageNdef, Type5ReadsMayIncludeCcButWritesStartAtDataBlocks) {
  EXPECT_TRUE(nfc_storage_type5_read_span_ok(4u, 320u, 4u, 80u, 0u, 4u));
  EXPECT_FALSE(nfc_storage_type5_write_span_ok(4u, 320u, 4u, 80u, 0u, 4u));
  EXPECT_TRUE(nfc_storage_type5_write_span_ok(4u, 320u, 4u, 80u, 1u, 4u));
  EXPECT_FALSE(nfc_storage_type5_write_span_ok(8u, 2048u, 4u, 0u, 1u, 4u));
  EXPECT_TRUE(nfc_storage_type5_write_span_ok(8u, 2048u, 4u, 0u, 2u, 4u));
  EXPECT_TRUE(nfc_storage_type5_write_span_ok(8u, 2048u, 4u, 0u, 2u, 8u));
  EXPECT_FALSE(nfc_storage_type5_write_span_ok(4u, 320u, 4u, 80u, 80u, 4u));
  EXPECT_FALSE(nfc_storage_type5_write_span_ok(4u, 320u, 4u, 80u, 0u, 5u));
  EXPECT_FALSE(nfc_storage_type5_write_span_ok(4u, 320u, 4u, 80u, 79u, 8u));
}

TEST(NfcStorageNdef, Type5ReadBlockLimitIsSharedWithHostScan) {
  EXPECT_EQ(nfc_storage_type5_read_block_limit(8u, 2048u,
                                               NERO_NFC_TYPE5_STORAGE_READ_MAX),
            514u);
  EXPECT_EQ(
      nfc_storage_type5_read_block_limit(NERO_NFC_TYPE5_STORAGE_READ_MAX, 4u,
                                         NERO_NFC_TYPE5_STORAGE_READ_MAX),
      0u);
}
