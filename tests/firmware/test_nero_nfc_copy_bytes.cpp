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
#include <cstddef>
#include <cstdint>

#include <gtest/gtest.h>

#include "nero_nfc_mem_util.h"

TEST(NeroNfcCopyBytes, NullDstOrSrcFails) {
  uint8_t buf[4] = {0};
  uint8_t src[] = {1, 2};
  EXPECT_FALSE(nero_nfc_copy_bytes(NERO_NFC_NULL, sizeof(buf), 0, src, 1));
  EXPECT_FALSE(nero_nfc_copy_bytes(buf, sizeof(buf), 0, NERO_NFC_NULL, 1));
}

TEST(NeroNfcCopyBytes, ZeroLengthNoop) {
  uint8_t buf[4] = {9, 9, 9, 9};
  uint8_t src[] = {1, 2, 3};
  ASSERT_TRUE(nero_nfc_copy_bytes(buf, sizeof(buf), 0, src, 0));
  EXPECT_EQ(buf[0], 9u);
}

TEST(NeroNfcCopyBytes, ZeroLengthNullSourceNoop) {
  uint8_t buf[4] = {9, 9, 9, 9};
  ASSERT_TRUE(nero_nfc_copy_bytes(buf, sizeof(buf), 0, NERO_NFC_NULL, 0));
  EXPECT_EQ(buf[0], 9u);
}

TEST(NeroNfcCopyBytes, OffsetPastEndFails) {
  uint8_t buf[4];
  uint8_t src[] = {1};
  EXPECT_FALSE(nero_nfc_copy_bytes(buf, sizeof(buf), 5, src, 1));
}

TEST(NeroNfcCopyBytes, LengthOverflowFails) {
  uint8_t buf[4];
  uint8_t src[] = {1, 2, 3, 4, 5};
  EXPECT_FALSE(nero_nfc_copy_bytes(buf, sizeof(buf), 2, src, 4));
}

TEST(NeroNfcCopyBytes, AppendsAtOffset) {
  uint8_t buf[8] = {1, 1, 1, 1, 1, 1, 1, 1};
  const uint8_t src[] = {0xA0u, 0xB0u};
  ASSERT_TRUE(nero_nfc_copy_bytes(buf, sizeof(buf), 3, src, sizeof(src)));
  EXPECT_EQ(buf[0], 1u);
  EXPECT_EQ(buf[3], 0xA0u);
  EXPECT_EQ(buf[4], 0xB0u);
  EXPECT_EQ(buf[5], 1u);
}

TEST(NeroNfcCopyBytes, FillsUpToEndInclusive) {
  uint8_t buf[4] = {0x10u, 0x20u, 0x30u, 0x40u};
  const uint8_t src[] = {0xEEu};
  ASSERT_TRUE(nero_nfc_copy_bytes(buf, sizeof(buf), 3, src, 1));
  EXPECT_EQ(buf[3], 0xEEu);
}

TEST(NeroNfcCopyBytes, CheckedArithmeticHelpersRejectWrap) {
  size_t size_out = 0u;
  uint16_t u16_out = 0u;

  EXPECT_TRUE(nero_nfc_try_add_size(3u, 4u, &size_out));
  EXPECT_EQ(size_out, 7u);
  EXPECT_FALSE(nero_nfc_try_add_size(SIZE_MAX, 1u, &size_out));
  EXPECT_TRUE(nero_nfc_try_sub_size(7u, 4u, &size_out));
  EXPECT_EQ(size_out, 3u);
  EXPECT_FALSE(nero_nfc_try_sub_size(3u, 4u, &size_out));
  EXPECT_TRUE(nero_nfc_try_add_u16(0x10u, 0x20u, &u16_out));
  EXPECT_EQ(u16_out, 0x30u);
  EXPECT_FALSE(nero_nfc_try_add_u16(UINT16_MAX, 1u, &u16_out));
}

TEST(NeroNfcCopyBytes, BoundedStrlenRejectsUnterminatedInput) {
  size_t len = 0u;
  const char text[] = "pcsc-fido";
  const char no_nul[3] = {'a', 'b', 'c'};

  ASSERT_TRUE(nero_nfc_bounded_strlen(text, sizeof(text), &len));
  EXPECT_EQ(len, 9u);
  len = 0xBEEFu;
  EXPECT_FALSE(nero_nfc_bounded_strlen(no_nul, sizeof(no_nul), &len));
  EXPECT_EQ(len, 0u);
  len = 0xBEEFu;
  EXPECT_FALSE(nero_nfc_bounded_strlen(NERO_NFC_NULL, sizeof(no_nul), &len));
  EXPECT_EQ(len, 0u);
  EXPECT_FALSE(nero_nfc_bounded_strlen(text, sizeof(text), NERO_NFC_NULL));
}
