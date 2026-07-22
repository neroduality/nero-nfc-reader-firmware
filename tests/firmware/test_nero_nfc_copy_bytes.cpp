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

namespace {
enum {
  kTestLit0x10u = 0x10u,
  kTestLit0x20u = 0x20u,
  kTestLit0x30u = 0x30u,
  kTestLit0x40u = 0x40u,
  kTestLit0xFFu = 0xFFu,
  kTestLit0xBeeFu = 0xBEEFu,
  kTestLit2 = 2,
  kTestLit3 = 3,
  kTestLit4 = 4,
  kTestLit5 = 5,
  kTestLit8 = 8,
  kTestLit9 = 9,
  kTestLit42u = 42u,
  kTestLit12345u = 12345u,
};
}  // namespace

#include <gtest/gtest.h>

#include "nero_nfc_mem_util.h"

TEST(NeroNfcCopyBytes, NullDstOrSrcFails) {
  uint8_t buf[kTestLit4] = {0};
  uint8_t src[] = {1, kTestLit2};
  EXPECT_FALSE(nero_nfc_copy_bytes(NERO_NFC_NULL, sizeof(buf), 0, &src[0], 1));
  EXPECT_FALSE(nero_nfc_copy_bytes(&buf[0], sizeof(buf), 0, NERO_NFC_NULL, 1));
}

TEST(NeroNfcCopyBytes, ZeroLengthNoop) {
  uint8_t buf[kTestLit4] = {kTestLit9, kTestLit9, kTestLit9, kTestLit9};
  uint8_t src[] = {1, kTestLit2, kTestLit3};
  ASSERT_TRUE(nero_nfc_copy_bytes(&buf[0], sizeof(buf), 0, &src[0], 0));
  EXPECT_EQ(buf[0], 9u);
}

TEST(NeroNfcCopyBytes, ZeroLengthNullSourceNoop) {
  uint8_t buf[kTestLit4] = {kTestLit9, kTestLit9, kTestLit9, kTestLit9};
  ASSERT_TRUE(nero_nfc_copy_bytes(&buf[0], sizeof(buf), 0, NERO_NFC_NULL, 0));
  EXPECT_EQ(buf[0], 9u);
}

TEST(NeroNfcCopyBytes, OffsetPastEndFails) {
  uint8_t buf[kTestLit4];
  uint8_t src[] = {1};
  EXPECT_FALSE(nero_nfc_copy_bytes(&buf[0], sizeof(buf), 5, &src[0], 1));
}

TEST(NeroNfcCopyBytes, LengthOverflowFails) {
  uint8_t buf[kTestLit4];
  uint8_t src[] = {1, kTestLit2, kTestLit3, kTestLit4, kTestLit5};
  EXPECT_FALSE(nero_nfc_copy_bytes(&buf[0], sizeof(buf), 2, &src[0], 4));
}

TEST(NeroNfcCopyBytes, AppendsAtOffset) {
  uint8_t buf[kTestLit8] = {1, 1, 1, 1, 1, 1, 1, 1};
  const uint8_t kSrc[] = {0xA0u, 0xB0u};
  ASSERT_TRUE(
      nero_nfc_copy_bytes(&buf[0], sizeof(buf), 3, &kSrc[0], sizeof(kSrc)));
  EXPECT_EQ(buf[0], 1u);
  EXPECT_EQ(buf[3], 0xA0u);
  EXPECT_EQ(buf[4], 0xB0u);
  EXPECT_EQ(buf[5], 1u);
}

TEST(NeroNfcCopyBytes, FillsUpToEndInclusive) {
  uint8_t buf[kTestLit4] = {kTestLit0x10u, kTestLit0x20u, kTestLit0x30u,
                            kTestLit0x40u};
  const uint8_t kSrc[] = {0xEEu};
  ASSERT_TRUE(nero_nfc_copy_bytes(&buf[0], sizeof(buf), 3, &kSrc[0], 1));
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
  const char kText[] = "pcsc-fido";
  const char kNoNul[3] = {'a', 'b', 'c'};

  ASSERT_TRUE(nero_nfc_bounded_strlen(&kText[0], sizeof(kText), &len));
  EXPECT_EQ(len, 9u);
  len = kTestLit0xBeeFu;
  EXPECT_FALSE(nero_nfc_bounded_strlen(&kNoNul[0], sizeof(kNoNul), &len));
  EXPECT_EQ(len, 0u);
  len = kTestLit0xBeeFu;
  EXPECT_FALSE(nero_nfc_bounded_strlen(NERO_NFC_NULL, sizeof(kNoNul), &len));
  EXPECT_EQ(len, 0u);
  EXPECT_FALSE(
      nero_nfc_bounded_strlen(&kText[0], sizeof(kText), NERO_NFC_NULL));
}

TEST(NeroNfcCopyBytes, CopyCstrFailClosed) {
  char dst[kTestLit8] = {kTestLit9, kTestLit9, kTestLit9, kTestLit9,
                         kTestLit9, kTestLit9, kTestLit9, kTestLit9};
  ASSERT_TRUE(nero_nfc_copy_cstr(&dst[0], sizeof(dst), "abc"));
  EXPECT_STREQ(&dst[0], "abc");
  EXPECT_FALSE(nero_nfc_copy_cstr(&dst[0], kTestLit3, "abcd"));
  ASSERT_TRUE(nero_nfc_copy_cstr(&dst[0], sizeof(dst), NERO_NFC_NULL));
  EXPECT_STREQ(&dst[0], "");
  EXPECT_FALSE(nero_nfc_copy_cstr(NERO_NFC_NULL, sizeof(dst), "abc"));
  EXPECT_FALSE(nero_nfc_copy_cstr(&dst[0], 0u, "abc"));
}

TEST(NeroNfcCopyBytes, LoadU8RejectsOutOfRange) {
  const uint8_t kBuf[] = {0x11u, 0x22u};
  uint8_t value = kTestLit0xFFu;
  ASSERT_TRUE(nero_nfc_load_u8(&kBuf[0], sizeof(kBuf), 1u, &value));
  EXPECT_EQ(value, 0x22u);
  value = kTestLit0xFFu;
  EXPECT_FALSE(nero_nfc_load_u8(&kBuf[0], sizeof(kBuf), 2u, &value));
  EXPECT_EQ(nero_nfc_u8_at(&kBuf[0], sizeof(kBuf), 2u), 0u);
}

#include "nero_nfc_format.h"
#include "nero_nfc_parse.h"

TEST(NeroNfcFormat, TrySnprintfRejectsNullAndTruncation) {
  char buf[kTestLit8] = {};
  EXPECT_FALSE(nero_nfc_try_snprintf(NERO_NFC_NULL, sizeof(buf), "%u", 1u));
  EXPECT_FALSE(nero_nfc_try_snprintf(&buf[0], 0u, "%u", 1u));
  EXPECT_FALSE(nero_nfc_try_snprintf(&buf[0], sizeof(buf), NERO_NFC_NULL));
  ASSERT_TRUE(nero_nfc_try_snprintf(&buf[0], sizeof(buf), "%u", kTestLit42u));
  EXPECT_STREQ(&buf[0], "42");
  EXPECT_FALSE(nero_nfc_try_snprintf(&buf[0], kTestLit2, "%u", kTestLit12345u));
  EXPECT_STREQ(&buf[0], "");
  EXPECT_EQ(nero_nfc_snprintf(NERO_NFC_NULL, sizeof(buf), "%u", 1u), -1);
}

TEST(NeroNfcFormat, AppendfAdvancesOffset) {
  char buf[kTestLit8] = {};
  size_t off = 0u;
  ASSERT_TRUE(nero_nfc_appendf(&buf[0], sizeof(buf), &off, "%u", 1u));
  ASSERT_TRUE(nero_nfc_appendf(&buf[0], sizeof(buf), &off, "%u", 2u));
  EXPECT_STREQ(&buf[0], "12");
  EXPECT_EQ(off, 2u);
  EXPECT_FALSE(nero_nfc_appendf(&buf[0], sizeof(buf), &off, "%s", "overflow"));
  EXPECT_STREQ(&buf[0], "12");
  EXPECT_EQ(off, 2u);
}

TEST(NeroNfcParse, ParseU32FailClosed) {
  uint32_t value = 0u;
  ASSERT_TRUE(nero_nfc_parse_u32("0", &value));
  EXPECT_EQ(value, 0u);
  ASSERT_TRUE(nero_nfc_parse_u32("4294967295", &value));
  EXPECT_EQ(value, UINT32_MAX);
  EXPECT_FALSE(nero_nfc_parse_u32("4294967296", &value));
  EXPECT_FALSE(nero_nfc_parse_u32("", &value));
  EXPECT_FALSE(nero_nfc_parse_u32("12a", &value));
  EXPECT_FALSE(nero_nfc_parse_u32(NERO_NFC_NULL, &value));
  EXPECT_FALSE(nero_nfc_parse_u32("1", NERO_NFC_NULL));
}
