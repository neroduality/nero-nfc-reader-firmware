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
#include <cstdint>
#include <vector>

extern "C" {
#include "nero_nfc_null.h"
#include "nfc_ndef_tlv.h"
#include "nfc_tag_geometry_limits.h"
#include "nfc_tag_info.h"
#include "reader_tags_type2_geometry.h"
}

namespace {
enum {
  kTestLit0x01u = 0x01u,
  kTestLit0x02u = 0x02u,
  kTestLit0x03u = 0x03u,
  kTestLit0x05u = 0x05u,
  kTestLit0x10u = 0x10u,
  kTestLit0x11u = 0x11u,
  kTestLit0x12u = 0x12u,
  kTestLit0x20u = 0x20u,
  kTestLit0x5Au = 0x5Au,
  kTestLit0xAAu = 0xAAu,
  kTestLit0xBBu = 0xBBu,
  kTestLit0xCCu = 0xCCu,
  kTestLit0xD1u = 0xD1u,
  kTestLit0xDDu = 0xDDu,
  kTestLit0xEEu = 0xEEu,
  kTestLit0xFFu = 0xFFu,
  kTestLit16u = 16u,
  kTestLit2u = 2u,
  kTestLit3u = 3u,
  kTestLit4u = 4u,
  kTestLit6u = 6u,
};

constexpr uint16_t kMaxPage = kTestLit0xFFu;
constexpr uint8_t kCcVer = kTestLit0x10u;
constexpr uint8_t kCcMlen = kTestLit0x12u;
constexpr uint8_t kCcAccess = 0x00u;
constexpr uint8_t kLockControlTlv = kTestLit0x01u;

std::vector<uint8_t> CcPrefix() {
  return {NFC_FORUM_CC_MAGIC, kCcVer, kCcMlen, kCcAccess};
}
}  // namespace

TEST(ReaderTagsType2Bounds, RejectsNullOrShortOrBadMagic) {
  constexpr std::array<uint8_t, kTestLit4u> kBadMagic{0x00u, kCcVer, kCcMlen,
                                                      kCcAccess};
  constexpr std::array<uint8_t, kTestLit4u> kCcOnly{NFC_FORUM_CC_MAGIC, kCcVer,
                                                    kCcMlen, kCcAccess};

  EXPECT_EQ(
      reader_tags_type2_needed_pages(NERO_NFC_NULL, kTestLit16u, kMaxPage), 0u);
  EXPECT_EQ(
      reader_tags_type2_needed_pages(kCcOnly.data(), kTestLit4u, kMaxPage), 0u);
  EXPECT_EQ(reader_tags_type2_needed_pages(kBadMagic.data(), kBadMagic.size(),
                                           kMaxPage),
            0u);
}

TEST(ReaderTagsType2Bounds, RejectsTruncatedExtendedTlvLength) {
  auto data = CcPrefix();
  data.push_back(NFC_NDEF_TLV_MESSAGE);
  data.push_back(NFC_NDEF_TLV_EXTENDED_LEN);

  EXPECT_EQ(reader_tags_type2_needed_pages(
                data.data(), static_cast<uint16_t>(data.size()), kMaxPage),
            0u);
}

TEST(ReaderTagsType2Bounds, RejectsTruncatedShortTlvHeader) {
  auto data = CcPrefix();
  data.push_back(NFC_NDEF_TLV_MESSAGE);

  EXPECT_EQ(reader_tags_type2_needed_pages(
                data.data(), static_cast<uint16_t>(data.size()), kMaxPage),
            0u);
}

TEST(ReaderTagsType2Bounds, TerminatorAfterCcReturnsTwoPages) {
  auto data = CcPrefix();
  data.push_back(NFC_NDEF_TLV_TERMINATOR);

  /* Terminator sits at byte offset 4; (4 + 4) / 4 = 2 pages. */
  EXPECT_EQ(reader_tags_type2_needed_pages(
                data.data(), static_cast<uint16_t>(data.size()), kMaxPage),
            kTestLit2u);
}

TEST(ReaderTagsType2Bounds, SkipsNullTlvThenHonorsTerminator) {
  auto data = CcPrefix();
  data.push_back(NFC_NDEF_TLV_NULL);
  data.push_back(NFC_NDEF_TLV_NULL);
  data.push_back(NFC_NDEF_TLV_TERMINATOR);

  EXPECT_EQ(reader_tags_type2_needed_pages(
                data.data(), static_cast<uint16_t>(data.size()), kMaxPage),
            kTestLit2u);
}

TEST(ReaderTagsType2Bounds, ShortNdefMessageComputesCeilPages) {
  auto data = CcPrefix();
  data.push_back(NFC_NDEF_TLV_MESSAGE);
  data.push_back(kTestLit0x05u);
  data.insert(data.end(), {kTestLit0xAAu, kTestLit0xBBu, kTestLit0xCCu,
                           kTestLit0xDDu, kTestLit0xEEu});

  /* Value starts at offset 6; need_bytes = 6 + 5 = 11 → ceil(11/4) = 3 pages.
   */
  EXPECT_EQ(reader_tags_type2_needed_pages(
                data.data(), static_cast<uint16_t>(data.size()), kMaxPage),
            kTestLit3u);
}

TEST(ReaderTagsType2Bounds, SkipsNonMessageTlvBeforeNdefMessage) {
  auto data = CcPrefix();
  data.push_back(kLockControlTlv);
  data.push_back(kTestLit0x03u);
  data.insert(data.end(), {kTestLit0x01u, kTestLit0x02u, kTestLit0x03u});
  data.push_back(NFC_NDEF_TLV_MESSAGE);
  data.push_back(kTestLit0x02u);
  data.insert(data.end(), {kTestLit0xD1u, 0x00u});

  /* Message value starts at offset 11; need_bytes = 11 + 2 = 13 → 4 pages. */
  EXPECT_EQ(reader_tags_type2_needed_pages(
                data.data(), static_cast<uint16_t>(data.size()), kMaxPage),
            kTestLit4u);
}

TEST(ReaderTagsType2Bounds, ExtendedLengthNdefMessage) {
  auto data = CcPrefix();
  data.push_back(NFC_NDEF_TLV_MESSAGE);
  data.push_back(NFC_NDEF_TLV_EXTENDED_LEN);
  data.push_back(0x00u);         /* MSB */
  data.push_back(kTestLit0x10u); /* LSB → 16-byte value */
  data.insert(data.end(), kTestLit16u, kTestLit0x5Au);

  /* Value starts at offset 8; need_bytes = 8 + 16 = 24 → 6 pages. */
  EXPECT_EQ(reader_tags_type2_needed_pages(
                data.data(), static_cast<uint16_t>(data.size()), kMaxPage),
            kTestLit6u);
}

TEST(ReaderTagsType2Bounds, ClampsToMaxPageWindow) {
  auto data = CcPrefix();
  data.push_back(NFC_NDEF_TLV_MESSAGE);
  data.push_back(kTestLit0x20u);
  data.insert(data.end(), kTestLit0x20u, kTestLit0x11u);

  /* Unclamped need would be ceil((6+32)/4)=10 pages; CC page index 3 with
   * max_page 5 yields max_pages = 5 - 3 + 1 = 3. */
  EXPECT_EQ(reader_tags_type2_needed_pages(
                data.data(), static_cast<uint16_t>(data.size()),
                NFC_TAG_T2T_CC_PAGE_INDEX + kTestLit2u),
            kTestLit3u);
}

TEST(ReaderTagsType2Bounds, ReturnsZeroWhenOnlyNonMessageTlvsPresent) {
  auto data = CcPrefix();
  data.push_back(kLockControlTlv);
  data.push_back(kTestLit0x01u);
  data.push_back(kTestLit0xFFu);

  EXPECT_EQ(reader_tags_type2_needed_pages(
                data.data(), static_cast<uint16_t>(data.size()), kMaxPage),
            0u);
}
