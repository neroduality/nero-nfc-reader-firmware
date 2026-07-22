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
#include <gtest/gtest.h>

namespace {
enum {
  kTestLit0x81u = 0x81u,
  kTestLit2 = 2,
  kTestLit2u = 2u,
  kTestLit3 = 3,
  kTestLit32 = 32,
  kTestLit4 = 4,
  kTestLit8 = 8,
  kTestLit99u = 99u,
};
}  // namespace

#include "nero_nfc_limits.h"
#include "reader_cbor.h"

#include <vector>

static cbor_reader_t Wrap(const uint8_t* data, size_t len) {
  cbor_reader_t c{};
  c.data = data;
  c.len = static_cast<uint16_t>(len);
  c.pos = 0;
  return c;
}

TEST(ReaderCbor, HasRemainingAndAtEnd) {
  const uint8_t kData[] = {0x00};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  EXPECT_TRUE(cbor_has_remaining(&c, 1u));
  EXPECT_FALSE(cbor_at_end(&c));
  (void)cbor_next(&c);
  EXPECT_TRUE(cbor_at_end(&c));
  EXPECT_FALSE(cbor_has_remaining(&c, 1u));
}

TEST(ReaderCbor, ReadUintAdditionalUnder24) {
  const uint8_t kData[] = {0x0Au};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  uint32_t v = 0u;
  ASSERT_TRUE(cbor_read_uint(&c, &v));
  EXPECT_EQ(v, 10u);
  EXPECT_TRUE(cbor_at_end(&c));
}

TEST(ReaderCbor, ReadUintAdditional24) {
  const uint8_t kData[] = {0x18u, 0x18u};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  uint32_t v = 0u;
  ASSERT_TRUE(cbor_read_uint(&c, &v));
  EXPECT_EQ(v, 24u);
}

TEST(ReaderCbor, ReadUintAdditional25) {
  const uint8_t kData[] = {0x19u, 0x03u, 0xE8u};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  uint32_t v = 0u;
  ASSERT_TRUE(cbor_read_uint(&c, &v));
  EXPECT_EQ(v, 1000u);
}

TEST(ReaderCbor, ReadUintAdditional26) {
  const uint8_t kData[] = {0x1Au, 0x00u, 0x01u, 0xE2u, 0x40u};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  uint32_t v = 0u;
  ASSERT_TRUE(cbor_read_uint(&c, &v));
  EXPECT_EQ(v, 123456u);
}

TEST(ReaderCbor, ReadUintRejectsWrongMajor) {
  const uint8_t kData[] = {0x41u, 'x'}; /* byte string, not uint */
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  uint32_t v = 0u;
  EXPECT_FALSE(cbor_read_uint(&c, &v));
  EXPECT_EQ(c.pos, 0u);
}

TEST(ReaderCbor, ReadHeadRejectsTruncated) {
  const uint8_t kData[] = {0x19u, 0x03u}; /* need 2 bytes after 0x19 */
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  uint8_t major = 0u;
  uint32_t value = 0u;
  EXPECT_FALSE(cbor_read_head(&c, &major, &value));
  EXPECT_EQ(c.pos, 0u);
}

TEST(ReaderCbor, ReadTextRejectsWhenBufferTooSmallForPayload) {
  const uint8_t kData[] = {0x66, 'h', 'e', 'l', 'l', 'o', '!'}; /* text len 6 */
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  char buf[kTestLit4];
  EXPECT_FALSE(cbor_read_text(&c, &buf[0], sizeof(buf)));
  EXPECT_EQ(c.pos, 0u);
}

TEST(ReaderCbor, ReadTextNoTruncationWhenBufferBigEnough) {
  const uint8_t kData[] = {0x62u, 'y', 'o'};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  char buf[kTestLit32];
  ASSERT_TRUE(cbor_read_text(&c, &buf[0], sizeof(buf)));
  EXPECT_STREQ(&buf[0], "yo");
}

TEST(ReaderCbor, BytesRejectsWhenBufferTooSmallForPayload) {
  const uint8_t kData[] = {0x42u, 0xAAu, 0xBBu};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  uint8_t buf[1];
  uint16_t out_len = 0u;
  EXPECT_FALSE(cbor_read_bytes(&c, &buf[0], sizeof(buf), &out_len));
  EXPECT_EQ(c.pos, 0u);
}

TEST(ReaderCbor, BytesIndefiniteHappyPath) {
  const uint8_t kData[] = {0x5Fu, 0x42u, 0xAAu, 0xBBu, 0x41u, 0xCCu, 0xFFu};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  uint8_t buf[kTestLit8];
  uint16_t out_len = 0u;
  ASSERT_TRUE(cbor_read_bytes_indefinite(&c, &buf[0], sizeof(buf), &out_len));
  EXPECT_EQ(out_len, 3u);
  EXPECT_EQ(buf[0], 0xAAu);
  EXPECT_EQ(buf[1], 0xBBu);
  EXPECT_EQ(buf[2], 0xCCu);
}

TEST(ReaderCbor, BytesFlexibleFallsBackToIndefinite) {
  const uint8_t kData[] = {0x5Fu, 0x42u, 0x01u, 0x02u, 0xFFu};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  uint8_t buf[kTestLit4];
  uint16_t out_len = 0u;
  ASSERT_TRUE(cbor_read_bytes_flexible(&c, &buf[0], sizeof(buf), &out_len));
  EXPECT_EQ(out_len, 2u);
}

TEST(ReaderCbor, BytesMaybeTaggedSkipsTag) {
  /* tag(0) + h'0102' === C0 42 01 02 */
  const uint8_t kData[] = {0xC0u, 0x42u, 0x01u, 0x02u};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  uint8_t buf[kTestLit8];
  uint16_t out_len = 0u;
  ASSERT_TRUE(cbor_read_bytes_maybe_tagged(&c, &buf[0], sizeof(buf), &out_len));
  EXPECT_EQ(out_len, 2u);
  EXPECT_EQ(buf[0], 0x01u);
  EXPECT_EQ(buf[1], 0x02u);
}

TEST(ReaderCbor, LegacySignatureTailAliasThree) {
  const uint8_t kData[] = {0x03u, 0x42u, 0xDEu, 0xADu};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  uint8_t buf[kTestLit8];
  uint16_t out_len = 0u;
  ASSERT_TRUE(
      cbor_read_legacy_signature_tail(&c, &buf[0], sizeof(buf), &out_len));
  EXPECT_EQ(out_len, 2u);
  EXPECT_EQ(buf[0], 0xDEu);
  EXPECT_EQ(buf[1], 0xADu);
  EXPECT_TRUE(cbor_at_end(&c));
}

TEST(ReaderCbor, SkipNestedArray) {
  const uint8_t kData[] = {0x82u, 0x01u, 0x02u};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  ASSERT_TRUE(cbor_skip(&c));
  EXPECT_TRUE(cbor_at_end(&c));
}

TEST(ReaderCbor, SkipTaggedValue) {
  const uint8_t kData[] = {0xC1u, 0x1Au, 0x00u, 0x00u, 0x00u, 0x2Au};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  ASSERT_TRUE(cbor_skip(&c));
  EXPECT_TRUE(cbor_at_end(&c));
}

TEST(ReaderCbor, SkipMapEntries) {
  const uint8_t kData[] = {0xA2u, 0x01u, 0x02u, 0x03u, 0x04u};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  ASSERT_TRUE(cbor_skip(&c));
  EXPECT_TRUE(cbor_at_end(&c));
}

TEST(ReaderCbor, SkipIndefiniteByteString) {
  const uint8_t kData[] = {0x5Fu, 0x41u, 0xAAu, 0xFFu};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  ASSERT_TRUE(cbor_skip(&c));
  EXPECT_TRUE(cbor_at_end(&c));
}

TEST(ReaderCbor, SkipFailsOnTruncatedMap) {
  const uint8_t kData[] = {0xA1u, 0x01u}; /* missing value */
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  EXPECT_FALSE(cbor_skip(&c));
}

TEST(ReaderCbor, ReadBytesRejectsNullOutLen) {
  const uint8_t kData[] = {0x40u};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  uint8_t buf[kTestLit4];
  EXPECT_FALSE(cbor_read_bytes(&c, &buf[0], sizeof(buf), NERO_NFC_NULL));
}

TEST(ReaderCbor, ReadBytesRejectsMissingPayload) {
  const uint8_t kData[] = {0x42u,
                           0x00u}; /* declares len 2, only 1 payload byte */
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  uint8_t buf[kTestLit8];
  uint16_t out_len = 0u;
  EXPECT_FALSE(cbor_read_bytes(&c, &buf[0], sizeof(buf), &out_len));
}

TEST(ReaderCbor, ReadBytesRejectsUndersizedBuffer) {
  const uint8_t kData[] = {0x43u, 0x01u, 0x02u, 0x03u};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  uint8_t buf[kTestLit2];
  uint16_t out_len = kTestLit99u;
  EXPECT_FALSE(cbor_read_bytes(&c, &buf[0], sizeof(buf), &out_len));
  EXPECT_EQ(c.pos, 0u);
}

TEST(ReaderCbor, ReadTextRejectsUndersizedBuffer) {
  const uint8_t kData[] = {0x63u, 'a', 'b', 'c'};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  char buf[kTestLit3];
  EXPECT_FALSE(cbor_read_text(&c, &buf[0], sizeof(buf)));
  EXPECT_EQ(c.pos, 0u);
}

TEST(ReaderCbor, ReadHeadEmptyBuffer) {
  const uint8_t kData[] = {0x00u};
  cbor_reader_t c = Wrap(&kData[0], 0u);
  uint8_t major = 0u;
  uint32_t value = 0u;
  EXPECT_FALSE(cbor_read_head(&c, &major, &value));
}

TEST(ReaderCbor, ReadUintEmptyBuffer) {
  const uint8_t kDummy[] = {0x00u};
  cbor_reader_t c = Wrap(&kDummy[0], 0u);
  uint32_t v = 0u;
  EXPECT_FALSE(cbor_read_uint(&c, &v));
}

TEST(ReaderCbor, ReadTextIncompleteHead) {
  const uint8_t kData[] = {
      0x79u}; /* text + ai25 length, missing 2 length bytes */
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  char buf[kTestLit8];
  EXPECT_FALSE(cbor_read_text(&c, &buf[0], sizeof(buf)));
  EXPECT_EQ(c.pos, 0u);
}

TEST(ReaderCbor, ReadHeadAi24Truncated) {
  const uint8_t kData[] = {0x18u};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  uint8_t major = 0u;
  uint32_t value = 0u;
  EXPECT_FALSE(cbor_read_head(&c, &major, &value));
  EXPECT_EQ(c.pos, 0u);
}

TEST(ReaderCbor, ReadHeadAi26Truncated) {
  const uint8_t kData[] = {0x1Au, 0x00u, 0x00u, 0x00u};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  uint8_t major = 0u;
  uint32_t value = 0u;
  EXPECT_FALSE(cbor_read_head(&c, &major, &value));
  EXPECT_EQ(c.pos, 0u);
}

TEST(ReaderCbor, ReadTextNullOrZeroBuffer) {
  const uint8_t kData[] = {0x61u, 'x'};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  char buf[kTestLit4];
  EXPECT_FALSE(cbor_read_text(&c, NERO_NFC_NULL, sizeof(buf)));
  c = Wrap(&kData[0], sizeof(kData));
  EXPECT_FALSE(cbor_read_text(&c, &buf[0], 0u));
}

TEST(ReaderCbor, ReadTextWrongMajor) {
  const uint8_t kData[] = {0x40u}; /* definite-length byte string, length 0 */
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  char buf[kTestLit4];
  EXPECT_FALSE(cbor_read_text(&c, &buf[0], sizeof(buf)));
  EXPECT_EQ(c.pos, 0u);
}

TEST(ReaderCbor, ReadTextTruncatedPayload) {
  const uint8_t kData[] = {0x62u, 'a'}; /* text len 2, one content byte */
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  char buf[kTestLit4];
  EXPECT_FALSE(cbor_read_text(&c, &buf[0], sizeof(buf)));
}

TEST(ReaderCbor, ReadBytesNullBufferWithNonzeroCap) {
  const uint8_t kData[] = {0x40u};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  uint16_t out_len = 0u;
  EXPECT_FALSE(cbor_read_bytes(&c, NERO_NFC_NULL, 1u, &out_len));
}

TEST(ReaderCbor, BytesIndefiniteWrongChunkMajor) {
  const uint8_t kData[] = {0x5Fu, 0x63u, 'a',
                           'a',   'a',   0xFFu}; /* text chunk in byte stream */
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  uint8_t buf[kTestLit8];
  uint16_t out_len = 0u;
  EXPECT_FALSE(cbor_read_bytes_indefinite(&c, &buf[0], sizeof(buf), &out_len));
}

TEST(ReaderCbor, BytesIndefiniteTruncatedChunk) {
  const uint8_t kData[] = {0x5Fu, 0x42u, 0x00u,
                           0x00u}; /* len 2, no payload bytes */
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  uint8_t buf[kTestLit8];
  uint16_t out_len = 0u;
  EXPECT_FALSE(cbor_read_bytes_indefinite(&c, &buf[0], sizeof(buf), &out_len));
}

TEST(ReaderCbor, BytesIndefiniteMissingTerminator) {
  const uint8_t kData[] = {0x5Fu, 0x41u, 0xAAu}; /* no break byte */
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  uint8_t buf[kTestLit8];
  uint16_t out_len = 0u;
  EXPECT_FALSE(cbor_read_bytes_indefinite(&c, &buf[0], sizeof(buf), &out_len));
}

TEST(ReaderCbor, BytesMaybeTaggedUintPayloadFails) {
  const uint8_t kData[] = {0x01u, 0x00u}; /* unsigned(1), not bytes */
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  uint8_t buf[kTestLit4];
  uint16_t out_len = 0u;
  EXPECT_FALSE(
      cbor_read_bytes_maybe_tagged(&c, &buf[0], sizeof(buf), &out_len));
}

TEST(ReaderCbor, BytesMaybeTaggedInnerNotBytes) {
  /* Tag + unsigned int: after consuming the tag, flexible cannot read bytes. */
  const uint8_t kData[] = {0xC0u, 0x01u, 0x00u};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  uint8_t buf[kTestLit4];
  uint16_t out_len = 0u;
  EXPECT_FALSE(
      cbor_read_bytes_maybe_tagged(&c, &buf[0], sizeof(buf), &out_len));
}

TEST(ReaderCbor, BytesMaybeTaggedTruncatedTagFollowUp) {
  /* Tag number uses ai=25 (two length bytes): provide only one follow-up byte.
   */
  const uint8_t kData[] = {0xD9u, 0x01u};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  uint8_t buf[kTestLit4];
  uint16_t out_len = 0u;
  EXPECT_FALSE(
      cbor_read_bytes_maybe_tagged(&c, &buf[0], sizeof(buf), &out_len));
}

TEST(ReaderCbor, BytesMaybeTaggedTruncatedSecondTagByte) {
  const uint8_t kData[] = {0xC0u};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  uint8_t buf[kTestLit4];
  uint16_t out_len = 0u;
  EXPECT_FALSE(
      cbor_read_bytes_maybe_tagged(&c, &buf[0], sizeof(buf), &out_len));
}

TEST(ReaderCbor, LegacySignatureTailRejectsWrongAlias) {
  const uint8_t kData[] = {0x04u, 0x42u, 0x01u, 0x02u};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  uint8_t buf[kTestLit4];
  uint16_t out_len = 0u;
  EXPECT_FALSE(
      cbor_read_legacy_signature_tail(&c, &buf[0], sizeof(buf), &out_len));
}

TEST(ReaderCbor, LegacySignatureTailRejectsNonBytes) {
  const uint8_t kData[] = {
      0x03u, 0x00u}; /* unsigned(3) then unsigned(0): no byte string */
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  uint8_t buf[kTestLit4];
  uint16_t out_len = 0u;
  EXPECT_FALSE(
      cbor_read_legacy_signature_tail(&c, &buf[0], sizeof(buf), &out_len));
}

TEST(ReaderCbor, SkipDefiniteByteString) {
  const uint8_t kData[] = {0x42u, 0x01u, 0x02u};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  ASSERT_TRUE(cbor_skip(&c));
  EXPECT_TRUE(cbor_at_end(&c));
}

TEST(ReaderCbor, SkipDefiniteTextString) {
  const uint8_t kData[] = {0x62u, 'o', 'k'};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  ASSERT_TRUE(cbor_skip(&c));
  EXPECT_TRUE(cbor_at_end(&c));
}

TEST(ReaderCbor, SkipIndefiniteTextString) {
  /* Indefinite text: chunks must be major type 3 (e.g. 0x61 = one UTF-8 byte).
   */
  const uint8_t kData[] = {0x7Fu, 0x61u, 0xAAu, 0xFFu};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  ASSERT_TRUE(cbor_skip(&c));
  EXPECT_TRUE(cbor_at_end(&c));
}

TEST(ReaderCbor, SkipIndefiniteArray) {
  const uint8_t kData[] = {0x9Fu, 0x01u, 0x02u, 0xFFu};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  ASSERT_TRUE(cbor_skip(&c));
  EXPECT_TRUE(cbor_at_end(&c));
}

TEST(ReaderCbor, SkipIndefiniteMap) {
  const uint8_t kData[] = {0xBFu, 0x01u, 0x02u, 0xFFu};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  ASSERT_TRUE(cbor_skip(&c));
  EXPECT_TRUE(cbor_at_end(&c));
}

TEST(ReaderCbor, SkipIndefiniteBytesBadInnerItem) {
  const uint8_t kData[] = {0x5Fu, 0x63u, 'a', 'a', 'a', 0xFFu};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  EXPECT_FALSE(cbor_skip(&c));
}

TEST(ReaderCbor, SkipIndefiniteBytesMissingChunksAndBreak) {
  const uint8_t kData[] = {0x5Fu};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  EXPECT_FALSE(cbor_skip(&c));
}

TEST(ReaderCbor, SkipIndefiniteArrayItemFails) {
  const uint8_t kData[] = {0x9Fu, 0x4Au};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  EXPECT_FALSE(cbor_skip(&c));
}

TEST(ReaderCbor, SkipIndefiniteMapValueFails) {
  const uint8_t kData[] = {0xBFu, 0x01u, 0x4Au};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  EXPECT_FALSE(cbor_skip(&c));
}

TEST(ReaderCbor, SkipIndefiniteArrayWithoutBreak) {
  const uint8_t kData[] = {0x9Fu, 0x01u, 0x02u};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  EXPECT_FALSE(cbor_skip(&c));
}

TEST(ReaderCbor, SkipIndefiniteMapWithoutBreak) {
  const uint8_t kData[] = {0xBFu, 0x01u, 0x02u};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  EXPECT_FALSE(cbor_skip(&c));
}

TEST(ReaderCbor, SkipFailsWhenHeadTruncated) {
  const uint8_t kData[] = {0x19u};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  EXPECT_FALSE(cbor_skip(&c));
}

TEST(ReaderCbor, SkipDefiniteArrayElementFails) {
  const uint8_t kData[] = {0x81u, 0x4Au};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  EXPECT_FALSE(cbor_skip(&c));
}

TEST(ReaderCbor, SkipTaggedItemTruncated) {
  const uint8_t kData[] = {0xC0u, 0x19u};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  EXPECT_FALSE(cbor_skip(&c));
}

TEST(ReaderCbor, SkipTruncatedByteStringPayload) {
  const uint8_t kData[] = {
      0x4Au}; /* byte string length 10 (ai=10), no payload */
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  EXPECT_FALSE(cbor_skip(&c));
}

TEST(ReaderCbor, SkipRejectsExcessiveNestDepth) {
  std::vector<uint8_t> data;
  data.reserve(static_cast<size_t>(NERO_NFC_CBOR_MAX_NEST_DEPTH) +
               static_cast<size_t>(kTestLit2u));
  for (unsigned i = 0u; i <= NERO_NFC_CBOR_MAX_NEST_DEPTH; ++i) {
    data.push_back(kTestLit0x81u);
  }
  data.push_back(0x00u);
  cbor_reader_t c = Wrap(data.data(), data.size());
  EXPECT_FALSE(cbor_skip(&c));
}

TEST(ReaderCbor, SkipIllegalIndefiniteUint) {
  const uint8_t kData[] = {0x1Fu};
  cbor_reader_t c = Wrap(&kData[0], sizeof(kData));
  EXPECT_FALSE(cbor_skip(&c));
}
