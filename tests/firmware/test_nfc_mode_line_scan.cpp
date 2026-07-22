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

#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace {
enum {
  kTestLit25u = 25u,
  kTestLit64 = 64,
  kTestLit8 = 8,
};
}  // namespace

#include <gtest/gtest.h>

#include "nero_nfc_attrs.h"

extern "C" {
#include "nfc_mode_line_scan.h"
}

namespace {

nfc_mode_scan_result_t FeedAll(nfc_mode_scan_state_t* st, const std::string& in,
                               std::vector<uint8_t>* pushbacks) {
  uint8_t pb[kTestLit64];
  uint16_t pblen = 0;
  nfc_mode_scan_result_t last = NFC_MODE_SCAN_INGESTED;
  if (pushbacks != NERO_NFC_NULL) {
    pushbacks->clear();
  }
  for (char byte : in) {
    last = nfc_mode_scan_feed(st, static_cast<uint8_t>(byte), &pb[0], &pblen,
                              sizeof(pb));
    if (last == NFC_MODE_SCAN_PUSHBACK_STOP && pblen > 0 &&
        pushbacks != NERO_NFC_NULL) {
      const auto kPushback = std::span<uint8_t>{pb}.subspan(0u, pblen);
      pushbacks->insert(pushbacks->end(), kPushback.begin(), kPushback.end());
    }
    if (last == NFC_MODE_SCAN_GOT_READER || last == NFC_MODE_SCAN_GOT_WRITER ||
        last == NFC_MODE_SCAN_PUSHBACK_STOP) {
      return last;
    }
  }
  return last;
}

}  // namespace

TEST(NfcModeLineScan, ModeWriterCrlf) {
  nfc_mode_scan_state_t st{};
  nfc_mode_scan_reset(&st);
  std::vector<uint8_t> pb;
  EXPECT_EQ(FeedAll(&st, "mode writer\r\n", &pb), NFC_MODE_SCAN_GOT_WRITER);
  EXPECT_TRUE(pb.empty());
}

TEST(NfcModeLineScan, ModeReaderSplitChunks) {
  nfc_mode_scan_state_t st{};
  nfc_mode_scan_reset(&st);
  uint8_t buf[kTestLit64];
  uint16_t len = 0;

  EXPECT_EQ(nfc_mode_scan_feed(&st, static_cast<uint8_t>('m'), &buf[0], &len,
                               sizeof(buf)),
            NFC_MODE_SCAN_INGESTED);
  EXPECT_EQ(nfc_mode_scan_feed(&st, static_cast<uint8_t>('o'), &buf[0], &len,
                               sizeof(buf)),
            NFC_MODE_SCAN_INGESTED);

  EXPECT_EQ(FeedAll(&st, "de reader\n", NERO_NFC_NULL),
            NFC_MODE_SCAN_GOT_READER);
}

TEST(NfcModeLineScan, ModeFooPushbackIncludesNewline) {
  nfc_mode_scan_state_t st{};
  nfc_mode_scan_reset(&st);
  std::vector<uint8_t> pb;
  EXPECT_EQ(FeedAll(&st, "mode foo\n", &pb), NFC_MODE_SCAN_PUSHBACK_STOP);
  ASSERT_EQ(pb.size(), 9u);
  EXPECT_EQ(std::memcmp(pb.data(), "mode foo\n", 9), 0);
}

TEST(NfcModeLineScan, PrefixMismatchFirstChar) {
  nfc_mode_scan_state_t st{};
  nfc_mode_scan_reset(&st);
  std::vector<uint8_t> pb;
  EXPECT_EQ(FeedAll(&st, "x", &pb), NFC_MODE_SCAN_PUSHBACK_STOP);
  ASSERT_EQ(pb.size(), 1u);
  EXPECT_EQ(pb[0], 'x');
}

TEST(NfcModeLineScan, BackToBackReaderThenWriter) {
  nfc_mode_scan_state_t st{};
  nfc_mode_scan_reset(&st);
  std::vector<uint8_t> pb;

  EXPECT_EQ(FeedAll(&st, "mode reader\n", &pb), NFC_MODE_SCAN_GOT_READER);
  EXPECT_TRUE(pb.empty());

  EXPECT_EQ(FeedAll(&st, "mode writer\n", &pb), NFC_MODE_SCAN_GOT_WRITER);
  EXPECT_TRUE(pb.empty());
}

TEST(NfcModeLineScan, AlmostModeLineThenRealCommand) {
  nfc_mode_scan_state_t st{};
  nfc_mode_scan_reset(&st);
  std::vector<uint8_t> pb;

  EXPECT_EQ(FeedAll(&st, "mode tool\n", &pb), NFC_MODE_SCAN_PUSHBACK_STOP);
  ASSERT_EQ(pb.size(), 10u);

  pb.clear();
  EXPECT_EQ(FeedAll(&st, "mode reader\n", &pb), NFC_MODE_SCAN_GOT_READER);
}

TEST(NfcModeLineScan, ResetClearsPartial) {
  nfc_mode_scan_state_t st{};
  uint8_t buf[kTestLit64];
  uint16_t len = 0;
  nfc_mode_scan_reset(&st);
  EXPECT_EQ(nfc_mode_scan_feed(&st, static_cast<uint8_t>('m'), &buf[0], &len,
                               sizeof(buf)),
            NFC_MODE_SCAN_INGESTED);
  nfc_mode_scan_reset(&st);
  EXPECT_EQ(FeedAll(&st, "mode writer\n", NERO_NFC_NULL),
            NFC_MODE_SCAN_GOT_WRITER);
}

TEST(NfcModeLineScan, ResetNullIsSafe) { nfc_mode_scan_reset(NERO_NFC_NULL); }

TEST(NfcModeLineScan, FeedNullPointersReturnsStop) {
  nfc_mode_scan_state_t st{};
  uint8_t buf[kTestLit8];
  uint16_t len = 0;
  nfc_mode_scan_reset(&st);
  EXPECT_EQ(nfc_mode_scan_feed(NERO_NFC_NULL, static_cast<uint8_t>('a'),
                               &buf[0], &len, sizeof(buf)),
            NFC_MODE_SCAN_PUSHBACK_STOP);
  EXPECT_EQ(nfc_mode_scan_feed(&st, static_cast<uint8_t>('a'), NERO_NFC_NULL,
                               &len, sizeof(buf)),
            NFC_MODE_SCAN_PUSHBACK_STOP);
  EXPECT_EQ(nfc_mode_scan_feed(&st, static_cast<uint8_t>('a'), &buf[0],
                               NERO_NFC_NULL, sizeof(buf)),
            NFC_MODE_SCAN_PUSHBACK_STOP);
}

TEST(NfcModeLineScan, CarriageReturnDoesNotAdvanceState) {
  nfc_mode_scan_state_t st{};
  uint8_t buf[kTestLit64];
  uint16_t len = 0;
  nfc_mode_scan_reset(&st);
  EXPECT_EQ(nfc_mode_scan_feed(&st, static_cast<uint8_t>('m'), &buf[0], &len,
                               sizeof(buf)),
            NFC_MODE_SCAN_INGESTED);
  EXPECT_EQ(nfc_mode_scan_feed(&st, static_cast<uint8_t>('\r'), &buf[0], &len,
                               sizeof(buf)),
            NFC_MODE_SCAN_INGESTED);
  EXPECT_EQ(nfc_mode_scan_feed(&st, static_cast<uint8_t>('o'), &buf[0], &len,
                               sizeof(buf)),
            NFC_MODE_SCAN_INGESTED);
  EXPECT_EQ(FeedAll(&st, "de writer\n", NERO_NFC_NULL),
            NFC_MODE_SCAN_GOT_WRITER);
}

TEST(NfcModeLineScan, NewlineFlushExceedsPushbackCap) {
  nfc_mode_scan_state_t st{};
  nfc_mode_scan_reset(&st);
  uint8_t pb[kTestLit64];
  uint16_t pblen = 0;
  const std::string kPayload("mode xy");
  for (char byte : kPayload) {
    ASSERT_EQ(nfc_mode_scan_feed(&st, static_cast<uint8_t>(byte), &pb[0],
                                 &pblen, /*pushback_cap=*/2),
              NFC_MODE_SCAN_INGESTED);
  }
  EXPECT_EQ(st.len, 7u);
  EXPECT_EQ(
      nfc_mode_scan_feed(&st, static_cast<uint8_t>('\n'), &pb[0], &pblen, 2),
      NFC_MODE_SCAN_PUSHBACK_STOP);
  EXPECT_EQ(pblen, 0u);
}

TEST(NfcModeLineScan, NewlineFlushCopiesWhenFinalLenEqualsPushbackCap) {
  nfc_mode_scan_state_t st{};
  nfc_mode_scan_reset(&st);
  uint8_t pb[kTestLit64];
  uint16_t pblen = 0;
  const std::string kPayload("mode x");
  for (char byte : kPayload) {
    ASSERT_EQ(nfc_mode_scan_feed(&st, static_cast<uint8_t>(byte), &pb[0],
                                 &pblen, sizeof(pb)),
              NFC_MODE_SCAN_INGESTED);
  }
  EXPECT_EQ(st.len, 6u);
  EXPECT_EQ(nfc_mode_scan_feed(&st, static_cast<uint8_t>('\n'), &pb[0], &pblen,
                               /*pushback_cap=*/7),
            NFC_MODE_SCAN_PUSHBACK_STOP);
  ASSERT_EQ(pblen, 7u);
  EXPECT_EQ(std::memcmp(&pb[0], "mode x\n", 7), 0);
}

TEST(NfcModeLineScan, NewlineFlushDropsWhenFinalLenOnePastPushbackCap) {
  nfc_mode_scan_state_t st{};
  nfc_mode_scan_reset(&st);
  uint8_t pb[kTestLit64];
  uint16_t pblen = 0;
  const std::string kPayload2("mode x");
  for (char byte : kPayload2) {
    ASSERT_EQ(nfc_mode_scan_feed(&st, static_cast<uint8_t>(byte), &pb[0],
                                 &pblen, sizeof(pb)),
              NFC_MODE_SCAN_INGESTED);
  }
  EXPECT_EQ(nfc_mode_scan_feed(&st, static_cast<uint8_t>('\n'), &pb[0], &pblen,
                               /*pushback_cap=*/6),
            NFC_MODE_SCAN_PUSHBACK_STOP);
  EXPECT_EQ(pblen, 0u);
}

TEST(NfcModeLineScan, LongLineCapFlushDropsWhenLenExceedsPushbackCap) {
  nfc_mode_scan_state_t st{};
  nfc_mode_scan_reset(&st);
  std::string long_line = "mode ";
  long_line.append(kTestLit25u, 'a');
  ASSERT_EQ(long_line.size(), 30u);
  uint8_t pb[kTestLit64];
  uint16_t pblen = 0;
  {
    for (char byte : long_line) {
      ASSERT_EQ(nfc_mode_scan_feed(&st, static_cast<uint8_t>(byte), &pb[0],
                                   &pblen, sizeof(pb)),
                NFC_MODE_SCAN_INGESTED);
    }
  }
  EXPECT_EQ(st.len, 30u);
  EXPECT_EQ(nfc_mode_scan_feed(&st, static_cast<uint8_t>('a'), &pb[0], &pblen,
                               /*pushback_cap=*/30),
            NFC_MODE_SCAN_PUSHBACK_STOP);
  EXPECT_EQ(pblen, 0u);
}

TEST(NfcModeLineScan, LongLineCapFlushCopiesWhenLenEqualsPushbackCap) {
  nfc_mode_scan_state_t st{};
  nfc_mode_scan_reset(&st);
  std::string long_line = "mode ";
  long_line.append(kTestLit25u, 'a');
  uint8_t pb[kTestLit64];
  uint16_t pblen = 0;
  {
    for (char byte : long_line) {
      ASSERT_EQ(nfc_mode_scan_feed(&st, static_cast<uint8_t>(byte), &pb[0],
                                   &pblen, sizeof(pb)),
                NFC_MODE_SCAN_INGESTED);
    }
  }
  EXPECT_EQ(nfc_mode_scan_feed(&st, static_cast<uint8_t>('a'), &pb[0], &pblen,
                               /*pushback_cap=*/31),
            NFC_MODE_SCAN_PUSHBACK_STOP);
  ASSERT_EQ(pblen, 31u);
  EXPECT_EQ(std::memcmp(&pb[0], (long_line + "a").c_str(), 31), 0);
}

TEST(NfcModeLineScan, PrefixMismatchMidPrefixCopiesWhenCapIsLargeEnough) {
  nfc_mode_scan_state_t st{};
  nfc_mode_scan_reset(&st);
  uint8_t pb[kTestLit64];
  uint16_t pblen = 0;
  const std::string kPrefix("mode");
  for (char byte : kPrefix) {
    ASSERT_EQ(nfc_mode_scan_feed(&st, static_cast<uint8_t>(byte), &pb[0],
                                 &pblen, sizeof(pb)),
              NFC_MODE_SCAN_INGESTED);
  }
  EXPECT_EQ(nfc_mode_scan_feed(&st, static_cast<uint8_t>('X'), &pb[0], &pblen,
                               /*pushback_cap=*/5),
            NFC_MODE_SCAN_PUSHBACK_STOP);
  ASSERT_EQ(pblen, 5u);
  EXPECT_EQ(std::memcmp(&pb[0], "modeX", 5), 0);
}

TEST(NfcModeLineScan, PrefixMismatchMidPrefixDropsWhenCapTooSmall) {
  nfc_mode_scan_state_t st{};
  nfc_mode_scan_reset(&st);
  uint8_t pb[kTestLit64];
  uint16_t pblen = 0;
  const std::string kPrefix2("mode");
  for (char byte : kPrefix2) {
    ASSERT_EQ(nfc_mode_scan_feed(&st, static_cast<uint8_t>(byte), &pb[0],
                                 &pblen, sizeof(pb)),
              NFC_MODE_SCAN_INGESTED);
  }
  EXPECT_EQ(nfc_mode_scan_feed(&st, static_cast<uint8_t>('X'), &pb[0], &pblen,
                               /*pushback_cap=*/4),
            NFC_MODE_SCAN_PUSHBACK_STOP);
  EXPECT_EQ(pblen, 0u);
}

TEST(NfcModeLineScan, PrefixMismatchExceedsPushbackCap) {
  nfc_mode_scan_state_t st{};
  nfc_mode_scan_reset(&st);
  uint8_t pb[kTestLit64];
  uint16_t pblen = 0;
  EXPECT_EQ(
      nfc_mode_scan_feed(&st, static_cast<uint8_t>('z'), &pb[0], &pblen, 0),
      NFC_MODE_SCAN_PUSHBACK_STOP);
  EXPECT_EQ(pblen, 0u);
}

TEST(NfcModeLineScan, LongLineWithoutNewlineTriggersCapsPath) {
  nfc_mode_scan_state_t st{};
  nfc_mode_scan_reset(&st);
  std::string long_line = "mode ";
  long_line.append(kTestLit25u, 'a');
  ASSERT_EQ(long_line.size(), 30u);
  uint8_t pb[kTestLit64];
  uint16_t pblen = 0;
  {
    for (char byte : long_line) {
      EXPECT_EQ(nfc_mode_scan_feed(&st, static_cast<uint8_t>(byte), &pb[0],
                                   &pblen, sizeof(pb)),
                NFC_MODE_SCAN_INGESTED);
    }
  }
  EXPECT_EQ(st.len, 30u);
  EXPECT_EQ(nfc_mode_scan_feed(&st, static_cast<uint8_t>('a'), &pb[0], &pblen,
                               sizeof(pb)),
            NFC_MODE_SCAN_PUSHBACK_STOP);
  EXPECT_EQ(pblen, 31u);
  EXPECT_EQ(std::memcmp(&pb[0], (long_line + "a").c_str(), 31), 0);
}
