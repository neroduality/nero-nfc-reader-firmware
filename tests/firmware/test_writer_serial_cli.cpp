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
#include "writer_serial_cli.h"

namespace {
enum {
  kTestLit16u = 16u,
  kTestLit1776u = 1776u,
  kTestLit2u = 2u,
};
}  // namespace

#include "writer_hal_utest_stub.hpp"
#include "writer_payload.h"

#include "nero_nfc_mem_util.h"

#include <gtest/gtest.h>
#include <span>

#include <string>

static_assert(WRITER_CLI_LINE_CAP == kTestLit1776u,
              "sync Makefile NFC_CDC_SERIAL_LINE_CAP");

namespace {

bool PollUntilIdle(writer_payload_config_t* cfg) {
  bool changed = false;
  while (WriterHalUtestInputAvailable()) {
    changed = writer_serial_cli_poll(cfg) || changed;
  }
  return changed;
}

}  // namespace

TEST(WriterSerialCli, NdefHexUsesContextOwnedRawBuffer) {
  writer_payload_config_t cfg{};
  writer_payload_default(&cfg);
  WriterHalUtestReset();
  writer_serial_cli_init();

  WriterHalUtestFeed("ndef-hex D101015500\n");
  ASSERT_TRUE(PollUntilIdle(&cfg));

  EXPECT_EQ(cfg.kind, WRITER_PAYLOAD_RAW_NDEF);
  ASSERT_NE(cfg.raw_ndef, NERO_NFC_NULL);
  ASSERT_EQ(cfg.raw_ndef_len, 5u);
  EXPECT_EQ(nero_nfc_u8_at(cfg.raw_ndef, cfg.raw_ndef_len, 0u), 0xD1u);
  EXPECT_EQ(nero_nfc_u8_at(cfg.raw_ndef, cfg.raw_ndef_len, 1u), 0x01u);
  EXPECT_EQ(nero_nfc_u8_at(cfg.raw_ndef, cfg.raw_ndef_len, 2u), 0x01u);
  EXPECT_EQ(nero_nfc_u8_at(cfg.raw_ndef, cfg.raw_ndef_len, 3u), 0x55u);
  EXPECT_EQ(nero_nfc_u8_at(cfg.raw_ndef, cfg.raw_ndef_len, 4u), 0x00u);
  EXPECT_NE(WriterHalUtestOutput().find("OK"), std::string::npos);
}

TEST(WriterSerialCli, RejectsOversizedNdefHexWithoutClearingPreviousPayload) {
  writer_payload_config_t cfg{};
  writer_payload_default(&cfg);
  WriterHalUtestReset();
  writer_serial_cli_init();

  WriterHalUtestFeed("ndef-hex D101015500\n");
  ASSERT_TRUE(PollUntilIdle(&cfg));
  ASSERT_EQ(cfg.kind, WRITER_PAYLOAD_RAW_NDEF);
  const uint16_t kPreviousLen = cfg.raw_ndef_len;
  const uint8_t kPreviousFirst =
      nero_nfc_u8_at(cfg.raw_ndef, cfg.raw_ndef_len, 0u);

  std::string too_large = "ndef-hex ";
  too_large.append(static_cast<size_t>(WRITER_NDEF_MAX_BYTES + 1u) * kTestLit2u,
                   'A');
  too_large.push_back('\n');

  WriterHalUtestFeed(too_large.c_str());
  EXPECT_FALSE(PollUntilIdle(&cfg));

  EXPECT_EQ(cfg.kind, WRITER_PAYLOAD_RAW_NDEF);
  EXPECT_EQ(cfg.raw_ndef_len, kPreviousLen);
  ASSERT_NE(cfg.raw_ndef, NERO_NFC_NULL);
  EXPECT_EQ(nero_nfc_u8_at(cfg.raw_ndef, cfg.raw_ndef_len, 0u), kPreviousFirst);
  EXPECT_NE(WriterHalUtestOutput().find("invalid or oversized"),
            std::string::npos);
}

TEST(WriterSerialCli, ReplacesPreviousNdefHexOnSecondValidCommand) {
  writer_payload_config_t cfg{};
  writer_payload_default(&cfg);
  WriterHalUtestReset();
  writer_serial_cli_init();

  WriterHalUtestFeed("ndef-hex D101015500\n");
  ASSERT_TRUE(PollUntilIdle(&cfg));

  WriterHalUtestFeed("ndef-hex D101015501\n");
  ASSERT_TRUE(PollUntilIdle(&cfg));

  EXPECT_EQ(cfg.kind, WRITER_PAYLOAD_RAW_NDEF);
  ASSERT_EQ(cfg.raw_ndef_len, 5u);
  ASSERT_NE(cfg.raw_ndef, NERO_NFC_NULL);
  EXPECT_EQ(nero_nfc_u8_at(cfg.raw_ndef, cfg.raw_ndef_len, 4u), 0x01u);
}

TEST(WriterSerialCli, UrlCommandClearsRawNdefState) {
  writer_payload_config_t cfg{};
  writer_payload_default(&cfg);
  WriterHalUtestReset();
  writer_serial_cli_init();

  WriterHalUtestFeed("ndef-hex D101015500\n");
  ASSERT_TRUE(PollUntilIdle(&cfg));
  ASSERT_EQ(cfg.kind, WRITER_PAYLOAD_RAW_NDEF);

  WriterHalUtestFeed("url https://example.test/\n");
  ASSERT_TRUE(PollUntilIdle(&cfg));

  EXPECT_EQ(cfg.kind, WRITER_PAYLOAD_URL_HTTPS);
  EXPECT_EQ(cfg.raw_ndef, NERO_NFC_NULL);
  EXPECT_EQ(cfg.raw_ndef_len, 0u);
  EXPECT_STREQ(&cfg.str1[0], "example.test/");
}

TEST(WriterSerialCli, OverlongCommandIsDiscardedInsteadOfTruncated) {
  writer_payload_config_t cfg{};
  writer_payload_default(&cfg);
  WriterHalUtestReset();
  writer_serial_cli_init();

  WriterHalUtestFeed("url https://known-good.test/\n");
  ASSERT_TRUE(PollUntilIdle(&cfg));
  ASSERT_EQ(cfg.kind, WRITER_PAYLOAD_URL_HTTPS);
  ASSERT_STREQ(&cfg.str1[0], "known-good.test/");

  std::string overlong = "url https://evil.test/";
  overlong.append(WRITER_CLI_LINE_CAP + kTestLit16u, 'a');
  overlong.push_back('\n');
  WriterHalUtestFeed(overlong.c_str());

  EXPECT_FALSE(PollUntilIdle(&cfg));
  EXPECT_EQ(cfg.kind, WRITER_PAYLOAD_URL_HTTPS);
  EXPECT_STREQ(&cfg.str1[0], "known-good.test/");
  EXPECT_NE(WriterHalUtestOutput().find("command too long"), std::string::npos);
}
