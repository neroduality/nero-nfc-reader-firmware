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

#include "writer_hal_utest_stub.h"
#include "writer_payload.h"

#include <gtest/gtest.h>

#include <string>

static_assert(WRITER_CLI_LINE_CAP == 1776u, "sync Makefile NFC_CDC_SERIAL_LINE_CAP");

namespace {

bool PollUntilIdle(writer_payload_config_t *cfg) {
  bool changed = false;
  while (writer_hal_utest_input_available()) {
    changed = writer_serial_cli_poll(cfg) || changed;
  }
  return changed;
}

} // namespace

TEST(WriterSerialCli, NdefHexUsesStaticRawBuffer) {
  writer_payload_config_t cfg{};
  writer_payload_default(&cfg);
  writer_hal_utest_reset();
  writer_serial_cli_init();

  writer_hal_utest_feed("ndef-hex D101015500\n");
  ASSERT_TRUE(PollUntilIdle(&cfg));

  EXPECT_EQ(cfg.kind, WRITER_PAYLOAD_RAW_NDEF);
  ASSERT_NE(cfg.raw_ndef, NERO_NFC_NULL);
  ASSERT_EQ(cfg.raw_ndef_len, 5u);
  EXPECT_EQ(cfg.raw_ndef[0], 0xD1u);
  EXPECT_EQ(cfg.raw_ndef[1], 0x01u);
  EXPECT_EQ(cfg.raw_ndef[2], 0x01u);
  EXPECT_EQ(cfg.raw_ndef[3], 0x55u);
  EXPECT_EQ(cfg.raw_ndef[4], 0x00u);
  EXPECT_NE(writer_hal_utest_output().find("OK"), std::string::npos);
}

TEST(WriterSerialCli, RejectsOversizedNdefHexWithoutClearingPreviousPayload) {
  writer_payload_config_t cfg{};
  writer_payload_default(&cfg);
  writer_hal_utest_reset();
  writer_serial_cli_init();

  writer_hal_utest_feed("ndef-hex D101015500\n");
  ASSERT_TRUE(PollUntilIdle(&cfg));
  ASSERT_EQ(cfg.kind, WRITER_PAYLOAD_RAW_NDEF);
  const uint16_t previous_len = cfg.raw_ndef_len;
  const uint8_t previous_first = cfg.raw_ndef[0];

  std::string too_large = "ndef-hex ";
  too_large.append((WRITER_NDEF_MAX_BYTES + 1u) * 2u, 'A');
  too_large.push_back('\n');

  writer_hal_utest_feed(too_large.c_str());
  EXPECT_FALSE(PollUntilIdle(&cfg));

  EXPECT_EQ(cfg.kind, WRITER_PAYLOAD_RAW_NDEF);
  EXPECT_EQ(cfg.raw_ndef_len, previous_len);
  ASSERT_NE(cfg.raw_ndef, NERO_NFC_NULL);
  EXPECT_EQ(cfg.raw_ndef[0], previous_first);
  EXPECT_NE(writer_hal_utest_output().find("invalid or oversized"), std::string::npos);
}

TEST(WriterSerialCli, ReplacesPreviousNdefHexOnSecondValidCommand) {
  writer_payload_config_t cfg{};
  writer_payload_default(&cfg);
  writer_hal_utest_reset();
  writer_serial_cli_init();

  writer_hal_utest_feed("ndef-hex D101015500\n");
  ASSERT_TRUE(PollUntilIdle(&cfg));

  writer_hal_utest_feed("ndef-hex D101015501\n");
  ASSERT_TRUE(PollUntilIdle(&cfg));

  EXPECT_EQ(cfg.kind, WRITER_PAYLOAD_RAW_NDEF);
  ASSERT_EQ(cfg.raw_ndef_len, 5u);
  ASSERT_NE(cfg.raw_ndef, NERO_NFC_NULL);
  EXPECT_EQ(cfg.raw_ndef[4], 0x01u);
}

TEST(WriterSerialCli, UrlCommandClearsRawNdefState) {
  writer_payload_config_t cfg{};
  writer_payload_default(&cfg);
  writer_hal_utest_reset();
  writer_serial_cli_init();

  writer_hal_utest_feed("ndef-hex D101015500\n");
  ASSERT_TRUE(PollUntilIdle(&cfg));
  ASSERT_EQ(cfg.kind, WRITER_PAYLOAD_RAW_NDEF);

  writer_hal_utest_feed("url https://example.test/\n");
  ASSERT_TRUE(PollUntilIdle(&cfg));

  EXPECT_EQ(cfg.kind, WRITER_PAYLOAD_URL_HTTPS);
  EXPECT_EQ(cfg.raw_ndef, NERO_NFC_NULL);
  EXPECT_EQ(cfg.raw_ndef_len, 0u);
  EXPECT_STREQ(cfg.str1, "example.test/");
}

TEST(WriterSerialCli, OverlongCommandIsDiscardedInsteadOfTruncated) {
  writer_payload_config_t cfg{};
  writer_payload_default(&cfg);
  writer_hal_utest_reset();
  writer_serial_cli_init();

  writer_hal_utest_feed("url https://known-good.test/\n");
  ASSERT_TRUE(PollUntilIdle(&cfg));
  ASSERT_EQ(cfg.kind, WRITER_PAYLOAD_URL_HTTPS);
  ASSERT_STREQ(cfg.str1, "known-good.test/");

  std::string overlong = "url https://evil.test/";
  overlong.append(WRITER_CLI_LINE_CAP + 16u, 'a');
  overlong.push_back('\n');
  writer_hal_utest_feed(overlong.c_str());

  EXPECT_FALSE(PollUntilIdle(&cfg));
  EXPECT_EQ(cfg.kind, WRITER_PAYLOAD_URL_HTTPS);
  EXPECT_STREQ(cfg.str1, "known-good.test/");
  EXPECT_NE(writer_hal_utest_output().find("command too long"), std::string::npos);
}
