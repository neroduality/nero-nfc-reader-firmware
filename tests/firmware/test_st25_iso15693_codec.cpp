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

#include "nero_nfc_null.h"
#include "st25_iso15693_codec_host.h"

#include <array>

TEST(St25Iso15693Codec, Crc16KnownVector) {
  static const uint8_t kData[] = {0x01u, 0x03u, 0x00u, 0xA0u};
  EXPECT_EQ(st25_iso15693_crc16(kData, (uint16_t)sizeof(kData)), 0xAA0Bu);
}

TEST(St25Iso15693Codec, StreamEncodeAddsSofCrcAndEof) {
  static const uint8_t kTx[] = {0x26u, 0x01u, 0x00u};
  std::array<uint8_t, 64> encoded{};
  uint16_t enc_len = 0u;
  ASSERT_TRUE(st25_iso15693_stream_encode(kTx, (uint16_t)sizeof(kTx), encoded.data(),
                                          (uint16_t)encoded.size(), &enc_len));
  EXPECT_GT(enc_len, (uint16_t)sizeof(kTx));
  EXPECT_EQ(encoded[0], ST25_ISO15693_STREAM_SOF_1OF4);
  EXPECT_EQ(encoded[enc_len - 1u], ST25_ISO15693_STREAM_EOF_1OF4);
}

TEST(St25Iso15693Codec, StreamEncodeClearsLengthOnInvalidInput) {
  std::array<uint8_t, 4> encoded{};
  uint16_t enc_len = 0xBEEFu;

  EXPECT_FALSE(st25_iso15693_stream_encode(NERO_NFC_NULL, 1u, encoded.data(),
                                           (uint16_t)encoded.size(), &enc_len));
  EXPECT_EQ(enc_len, 0u);
}

TEST(St25Iso15693Codec, StreamPut1of4RejectsOverflow) {
  std::array<uint8_t, 2> out{};
  uint16_t bit_pos = 0u;
  EXPECT_FALSE(st25_iso15693_stream_put_1of4(0x0Fu, out.data(), (uint16_t)out.size(), &bit_pos));
}

TEST(St25Iso15693Codec, TxWaitBudgetScalesWithLength) {
  EXPECT_GT(st25_runtime_tx_wait_budget_us(64u), st25_runtime_tx_wait_budget_us(8u));
}
