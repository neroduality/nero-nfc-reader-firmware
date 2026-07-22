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
#include <span>

namespace {
enum {
  kTestLit0xBeeFu = 0xBEEFu,
  kTestLit2 = 2,
  kTestLit4 = 4,
  kTestLit64 = 64,
};
}  // namespace

#include "nero_nfc_null.h"
#include "st25_iso15693_codec_host.hpp"

#include "nero_nfc_mem_util.h"

#include <array>

TEST(St25Iso15693Codec, Crc16KnownVector) {
  static const uint8_t kData[] = {0x01u, 0x03u, 0x00u, 0xA0u};
  EXPECT_EQ(St25Iso15693Crc16(&kData[0], (uint16_t)sizeof(kData)), 0xAA0Bu);
}

TEST(St25Iso15693Codec, StreamEncodeAddsSofCrcAndEof) {
  static const uint8_t kTx[] = {0x26u, 0x01u, 0x00u};
  std::array<uint8_t, kTestLit64> encoded{};
  uint16_t enc_len = 0u;
  ASSERT_TRUE(St25Iso15693StreamEncode(&kTx[0], (uint16_t)sizeof(kTx),
                                       encoded.data(), (uint16_t)encoded.size(),
                                       &enc_len));
  EXPECT_GT(enc_len, (uint16_t)sizeof(kTx));
  EXPECT_EQ(std::span{encoded}[0], kSt25Iso15693StreamSof1of4);
  EXPECT_EQ(nero_nfc_u8_at(encoded.data(), enc_len, enc_len - 1u),
            kSt25Iso15693StreamEof1of4);
}

TEST(St25Iso15693Codec, StreamEncodeClearsLengthOnInvalidInput) {
  std::array<uint8_t, kTestLit4> encoded{};
  uint16_t enc_len = kTestLit0xBeeFu;

  EXPECT_FALSE(St25Iso15693StreamEncode(NERO_NFC_NULL, 1u, encoded.data(),
                                        (uint16_t)encoded.size(), &enc_len));
  EXPECT_EQ(enc_len, 0u);
}

TEST(St25Iso15693Codec, StreamPut1of4RejectsOverflow) {
  std::array<uint8_t, kTestLit2> out{};
  uint16_t bit_pos = 0u;
  EXPECT_FALSE(St25Iso15693StreamPut1of4(0x0Fu, out.data(),
                                         (uint16_t)out.size(), &bit_pos));
}

TEST(St25Iso15693Codec, TxWaitBudgetScalesWithLength) {
  EXPECT_GT(St25RuntimeTxWaitBudgetUs(64u), St25RuntimeTxWaitBudgetUs(8u));
}
