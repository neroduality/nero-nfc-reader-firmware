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
#include "reader_context.h"
#include "reader_iso_dep_timing.h"

#include <gtest/gtest.h>

#include <cstring>

TEST(ReaderContext, ResetAppliesIsoDepDefaults) {
  reader_context_t ctx{};
  ctx.iso_dep.fwi = 0u;
  ctx.iso_dep.fwt_us = 0u;
  ctx.iso_dep.pic_frame_max = 0u;
  ctx.iso_dep_debug.iso_trace = 1u;

  reader_context_reset(&ctx);

  EXPECT_EQ(ctx.iso_dep.fwi, 4u);
  EXPECT_EQ(ctx.iso_dep.fwt_us, reader_iso_dep_fwt_us_from_fwi(4u));
  EXPECT_EQ(ctx.iso_dep.pic_frame_max, 256u);
  EXPECT_EQ(ctx.iso_dep_debug.iso_trace, 0u);
}

TEST(ReaderContext, ResetNullIsNoOp) {
  reader_context_reset(NERO_NFC_NULL);
}

TEST(ReaderContext, ResetClearsSensitiveIsoDepBuffers) {
  reader_context_t ctx{};
  for (std::size_t i = 0u; i < sizeof(ctx.iso_dep.iblock_tx); ++i) {
    ctx.iso_dep.iblock_tx[i] = 0xA5u;
  }
  for (std::size_t i = 0u; i < sizeof(ctx.iso_dep.raw_rx); ++i) {
    ctx.iso_dep.raw_rx[i] = 0x5Au;
  }
  for (std::size_t i = 0u; i < sizeof(ctx.iso_dep.ats_data); ++i) {
    ctx.iso_dep.ats_data[i] = 0xC3u;
  }

  reader_context_reset(&ctx);

  for (std::size_t i = 0u; i < sizeof(ctx.iso_dep.iblock_tx); ++i) {
    EXPECT_EQ(ctx.iso_dep.iblock_tx[i], 0u);
  }
  for (std::size_t i = 0u; i < sizeof(ctx.iso_dep.raw_rx); ++i) {
    EXPECT_EQ(ctx.iso_dep.raw_rx[i], 0u);
  }
  for (std::size_t i = 0u; i < sizeof(ctx.iso_dep.ats_data); ++i) {
    EXPECT_EQ(ctx.iso_dep.ats_data[i], 0u);
  }
}

TEST(ReaderContext, GlobalResetClearsIsoDepTrace) {
  g_iso_dep_trace = 1u;
  reader_context_reset(&g_reader);
  EXPECT_EQ(g_iso_dep_trace, 0u);
}
