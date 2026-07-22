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
#include "nero_nfc_reader_app_fixture.hpp"
#include "nfc_tag_geometry_limits.h"
#include "reader_context.h"
#include "reader_iso_dep_timing.h"
#include "writer_context.h"

namespace {
enum {
  kTestLit0x5Au = 0x5Au,
  kTestLit0xA5u = 0xA5u,
  kTestLit0xC3u = 0xC3u,
};
}  // namespace

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

TEST(ReaderContext, ResetNullIsNoOp) { reader_context_reset(NERO_NFC_NULL); }

TEST(ReaderContext, ResetDoesNotPreserveAnUnknownFrontendPointer) {
  reader_context_t ctx{};
  nfc_frontend_t stale_frontend{};
  ctx.frontend = &stale_frontend;

  reader_context_reset(&ctx);

  EXPECT_EQ(ctx.frontend, NERO_NFC_NULL);
}

TEST(ReaderContext, ResetClearsSensitiveIsoDepBuffers) {
  reader_context_t ctx{};
  for (unsigned char& i : ctx.iso_dep.iblock_tx) {
    i = kTestLit0xA5u;
  }
  for (unsigned char& i : ctx.iso_dep.raw_rx) {
    i = kTestLit0x5Au;
  }
  for (unsigned char& i : ctx.iso_dep.ats_data) {
    i = kTestLit0xC3u;
  }

  reader_context_reset(&ctx);

  for (unsigned char i : ctx.iso_dep.iblock_tx) {
    EXPECT_EQ(i, 0u);
  }
  for (unsigned char i : ctx.iso_dep.raw_rx) {
    EXPECT_EQ(i, 0u);
  }
  for (unsigned char i : ctx.iso_dep.ats_data) {
    EXPECT_EQ(i, 0u);
  }
}

TEST_F(NeroNfcReaderAppFixture, ActiveResetClearsIsoDepTrace) {
  G_ISO_DEP_TRACE = 1u;
  reader_context_reset(reader_context_active());
  EXPECT_EQ(G_ISO_DEP_TRACE, 0u);
}

TEST_F(NeroNfcReaderAppFixture, ReaderContextLivesInAppStorage) {
  reader_context_t* ctx = nero_nfc_app_reader(App());
  ASSERT_NE(ctx, NERO_NFC_NULL);
  EXPECT_EQ(ctx, reader_context_active());
  EXPECT_EQ(ctx, &G_READER);
}

TEST_F(NeroNfcReaderAppFixture, WriterContextLivesInAppStorage) {
  writer_context_t* ctx = nero_nfc_app_writer(App());
  ASSERT_NE(ctx, NERO_NFC_NULL);
  EXPECT_EQ(ctx, writer_context_active());
  WRITER_APP_SAK = NFC_TAG_T4T_SAK_ISO14443_4_BIT;
  EXPECT_EQ(ctx->sak, NFC_TAG_T4T_SAK_ISO14443_4_BIT);
}
