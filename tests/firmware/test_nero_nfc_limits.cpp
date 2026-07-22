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

#include "nero_nfc_limits.h"
#include "nfc_tag_geometry_limits.h"

#include <gtest/gtest.h>

TEST(NeroNfcLimits, UnoR4SramBudgetConstants) {
  EXPECT_EQ(NERO_NFC_UNO_R4_SRAM_BYTES, 32768u);
  EXPECT_LE(NERO_NFC_UNO_R4_GLOBAL_RAM_MAX, NERO_NFC_UNO_R4_SRAM_BYTES);
  EXPECT_EQ(NERO_NFC_CONSTRAINED_SERIAL_LINE_MAX, 256u);
}

TEST(NeroNfcLimits, SharedNdefAndHostCaps) {
  EXPECT_EQ(NERO_NFC_READER_NDEF_BUF_MAX, 1024u);
  EXPECT_EQ(NERO_NFC_CCID_APDU_RSP_BUF_MAX, 2048u);
  EXPECT_EQ(NERO_NFC_PCSC_APDU_RX_MAX, 65536u);
  EXPECT_EQ(NERO_NFC_HOST_SERIAL_LINE_MAX, 8192u);
  EXPECT_EQ(NERO_NFC_NDEF_SHORT_URI_SUFFIX_MAX, 254u);
  EXPECT_EQ(NERO_NFC_NDEF_SR_PAYLOAD_MAX, 255u);
  EXPECT_EQ(NERO_NFC_NDEF_TEXT_LANG_MAX, 63u);
  EXPECT_LE(NERO_NFC_NDEF_SHORT_URI_SUFFIX_MAX + 1u,
            NERO_NFC_NDEF_SR_PAYLOAD_MAX);
}

TEST(NeroNfcLimits, Type2MinNdefDumpBytesDerivedFromPages) {
  EXPECT_EQ(NFC_TAG_T2T_MIN_NDEF_USER_PAGES, 1u);
  EXPECT_EQ(NFC_TAG_T2T_MIN_NDEF_DUMP_BYTES, 8u);
  EXPECT_EQ(NFC_TAG_T2T_MIN_NDEF_DUMP_BYTES,
            NFC_TAG_T2T_PAGE_SIZE_BYTES + (NFC_TAG_T2T_MIN_NDEF_USER_PAGES *
                                           NFC_TAG_T2T_PAGE_SIZE_BYTES));
}
