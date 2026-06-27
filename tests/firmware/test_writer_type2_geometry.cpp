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

#include "writer_type2_geometry.h"

#include <gtest/gtest.h>

TEST(WriterType2Geometry, Ntag21xVersionReply) {
  const uint8_t ok[] = {0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x0F, 0x03};
  EXPECT_TRUE(writer_type2_is_ntag21x_version_reply(ok, 8));
  EXPECT_FALSE(writer_type2_is_ntag21x_version_reply(ok, 7));
  EXPECT_FALSE(writer_type2_is_ntag21x_version_reply(NERO_NFC_NULL, 8));
}

TEST(WriterType2Geometry, CapLastPageFromMlen) {
  EXPECT_EQ(writer_type2_cap_last_page_from_mlen(0x12u), 39u);
  EXPECT_EQ(writer_type2_cap_last_page_from_mlen(0x3Eu), 129u);
  EXPECT_EQ(writer_type2_cap_last_page_from_mlen(0x6Du), 225u);
}

TEST(WriterType2Geometry, CcSizePrefersTagCc) {
  const uint8_t cc[] = {0xE1u, 0x10u, 0x3Eu, 0x00u};
  EXPECT_EQ(writer_type2_cc_size(WRITER_TYPE2_FAMILY_NTAG21X, true, cc, 0u, NERO_NFC_NULL), 0x3Eu);
  EXPECT_EQ(writer_type2_cc_size(WRITER_TYPE2_FAMILY_ST25TN, true, cc, 0u, NERO_NFC_NULL), 0x3Eu);
  EXPECT_EQ(writer_type2_cc_size(WRITER_TYPE2_FAMILY_ST25TN, false, NERO_NFC_NULL, 0u, NERO_NFC_NULL), 0x08u);
}

TEST(WriterType2Geometry, MaxPageFromCcMlen) {
  const uint8_t cc[] = {0xE1u, 0x10u, 0x12u, 0x00u};
  EXPECT_EQ(writer_type2_max_page(WRITER_TYPE2_FAMILY_NTAG21X, true, cc, 0u, NERO_NFC_NULL), 39u);
}

TEST(WriterType2Geometry, St25TnGeometryUsesFactoryCcWhenAvailable) {
  const uint8_t st25tn512_cc[] = {0xE1u, 0x10u, 0x08u, 0x00u};
  const uint8_t st25tn01k_cc[] = {0xE1u, 0x10u, 0x14u, 0x00u};

  EXPECT_EQ(writer_type2_max_page(WRITER_TYPE2_FAMILY_ST25TN, true, st25tn512_cc, 0u,
                                  NERO_NFC_NULL),
            19u);
  EXPECT_EQ(writer_type2_max_page(WRITER_TYPE2_FAMILY_ST25TN, true, st25tn01k_cc, 0u,
                                  NERO_NFC_NULL),
            43u);
  EXPECT_EQ(writer_type2_max_page(WRITER_TYPE2_FAMILY_ST25TN, false, NERO_NFC_NULL, 0u,
                                  NERO_NFC_NULL),
            19u);
}

TEST(WriterType2Geometry, Ntag213ClassSizeIdUsesPage39) {
  const uint8_t version[] = {0x00u, 0x04u, 0x04u, 0x02u, 0x01u, 0x00u, 0x0Fu, 0x03u};

  EXPECT_EQ(writer_type2_physical_cap_last_page(false, NERO_NFC_NULL, (uint8_t)sizeof(version),
                                                version),
            39u);
  EXPECT_EQ(writer_type2_cc_size(WRITER_TYPE2_FAMILY_NTAG21X, false, NERO_NFC_NULL,
                                 (uint8_t)sizeof(version), version),
            0x12u);
  EXPECT_EQ(writer_type2_max_page(WRITER_TYPE2_FAMILY_NTAG21X, false, NERO_NFC_NULL,
                                  (uint8_t)sizeof(version), version),
            39u);
}

TEST(WriterType2Geometry, UnknownNtagSizeIdHasNoPhysicalCap) {
  /* [T2T-ISO14443-A-NTAG21x] storage-size 0x0E is not a defined NTAG21x value; physical cap must
   * fail closed (0) rather than be assumed NTAG213. */
  const uint8_t version[] = {0x00u, 0x04u, 0x04u, 0x02u, 0x01u, 0x00u, 0x0Eu, 0x03u};

  EXPECT_EQ(writer_type2_physical_cap_last_page(false, NERO_NFC_NULL, (uint8_t)sizeof(version),
                                                version),
            0u);
}
