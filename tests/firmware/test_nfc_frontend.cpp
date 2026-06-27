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

#include <cstring>

extern "C" {
#include "nero_nfc_null.h"
#include "nfc_frontend.h"
#include "st25r3916_iso14443a_uid.h"
}

TEST(NfcFrontend, AssemblesFourByteUid) {
  const uint8_t cl1[] = {0x11u, 0x22u, 0x33u, 0x44u};
  uint8_t uid[10] = {0};
  uint8_t sak = 0xFFu;
  EXPECT_EQ(st25_iso14443a_assemble_cascaded_uid(1u, cl1, 0x20, NERO_NFC_NULL, -1, NERO_NFC_NULL, -1, uid,
                                                 sizeof(uid), &sak),
            4u);
  EXPECT_EQ(sak, 0x20u);
  EXPECT_EQ(uid[0], 0x11u);
  EXPECT_EQ(uid[3], 0x44u);
}

TEST(NfcFrontend, AssemblesSevenByteUidSkippingCascadeTag) {
  /* [ISO14443-3] §6.5.4 — CL1 = CT + UID0..2; CL2 = UID3..6 (double cascade). */
  const uint8_t cl1[] = {ST25_ISO14443A_CASCADE_TAG, 0x01u, 0x02u, 0x03u};
  const uint8_t cl2[] = {0x04u, 0x05u, 0x06u, 0x07u};
  uint8_t uid[10] = {0};
  uint8_t sak = 0u;
  EXPECT_EQ(st25_iso14443a_assemble_cascaded_uid(2u, cl1, 0x04, cl2, 0x20, NERO_NFC_NULL, -1, uid,
                                                 sizeof(uid), &sak),
            7u);
  EXPECT_EQ(sak, 0x20u);
  const uint8_t expect[] = {0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u};
  EXPECT_EQ(std::memcmp(uid, expect, sizeof(expect)), 0);
}

TEST(NfcFrontend, AssemblesTenByteUidTripleCascade) {
  /* [ISO14443-3] §6.5.4 — CL1 = CT+UID0..2, CL2 = CT+UID3..5, CL3 = UID6..9. */
  const uint8_t cl1[] = {ST25_ISO14443A_CASCADE_TAG, 0x01u, 0x02u, 0x03u};
  const uint8_t cl2[] = {ST25_ISO14443A_CASCADE_TAG, 0x04u, 0x05u, 0x06u};
  const uint8_t cl3[] = {0x07u, 0x08u, 0x09u, 0x0Au};
  uint8_t uid[10] = {0};
  uint8_t sak = 0u;
  EXPECT_EQ(st25_iso14443a_assemble_cascaded_uid(3u, cl1, 0x04, cl2, 0x04, cl3, 0x20, uid,
                                                 sizeof(uid), &sak),
            10u);
  EXPECT_EQ(sak, 0x20u);
  const uint8_t expect[] = {0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u, 0x08u, 0x09u, 0x0Au};
  EXPECT_EQ(std::memcmp(uid, expect, sizeof(expect)), 0);
}

TEST(NfcFrontend, RejectsMalformedCascadeFraming) {
  const uint8_t ct1[] = {ST25_ISO14443A_CASCADE_TAG, 0x01u, 0x02u, 0x03u};
  const uint8_t lvl2[] = {0x04u, 0x05u, 0x06u, 0x07u};
  const uint8_t no_ct[] = {0x77u, 0x01u, 0x02u, 0x03u};
  uint8_t uid[10] = {0};
  uint8_t sak = 0u;

  /* Final level still reports cascading -> invalid. */
  EXPECT_EQ(st25_iso14443a_assemble_cascaded_uid(2u, ct1, 0x04, lvl2, 0x04, NERO_NFC_NULL, -1, uid,
                                                 sizeof(uid), &sak),
            0u);
  /* Missing cascade tag on an incomplete level -> invalid. */
  EXPECT_EQ(st25_iso14443a_assemble_cascaded_uid(2u, no_ct, 0x04, lvl2, 0x20, NERO_NFC_NULL, -1, uid,
                                                 sizeof(uid), &sak),
            0u);
  /* 10-byte UID into a 7-byte buffer -> invalid (capacity). */
  const uint8_t c2[] = {ST25_ISO14443A_CASCADE_TAG, 0x04u, 0x05u, 0x06u};
  const uint8_t c3[] = {0x07u, 0x08u, 0x09u, 0x0Au};
  EXPECT_EQ(st25_iso14443a_assemble_cascaded_uid(3u, ct1, 0x04, c2, 0x04, c3, 0x20, uid, 7u, &sak),
            0u);
  /* CL1 claims complete (no cascade bit) but caller asked for 2 levels -> invalid. */
  EXPECT_EQ(st25_iso14443a_assemble_cascaded_uid(2u, ct1, 0x20, lvl2, 0x20, NERO_NFC_NULL, -1, uid,
                                                 sizeof(uid), &sak),
            0u);
}

TEST(NfcFrontend, Iso14443aConstants) {
  EXPECT_EQ(NFC_FRONTEND_ISO14443A_SEL_CL1, 0x93u);
  EXPECT_EQ(NFC_FRONTEND_ISO14443A_SEL_CL2, 0x95u);
  EXPECT_EQ(NFC_FRONTEND_ISO14443_CMD_RATS, 0xE0u);
}

TEST(NfcFrontend, NtagConstants) {
  EXPECT_EQ(NFC_FRONTEND_NTAG_CMD_READ, 0x30u);
  EXPECT_EQ(NFC_FRONTEND_NTAG_CMD_FAST_READ, 0x3Au);
  EXPECT_EQ(NFC_FRONTEND_NTAG_CMD_WRITE, 0xA2u);
  EXPECT_EQ(NFC_FRONTEND_NTAG_CMD_GET_VERSION, 0x60u);
}

TEST(NfcFrontend, Iso15693ShapeConstants) {
  EXPECT_EQ(NFC_FRONTEND_ISO15693_UID_LEN, 8u);
  EXPECT_EQ(NFC_FRONTEND_ISO15693_MAX_STREAM_FRAME, 128u);
}

TEST(NfcFrontend, InitStatusValues) {
  EXPECT_EQ(NFC_FRONTEND_INIT_OK, 0);
  EXPECT_EQ(NFC_FRONTEND_INIT_CHIP_ID_FAIL, 1);
  EXPECT_EQ(NFC_FRONTEND_INIT_OSC_FAIL, 2);
}

TEST(NfcFrontend, FieldOnStatusValues) {
  EXPECT_EQ(NFC_FRONTEND_FIELD_ON_OK, 0);
  EXPECT_EQ(NFC_FRONTEND_FIELD_ON_COLLISION, 1);
  EXPECT_EQ(NFC_FRONTEND_FIELD_ON_TXRX_VERIFY_FAIL, 2);
}

TEST(NfcFrontend, TransceiveDiagDefaultInitializes) {
  nfc_frontend_transceive_diag_t d{};
  EXPECT_EQ(d.requested_timeout_ms, 0u);
  EXPECT_EQ(d.nrt_steps_programmed, 0u);
  EXPECT_EQ(d.tx_wait_us, 0u);
  EXPECT_EQ(d.tx_irq_status, 0u);
  EXPECT_EQ(d.final_irq_status, 0u);
  EXPECT_FALSE(d.extended_nrt_16bit);
  EXPECT_FALSE(d.nrt_clamped);
  EXPECT_FALSE(d.got_txe);
  EXPECT_FALSE(d.got_rxe);
  EXPECT_FALSE(d.got_nre);
}
