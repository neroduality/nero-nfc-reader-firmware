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

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <ranges>

extern "C" {
#include "nero_nfc_null.h"
#include "nero_nfc_frontend.h"
#include "st25r3916_iso14443a.h"
#include "st25r3916_iso14443a_uid.h"
}

namespace {

constexpr std::size_t kActivationUidCapacity = 10u;
constexpr uint8_t kUnsetByte = 0xFFu;
constexpr uint8_t kUidFillByte = 0xAAu;
constexpr uint8_t kIsoDepSak = 0x20u;
constexpr std::array<uint8_t, 2u> kActivationAtqa{0x04u, 0x00u};
constexpr std::array<uint8_t, 4u> kActivationUid{0x11u, 0x22u, 0x33u, 0x44u};
constexpr uint8_t kActivationUidLen =
    static_cast<uint8_t>(kActivationUid.size());

struct Iso14443aActivationFake {
  unsigned short_frame_calls_;
  unsigned select_calls_;
  bool tag_present_;
};

bool ActivationSendFrame(void* context, uint8_t* atqa_out) {
  auto* fake = static_cast<Iso14443aActivationFake*>(context);
  ++fake->short_frame_calls_;
  if (!fake->tag_present_) {
    return false;
  }
  std::ranges::copy(kActivationAtqa, atqa_out);
  return true;
}

void ActivationDelay(void* context, uint32_t ms) {
  (void)context;
  (void)ms;
}

int ActivationSelect(void* context, uint8_t sel_cmd, uint8_t* uid_out) {
  auto* fake = static_cast<Iso14443aActivationFake*>(context);
  ++fake->select_calls_;
  if (sel_cmd != NFC_FRONTEND_ISO14443A_SEL_CL1) {
    return -1;
  }
  std::ranges::copy(kActivationUid, uid_out);
  return kIsoDepSak;
}

}  // namespace

TEST(NfcFrontend, Iso14443aActivationDoesNotReportPhantomTag) {
  Iso14443aActivationFake fake{};
  std::array<uint8_t, kActivationUidCapacity> uid{};
  uid.fill(kUidFillByte);
  uint8_t uid_len = kUnsetByte;
  uint8_t sak = kUnsetByte;

  EXPECT_FALSE(st25_iso14443a_activate_tag(
      ActivationSendFrame, ActivationSendFrame, ActivationDelay, &fake, true,
      ActivationSelect, uid.data(), static_cast<uint8_t>(uid.size()), &uid_len,
      &sak));
  EXPECT_EQ(fake.short_frame_calls_, 2u);
  EXPECT_EQ(fake.select_calls_, 0u);
  EXPECT_EQ(uid_len, 0u);
  EXPECT_EQ(sak, 0u);
}

TEST(NfcFrontend, Iso14443aActivationRunsRfCallbacksAndReturnsUid) {
  Iso14443aActivationFake fake{};
  fake.tag_present_ = true;
  std::array<uint8_t, kActivationUidCapacity> uid{};
  uid.fill(kUidFillByte);
  uint8_t uid_len = 0u;
  uint8_t sak = 0u;

  ASSERT_TRUE(st25_iso14443a_activate_tag(
      ActivationSendFrame, ActivationSendFrame, ActivationDelay, &fake, true,
      ActivationSelect, uid.data(), static_cast<uint8_t>(uid.size()), &uid_len,
      &sak));
  EXPECT_EQ(fake.short_frame_calls_, 1u);
  EXPECT_EQ(fake.select_calls_, 1u);
  EXPECT_EQ(uid_len, kActivationUidLen);
  EXPECT_EQ(sak, kIsoDepSak);
  EXPECT_TRUE(
      std::equal(kActivationUid.begin(), kActivationUid.end(), uid.begin()));
}

TEST(NfcFrontend, AssemblesFourByteUid) {
  const uint8_t kCl1[] = {0x11u, 0x22u, 0x33u, 0x44u};
  uint8_t uid[kActivationUidCapacity] = {0};
  uint8_t sak = kUnsetByte;
  EXPECT_EQ(st25_iso14443a_assemble_cascaded_uid(
                1u, &kCl1[0], 0x20, NERO_NFC_NULL, -1, NERO_NFC_NULL, -1,
                &uid[0], sizeof(uid), &sak),
            4u);
  EXPECT_EQ(sak, 0x20u);
  EXPECT_EQ(uid[0], 0x11u);
  EXPECT_EQ(uid[3], 0x44u);
}

TEST(NfcFrontend, AssemblesSevenByteUidSkippingCascadeTag) {
  /* [ISO14443-3] §6.5.4 — CL1 = CT + UID0..2; CL2 = UID3..6 (double cascade).
   */
  const uint8_t kCl1[] = {K_S_T25_ISO14443_A_CASCADE_TAG, 0x01u, 0x02u, 0x03u};
  const uint8_t kCl2[] = {0x04u, 0x05u, 0x06u, 0x07u};
  uint8_t uid[kActivationUidCapacity] = {0};
  uint8_t sak = 0u;
  EXPECT_EQ(st25_iso14443a_assemble_cascaded_uid(2u, &kCl1[0], 0x04, &kCl2[0],
                                                 0x20, NERO_NFC_NULL, -1,
                                                 &uid[0], sizeof(uid), &sak),
            7u);
  EXPECT_EQ(sak, 0x20u);
  const uint8_t kExpect[] = {0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u};
  EXPECT_EQ(std::memcmp(&uid[0], &kExpect[0], sizeof(kExpect)), 0);
}

TEST(NfcFrontend, AssemblesTenByteUidTripleCascade) {
  /* [ISO14443-3] §6.5.4 — CL1 = CT+UID0..2, CL2 = CT+UID3..5, CL3 = UID6..9. */
  const uint8_t kCl1[] = {K_S_T25_ISO14443_A_CASCADE_TAG, 0x01u, 0x02u, 0x03u};
  const uint8_t kCl2[] = {K_S_T25_ISO14443_A_CASCADE_TAG, 0x04u, 0x05u, 0x06u};
  const uint8_t kCl3[] = {0x07u, 0x08u, 0x09u, 0x0Au};
  uint8_t uid[kActivationUidCapacity] = {0};
  uint8_t sak = 0u;
  EXPECT_EQ(st25_iso14443a_assemble_cascaded_uid(3u, &kCl1[0], 0x04, &kCl2[0],
                                                 0x04, &kCl3[0], 0x20, &uid[0],
                                                 sizeof(uid), &sak),
            10u);
  EXPECT_EQ(sak, 0x20u);
  const uint8_t kExpect[] = {0x01u, 0x02u, 0x03u, 0x04u, 0x05u,
                             0x06u, 0x07u, 0x08u, 0x09u, 0x0Au};
  EXPECT_EQ(std::memcmp(&uid[0], &kExpect[0], sizeof(kExpect)), 0);
}

TEST(NfcFrontend, RejectsMalformedCascadeFraming) {
  const uint8_t kCt1[] = {K_S_T25_ISO14443_A_CASCADE_TAG, 0x01u, 0x02u, 0x03u};
  const uint8_t kLvl2[] = {0x04u, 0x05u, 0x06u, 0x07u};
  const uint8_t kNoCt[] = {0x77u, 0x01u, 0x02u, 0x03u};
  uint8_t uid[kActivationUidCapacity] = {0};
  uint8_t sak = 0u;

  /* Final level still reports cascading -> invalid. */
  EXPECT_EQ(st25_iso14443a_assemble_cascaded_uid(2u, &kCt1[0], 0x04, &kLvl2[0],
                                                 0x04, NERO_NFC_NULL, -1,
                                                 &uid[0], sizeof(uid), &sak),
            0u);
  /* Missing cascade tag on an incomplete level -> invalid. */
  EXPECT_EQ(st25_iso14443a_assemble_cascaded_uid(2u, &kNoCt[0], 0x04, &kLvl2[0],
                                                 0x20, NERO_NFC_NULL, -1,
                                                 &uid[0], sizeof(uid), &sak),
            0u);
  /* 10-byte UID into a 7-byte buffer -> invalid (capacity). */
  const uint8_t kC2[] = {K_S_T25_ISO14443_A_CASCADE_TAG, 0x04u, 0x05u, 0x06u};
  const uint8_t kC3[] = {0x07u, 0x08u, 0x09u, 0x0Au};
  EXPECT_EQ(
      st25_iso14443a_assemble_cascaded_uid(3u, &kCt1[0], 0x04, &kC2[0], 0x04,
                                           &kC3[0], 0x20, &uid[0], 7u, &sak),
      0u);
  /* CL1 claims complete (no cascade bit) but caller asked for 2 levels ->
   * invalid. */
  EXPECT_EQ(st25_iso14443a_assemble_cascaded_uid(2u, &kCt1[0], 0x20, &kLvl2[0],
                                                 0x20, NERO_NFC_NULL, -1,
                                                 &uid[0], sizeof(uid), &sak),
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
