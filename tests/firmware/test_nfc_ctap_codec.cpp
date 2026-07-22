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
#include "nfc_ctap_codec.h"
#include "nero_nfc_mem_util.h"
#include "test_bounds.hpp"
#include <span>

namespace {
enum {
  kTestLit0x0Cu = 0x0Cu,
  kTestLit0x11u = 0x11u,
  kTestLit0x40u = 0x40u,
  kTestLit0x80u = 0x80u,
  kTestLit0xA5u = 0xA5u,
  kTestLit0xBeeFu = 0xBEEFu,
  kTestLit0xEEu = 0xEEu,
  kTestLit16 = 16,
  kTestLit2 = 2,
  kTestLit2u = 2u,
  kTestLit32 = 32,
  kTestLit4 = 4,
  kTestLit5 = 5,
  kTestLit64 = 64,
  kTestLit7u = 7u,
  kTestLit8 = 8,
};
}  // namespace

#include <cstring>

#include <gtest/gtest.h>

namespace {

enum {
  kCborScratchSmallCap = 128u,
  kCborScratchMediumCap = 256u,
  kCborScratchLargeCap = 512u,
  kExtendedCborCap = 260u,
  kExtendedApduScratchCap = 300u,
  kShortApduRoundTripCap = 160u,
};

void FillTestBytes(uint8_t* dst, uint8_t value, uint16_t len) {
  nero_nfc_test::FillBytes(dst, len, value);
}

}  // namespace

TEST(NfcCtapCodec, FidoAidMatchesExpectedValue) {
  const uint8_t kExpected[NFC_CTAP_FIDO_AID_LEN] = {
      0xA0u, 0x00u, 0x00u, 0x06u, 0x47u, 0x2Fu, 0x00u, 0x01u,
  };
  EXPECT_EQ(
      std::memcmp(&NFC_CTAP_FIDO_AID[0], &kExpected[0], sizeof(kExpected)), 0);
}

TEST(NfcCtapCodec, IsoDepIblockTxBufferTracksApduRecommendedSize) {
  EXPECT_EQ(NFC_CTAP_APDU_BUF_RECOMMENDED, 820u);
  EXPECT_EQ(NFC_ISO_DEP_IBLOCK_TX_BUF_LEN,
            NFC_CTAP_APDU_BUF_RECOMMENDED + NFC_ISO_DEP_IBLOCK_TX_OVERHEAD);
  EXPECT_EQ(NFC_ISO_DEP_IBLOCK_TX_BUF_LEN, 832u);
}

TEST(NfcCtapCodec, EncodesDiscoveryGetAssertionCbor) {
  uint8_t hash[kTestLit32]{};
  FillTestBytes(&hash[0], kTestLit0x11u, sizeof(hash));
  uint8_t cbor[kCborScratchSmallCap];
  uint16_t len = 0;

  ASSERT_TRUE(nfc_ctap_encode_get_assertion(&hash[0], "example.com",
                                            NERO_NFC_NULL, 0u, &cbor[0],
                                            sizeof(cbor), &len));

  ASSERT_GE(len, 16u);
  EXPECT_EQ(cbor[0], 0xA3u);
  EXPECT_EQ(cbor[1], 0x01u);
  EXPECT_EQ(cbor[2], 0x6Bu); /* text string len 11 */
  EXPECT_EQ(
      std::memcmp(std::span{cbor}.subspan(3u, 11u).data(), "example.com", 11u),
      0);
}

TEST(NfcCtapCodec, EncodesGetAssertionWithAllowCredential) {
  uint8_t hash[kTestLit32]{};
  const uint8_t kCred[] = {0x01u, 0x02u, 0x03u, 0x04u};
  uint8_t cbor[kCborScratchMediumCap];
  uint16_t len = 0;

  ASSERT_TRUE(nfc_ctap_encode_get_assertion(&hash[0], "webauthn.io", &kCred[0],
                                            sizeof(kCred), &cbor[0],
                                            sizeof(cbor), &len));

  EXPECT_EQ(cbor[0], 0xA4u);
  EXPECT_NE(std::memchr(&cbor[0], 0x03u, len), NERO_NFC_NULL);
}

TEST(NfcCtapCodec, RejectsInvalidGetAssertionInputs) {
  uint8_t hash[kTestLit32]{};
  uint8_t cbor[kTestLit64];
  uint16_t len = 0;

  EXPECT_FALSE(nfc_ctap_encode_get_assertion(NERO_NFC_NULL, "rp", NERO_NFC_NULL,
                                             0u, &cbor[0], sizeof(cbor), &len));
  EXPECT_FALSE(nfc_ctap_encode_get_assertion(&hash[0], "", NERO_NFC_NULL, 0u,
                                             &cbor[0], sizeof(cbor), &len));
  EXPECT_FALSE(nfc_ctap_encode_get_assertion(&hash[0], "rp", NERO_NFC_NULL, 0u,
                                             &cbor[0], sizeof(cbor),
                                             NERO_NFC_NULL));
}

TEST(NfcCtapCodec, ClearsOutputsOnRejectedPublicHelpers) {
  uint8_t hash[kTestLit32]{};
  uint8_t apdu[kTestLit16]{};
  uint8_t cbor[kTestLit8]{};
  const uint8_t kBadResponse[] = {0x00u, 0x01u, 0x63u, 0x00u};
  uint16_t len = kTestLit0xBeeFu;
  bool add_le = true;
  uint8_t cmd = kTestLit0xA5u;
  nfc_ctap_fido_app_select_variant_t variant{.aid = &NFC_CTAP_FIDO_AID[0],
                                             .aid_len = NFC_CTAP_FIDO_AID_LEN,
                                             .p2 = kTestLit0x0Cu,
                                             .add_le_00 = true};
  nfc_ctap_fido_webauthn_select_step_t step{
      .variant_index = 1u,
      .prep = NFC_CTAP_FIDO_SELECT_PREP_RECOVER,
      .log_before_prep = kTestLit2u};

  EXPECT_FALSE(nfc_ctap_encode_get_assertion(&hash[0], "", NERO_NFC_NULL, 0u,
                                             &cbor[0], sizeof(cbor), &len));
  EXPECT_EQ(len, 0u);

  len = kTestLit0xBeeFu;
  EXPECT_FALSE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_GET_INFO, NERO_NFC_NULL, 1u,
                                       false, &apdu[0], sizeof(apdu), &len));
  EXPECT_EQ(len, 0u);

  len = kTestLit0xBeeFu;
  EXPECT_FALSE(nfc_ctap_pack_select_fido_apdu(true, &apdu[0], 1u, &len));
  EXPECT_EQ(len, 0u);

  EXPECT_FALSE(nfc_ctap_apdu_is_select_fido_aid(NERO_NFC_NULL, 0u, &add_le));
  EXPECT_FALSE(add_le);

  EXPECT_FALSE(nfc_ctap_apdu_command(NERO_NFC_NULL, 0u, &cmd));
  EXPECT_EQ(cmd, 0u);

  len = kTestLit0xBeeFu;
  EXPECT_FALSE(nfc_ctap_dissect_response(&kBadResponse[0], sizeof(kBadResponse),
                                         NERO_NFC_NULL, 0u, &len));
  EXPECT_EQ(len, 0u);

  EXPECT_FALSE(
      nfc_ctap_response_more_data(&kBadResponse[0], sizeof(kBadResponse)));

  EXPECT_FALSE(nfc_ctap_fido_app_select_variant(
      NFC_CTAP_FIDO_APP_SELECT_VARIANT_COUNT, &variant));
  EXPECT_EQ(variant.aid, NERO_NFC_NULL);
  EXPECT_EQ(variant.aid_len, 0u);

  variant = {.aid = &NFC_CTAP_FIDO_AID[0],
             .aid_len = NFC_CTAP_FIDO_AID_LEN,
             .p2 = kTestLit0x0Cu,
             .add_le_00 = true};
  EXPECT_FALSE(nfc_ctap_fido_app_select_variant_match(0xFFu, false, &variant));
  EXPECT_EQ(variant.aid, NERO_NFC_NULL);
  EXPECT_EQ(variant.aid_len, 0u);

  EXPECT_FALSE(nfc_ctap_fido_webauthn_select_step(
      NFC_CTAP_FIDO_WEBAUTHN_SELECT_STEP_COUNT, &step));
  EXPECT_EQ(step.variant_index, 0u);
  EXPECT_EQ(step.prep, NFC_CTAP_FIDO_SELECT_PREP_NONE);
  EXPECT_EQ(step.log_before_prep, 0u);
}

TEST(NfcCtapCodec, RejectsUnterminatedOrOversizedRpIds) {
  uint8_t hash[kTestLit32]{};
  uint8_t cbor[kCborScratchLargeCap];
  uint16_t len = 0;
  char rp_id[NFC_CTAP_RP_ID_MAX + 1u];

  for (char& i : rp_id) {
    i = 'a';
  }

  EXPECT_FALSE(nfc_ctap_encode_get_assertion(&hash[0], &rp_id[0], NERO_NFC_NULL,
                                             0u, &cbor[0], sizeof(cbor), &len));

  rp_id[NFC_CTAP_RP_ID_MAX] = '\0';
  EXPECT_TRUE(nfc_ctap_encode_get_assertion(&hash[0], &rp_id[0], NERO_NFC_NULL,
                                            0u, &cbor[0], sizeof(cbor), &len));

  rp_id[NFC_CTAP_RP_ID_MAX] = 'b';
  EXPECT_FALSE(nfc_ctap_encode_get_assertion(&hash[0], &rp_id[0], NERO_NFC_NULL,
                                             0u, &cbor[0], sizeof(cbor), &len));
}

TEST(NfcCtapCodec, RejectsTinyGetAssertionOutputBufferBeforeWriting) {
  uint8_t hash[kTestLit32]{};
  uint8_t cbor[kTestLit8]{kTestLit0xEEu, kTestLit0xEEu, kTestLit0xEEu,
                          kTestLit0xEEu, kTestLit0xEEu, kTestLit0xEEu,
                          kTestLit0xEEu, kTestLit0xEEu};
  uint16_t len = 0;

  EXPECT_FALSE(nfc_ctap_encode_get_assertion(&hash[0], "example.com",
                                             NERO_NFC_NULL, 0u, &cbor[0],
                                             sizeof(cbor), &len));
  EXPECT_EQ(cbor[0], 0xEEu);
}

TEST(NfcCtapCodec, PacksShortCtapApdu) {
  const uint8_t kCbor[] = {0xA1u, 0x01u, 0x02u, 0x03u};
  uint8_t apdu[kTestLit32];
  uint16_t apdu_len = 0;

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_GET_ASSERTION, &kCbor[0],
                                      sizeof(kCbor), false, &apdu[0],
                                      sizeof(apdu), &apdu_len));

  ASSERT_EQ(apdu_len, 11u);
  EXPECT_EQ(apdu[0], 0x80u);
  EXPECT_EQ(apdu[1], 0x10u);
  EXPECT_EQ(apdu[4], 0x05u); /* LC = cbor + cmd */
  EXPECT_EQ(apdu[5], NFC_CTAP_CMD_GET_ASSERTION);
  EXPECT_EQ(std::span{apdu}[6], 0xA1u);
  EXPECT_EQ(std::span{apdu}[apdu_len - 1u], 0x00u);
}

TEST(NfcCtapCodec, PacksCommandOnlyCtapApdu) {
  uint8_t apdu[kTestLit8];
  uint16_t apdu_len = 0;
  uint8_t cmd = 0u;

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_GET_INFO, NERO_NFC_NULL, 0u,
                                      false, &apdu[0], sizeof(apdu),
                                      &apdu_len));

  ASSERT_EQ(apdu_len, 7u);
  EXPECT_EQ(apdu[0], 0x80u);
  EXPECT_EQ(apdu[1], 0x10u);
  EXPECT_EQ(apdu[4], 0x01u);
  EXPECT_EQ(apdu[5], NFC_CTAP_CMD_GET_INFO);
  EXPECT_EQ(apdu[6], 0x00u);
  ASSERT_TRUE(nfc_ctap_apdu_command(&apdu[0], apdu_len, &cmd));
  EXPECT_EQ(cmd, NFC_CTAP_CMD_GET_INFO);
}

TEST(NfcCtapCodec, RejectsOverflowingCborLength) {
  const uint8_t kCbor[] = {0xA1u};
  uint8_t apdu[kTestLit32];
  uint16_t apdu_len = 0;

  EXPECT_FALSE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_GET_ASSERTION, &kCbor[0],
                                       UINT16_MAX, false, &apdu[0],
                                       sizeof(apdu), &apdu_len));
}

TEST(NfcCtapCodec, PacksExtendedCtapApduWhenForced) {
  uint8_t cbor[kExtendedCborCap]{};
  cbor[0] = kTestLit0x40u;
  uint8_t apdu[kExtendedApduScratchCap];
  uint16_t apdu_len = 0;

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_MAKE_CREDENTIAL, &cbor[0],
                                      sizeof(cbor), true, &apdu[0],
                                      sizeof(apdu), &apdu_len));

  EXPECT_EQ(apdu[4], 0x00u);
  EXPECT_EQ(apdu[5], 0x01u);
  EXPECT_EQ(apdu[6], 0x05u); /* 260 + 1 */
  EXPECT_EQ(std::span{apdu}[7], NFC_CTAP_CMD_MAKE_CREDENTIAL);
  EXPECT_EQ(std::span{apdu}[apdu_len - 2u], 0x00u);
  EXPECT_EQ(std::span{apdu}[apdu_len - 1u], 0x00u);
}

TEST(NfcCtapCodec, PacksSelectFidoApduWithOptionalLe) {
  uint8_t apdu[kTestLit16];
  uint16_t apdu_len = 0;
  bool add_le_00 = false;

  ASSERT_TRUE(
      nfc_ctap_pack_select_fido_apdu(false, &apdu[0], sizeof(apdu), &apdu_len));
  EXPECT_EQ(apdu_len, 13u);
  EXPECT_EQ(apdu[1], 0xA4u);
  EXPECT_EQ(apdu[4], NFC_CTAP_FIDO_AID_LEN);
  ASSERT_TRUE(nfc_ctap_apdu_is_select_fido_aid(&apdu[0], apdu_len, &add_le_00));
  EXPECT_FALSE(add_le_00);

  apdu_len = 0;
  ASSERT_TRUE(
      nfc_ctap_pack_select_fido_apdu(true, &apdu[0], sizeof(apdu), &apdu_len));
  EXPECT_EQ(apdu_len, 14u);
  EXPECT_EQ(std::span{apdu}[apdu_len - 1u], 0x00u);
  ASSERT_TRUE(nfc_ctap_apdu_is_select_fido_aid(&apdu[0], apdu_len, &add_le_00));
  EXPECT_TRUE(add_le_00);
}

TEST(NfcCtapCodec, RecognizesFidoSelectP2NoFciVariant) {
  const uint8_t kSelectNoFciNoLe[] = {0x00u, 0xA4u, 0x04u, 0x0Cu, 0x08u,
                                      0xA0u, 0x00u, 0x00u, 0x06u, 0x47u,
                                      0x2Fu, 0x00u, 0x01u};
  const uint8_t kSelectNoFciLe[] = {0x00u, 0xA4u, 0x04u, 0x0Cu, 0x08u,
                                    0xA0u, 0x00u, 0x00u, 0x06u, 0x47u,
                                    0x2Fu, 0x00u, 0x01u, 0x00u};
  bool add_le_00 = true;

  ASSERT_TRUE(nfc_ctap_apdu_is_select_fido_aid(
      &kSelectNoFciNoLe[0], sizeof(kSelectNoFciNoLe), &add_le_00));
  EXPECT_FALSE(add_le_00);

  ASSERT_TRUE(nfc_ctap_apdu_is_select_fido_aid(
      &kSelectNoFciLe[0], sizeof(kSelectNoFciLe), &add_le_00));
  EXPECT_TRUE(add_le_00);
}

TEST(NfcCtapCodec, RejectsMalformedSelectFidoApdus) {
  uint8_t apdu[kTestLit16];
  uint16_t apdu_len = 0;

  ASSERT_TRUE(
      nfc_ctap_pack_select_fido_apdu(true, &apdu[0], sizeof(apdu), &apdu_len));
  EXPECT_FALSE(nfc_ctap_apdu_is_select_fido_aid(
      &apdu[0], static_cast<uint16_t>(apdu_len - 2u), NERO_NFC_NULL));

  apdu[kTestLit4] = kTestLit7u;
  EXPECT_FALSE(
      nfc_ctap_apdu_is_select_fido_aid(&apdu[0], apdu_len, NERO_NFC_NULL));

  ASSERT_TRUE(
      nfc_ctap_pack_select_fido_apdu(true, &apdu[0], sizeof(apdu), &apdu_len));
  apdu[kTestLit5 + NFC_CTAP_FIDO_AID_LEN] = 0x01u;
  EXPECT_FALSE(
      nfc_ctap_apdu_is_select_fido_aid(&apdu[0], apdu_len, NERO_NFC_NULL));
}

TEST(NfcCtapCodec, IdentifiesCtapApduCommandLayouts) {
  const uint8_t kCbor[] = {0xA1u, 0x01u, 0x02u};
  uint8_t apdu[kTestLit32];
  uint16_t apdu_len = 0;
  uint8_t cmd = 0u;

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_GET_INFO, &kCbor[0],
                                      sizeof(kCbor), false, &apdu[0],
                                      sizeof(apdu), &apdu_len));
  ASSERT_TRUE(nfc_ctap_apdu_command(&apdu[0], apdu_len, &cmd));
  EXPECT_EQ(cmd, NFC_CTAP_CMD_GET_INFO);

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_MAKE_CREDENTIAL, &kCbor[0],
                                      sizeof(kCbor), true, &apdu[0],
                                      sizeof(apdu), &apdu_len));
  ASSERT_TRUE(nfc_ctap_apdu_command(&apdu[0], apdu_len, &cmd));
  EXPECT_EQ(cmd, NFC_CTAP_CMD_MAKE_CREDENTIAL);

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_CLIENT_PIN, &kCbor[0],
                                      sizeof(kCbor), false, &apdu[0],
                                      sizeof(apdu), &apdu_len));
  ASSERT_TRUE(nfc_ctap_apdu_command(&apdu[0], apdu_len, &cmd));
  EXPECT_EQ(cmd, NFC_CTAP_CMD_CLIENT_PIN);

  ASSERT_TRUE(nfc_ctap_apdu_command(
      &apdu[0], static_cast<uint16_t>(apdu_len - 1u), &cmd));
  EXPECT_EQ(cmd, NFC_CTAP_CMD_CLIENT_PIN);

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_GET_ASSERTION, &kCbor[0],
                                      sizeof(kCbor), true, &apdu[0],
                                      sizeof(apdu), &apdu_len));
  ASSERT_TRUE(nfc_ctap_apdu_command(&apdu[0], apdu_len, &cmd));
  EXPECT_EQ(cmd, NFC_CTAP_CMD_GET_ASSERTION);
  EXPECT_EQ(apdu[2], NFC_CTAP_P1_GETRESPONSE_SUPPORTED);

  ASSERT_TRUE(nfc_ctap_apdu_command(
      &apdu[0], static_cast<uint16_t>(apdu_len - 2u), &cmd));
  EXPECT_EQ(cmd, NFC_CTAP_CMD_GET_ASSERTION);

  apdu[kTestLit2] = kTestLit0x80u; /* CTAP NFC P1 bit: client supports
                                        NFCCTAP_GETRESPONSE. */
  ASSERT_TRUE(nfc_ctap_apdu_command(&apdu[0], apdu_len, &cmd));
  EXPECT_EQ(cmd, NFC_CTAP_CMD_GET_ASSERTION);

  const uint8_t kExtendedGetInfoNoLe[] = {
      0x80u, 0x10u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u, NFC_CTAP_CMD_GET_INFO};
  ASSERT_TRUE(nfc_ctap_apdu_command(&kExtendedGetInfoNoLe[0],
                                    sizeof(kExtendedGetInfoNoLe), &cmd));
  EXPECT_EQ(cmd, NFC_CTAP_CMD_GET_INFO);
}

TEST(NfcCtapCodec, ClassifiesOnlyCtapCommandApdus) {
  const uint8_t kCbor[] = {0xA1u, 0x01u, 0x02u};
  const uint8_t kNdefSelect[] = {0x00u, 0xA4u, 0x04u, 0x00u, 0x07u,
                                 0xD2u, 0x76u, 0x00u, 0x00u, 0x85u,
                                 0x01u, 0x01u, 0x00u};
  const uint8_t kRawReadBinary[] = {0x00u, 0xB0u, 0x00u, 0x00u, 0x10u};
  uint8_t apdu[kTestLit32];
  uint16_t apdu_len = 0;
  uint8_t cmd = 0u;
  bool add_le_00 = false;

  ASSERT_TRUE(
      nfc_ctap_pack_select_fido_apdu(true, &apdu[0], sizeof(apdu), &apdu_len));
  EXPECT_TRUE(nfc_ctap_apdu_is_select_fido_aid(&apdu[0], apdu_len, &add_le_00));
  EXPECT_FALSE(nfc_ctap_apdu_command(&apdu[0], apdu_len, &cmd));

  EXPECT_FALSE(nfc_ctap_apdu_is_select_fido_aid(
      &kNdefSelect[0], sizeof(kNdefSelect), NERO_NFC_NULL));
  EXPECT_FALSE(
      nfc_ctap_apdu_command(&kNdefSelect[0], sizeof(kNdefSelect), &cmd));
  EXPECT_FALSE(
      nfc_ctap_apdu_command(&kRawReadBinary[0], sizeof(kRawReadBinary), &cmd));

  const uint8_t kControlEnd[] = {0x80u, NFC_CTAP_INS_CONTROL,
                                 NFC_CTAP_P1_CONTROL_END, 0x00u};
  EXPECT_TRUE(
      nfc_ctap_apdu_is_control_end(&kControlEnd[0], sizeof(kControlEnd)));
  EXPECT_FALSE(
      nfc_ctap_apdu_command(&kControlEnd[0], sizeof(kControlEnd), &cmd));

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_GET_ASSERTION, &kCbor[0],
                                      sizeof(kCbor), false, &apdu[0],
                                      sizeof(apdu), &apdu_len));
  ASSERT_TRUE(nfc_ctap_apdu_command(&apdu[0], apdu_len, &cmd));
  EXPECT_EQ(cmd, NFC_CTAP_CMD_GET_ASSERTION);
}

TEST(NfcCtapCodec, RejectsIncompleteOrOverlongCtapApduLayouts) {
  const uint8_t kCbor[] = {0xA1u, 0x01u, 0x02u};
  uint8_t apdu[kTestLit32];
  uint16_t apdu_len = 0;
  uint8_t cmd = 0u;

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_GET_INFO, &kCbor[0],
                                      sizeof(kCbor), false, &apdu[0],
                                      sizeof(apdu), &apdu_len));
  EXPECT_FALSE(nfc_ctap_apdu_command(std::span<uint8_t>{apdu}.data(),
                                     static_cast<uint16_t>(apdu_len - 2u),
                                     &cmd));
  (void)nero_nfc_store_u8(&apdu[0], sizeof(apdu), apdu_len, 0x00u);
  EXPECT_FALSE(nfc_ctap_apdu_command(
      &apdu[0], static_cast<uint16_t>(apdu_len + 1u), &cmd));

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_CLIENT_PIN, &kCbor[0],
                                      sizeof(kCbor), true, &apdu[0],
                                      sizeof(apdu), &apdu_len));
  EXPECT_FALSE(nfc_ctap_apdu_command(std::span<uint8_t>{apdu}.data(),
                                     static_cast<uint16_t>(apdu_len - 3u),
                                     &cmd));
  (void)nero_nfc_store_u8(&apdu[0], sizeof(apdu), apdu_len, 0x00u);
  EXPECT_FALSE(nfc_ctap_apdu_command(
      &apdu[0], static_cast<uint16_t>(apdu_len + 1u), &cmd));

  const uint8_t kZeroLcShort[] = {0x80u, 0x10u, 0x00u, 0x00u, 0x00u};
  EXPECT_FALSE(
      nfc_ctap_apdu_command(&kZeroLcShort[0], sizeof(kZeroLcShort), &cmd));

  const uint8_t kZeroLcExtended[] = {0x80u, 0x10u, 0x00u, 0x00u, 0x00u,
                                     0x00u, 0x00u, 0x00u, 0x00u};
  EXPECT_FALSE(nfc_ctap_apdu_command(&kZeroLcExtended[0],
                                     sizeof(kZeroLcExtended), &cmd));

  const uint8_t kWrappedExtendedLc[] = {
      0x80u, 0x10u, 0x00u, 0x00u, 0x00u, 0xFFu, 0xFFu, NFC_CTAP_CMD_GET_INFO};
  EXPECT_FALSE(nfc_ctap_apdu_command(&kWrappedExtendedLc[0],
                                     sizeof(kWrappedExtendedLc), &cmd));

  const uint8_t kP1Rfu[] = {0x80u, 0x10u, 0x01u,
                            0x00u, 0x01u, NFC_CTAP_CMD_GET_INFO};
  EXPECT_FALSE(nfc_ctap_apdu_command(&kP1Rfu[0], sizeof(kP1Rfu), &cmd));
  const uint8_t kP2Rfu[] = {0x80u, 0x10u, 0x00u,
                            0x01u, 0x01u, NFC_CTAP_CMD_GET_INFO};
  EXPECT_FALSE(nfc_ctap_apdu_command(&kP2Rfu[0], sizeof(kP2Rfu), &cmd));
}

TEST(NfcCtapCodec, RelayResponseDispositionPassesThroughCompliantStatusWords) {
  /* [CTAP2.3] §11.3.5.2 — 9000 success and 61xx/91xx status-update relay
   * verbatim. */
  const uint8_t kSuccess[] = {0x00u, 0xA1u, 0x90u, 0x00u};
  const uint8_t kGetresponseContinuation[] = {0x91u, 0x00u};
  const uint8_t kIsoMoreData[] = {0x61u, 0x1Au};
  const uint8_t kErrorStatusRelayed[] = {
      0x14u, 0x69u, 0x01u}; /* CTAP err + warning, status!=0 */

  EXPECT_EQ(nfc_ctap_relay_response_disposition(&kSuccess[0], sizeof(kSuccess)),
            NFC_CTAP_RELAY_PASSTHROUGH);
  EXPECT_EQ(nfc_ctap_relay_response_disposition(
                &kGetresponseContinuation[0], sizeof(kGetresponseContinuation)),
            NFC_CTAP_RELAY_PASSTHROUGH);
  EXPECT_EQ(nfc_ctap_relay_response_disposition(&kIsoMoreData[0],
                                                sizeof(kIsoMoreData)),
            NFC_CTAP_RELAY_PASSTHROUGH);
  EXPECT_EQ(nfc_ctap_relay_response_disposition(&kErrorStatusRelayed[0],
                                                sizeof(kErrorStatusRelayed)),
            NFC_CTAP_RELAY_PASSTHROUGH);
}

TEST(NfcCtapCodec,
     RelayResponseDispositionFailsClosedWithoutSynthesizingSuccess) {
  /* [CTAP2.3] §11.3.5.2 — a transparent relay never appends/synthesizes 9000.
   */
  const uint8_t kNoStatusWord[] = {0x2Eu};          /* 1 byte: no SW at all */
  const uint8_t kStatuslessBody[] = {0x00u, 0xA1u}; /* misreads as SW 0x00A1 */
  const uint8_t kHardError[] = {0x00u, 0xA1u, 0x6Au,
                                0x82u}; /* CTAP success + warning = bad */
  const uint8_t kWarningSuccessConflict[] = {0x00u, 0xA1u, 0x63u, 0x00u};

  EXPECT_EQ(nfc_ctap_relay_response_disposition(&kNoStatusWord[0],
                                                sizeof(kNoStatusWord)),
            NFC_CTAP_RELAY_FAIL_CLOSED);
  EXPECT_EQ(nfc_ctap_relay_response_disposition(&kStatuslessBody[0],
                                                sizeof(kStatuslessBody)),
            NFC_CTAP_RELAY_FAIL_CLOSED);
  EXPECT_EQ(
      nfc_ctap_relay_response_disposition(&kHardError[0], sizeof(kHardError)),
      NFC_CTAP_RELAY_FAIL_CLOSED);
  EXPECT_EQ(nfc_ctap_relay_response_disposition(
                &kWarningSuccessConflict[0], sizeof(kWarningSuccessConflict)),
            NFC_CTAP_RELAY_FAIL_CLOSED);
  EXPECT_EQ(nfc_ctap_relay_response_disposition(NERO_NFC_NULL, 4u),
            NFC_CTAP_RELAY_FAIL_CLOSED);
}

TEST(NfcCtapCodec, MarksOnlyLongRunningFidoApdusForCcidTimeExtension) {
  const uint8_t kCbor[] = {0xA1u, 0x01u, 0x02u};
  uint8_t apdu[kTestLit32];
  uint16_t apdu_len = 0;
  uint8_t cmd = 0u;

  ASSERT_TRUE(
      nfc_ctap_pack_select_fido_apdu(true, &apdu[0], sizeof(apdu), &apdu_len));
  EXPECT_TRUE(nfc_ctap_apdu_needs_ccid_time_extension(&apdu[0], apdu_len));

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_MAKE_CREDENTIAL, &kCbor[0],
                                      sizeof(kCbor), false, &apdu[0],
                                      sizeof(apdu), &apdu_len));
  EXPECT_TRUE(nfc_ctap_apdu_needs_ccid_time_extension(&apdu[0], apdu_len));

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_GET_ASSERTION, &kCbor[0],
                                      sizeof(kCbor), false, &apdu[0],
                                      sizeof(apdu), &apdu_len));
  EXPECT_TRUE(nfc_ctap_apdu_needs_ccid_time_extension(&apdu[0], apdu_len));

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_GET_INFO, &kCbor[0],
                                      sizeof(kCbor), false, &apdu[0],
                                      sizeof(apdu), &apdu_len));
  EXPECT_FALSE(nfc_ctap_apdu_needs_ccid_time_extension(&apdu[0], apdu_len));

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_CLIENT_PIN, &kCbor[0],
                                      sizeof(kCbor), false, &apdu[0],
                                      sizeof(apdu), &apdu_len));
  EXPECT_TRUE(nfc_ctap_apdu_needs_ccid_time_extension(&apdu[0], apdu_len));

  const uint8_t kGetresponse[] = {0x80u, NFC_CTAP_INS_GETRESPONSE, 0x00u,
                                  0x00u};
  EXPECT_TRUE(
      nfc_ctap_apdu_is_getresponse(&kGetresponse[0], sizeof(kGetresponse)));
  EXPECT_TRUE(nfc_ctap_apdu_needs_ccid_time_extension(&kGetresponse[0],
                                                      sizeof(kGetresponse)));
  EXPECT_FALSE(
      nfc_ctap_apdu_command(&kGetresponse[0], sizeof(kGetresponse), &cmd));

  const uint8_t kGetresponseCancel[] = {0x80u, NFC_CTAP_INS_GETRESPONSE,
                                        NFC_CTAP_P1_GETRESPONSE_CANCEL, 0x00u};
  EXPECT_TRUE(nfc_ctap_apdu_is_getresponse(&kGetresponseCancel[0],
                                           sizeof(kGetresponseCancel)));
  EXPECT_TRUE(nfc_ctap_apdu_needs_ccid_time_extension(
      &kGetresponseCancel[0], sizeof(kGetresponseCancel)));
}

TEST(NfcCtapCodec, DetectsNfcCtap9100ContinuationStatus) {
  const uint8_t kContinuation[] = {0x01u, 0x02u, 0x91u, 0x00u};
  const uint8_t kNonContinuation[] = {0x01u, 0x02u, 0x91u, 0x40u};
  const uint8_t kComplete[] = {0x01u, 0x02u, 0x90u, 0x00u};

  EXPECT_TRUE(nfc_ctap_response_more_data(&kContinuation[0], 4));
  /* [CTAP2.3] §11.3.7.2 — only exactly 0x9100 is a continuation, not other
   * 0x91xx. */
  EXPECT_FALSE(nfc_ctap_response_more_data(&kNonContinuation[0], 4));
  EXPECT_FALSE(nfc_ctap_response_more_data(&kComplete[0], 4));
  EXPECT_FALSE(nfc_ctap_response_more_data(&kComplete[0], 2));
}

TEST(NfcCtapCodec, RecognizesControlEndApduPerSection1134) {
  const uint8_t kEndNoLe[] = {0x80u, NFC_CTAP_INS_CONTROL,
                              NFC_CTAP_P1_CONTROL_END, 0x00u};
  const uint8_t kEndWithLe[] = {0x80u, NFC_CTAP_INS_CONTROL,
                                NFC_CTAP_P1_CONTROL_END, 0x00u, 0x00u};
  const uint8_t kWrongP1[] = {0x80u, NFC_CTAP_INS_CONTROL, 0x00u, 0x00u};

  EXPECT_TRUE(nfc_ctap_apdu_is_control_end(&kEndNoLe[0], sizeof(kEndNoLe)));
  EXPECT_TRUE(nfc_ctap_apdu_is_control_end(&kEndWithLe[0], sizeof(kEndWithLe)));
  EXPECT_FALSE(nfc_ctap_apdu_is_control_end(&kWrongP1[0], sizeof(kWrongP1)));
  EXPECT_FALSE(nfc_ctap_apdu_is_control_end(NERO_NFC_NULL, 0u));
  EXPECT_FALSE(
      nfc_ctap_apdu_needs_ccid_time_extension(&kEndNoLe[0], sizeof(kEndNoLe)));
}

TEST(NfcCtapCodec, DissectsSuccessfulCtapResponse) {
  const uint8_t kRaw[] = {0x00u, 0xA1u, 0x01u, 0x02u, 0x90u, 0x00u};
  uint8_t inner[kTestLit8];
  uint16_t inner_len = 0;

  ASSERT_TRUE(nfc_ctap_dissect_response(&kRaw[0], sizeof(kRaw), &inner[0],
                                        sizeof(inner), &inner_len));
  EXPECT_EQ(inner_len, 3u);
  EXPECT_EQ(inner[0], 0xA1u);
}

TEST(NfcCtapCodec, RejectsBadCtapResponseStatusWords) {
  const uint8_t kRawSw[] = {0x00u, 0x01u, 0x02u, 0x63u, 0x00u};
  const uint8_t kRawCtap[] = {0x01u, 0x02u, 0x90u, 0x00u};
  const uint8_t kRawSwOnly[] = {0x90u, 0x00u};
  uint16_t inner_len = 0;

  EXPECT_FALSE(nfc_ctap_dissect_response(&kRawSw[0], sizeof(kRawSw),
                                         NERO_NFC_NULL, 0u, &inner_len));
  EXPECT_FALSE(nfc_ctap_dissect_response(&kRawCtap[0], sizeof(kRawCtap),
                                         NERO_NFC_NULL, 0u, &inner_len));
  EXPECT_FALSE(nfc_ctap_dissect_response(&kRawSwOnly[0], sizeof(kRawSwOnly),
                                         NERO_NFC_NULL, 0u, &inner_len));
}

TEST(NfcCtapCodec, EncodeThenPackRoundTripMatchesShortApduLayout) {
  uint8_t hash[kTestLit32]{};
  uint8_t cbor[kCborScratchSmallCap];
  uint16_t cbor_len = 0;
  uint8_t apdu[kShortApduRoundTripCap];
  uint16_t apdu_len = 0;

  ASSERT_TRUE(nfc_ctap_encode_get_assertion(&hash[0], "localhost",
                                            NERO_NFC_NULL, 0u, &cbor[0],
                                            sizeof(cbor), &cbor_len));
  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_GET_ASSERTION, &cbor[0],
                                      cbor_len, false, &apdu[0], sizeof(apdu),
                                      &apdu_len));
  EXPECT_EQ(apdu[5], NFC_CTAP_CMD_GET_ASSERTION);
  EXPECT_EQ(apdu[4], static_cast<uint8_t>(cbor_len + 1u));
  EXPECT_EQ(std::memcmp(std::span{apdu}.subspan(6u, cbor_len).data(), &cbor[0],
                        cbor_len),
            0);
}

TEST(NfcCtapCodec, FidoAppSelectVariantTableMatchesExpectedOrder) {
  nfc_ctap_fido_app_select_variant_t variant{};

  ASSERT_TRUE(nfc_ctap_fido_app_select_variant(0u, &variant));
  EXPECT_EQ(variant.aid, NFC_CTAP_FIDO_AID);
  EXPECT_EQ(variant.aid_len, NFC_CTAP_FIDO_AID_LEN);
  EXPECT_EQ(variant.p2, 0x00u);
  EXPECT_FALSE(variant.add_le_00);
  ASSERT_TRUE(nfc_ctap_fido_app_select_variant(1u, &variant));
  EXPECT_EQ(variant.p2, 0x00u);
  EXPECT_TRUE(variant.add_le_00);
  ASSERT_TRUE(nfc_ctap_fido_app_select_variant(2u, &variant));
  EXPECT_EQ(variant.p2, 0x0Cu);
  EXPECT_FALSE(variant.add_le_00);
  ASSERT_TRUE(nfc_ctap_fido_app_select_variant(3u, &variant));
  EXPECT_EQ(variant.p2, 0x0Cu);
  EXPECT_TRUE(variant.add_le_00);
  EXPECT_FALSE(nfc_ctap_fido_app_select_variant(
      NFC_CTAP_FIDO_APP_SELECT_VARIANT_COUNT, &variant));
}

TEST(NfcCtapCodec, FidoAppSelectVariantMatchFindsTableEntry) {
  nfc_ctap_fido_app_select_variant_t variant{};

  ASSERT_TRUE(nfc_ctap_fido_app_select_variant_match(0x0Cu, true, &variant));
  EXPECT_EQ(variant.p2, 0x0Cu);
  EXPECT_TRUE(variant.add_le_00);
  EXPECT_FALSE(
      nfc_ctap_fido_app_select_variant_match(0x04u, false, NERO_NFC_NULL));
}

TEST(NfcCtapCodec, FidoWebAuthnSelectStepTableMatchesRecoverSettlePattern) {
  nfc_ctap_fido_webauthn_select_step_t step{};

  ASSERT_TRUE(nfc_ctap_fido_webauthn_select_step(0u, &step));
  EXPECT_EQ(step.variant_index, 1u);
  EXPECT_EQ(step.prep, NFC_CTAP_FIDO_SELECT_PREP_NONE);
  EXPECT_EQ(step.log_before_prep, 0u);
  ASSERT_TRUE(nfc_ctap_fido_webauthn_select_step(1u, &step));
  EXPECT_EQ(step.variant_index, 1u);
  EXPECT_EQ(step.prep, NFC_CTAP_FIDO_SELECT_PREP_RECOVER);
  EXPECT_EQ(step.log_before_prep, 1u);
  ASSERT_TRUE(nfc_ctap_fido_webauthn_select_step(2u, &step));
  EXPECT_EQ(step.variant_index, 0u);
  EXPECT_EQ(step.prep, NFC_CTAP_FIDO_SELECT_PREP_SETTLE);
  EXPECT_EQ(step.log_before_prep, 0u);
  ASSERT_TRUE(nfc_ctap_fido_webauthn_select_step(3u, &step));
  EXPECT_EQ(step.variant_index, 1u);
  EXPECT_EQ(step.prep, NFC_CTAP_FIDO_SELECT_PREP_RECOVER);
  EXPECT_EQ(step.log_before_prep, 2u);
  EXPECT_FALSE(nfc_ctap_fido_webauthn_select_step(
      NFC_CTAP_FIDO_WEBAUTHN_SELECT_STEP_COUNT, &step));
}
