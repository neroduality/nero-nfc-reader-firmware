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
  const uint8_t expected[NFC_CTAP_FIDO_AID_LEN] = {
      0xA0u, 0x00u, 0x00u, 0x06u, 0x47u, 0x2Fu, 0x00u, 0x01u,
  };
  EXPECT_EQ(std::memcmp(&NFC_CTAP_FIDO_AID[0], &expected[0], sizeof(expected)),
            0);
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
  uint8_t const hash[kTestLit32]{};
  const uint8_t cred[] = {0x01u, 0x02u, 0x03u, 0x04u};
  uint8_t cbor[kCborScratchMediumCap];
  uint16_t len = 0;

  ASSERT_TRUE(nfc_ctap_encode_get_assertion(&hash[0], "webauthn.io", &cred[0],
                                            sizeof(cred), &cbor[0],
                                            sizeof(cbor), &len));

  EXPECT_EQ(cbor[0], 0xA4u);
  EXPECT_NE(std::memchr(&cbor[0], 0x03u, len), NERO_NFC_NULL);
}

TEST(NfcCtapCodec, RejectsInvalidGetAssertionInputs) {
  uint8_t const hash[kTestLit32]{};
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
  uint8_t const hash[kTestLit32]{};
  uint8_t apdu[kTestLit16]{};
  uint8_t cbor[kTestLit8]{};
  const uint8_t bad_response[] = {0x00u, 0x01u, 0x63u, 0x00u};
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
  EXPECT_FALSE(nfc_ctap_dissect_response(&bad_response[0], sizeof(bad_response),
                                         NERO_NFC_NULL, 0u, &len));
  EXPECT_EQ(len, 0u);

  EXPECT_FALSE(
      nfc_ctap_response_more_data(&bad_response[0], sizeof(bad_response)));

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
  uint8_t const hash[kTestLit32]{};
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
  uint8_t const hash[kTestLit32]{};
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
  const uint8_t cbor[] = {0xA1u, 0x01u, 0x02u, 0x03u};
  uint8_t apdu[kTestLit32];
  uint16_t apdu_len = 0;

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_GET_ASSERTION, &cbor[0],
                                      sizeof(cbor), false, &apdu[0],
                                      sizeof(apdu), &apdu_len));

  ASSERT_EQ(apdu_len, 11u);
  EXPECT_EQ(apdu[0], 0x80u);
  EXPECT_EQ(apdu[1], 0x10u);
  EXPECT_EQ(apdu[4], 0x05u); /* LC = cbor + cmd */
  EXPECT_EQ(apdu[5], NFC_CTAP_CMD_GET_ASSERTION);
  EXPECT_EQ(nero_nfc_test::At(apdu, 6), 0xA1u);
  EXPECT_EQ(nero_nfc_test::At(apdu, apdu_len - 1u), 0x00u);
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
  const uint8_t cbor[] = {0xA1u};
  uint8_t apdu[kTestLit32];
  uint16_t apdu_len = 0;

  EXPECT_FALSE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_GET_ASSERTION, &cbor[0],
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
  EXPECT_EQ(nero_nfc_test::At(apdu, 7), NFC_CTAP_CMD_MAKE_CREDENTIAL);
  EXPECT_EQ(nero_nfc_test::At(apdu, apdu_len - 2u), 0x00u);
  EXPECT_EQ(nero_nfc_test::At(apdu, apdu_len - 1u), 0x00u);
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
  EXPECT_EQ(nero_nfc_test::At(apdu, apdu_len - 1u), 0x00u);
  ASSERT_TRUE(nfc_ctap_apdu_is_select_fido_aid(&apdu[0], apdu_len, &add_le_00));
  EXPECT_TRUE(add_le_00);
}

TEST(NfcCtapCodec, RecognizesFidoSelectP2NoFciVariant) {
  const uint8_t select_no_fci_no_le[] = {0x00u, 0xA4u, 0x04u, 0x0Cu, 0x08u,
                                         0xA0u, 0x00u, 0x00u, 0x06u, 0x47u,
                                         0x2Fu, 0x00u, 0x01u};
  const uint8_t select_no_fci_le[] = {0x00u, 0xA4u, 0x04u, 0x0Cu, 0x08u,
                                      0xA0u, 0x00u, 0x00u, 0x06u, 0x47u,
                                      0x2Fu, 0x00u, 0x01u, 0x00u};
  bool add_le_00 = true;

  ASSERT_TRUE(nfc_ctap_apdu_is_select_fido_aid(
      &select_no_fci_no_le[0], sizeof(select_no_fci_no_le), &add_le_00));
  EXPECT_FALSE(add_le_00);

  ASSERT_TRUE(nfc_ctap_apdu_is_select_fido_aid(
      &select_no_fci_le[0], sizeof(select_no_fci_le), &add_le_00));
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
  const uint8_t cbor[] = {0xA1u, 0x01u, 0x02u};
  uint8_t apdu[kTestLit32];
  uint16_t apdu_len = 0;
  uint8_t cmd = 0u;

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_GET_INFO, &cbor[0],
                                      sizeof(cbor), false, &apdu[0],
                                      sizeof(apdu), &apdu_len));
  ASSERT_TRUE(nfc_ctap_apdu_command(&apdu[0], apdu_len, &cmd));
  EXPECT_EQ(cmd, NFC_CTAP_CMD_GET_INFO);

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_MAKE_CREDENTIAL, &cbor[0],
                                      sizeof(cbor), true, &apdu[0],
                                      sizeof(apdu), &apdu_len));
  ASSERT_TRUE(nfc_ctap_apdu_command(&apdu[0], apdu_len, &cmd));
  EXPECT_EQ(cmd, NFC_CTAP_CMD_MAKE_CREDENTIAL);

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_CLIENT_PIN, &cbor[0],
                                      sizeof(cbor), false, &apdu[0],
                                      sizeof(apdu), &apdu_len));
  ASSERT_TRUE(nfc_ctap_apdu_command(&apdu[0], apdu_len, &cmd));
  EXPECT_EQ(cmd, NFC_CTAP_CMD_CLIENT_PIN);

  ASSERT_TRUE(nfc_ctap_apdu_command(
      &apdu[0], static_cast<uint16_t>(apdu_len - 1u), &cmd));
  EXPECT_EQ(cmd, NFC_CTAP_CMD_CLIENT_PIN);

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_GET_ASSERTION, &cbor[0],
                                      sizeof(cbor), true, &apdu[0],
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

  const uint8_t extended_get_info_no_le[] = {
      0x80u, 0x10u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u, NFC_CTAP_CMD_GET_INFO};
  ASSERT_TRUE(nfc_ctap_apdu_command(&extended_get_info_no_le[0],
                                    sizeof(extended_get_info_no_le), &cmd));
  EXPECT_EQ(cmd, NFC_CTAP_CMD_GET_INFO);
}

TEST(NfcCtapCodec, ClassifiesOnlyCtapCommandApdus) {
  const uint8_t cbor[] = {0xA1u, 0x01u, 0x02u};
  const uint8_t ndef_select[] = {0x00u, 0xA4u, 0x04u, 0x00u, 0x07u,
                                 0xD2u, 0x76u, 0x00u, 0x00u, 0x85u,
                                 0x01u, 0x01u, 0x00u};
  const uint8_t raw_read_binary[] = {0x00u, 0xB0u, 0x00u, 0x00u, 0x10u};
  uint8_t apdu[kTestLit32];
  uint16_t apdu_len = 0;
  uint8_t cmd = 0u;
  bool add_le_00 = false;

  ASSERT_TRUE(
      nfc_ctap_pack_select_fido_apdu(true, &apdu[0], sizeof(apdu), &apdu_len));
  EXPECT_TRUE(nfc_ctap_apdu_is_select_fido_aid(&apdu[0], apdu_len, &add_le_00));
  EXPECT_FALSE(nfc_ctap_apdu_command(&apdu[0], apdu_len, &cmd));

  EXPECT_FALSE(nfc_ctap_apdu_is_select_fido_aid(
      &ndef_select[0], sizeof(ndef_select), NERO_NFC_NULL));
  EXPECT_FALSE(
      nfc_ctap_apdu_command(&ndef_select[0], sizeof(ndef_select), &cmd));
  EXPECT_FALSE(nfc_ctap_apdu_command(&raw_read_binary[0],
                                     sizeof(raw_read_binary), &cmd));

  const uint8_t control_end[] = {0x80u, NFC_CTAP_INS_CONTROL,
                                 NFC_CTAP_P1_CONTROL_END, 0x00u};
  EXPECT_TRUE(
      nfc_ctap_apdu_is_control_end(&control_end[0], sizeof(control_end)));
  EXPECT_FALSE(
      nfc_ctap_apdu_command(&control_end[0], sizeof(control_end), &cmd));

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_GET_ASSERTION, &cbor[0],
                                      sizeof(cbor), false, &apdu[0],
                                      sizeof(apdu), &apdu_len));
  ASSERT_TRUE(nfc_ctap_apdu_command(&apdu[0], apdu_len, &cmd));
  EXPECT_EQ(cmd, NFC_CTAP_CMD_GET_ASSERTION);
}

TEST(NfcCtapCodec, RejectsIncompleteOrOverlongCtapApduLayouts) {
  const uint8_t cbor[] = {0xA1u, 0x01u, 0x02u};
  uint8_t apdu[kTestLit32];
  uint16_t apdu_len = 0;
  uint8_t cmd = 0u;

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_GET_INFO, &cbor[0],
                                      sizeof(cbor), false, &apdu[0],
                                      sizeof(apdu), &apdu_len));
  EXPECT_FALSE(nfc_ctap_apdu_command(std::span<uint8_t>{apdu}.data(),
                                     static_cast<uint16_t>(apdu_len - 2u),
                                     &cmd));
  (void)nero_nfc_store_u8(&apdu[0], sizeof(apdu), apdu_len, 0x00u);
  EXPECT_FALSE(nfc_ctap_apdu_command(
      &apdu[0], static_cast<uint16_t>(apdu_len + 1u), &cmd));

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_CLIENT_PIN, &cbor[0],
                                      sizeof(cbor), true, &apdu[0],
                                      sizeof(apdu), &apdu_len));
  EXPECT_FALSE(nfc_ctap_apdu_command(std::span<uint8_t>{apdu}.data(),
                                     static_cast<uint16_t>(apdu_len - 3u),
                                     &cmd));
  (void)nero_nfc_store_u8(&apdu[0], sizeof(apdu), apdu_len, 0x00u);
  EXPECT_FALSE(nfc_ctap_apdu_command(
      &apdu[0], static_cast<uint16_t>(apdu_len + 1u), &cmd));

  const uint8_t zero_lc_short[] = {0x80u, 0x10u, 0x00u, 0x00u, 0x00u};
  EXPECT_FALSE(
      nfc_ctap_apdu_command(&zero_lc_short[0], sizeof(zero_lc_short), &cmd));

  const uint8_t zero_lc_extended[] = {0x80u, 0x10u, 0x00u, 0x00u, 0x00u,
                                      0x00u, 0x00u, 0x00u, 0x00u};
  EXPECT_FALSE(nfc_ctap_apdu_command(&zero_lc_extended[0],
                                     sizeof(zero_lc_extended), &cmd));

  const uint8_t wrapped_extended_lc[] = {
      0x80u, 0x10u, 0x00u, 0x00u, 0x00u, 0xFFu, 0xFFu, NFC_CTAP_CMD_GET_INFO};
  EXPECT_FALSE(nfc_ctap_apdu_command(&wrapped_extended_lc[0],
                                     sizeof(wrapped_extended_lc), &cmd));

  const uint8_t p1_rfu[] = {0x80u, 0x10u, 0x01u,
                            0x00u, 0x01u, NFC_CTAP_CMD_GET_INFO};
  EXPECT_FALSE(nfc_ctap_apdu_command(&p1_rfu[0], sizeof(p1_rfu), &cmd));
  const uint8_t p2_rfu[] = {0x80u, 0x10u, 0x00u,
                            0x01u, 0x01u, NFC_CTAP_CMD_GET_INFO};
  EXPECT_FALSE(nfc_ctap_apdu_command(&p2_rfu[0], sizeof(p2_rfu), &cmd));
}

TEST(NfcCtapCodec, RelayResponseDispositionPassesThroughCompliantStatusWords) {
  /* [CTAP2.3] §11.3.5.2 -- 9000 success and 61xx/91xx status-update relay
   * verbatim. */
  const uint8_t success[] = {0x00u, 0xA1u, 0x90u, 0x00u};
  const uint8_t getresponse_continuation[] = {0x91u, 0x00u};
  const uint8_t iso_more_data[] = {0x61u, 0x1Au};
  const uint8_t error_status_relayed[] = {
      0x14u, 0x69u, 0x01u}; /* CTAP err + warning, status!=0 */

  EXPECT_EQ(nfc_ctap_relay_response_disposition(&success[0], sizeof(success)),
            NFC_CTAP_RELAY_PASSTHROUGH);
  EXPECT_EQ(nfc_ctap_relay_response_disposition(
                &getresponse_continuation[0], sizeof(getresponse_continuation)),
            NFC_CTAP_RELAY_PASSTHROUGH);
  EXPECT_EQ(nfc_ctap_relay_response_disposition(&iso_more_data[0],
                                                sizeof(iso_more_data)),
            NFC_CTAP_RELAY_PASSTHROUGH);
  EXPECT_EQ(nfc_ctap_relay_response_disposition(&error_status_relayed[0],
                                                sizeof(error_status_relayed)),
            NFC_CTAP_RELAY_PASSTHROUGH);
}

TEST(NfcCtapCodec,
     RelayResponseDispositionFailsClosedWithoutSynthesizingSuccess) {
  /* [CTAP2.3] §11.3.5.2 -- a transparent relay never appends/synthesizes 9000.
   */
  const uint8_t no_status_word[] = {0x2Eu};         /* 1 byte: no SW at all */
  const uint8_t statusless_body[] = {0x00u, 0xA1u}; /* misreads as SW 0x00A1 */
  const uint8_t hard_error[] = {0x00u, 0xA1u, 0x6Au,
                                0x82u}; /* CTAP success + warning = bad */
  const uint8_t warning_success_conflict[] = {0x00u, 0xA1u, 0x63u, 0x00u};

  EXPECT_EQ(nfc_ctap_relay_response_disposition(&no_status_word[0],
                                                sizeof(no_status_word)),
            NFC_CTAP_RELAY_FAIL_CLOSED);
  EXPECT_EQ(nfc_ctap_relay_response_disposition(&statusless_body[0],
                                                sizeof(statusless_body)),
            NFC_CTAP_RELAY_FAIL_CLOSED);
  EXPECT_EQ(
      nfc_ctap_relay_response_disposition(&hard_error[0], sizeof(hard_error)),
      NFC_CTAP_RELAY_FAIL_CLOSED);
  EXPECT_EQ(nfc_ctap_relay_response_disposition(
                &warning_success_conflict[0], sizeof(warning_success_conflict)),
            NFC_CTAP_RELAY_FAIL_CLOSED);
  EXPECT_EQ(nfc_ctap_relay_response_disposition(NERO_NFC_NULL, 4u),
            NFC_CTAP_RELAY_FAIL_CLOSED);
}

TEST(NfcCtapCodec, MarksOnlyLongRunningFidoApdusForCcidTimeExtension) {
  const uint8_t cbor[] = {0xA1u, 0x01u, 0x02u};
  uint8_t apdu[kTestLit32];
  uint16_t apdu_len = 0;
  uint8_t cmd = 0u;

  ASSERT_TRUE(
      nfc_ctap_pack_select_fido_apdu(true, &apdu[0], sizeof(apdu), &apdu_len));
  EXPECT_TRUE(nfc_ctap_apdu_needs_ccid_time_extension(&apdu[0], apdu_len));

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_MAKE_CREDENTIAL, &cbor[0],
                                      sizeof(cbor), false, &apdu[0],
                                      sizeof(apdu), &apdu_len));
  EXPECT_TRUE(nfc_ctap_apdu_needs_ccid_time_extension(&apdu[0], apdu_len));

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_GET_ASSERTION, &cbor[0],
                                      sizeof(cbor), false, &apdu[0],
                                      sizeof(apdu), &apdu_len));
  EXPECT_TRUE(nfc_ctap_apdu_needs_ccid_time_extension(&apdu[0], apdu_len));

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_GET_INFO, &cbor[0],
                                      sizeof(cbor), false, &apdu[0],
                                      sizeof(apdu), &apdu_len));
  EXPECT_FALSE(nfc_ctap_apdu_needs_ccid_time_extension(&apdu[0], apdu_len));

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_CLIENT_PIN, &cbor[0],
                                      sizeof(cbor), false, &apdu[0],
                                      sizeof(apdu), &apdu_len));
  EXPECT_TRUE(nfc_ctap_apdu_needs_ccid_time_extension(&apdu[0], apdu_len));

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_RESET, NERO_NFC_NULL, 0u,
                                      false, &apdu[0], sizeof(apdu),
                                      &apdu_len));
  EXPECT_TRUE(nfc_ctap_apdu_needs_ccid_time_extension(&apdu[0], apdu_len));

  const uint8_t getresponse[] = {0x80u, NFC_CTAP_INS_GETRESPONSE, 0x00u, 0x00u};
  EXPECT_TRUE(
      nfc_ctap_apdu_is_getresponse(&getresponse[0], sizeof(getresponse)));
  EXPECT_TRUE(nfc_ctap_apdu_needs_ccid_time_extension(&getresponse[0],
                                                      sizeof(getresponse)));
  EXPECT_FALSE(
      nfc_ctap_apdu_command(&getresponse[0], sizeof(getresponse), &cmd));

  const uint8_t getresponse_cancel[] = {0x80u, NFC_CTAP_INS_GETRESPONSE,
                                        NFC_CTAP_P1_GETRESPONSE_CANCEL, 0x00u};
  EXPECT_TRUE(nfc_ctap_apdu_is_getresponse(&getresponse_cancel[0],
                                           sizeof(getresponse_cancel)));
  EXPECT_TRUE(nfc_ctap_apdu_needs_ccid_time_extension(
      &getresponse_cancel[0], sizeof(getresponse_cancel)));
}

TEST(NfcCtapCodec, DetectsNfcCtap9100ContinuationStatus) {
  const uint8_t continuation[] = {0x01u, 0x02u, 0x91u, 0x00u};
  const uint8_t non_continuation[] = {0x01u, 0x02u, 0x91u, 0x40u};
  const uint8_t complete[] = {0x01u, 0x02u, 0x90u, 0x00u};

  EXPECT_TRUE(nfc_ctap_response_more_data(&continuation[0], 4));
  /* [CTAP2.3] §11.3.7.2 -- only exactly 0x9100 is a continuation, not other
   * 0x91xx. */
  EXPECT_FALSE(nfc_ctap_response_more_data(&non_continuation[0], 4));
  EXPECT_FALSE(nfc_ctap_response_more_data(&complete[0], 4));
  EXPECT_FALSE(nfc_ctap_response_more_data(&complete[0], 2));
}

TEST(NfcCtapCodec, RecognizesControlEndApduPerSection1134) {
  const uint8_t end_no_le[] = {0x80u, NFC_CTAP_INS_CONTROL,
                               NFC_CTAP_P1_CONTROL_END, 0x00u};
  const uint8_t end_with_le[] = {0x80u, NFC_CTAP_INS_CONTROL,
                                 NFC_CTAP_P1_CONTROL_END, 0x00u, 0x00u};
  const uint8_t wrong_p1[] = {0x80u, NFC_CTAP_INS_CONTROL, 0x00u, 0x00u};

  EXPECT_TRUE(nfc_ctap_apdu_is_control_end(&end_no_le[0], sizeof(end_no_le)));
  EXPECT_TRUE(
      nfc_ctap_apdu_is_control_end(&end_with_le[0], sizeof(end_with_le)));
  EXPECT_FALSE(nfc_ctap_apdu_is_control_end(&wrong_p1[0], sizeof(wrong_p1)));
  EXPECT_FALSE(nfc_ctap_apdu_is_control_end(NERO_NFC_NULL, 0u));
  EXPECT_FALSE(nfc_ctap_apdu_needs_ccid_time_extension(&end_no_le[0],
                                                       sizeof(end_no_le)));
}

TEST(NfcCtapCodec, DissectsSuccessfulCtapResponse) {
  const uint8_t raw[] = {0x00u, 0xA1u, 0x01u, 0x02u, 0x90u, 0x00u};
  uint8_t inner[kTestLit8];
  uint16_t inner_len = 0;

  ASSERT_TRUE(nfc_ctap_dissect_response(&raw[0], sizeof(raw), &inner[0],
                                        sizeof(inner), &inner_len));
  EXPECT_EQ(inner_len, 3u);
  EXPECT_EQ(inner[0], 0xA1u);
}

TEST(NfcCtapCodec, RejectsBadCtapResponseStatusWords) {
  const uint8_t raw_sw[] = {0x00u, 0x01u, 0x02u, 0x63u, 0x00u};
  const uint8_t raw_ctap[] = {0x01u, 0x02u, 0x90u, 0x00u};
  const uint8_t raw_sw_only[] = {0x90u, 0x00u};
  uint16_t inner_len = 0;

  EXPECT_FALSE(nfc_ctap_dissect_response(&raw_sw[0], sizeof(raw_sw),
                                         NERO_NFC_NULL, 0u, &inner_len));
  EXPECT_FALSE(nfc_ctap_dissect_response(&raw_ctap[0], sizeof(raw_ctap),
                                         NERO_NFC_NULL, 0u, &inner_len));
  EXPECT_FALSE(nfc_ctap_dissect_response(&raw_sw_only[0], sizeof(raw_sw_only),
                                         NERO_NFC_NULL, 0u, &inner_len));
}

TEST(NfcCtapCodec, EncodeThenPackRoundTripMatchesShortApduLayout) {
  uint8_t const hash[kTestLit32]{};
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
