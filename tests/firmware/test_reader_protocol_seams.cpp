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
#include "nfc_storage_ndef.h"
#include "nfc_tag_geometry_limits.h"
#include "reader_security_key_ccid_codec.h"
#include "reader_security_key_iso_dep_session.h"
#include "reader_ccid_protocol.h"
#include "reader_ccid_bulk_codec.h"
#include "reader_ccid_internal.h"
#include "reader_iso_dep_apdu_relay.h"
#include "reader_iso_dep_ats.h"
#include "reader_iso_dep_frame.h"
#include "reader_iso_dep_timing.h"
#include "reader_tags_internal.h"
#include "reader_tags_utest.h"

#include "nero_nfc_mem_util.h"

namespace {
enum {
  kTestLit0x00FFu = 0x00FFu,
  kTestLit0x01u = 0x01u,
  kTestLit0x02u = 0x02u,
  kTestLit0x03u = 0x03u,
  kTestLit0x04u = 0x04u,
  kTestLit0x10u = 0x10u,
  kTestLit0x11u = 0x11u,
  kTestLit0x12u = 0x12u,
  kTestLit0x13u = 0x13u,
  kTestLit0x14u = 0x14u,
  kTestLit0x15u = 0x15u,
  kTestLit0x16u = 0x16u,
  kTestLit0x17u = 0x17u,
  kTestLit0x22u = 0x22u,
  kTestLit0x33u = 0x33u,
  kTestLit0x40u = 0x40u,
  kTestLit0x44u = 0x44u,
  kTestLit0x61u = 0x61u,
  kTestLit0x7Fu = 0x7Fu,
  kTestLit0xA1u = 0xA1u,
  kTestLit0xA2u = 0xA2u,
  kTestLit0xABu = 0xABu,
  kTestLit0xFffFu = 0xFFFFu,
  kTestLit0xFFu = 0xFFu,
  kTestLit10 = 10,
  kTestLit12 = 12,
  kTestLit144u = 144u,
  kTestLit17 = 17,
  kTestLit18 = 18,
  kTestLit2 = 2,
  kTestLit20 = 20,
  kTestLit256u = 256u,
  kTestLit3 = 3,
  kTestLit32 = 32,
  kTestLit320u = 320u,
  kTestLit4 = 4,
  kTestLit5 = 5,
  kTestLit7 = 7,
  kTestLit7u = 7u,
  kTestLit8 = 8,
  kTestLit80u = 80u,
  kTestLit8u = 8u,
  kTestLit9 = 9,
};
}  // namespace

#include "nero_nfc_frontend.h"
#include "reader_context.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>

TEST(ReaderCcIdProtocol, EncodesT1ParametersResponse) {
  std::array<std::uint8_t, kTestLit20> buf{};
  ASSERT_TRUE(reader_ccid_encode_params_response(
      buf.data(), buf.size(), 0x82u, 0x44u, 0x00u, 0x00u, 0x01u, 0x01u));

  EXPECT_EQ(buf[0], 0x82u);
  EXPECT_EQ(buf[1], 7u);
  EXPECT_EQ(buf[6], 0x44u);
  EXPECT_EQ(buf[7], 0x00u);
  EXPECT_EQ(buf[8], 0x00u);
  EXPECT_EQ(buf[9], 0x01u);
  EXPECT_EQ(buf[10], 0x11u);
  EXPECT_EQ(buf[13], 0x4Du);
  EXPECT_EQ(buf[15], 0xFEu);
}

TEST(ReaderCcIdProtocol, RejectsUndersizedParametersResponseBuffer) {
  std::array<std::uint8_t, kTestLit12> buf{};

  EXPECT_FALSE(reader_ccid_encode_params_response(
      buf.data(), buf.size(), 0x82u, 0x44u, 0x00u, 0x00u, 0x01u, 0x01u));
}

TEST(ReaderCcIdProtocol, RejectsNonT1SetParameters) {
  std::array<std::uint8_t, kTestLit10> frame{};
  frame[0] = kTestLit0x61u;

  /* [CCID1.10] §6.2.6 — bError is the byte offset of the first offending field.
   * A wrong dwLength (bytes 1..4) reports offset 0x01, regardless of
   * bProtocolNum. */
  frame[kTestLit7] = 0x01u; /* bProtocolNum = T1 (correct) */
  EXPECT_EQ(reader_ccid_param_error_for_request(frame.data(), frame.size(),
                                                0x61u, 0x01u),
            0x01u);
  EXPECT_EQ(reader_ccid_param_icc_level(frame.data(), frame.size(), 0x00u,
                                        0x40u, 0x61u, 0x01u),
            0x40u);

  /* dwLength correct, bProtocolNum wrong: bError = offset of bProtocolNum
   * (0x07). */
  nfc_ccid_u32_store_le(&frame[1], kTestLit7u);
  frame[kTestLit7] = 0x00u;
  EXPECT_EQ(reader_ccid_param_error_for_request(frame.data(), frame.size(),
                                                0x61u, 0x01u),
            0x07u);

  /* All fields valid: no error. */
  frame[kTestLit7] = 0x01u;
  EXPECT_EQ(reader_ccid_param_error_for_request(frame.data(), frame.size(),
                                                0x61u, 0x01u),
            0u);
  EXPECT_EQ(reader_ccid_param_icc_level(frame.data(), frame.size(), 0x00u,
                                        0x40u, 0x61u, 0x01u),
            0x00u);

  /* abRFU[0] non-zero: bError = offset 0x08. */
  frame[kTestLit8] = 0x01u;
  EXPECT_EQ(reader_ccid_param_error_for_request(frame.data(), frame.size(),
                                                0x61u, 0x01u),
            0x08u);

  /* abRFU[1] non-zero: bError = offset 0x09. */
  frame[kTestLit8] = 0x00u;
  frame[kTestLit9] = 0x01u;
  EXPECT_EQ(reader_ccid_param_error_for_request(frame.data(), frame.size(),
                                                0x61u, 0x01u),
            0x09u);
}

TEST(ReaderCcIdProtocol, EncodesDataRateClockResponse) {
  std::array<std::uint8_t, kTestLit18> buf{};
  ASSERT_TRUE(reader_ccid_encode_data_rate_clock_response(
      buf.data(), buf.size(), 0x84u, 0x22u, 0x01u, 0u));

  EXPECT_EQ(buf[0], 0x84u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&buf[1]), 8u);
  EXPECT_EQ(buf[6], 0x22u);
  EXPECT_EQ(buf[7], 0x01u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&buf[10]), NERO_CCID_DESC_DEFAULT_CLOCK_KHZ);
  EXPECT_EQ(nfc_ccid_u32_load_le(&buf[14]),
            NERO_CCID_DESC_DEFAULT_DATA_RATE_BPS);
}

TEST(ReaderCcIdProtocol, RejectsUndersizedDataRateClockResponseBuffer) {
  std::array<std::uint8_t, kTestLit17> buf{};
  EXPECT_FALSE(reader_ccid_encode_data_rate_clock_response(
      buf.data(), buf.size(), 0x84u, 0x22u, 0x01u, 0u));
}

TEST(ReaderCcIdProtocol, ValidatesXfrBlockLevelParameters) {
  constexpr std::uint8_t kBadLen = 0x01u;
  constexpr std::uint8_t kBadLevel = 0x08u;

  EXPECT_EQ(reader_ccid_xfr_level_error(NFC_CCID_XFR_LEVEL_SINGLE, 1u, kBadLen,
                                        kBadLevel),
            0u);
  EXPECT_EQ(reader_ccid_xfr_level_error(NFC_CCID_XFR_LEVEL_CHAIN_BEGIN, 1u,
                                        kBadLen, kBadLevel),
            0u);
  EXPECT_EQ(reader_ccid_xfr_level_error(NFC_CCID_XFR_LEVEL_CHAIN_MIDDLE, 1u,
                                        kBadLen, kBadLevel),
            0u);
  EXPECT_EQ(reader_ccid_xfr_level_error(NFC_CCID_XFR_LEVEL_CHAIN_END, 1u,
                                        kBadLen, kBadLevel),
            0u);
  EXPECT_EQ(reader_ccid_xfr_level_error(NFC_CCID_XFR_RESPONSE_CONTINUE, 0u,
                                        kBadLen, kBadLevel),
            0u);

  EXPECT_EQ(reader_ccid_xfr_level_error(NFC_CCID_XFR_LEVEL_SINGLE, 0u, kBadLen,
                                        kBadLevel),
            0u);
  EXPECT_EQ(reader_ccid_xfr_level_error(NFC_CCID_XFR_RESPONSE_CONTINUE, 1u,
                                        kBadLen, kBadLevel),
            kBadLen);
  EXPECT_EQ(reader_ccid_xfr_level_error(0x04u, 1u, kBadLen, kBadLevel),
            kBadLevel);
}

TEST(ReaderCcIdProtocol, AcceptsAdvertisedPowerSelectValues) {
  constexpr std::uint8_t kUnsupported = 0x07u;

  EXPECT_EQ(reader_ccid_power_select_error(0x00u, kUnsupported), 0u);
  EXPECT_EQ(reader_ccid_power_select_error(0x01u, kUnsupported), 0u);
  EXPECT_EQ(reader_ccid_power_select_error(0x02u, kUnsupported), 0u);
  EXPECT_EQ(reader_ccid_power_select_error(0x03u, kUnsupported), 0u);
  EXPECT_EQ(reader_ccid_power_select_error(0x04u, kUnsupported), kUnsupported);
}

TEST(ReaderTagsType2Write, ReactivatesOnlyBeforeRetryAttempts) {
  EXPECT_FALSE(reader_tags_type2_write_attempt_needs_activation(0u));
  EXPECT_TRUE(reader_tags_type2_write_attempt_needs_activation(1u));
  EXPECT_TRUE(reader_tags_type2_write_attempt_needs_activation(UINT8_MAX));
}

TEST(ReaderTagsType5Geometry, CcByteLenAndTlvStartBlock) {
  nfc_tag_type5_info_t type5{};

  EXPECT_EQ(reader_tags_type5_cc_byte_len(NERO_NFC_NULL), 0u);
  EXPECT_EQ(reader_tags_type5_tlv_start_block(NERO_NFC_NULL), 0u);

  type5.cc_valid = true;
  type5.cc_len = NFC_TAG_T5T_CC_LEN_SHORT;
  type5.cc[NFC_TAG_T5T_CC_MLEN_BYTE_INDEX] = kTestLit0x40u;
  EXPECT_EQ(reader_tags_type5_cc_byte_len(&type5), NFC_TAG_T5T_CC_LEN_SHORT);
  EXPECT_EQ(reader_tags_type5_tlv_start_block(&type5), 1u);

  type5.cc_len = 0u;
  type5.cc[NFC_TAG_T5T_CC_MLEN_BYTE_INDEX] = 0u;
  EXPECT_EQ(reader_tags_type5_cc_byte_len(&type5), NFC_TAG_T5T_CC_LEN_EXTENDED);
  EXPECT_EQ(reader_tags_type5_tlv_start_block(&type5), 2u);

  type5.cc_valid = false;
  EXPECT_EQ(reader_tags_type5_cc_byte_len(&type5), 0u);
  EXPECT_EQ(reader_tags_type5_tlv_start_block(&type5), 0u);
}

TEST(ReaderCcIdBulkCodec, ClassifiesBulkCommandLengthRules) {
  EXPECT_TRUE(reader_ccid_bulk_command_requires_zero_length(
      (uint8_t)NFC_CCID_MSG_PC_TO_RDR_SLOTSTATUS));
  EXPECT_TRUE(reader_ccid_bulk_command_requires_zero_length(
      (uint8_t)NFC_CCID_MSG_PC_TO_RDR_ICC_POWER_ON));
  EXPECT_FALSE(reader_ccid_bulk_command_requires_zero_length(
      (uint8_t)NFC_CCID_MSG_PC_TO_RDR_XFR));

  EXPECT_TRUE(reader_ccid_bulk_command_requires_rfu_zero(
      (uint8_t)NFC_CCID_MSG_PC_TO_RDR_ABORT));
  EXPECT_FALSE(reader_ccid_bulk_command_requires_rfu_zero(
      (uint8_t)NFC_CCID_MSG_PC_TO_RDR_XFR));
}

TEST(ReaderCcIdBulkCodec, MapsBulkCommandsToResponseTypes) {
  EXPECT_EQ(reader_ccid_response_msg_for_bulk_command(
                (uint8_t)NFC_CCID_MSG_PC_TO_RDR_XFR),
            (uint8_t)NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
  EXPECT_EQ(reader_ccid_response_msg_for_bulk_command(
                (uint8_t)NFC_CCID_MSG_PC_TO_RDR_GET_PARAMETERS),
            (uint8_t)NFC_CCID_MSG_RDR_TO_PC_PARAMETERS);
  EXPECT_EQ(reader_ccid_response_msg_for_bulk_command(
                (uint8_t)NFC_CCID_MSG_PC_TO_RDR_SLOTSTATUS),
            (uint8_t)NFC_CCID_MSG_RDR_TO_PC_SLOTSTATUS);
}

TEST(ReaderCcIdBulkCodec, EncodesCommandFailedAndSlotAbsentResponses) {
  std::array<uint8_t, kTestLit32> work{};
  constexpr uint8_t kSlotMissing = 0x05u;

  const uint16_t kFailedLen = reader_ccid_encode_command_failed_response(
      work.data(), work.size(),
      static_cast<uint8_t>(NFC_CCID_MSG_PC_TO_RDR_XFR), 0x03u,
      static_cast<uint8_t>(NFC_CCID_ICC_ACTIVE), 0x01u);
  ASSERT_EQ(kFailedLen, NFC_CCID_BULK_HEADER_LEN);
  EXPECT_EQ(work[0], (uint8_t)NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
  EXPECT_EQ(work[6], 0x03u);
  EXPECT_EQ(work[8], 0x01u);

  const uint16_t kAbsentLen = reader_ccid_encode_slot_absent_response(
      work.data(), work.size(),
      static_cast<uint8_t>(NFC_CCID_MSG_PC_TO_RDR_SLOTSTATUS), 0x00u, 0x04u,
      kSlotMissing);
  ASSERT_EQ(kAbsentLen, NFC_CCID_BULK_HEADER_LEN);
  EXPECT_EQ(work[0], (uint8_t)NFC_CCID_MSG_RDR_TO_PC_SLOTSTATUS);
  EXPECT_EQ(work[5], 0x00u);
  EXPECT_EQ(work[8], kSlotMissing);
}

TEST(ReaderSecurityKeyCcidCodec, CopiesAtsAsPcscAtrAndSelectsCtapTimeouts) {
  const uint8_t kAts[] = {0x06u, 0x75u, 0x77u, 0x81u, 0x02u, 0x80u};
  std::array<uint8_t, kTestLit32> atr{};
  uint16_t atr_len = 0;

  ASSERT_TRUE(reader_security_key_copy_ats_as_pcsc_atr(
      &kAts[0], sizeof(kAts), atr.data(), atr.size(), &atr_len));
  EXPECT_EQ(atr_len, 10u);
  EXPECT_EQ(atr[0], 0x3Bu);
  EXPECT_EQ(atr[1], 0x86u);

  EXPECT_EQ(reader_security_key_ctap_timeout_for_command(
                NFC_CTAP_CMD_GET_ASSERTION, 5000u, 500u),
            5000u);
  EXPECT_EQ(reader_security_key_ctap_timeout_for_command(NFC_CTAP_CMD_GET_INFO,
                                                         5000u, 500u),
            500u);

  std::array<uint8_t, kTestLit4> rsp{};
  EXPECT_EQ(reader_security_key_relay_failure_response(rsp.data(), rsp.size()),
            2u);
  EXPECT_EQ(rsp[0], 0x6Fu);
  EXPECT_EQ(rsp[1], 0x00u);
}

TEST(ReaderIsoDepTiming, ComputesBoundedTimingValues) {
  EXPECT_GT(reader_iso_dep_fwt_us_from_fwi(4u), 4800u);
  EXPECT_LT(reader_iso_dep_fwt_us_from_fwi(4u), 4900u);
  EXPECT_EQ(reader_iso_dep_fwt_us_from_fwi(15u),
            reader_iso_dep_fwt_us_from_fwi(ISO_DEP_FWI_DEFAULT));
  EXPECT_EQ(reader_iso_dep_pre_first_iblock_delay_ms(1000u), 18u);
  EXPECT_EQ(reader_iso_dep_pre_first_iblock_delay_ms(250000u), 200u);
  EXPECT_EQ(reader_iso_dep_link_response_timeout_ms(1000u), 80u);
  EXPECT_EQ(reader_iso_dep_link_response_timeout_ms(500000u), 530u);
  /* [ISO14443-4] §7.2 — the full FWT range must be honored, not truncated at
   * 600 ms. A 700 ms FWT yields 700+30 margin = 730 ms; FWI=14 (~4949 ms FWT)
   * stays well under the 5000 ms ceiling; an over-large FWT clamps to the WTX
   * ceiling. */
  EXPECT_EQ(reader_iso_dep_link_response_timeout_ms(700000u), 730u);
  EXPECT_EQ(reader_iso_dep_link_response_timeout_ms(
                reader_iso_dep_fwt_us_from_fwi(14u)),
            4980u);
  EXPECT_EQ(reader_iso_dep_link_response_timeout_ms(9000000u),
            ISO_DEP_WTX_TIMEOUT_MAX_MS);
}

TEST(ReaderIsoDepTiming, ComputesChunkBudget) {
  EXPECT_EQ(reader_iso_dep_apdu_chunk_budget(256u, 1u), 48u);
  EXPECT_EQ(reader_iso_dep_apdu_chunk_budget(100u, 10u), 48u);
  EXPECT_EQ(reader_iso_dep_apdu_chunk_budget(64u, 3u), 48u);
  EXPECT_EQ(reader_iso_dep_apdu_chunk_budget(48u, 1u), 45u);
  EXPECT_EQ(reader_iso_dep_apdu_chunk_budget(48u, 3u), 43u);
  EXPECT_EQ(reader_iso_dep_apdu_chunk_budget(40u, 1u), 37u);
  EXPECT_EQ(reader_iso_dep_apdu_chunk_budget(32u, 1u), 29u);
  EXPECT_EQ(reader_iso_dep_apdu_chunk_budget(24u, 1u), 21u);
  EXPECT_EQ(reader_iso_dep_apdu_chunk_budget(16u, 1u), 13u);
  EXPECT_EQ(reader_iso_dep_apdu_chunk_budget(3u, 1u), 0u);
  EXPECT_EQ(reader_iso_dep_apdu_chunk_budget(2u, 1u), 0u);
}

TEST(ReaderIsoDepAts, RejectsShortAtsAndKeepsDefaults) {
  const std::array<std::uint8_t, 1> kAts = {0x01u};
  reader_iso_dep_ats_profile_t profile{};

  EXPECT_FALSE(
      reader_iso_dep_parse_ats_profile(kAts.data(), kAts.size(), &profile));
  EXPECT_EQ(profile.fsci, 0u);
  EXPECT_EQ(profile.pic_frame_max, 256u);
  EXPECT_EQ(profile.fwi, 4u);
  EXPECT_EQ(profile.fwt_us, reader_iso_dep_fwt_us_from_fwi(4u));
  EXPECT_FALSE(profile.has_ta);
  EXPECT_FALSE(profile.has_tb);
  EXPECT_FALSE(profile.has_tc);
  EXPECT_FALSE(profile.supports_cid);
  EXPECT_FALSE(profile.supports_nad);
  EXPECT_EQ(profile.historical_len, 0u);
}

TEST(ReaderIsoDepAts, MapsFsciToFrameSize) {
  /* [ISO14443-4] Table 6 — FSCI 0..8 -> FSC 16,24,32,40,48,64,96,128,256;
   * FSCI 9..15 are RFU and clamp to the maximum frame size (256). */
  EXPECT_EQ(reader_iso_dep_fsc_from_fsci(0u), 16u);
  EXPECT_EQ(reader_iso_dep_fsc_from_fsci(1u), 24u);
  EXPECT_EQ(reader_iso_dep_fsc_from_fsci(2u), 32u);
  EXPECT_EQ(reader_iso_dep_fsc_from_fsci(3u), 40u);
  EXPECT_EQ(reader_iso_dep_fsc_from_fsci(4u), 48u);
  EXPECT_EQ(reader_iso_dep_fsc_from_fsci(5u), 64u);
  EXPECT_EQ(reader_iso_dep_fsc_from_fsci(6u), 96u);
  EXPECT_EQ(reader_iso_dep_fsc_from_fsci(7u), 128u);
  EXPECT_EQ(reader_iso_dep_fsc_from_fsci(8u), 256u);
  EXPECT_EQ(reader_iso_dep_fsc_from_fsci(9u), 256u);
}

TEST(ReaderIsoDepAts, ParsesOptionalInterfaceBytesAndHistory) {
  /* [ISO14443-4] T0=0x78 -> TA/TB/TC present (b5/b6/b7) and FSCI=8 (FSC 256).
   */
  const std::array<std::uint8_t, 7> kAts = {0x07u, 0x78u, 0x11u, 0x80u,
                                            0x03u, 0xA1u, 0xA2u};
  reader_iso_dep_ats_profile_t profile{};

  ASSERT_TRUE(
      reader_iso_dep_parse_ats_profile(kAts.data(), kAts.size(), &profile));
  EXPECT_EQ(profile.fsci, 8u);
  EXPECT_EQ(profile.pic_frame_max, 256u);
  EXPECT_TRUE(profile.has_ta);
  EXPECT_EQ(profile.ta, 0x11u);
  EXPECT_TRUE(profile.has_tb);
  EXPECT_EQ(profile.tb, 0x80u);
  EXPECT_EQ(profile.fwi, 8u);
  EXPECT_EQ(profile.fwt_us, reader_iso_dep_fwt_us_from_fwi(8u));
  EXPECT_TRUE(profile.has_tc);
  EXPECT_EQ(profile.tc, 0x03u);
  EXPECT_TRUE(profile.supports_cid);
  EXPECT_TRUE(profile.supports_nad);
  EXPECT_EQ(profile.historical_offset, 5u);
  EXPECT_EQ(profile.historical_len, 2u);
}

TEST(ReaderIsoDepAts, RejectsRfuFwi) {
  const std::array<std::uint8_t, 3> kAts = {0x03u, 0x20u, 0xF0u};
  reader_iso_dep_ats_profile_t profile{};

  EXPECT_FALSE(
      reader_iso_dep_parse_ats_profile(kAts.data(), kAts.size(), &profile));
  EXPECT_EQ(profile.fwi, ISO_DEP_FWI_DEFAULT);
  EXPECT_EQ(profile.fwt_us,
            reader_iso_dep_fwt_us_from_fwi(ISO_DEP_FWI_DEFAULT));
}

TEST(ReaderIsoDepAts, UsesDefaultsWhenOptionalBytesAbsent) {
  const std::array<std::uint8_t, 3> kAts = {0x03u, 0x00u, 0xFEu};
  reader_iso_dep_ats_profile_t profile{};

  ASSERT_TRUE(
      reader_iso_dep_parse_ats_profile(kAts.data(), kAts.size(), &profile));
  EXPECT_EQ(profile.fsci, 0u);
  EXPECT_EQ(profile.pic_frame_max, 16u);
  EXPECT_EQ(profile.fwi, 4u);
  EXPECT_EQ(profile.fwt_us, reader_iso_dep_fwt_us_from_fwi(4u));
  EXPECT_FALSE(profile.has_ta);
  EXPECT_FALSE(profile.has_tb);
  EXPECT_FALSE(profile.has_tc);
  EXPECT_FALSE(profile.supports_cid);
  EXPECT_FALSE(profile.supports_nad);
  EXPECT_EQ(profile.historical_offset, 2u);
  EXPECT_EQ(profile.historical_len, 1u);
}

TEST(ReaderIsoDepAts, LeavesMissingAdvertisedBytesDefaulted) {
  /* [ISO14443-4] T0=0x78 advertises TA/TB/TC and FSCI=8, but only TA is
   * present. */
  const std::array<std::uint8_t, 3> kAts = {0x03u, 0x78u, 0x11u};
  reader_iso_dep_ats_profile_t profile{};

  ASSERT_TRUE(
      reader_iso_dep_parse_ats_profile(kAts.data(), kAts.size(), &profile));
  EXPECT_EQ(profile.fsci, 8u);
  EXPECT_EQ(profile.pic_frame_max, 256u);
  EXPECT_TRUE(profile.has_ta);
  EXPECT_EQ(profile.ta, 0x11u);
  EXPECT_FALSE(profile.has_tb);
  EXPECT_FALSE(profile.has_tc);
  EXPECT_FALSE(profile.supports_cid);
  EXPECT_FALSE(profile.supports_nad);
  EXPECT_EQ(profile.fwi, 4u);
  EXPECT_EQ(profile.historical_len, 0u);
}

TEST(ReaderIsoDepFrame, ComputesReceiveHeaderAndInfOffsets) {
  const std::array<std::uint8_t, 4> kCidWithoutPcbBit = {0x02u, 0x05u, 0x90u,
                                                         0x00u};
  const std::array<std::uint8_t, 5> kSilentNad = {0x0Au, 0x05u, 0x00u, 0x90u,
                                                  0x00u};

  EXPECT_EQ(reader_iso_dep_rx_hdr_skip(0x02u), 1u);
  EXPECT_EQ(reader_iso_dep_rx_hdr_skip(0x0Au), 2u);
  EXPECT_EQ(reader_iso_dep_rx_hdr_skip(0x06u), 2u);
  EXPECT_EQ(reader_iso_dep_rx_hdr_skip(0x0Eu), 3u);
  EXPECT_EQ(reader_iso_dep_pick_inf_offset(kCidWithoutPcbBit.data(),
                                           kCidWithoutPcbBit.size(), true,
                                           0x05u, false, 0u),
            2u);
  EXPECT_EQ(reader_iso_dep_pick_inf_offset(kSilentNad.data(), kSilentNad.size(),
                                           true, 0x05u, true, 0x01u),
            3u);
  EXPECT_EQ(reader_iso_dep_pick_inf_offset(kSilentNad.data(), kSilentNad.size(),
                                           false, 0u, true, 0x01u),
            2u);
}

TEST(ReaderIsoDepFrame, ReadsNadByteWhenPresent) {
  const std::array<std::uint8_t, 3> kCidNad = {0x0Eu, 0x05u, 0x7Fu};
  constexpr std::uint8_t kDefaultNad = 0x00u;

  EXPECT_EQ(reader_iso_dep_rx_nad_byte(kCidNad.data(), kCidNad.size(),
                                       kCidNad[0], kDefaultNad),
            0x7Fu);
  EXPECT_EQ(
      reader_iso_dep_rx_nad_byte(kCidNad.data(), 2, kCidNad[0], kDefaultNad),
      kDefaultNad);
}

TEST(ReaderIsoDepFrame, MatchesRBlockAckNakAndCid) {
  const std::array<std::uint8_t, 2> kAckCid = {0xAAu, 0x05u};
  const std::array<std::uint8_t, 2> kNakCid = {0xBAu, 0x05u};
  const std::array<std::uint8_t, 2> kWrongCid = {0xAAu, 0x06u};
  std::uint8_t ack_block = kTestLit0xFFu;

  EXPECT_TRUE(reader_iso_dep_rx_is_chain_ack_for_block(
      kAckCid.data(), kAckCid.size(), 0u, true, 0x05u, &ack_block));
  EXPECT_EQ(ack_block, 0u);
  EXPECT_TRUE(reader_iso_dep_rx_is_chain_nak_for_block(
      kNakCid.data(), kNakCid.size(), 0u, true, 0x05u));
  EXPECT_FALSE(reader_iso_dep_rx_is_chain_ack_for_block(
      kWrongCid.data(), kWrongCid.size(), 0u, true, 0x05u, NERO_NFC_NULL));
  EXPECT_FALSE(reader_iso_dep_rx_is_chain_ack_for_block(
      kNakCid.data(), kNakCid.size(), 0u, true, 0x05u, NERO_NFC_NULL));
  /* [ISO14443-4] §7.5.4 Rule 8 — R(ACK) block number must equal the chained
   * I-block (blk_sent); a toggled block number is rejected (no bespoke
   * tolerance). */
  const std::array<std::uint8_t, 2> kAckToggledBlock = {0xABu, 0x05u};
  EXPECT_FALSE(reader_iso_dep_rx_is_chain_ack_for_block(
      kAckToggledBlock.data(), kAckToggledBlock.size(), 0u, true, 0x05u,
      NERO_NFC_NULL));
  std::uint8_t ack_block1 = kTestLit0xFFu;
  const std::array<std::uint8_t, 2> kAckBlock1Match = {0xABu, 0x05u};
  EXPECT_TRUE(reader_iso_dep_rx_is_chain_ack_for_block(
      kAckBlock1Match.data(), kAckBlock1Match.size(), 1u, true, 0x05u,
      &ack_block1));
  EXPECT_EQ(ack_block1, 1u);
}

TEST(ReaderIsoDepFrame, ValidatesReceivedIBlockAgainstCurrentPcdNumber) {
  const std::array<std::uint8_t, 3> kBlock0 = {0x02u, 0x90u, 0x00u};
  const std::array<std::uint8_t, 4> kBlock1Cid = {0x0Bu, 0x05u, 0x90u, 0x00u};
  const std::array<std::uint8_t, 1> kShortCid = {0x0Au};
  const std::array<std::uint8_t, 1> kRBlock = {0xA2u};

  EXPECT_TRUE(reader_iso_dep_rx_i_block_number_matches(kBlock0.data(),
                                                       kBlock0.size(), 0u));
  EXPECT_FALSE(reader_iso_dep_rx_i_block_number_matches(kBlock0.data(),
                                                        kBlock0.size(), 1u));
  EXPECT_TRUE(reader_iso_dep_rx_i_block_number_matches(kBlock1Cid.data(),
                                                       kBlock1Cid.size(), 1u));
  EXPECT_FALSE(reader_iso_dep_rx_i_block_number_matches(kShortCid.data(),
                                                        kShortCid.size(), 0u));
  EXPECT_FALSE(reader_iso_dep_rx_i_block_number_matches(kRBlock.data(),
                                                        kRBlock.size(), 0u));
}

TEST(ReaderIsoDepFrame, ComputesWtxResponseTimeoutBounds) {
  const std::array<std::uint8_t, 2> kWtxMin = {0xF2u, 0x01u};
  const std::array<std::uint8_t, 2> kWtxMax = {0xF2u, 0x3Bu};
  const std::array<std::uint8_t, 2> kWtxInvalid = {0xF2u, 0x00u};

  EXPECT_EQ(reader_iso_dep_wtx_response_timeout_ms(4833u, kWtxMin.data(),
                                                   kWtxMin.size(), 1u),
            80u);
  EXPECT_EQ(reader_iso_dep_wtx_response_timeout_ms(100000u, kWtxMax.data(),
                                                   kWtxMax.size(), 1u),
            5000u);
  EXPECT_EQ(
      reader_iso_dep_wtx_response_timeout_ms(500000u, NERO_NFC_NULL, 0, 1u),
      530u);
  EXPECT_EQ(reader_iso_dep_wtx_response_timeout_ms(100000u, kWtxInvalid.data(),
                                                   kWtxInvalid.size(), 1u),
            130u);
}

TEST(ReaderIsoDepFrame, RecognizesPlausibleSelectResponsePrefixes) {
  EXPECT_TRUE(reader_iso_dep_inf_first_plausible_select_resp(0x61u));
  EXPECT_TRUE(reader_iso_dep_inf_first_plausible_select_resp(0x62u));
  EXPECT_TRUE(reader_iso_dep_inf_first_plausible_select_resp(0x63u));
  EXPECT_TRUE(reader_iso_dep_inf_first_plausible_select_resp(0x65u));
  EXPECT_TRUE(reader_iso_dep_inf_first_plausible_select_resp(0x6Cu));
  EXPECT_TRUE(reader_iso_dep_inf_first_plausible_select_resp(0x6Fu));
  EXPECT_TRUE(reader_iso_dep_inf_first_plausible_select_resp(0x78u));
  EXPECT_TRUE(reader_iso_dep_inf_first_plausible_select_resp(0x90u));
  EXPECT_FALSE(reader_iso_dep_inf_first_plausible_select_resp(0x00u));
  EXPECT_FALSE(reader_iso_dep_inf_first_plausible_select_resp(0x80u));
  EXPECT_FALSE(reader_iso_dep_inf_first_plausible_select_resp(0xA1u));
  EXPECT_FALSE(reader_iso_dep_inf_first_plausible_select_resp(0xFFu));
}

TEST(ReaderIsoDepFrame, ExtractsFinalIBlockInfWithoutTrimmingStatusTail) {
  const std::array<std::uint8_t, 4> kFrame = {0x02u, 0xA1u, 0x90u, 0x00u};
  std::uint16_t inf_len = 0u;
  std::uint8_t crc_tail_len = kTestLit0xFFu;

  ASSERT_TRUE(reader_iso_dep_i_block_inf_len(
      kFrame.data(), kFrame.size(), 1u, kFrame[0], &inf_len, &crc_tail_len));
  EXPECT_EQ(inf_len, 3u);
  EXPECT_EQ(crc_tail_len, 0u);
}

TEST(ReaderIsoDepFrame, ExtractsChainedIBlockInfAndTrimsRfCrcTail) {
  std::array<std::uint8_t, kTestLit5> frame = {kTestLit0x12u, kTestLit0xA1u,
                                               kTestLit0x61u, 0x00u, 0x00u};
  const std::uint16_t kCrc = reader_iso_dep_crc_a(frame.data(), 3u);
  std::uint16_t inf_len = 0u;
  std::uint8_t crc_tail_len = 0u;

  frame[kTestLit3] = static_cast<std::uint8_t>(kCrc & kTestLit0x00FFu);
  frame[kTestLit4] = static_cast<std::uint8_t>(kCrc >> kTestLit8u);

  ASSERT_TRUE(reader_iso_dep_i_block_inf_len(
      frame.data(), frame.size(), 1u, frame[0], &inf_len, &crc_tail_len));
  EXPECT_EQ(inf_len, 2u);
  EXPECT_EQ(crc_tail_len, 2u);
}

TEST(ReaderIsoDepFrame, RejectsShortIBlockInfFrame) {
  const std::array<std::uint8_t, 2> kFrame = {0x02u, 0xA1u};
  std::uint16_t inf_len = kTestLit0xFffFu;

  EXPECT_FALSE(reader_iso_dep_i_block_inf_len(
      kFrame.data(), kFrame.size(), 1u, kFrame[0], &inf_len, NERO_NFC_NULL));
  EXPECT_EQ(inf_len, 0u);
}

TEST(ReaderIsoDepFrame, BuildsChainedAckWithOptionalCidAndNeverNad) {
  std::array<std::uint8_t, kTestLit4> ack{};
  std::uint8_t ack_len = 0u;

  ASSERT_TRUE(reader_iso_dep_build_chained_ack(ack.data(), ack.size(), 1u, true,
                                               0x05u, &ack_len));
  EXPECT_EQ(ack_len, 2u);
  /* [ISO14443-4] R-blocks may carry CID, but have no NAD field. Bit 3 is RFU
   * and must remain zero even when the acknowledged I-block carried NAD. */
  EXPECT_EQ(ack[0], 0xABu);
  EXPECT_EQ(ack[1], 0x05u);

  ASSERT_TRUE(reader_iso_dep_build_chained_ack(ack.data(), ack.size(), 0u,
                                               false, 0u, &ack_len));
  EXPECT_EQ(ack_len, 1u);
  EXPECT_EQ(ack[0], 0xA2u);
}

TEST(ReaderIsoDepFrame, RejectsUndersizedChainedAckBuffer) {
  std::array<std::uint8_t, kTestLit2> ack{};
  std::uint8_t ack_len = 0u;

  EXPECT_FALSE(reader_iso_dep_build_chained_ack(ack.data(), 1u, 1u, true, 0x05u,
                                                &ack_len));
  EXPECT_EQ(ack_len, 0u);
  EXPECT_FALSE(reader_iso_dep_build_chained_ack(NERO_NFC_NULL, ack.size(), 1u,
                                                false, 0u, &ack_len));
  EXPECT_FALSE(reader_iso_dep_build_chained_ack(ack.data(), ack.size(), 1u,
                                                false, 0u, NERO_NFC_NULL));
}

TEST(ReaderIsoDepApduRelay, BuildsIBlockTxWithCidNadAndChaining) {
  const std::array<std::uint8_t, 4> kApdu = {0x80u, 0x10u, 0x20u, 0x30u};
  std::array<std::uint8_t, kTestLit8> tx{};
  reader_iso_dep_i_block_tx_t tx_info{};

  ASSERT_TRUE(reader_iso_dep_build_i_block_tx(
      tx.data(), tx.size(), kApdu.data(), kApdu.size(), 0u, 2u, true, 0x05u,
      true, 0x01u, 1u, &tx_info));
  EXPECT_EQ(tx_info.pcb, 0x1Fu);
  EXPECT_EQ(tx_info.hdr_len, 3u);
  EXPECT_EQ(tx_info.frag_len, 2u);
  EXPECT_EQ(tx_info.wire_len, 5u);
  EXPECT_TRUE(tx_info.chain_more);
  EXPECT_EQ(tx[0], 0x1Fu);
  EXPECT_EQ(tx[1], 0x05u);
  EXPECT_EQ(tx[2], 0x01u);
  EXPECT_EQ(tx[3], 0x80u);
  EXPECT_EQ(tx[4], 0x10u);
}

TEST(ReaderIsoDepApduRelay, RejectsUndersizedIBlockTxBuffer) {
  const std::array<std::uint8_t, 3> kApdu = {0x01u, 0x02u, 0x03u};
  std::array<std::uint8_t, kTestLit3> tx{};
  reader_iso_dep_i_block_tx_t tx_info{};

  EXPECT_FALSE(reader_iso_dep_build_i_block_tx(
      tx.data(), tx.size(), kApdu.data(), kApdu.size(), 0u, 2u, true, 0x05u,
      false, 0u, 0u, &tx_info));
  EXPECT_EQ(tx_info.wire_len, 0u);
}

TEST(ReaderIsoDepApduRelay, BuildsWtxEchoPrefix) {
  const std::array<std::uint8_t, 3> kRx = {0xFAu, 0x05u, 0x82u};
  std::array<std::uint8_t, kTestLit4> wtx{};
  std::uint8_t wtx_len = 0u;

  ASSERT_TRUE(reader_iso_dep_build_wtx_echo(wtx.data(), wtx.size(), kRx.data(),
                                            kRx.size(), 2u, &wtx_len));
  EXPECT_EQ(wtx_len, 3u);
  EXPECT_EQ(wtx[0], 0xFAu);
  EXPECT_EQ(wtx[1], 0x05u);
  EXPECT_EQ(wtx[2], 0x02u);
  EXPECT_FALSE(reader_iso_dep_build_wtx_echo(wtx.data(), 2u, kRx.data(),
                                             kRx.size(), 2u, &wtx_len));
  EXPECT_EQ(wtx_len, 0u);
}

TEST(ReaderIsoDepApduRelay, RejectsRfuWtxMultipliers) {
  std::array<std::uint8_t, kTestLit4> wtx{};
  std::uint8_t wtx_len = 0u;

  const std::array<std::uint8_t, 2> kWtxZero = {0xF2u, 0x00u};
  const std::array<std::uint8_t, 2> kWtxSixty = {0xF2u, 0x3Cu};
  const std::array<std::uint8_t, 2> kWtxSixtyThree = {0xF2u, 0x3Fu};

  EXPECT_FALSE(reader_iso_dep_build_wtx_echo(
      wtx.data(), wtx.size(), kWtxZero.data(), kWtxZero.size(), 1u, &wtx_len));
  EXPECT_EQ(wtx_len, 0u);
  EXPECT_FALSE(reader_iso_dep_build_wtx_echo(wtx.data(), wtx.size(),
                                             kWtxSixty.data(), kWtxSixty.size(),
                                             1u, &wtx_len));
  EXPECT_FALSE(reader_iso_dep_build_wtx_echo(
      wtx.data(), wtx.size(), kWtxSixtyThree.data(), kWtxSixtyThree.size(), 1u,
      &wtx_len));
}

TEST(ReaderIsoDepApduRelay, AppendsInfOrDropsOnCapacity) {
  const std::array<std::uint8_t, 3> kInfBytes = {0xA1u, 0x90u, 0x00u};
  std::array<std::uint8_t, kTestLit4> resp{};
  std::uint16_t total = 1u;
  bool appended = false;

  resp[0] = kTestLit0x7Fu;
  ASSERT_TRUE(reader_iso_dep_append_inf(resp.data(), resp.size(), &total,
                                        kInfBytes.data(), 2u, &appended));
  EXPECT_TRUE(appended);
  EXPECT_EQ(total, 3u);
  EXPECT_EQ(resp[0], 0x7Fu);
  EXPECT_EQ(resp[1], 0xA1u);
  EXPECT_EQ(resp[2], 0x90u);

  ASSERT_TRUE(reader_iso_dep_append_inf(resp.data(), resp.size(), &total,
                                        kInfBytes.data(), 3u, &appended));
  EXPECT_FALSE(appended);
  EXPECT_EQ(total, 3u);
}

TEST(ReaderIsoDepFrame, DetectsApduStatusWord) {
  const std::array<std::uint8_t, 3> kSuccess = {0x01u, 0x90u, 0x00u};
  const std::array<std::uint8_t, 3> kContinuation = {0x01u, 0x61u, 0x05u};
  const std::array<std::uint8_t, 3> kCtapGetresponse = {0x01u, 0x91u, 0x00u};
  const std::array<std::uint8_t, 3> kNoStatus = {0x01u, 0x60u, 0x00u};

  EXPECT_TRUE(reader_iso_dep_apdu_response_has_status_word(kSuccess.data(),
                                                           kSuccess.size()));
  EXPECT_TRUE(reader_iso_dep_apdu_response_has_status_word(
      kContinuation.data(), kContinuation.size()));
  EXPECT_TRUE(reader_iso_dep_apdu_response_has_status_word(
      kCtapGetresponse.data(), kCtapGetresponse.size()));
  EXPECT_FALSE(reader_iso_dep_apdu_response_has_status_word(kNoStatus.data(),
                                                            kNoStatus.size()));
  EXPECT_FALSE(reader_iso_dep_apdu_response_has_status_word(NERO_NFC_NULL, 0u));
}

TEST(ReaderIsoDepStatus, TrimsResidualCrcAfterSuccessStatus) {
  const std::array<std::uint8_t, 6> kResp = {0x00u, 0xA1u, 0x90u,
                                             0x00u, 0x65u, 0x39u};

  EXPECT_EQ(reader_iso_dep_trim_crc_suffix(kResp.data(), kResp.size()), 4u);
}

TEST(ReaderIsoDepStatus, DetectsIso14443aCrcSuffix) {
  const std::array<std::uint8_t, 7> kFrame = {0x02u, 0x00u, 0xA1u, 0x90u,
                                              0x00u, 0x88u, 0x5Au};
  const std::array<std::uint8_t, 7> kNoCrc = {0x02u, 0x00u, 0xA1u, 0x90u,
                                              0x00u, 0x90u, 0x00u};

  EXPECT_TRUE(reader_iso_dep_has_crc_a_suffix(kFrame.data(), kFrame.size()));
  EXPECT_FALSE(reader_iso_dep_has_crc_a_suffix(kNoCrc.data(), kNoCrc.size()));
  EXPECT_EQ(
      reader_iso_dep_chained_crc_tail_len(0x12u, kFrame.data(), kFrame.size()),
      2u);
  EXPECT_EQ(
      reader_iso_dep_chained_crc_tail_len(0x02u, kFrame.data(), kFrame.size()),
      0u);
}

TEST(ReaderIsoDepStatus, TrimsResidualCrcThatLooksLikeCommandError) {
  const std::array<std::uint8_t, 6> kResp = {0x00u, 0xA1u, 0x90u,
                                             0x00u, 0x69u, 0x01u};

  EXPECT_EQ(reader_iso_dep_trim_crc_suffix(kResp.data(), kResp.size()), 4u);
}

TEST(ReaderIsoDepStatus, TrimsTailWhenEarlierStatusHasHigherConfidence) {
  const std::array<std::uint8_t, 6> kResp = {0x00u, 0xA1u, 0x63u,
                                             0x01u, 0x01u, 0x02u};

  EXPECT_EQ(reader_iso_dep_trim_crc_suffix(kResp.data(), kResp.size()), 4u);
}

TEST(ReaderIsoDepStatus, TrimsResidualCrcAfterGetResponseStatus) {
  const std::array<std::uint8_t, 6> kResp = {0x00u, 0xA1u, 0x61u,
                                             0x00u, 0x65u, 0x39u};

  EXPECT_EQ(reader_iso_dep_trim_crc_suffix(kResp.data(), kResp.size()), 4u);
}

TEST(ReaderIsoDepStatus, KeepsUnchainedGetResponseStatus) {
  const std::array<std::uint8_t, 4> kResp = {0x00u, 0xA1u, 0x61u, 0x00u};

  EXPECT_EQ(reader_iso_dep_trim_crc_suffix(kResp.data(), kResp.size()),
            kResp.size());
}

TEST(ReaderIsoDepStatus, KeepsCommandErrorWithoutPrecedingStatus) {
  const std::array<std::uint8_t, 4> kResp = {0x01u, 0x02u, 0x69u, 0xFFu};

  EXPECT_EQ(reader_iso_dep_trim_crc_suffix(kResp.data(), kResp.size()),
            kResp.size());
}

TEST_F(NeroNfcReaderAppFixture, RejectsShortRatsCommit) {
  const std::array<std::uint8_t, 1> kRx = {0x06u};

  reader_context_reset(reader_context_active());
  EXPECT_FALSE(
      reader_security_key_iso_dep_commit_rats_rx(1, kRx.data(), 0x70u));
  EXPECT_EQ(G_BLOCK_NUM, 0u);
}

TEST_F(NeroNfcReaderAppFixture, CommitRatsStoresAtsAndResetsBlockNum) {
  /* [ISO14443-4] §5.2.5 — TL (byte 0) equals the ATS length including itself.
   */
  const std::array<std::uint8_t, 4> kRx = {0x04u, 0x75u, 0x77u, 0x81u};

  reader_context_reset(reader_context_active());
  G_BLOCK_NUM = 1u;
  ASSERT_TRUE(reader_security_key_iso_dep_commit_rats_rx(4, kRx.data(), 0x70u));
  EXPECT_EQ(G_ATS_LEN, 4u);
  EXPECT_EQ(G_ATS_DATA[0], 0x04u);
  EXPECT_EQ(G_ISO_DEP_RATS_PARAM, 0x70u);
  EXPECT_EQ(G_BLOCK_NUM, 0u);
}

TEST_F(NeroNfcReaderAppFixture, CommitRatsUsesTlAndDropsTrailingBytes) {
  /* TL=0x03 with extra received bytes (e.g. CRC): only the TL-length ATS is
   * kept. */
  const std::array<std::uint8_t, 5> kRx = {0x03u, 0x75u, 0x77u, 0xAAu, 0xBBu};

  reader_context_reset(reader_context_active());
  ASSERT_TRUE(reader_security_key_iso_dep_commit_rats_rx(5, kRx.data(), 0x70u));
  EXPECT_EQ(G_ATS_LEN, 3u);
  EXPECT_EQ(G_ATS_DATA[0], 0x03u);
}

TEST_F(NeroNfcReaderAppFixture, CommitRatsRejectsTruncatedAtsByTl) {
  /* TL claims 6 bytes but only 4 were received: fail closed, do not relay. */
  const std::array<std::uint8_t, 4> kRx = {0x06u, 0x75u, 0x77u, 0x81u};

  reader_context_reset(reader_context_active());
  EXPECT_FALSE(
      reader_security_key_iso_dep_commit_rats_rx(4, kRx.data(), 0x70u));
}

TEST_F(NeroNfcReaderAppFixture, ProbeCanUpgradeWhenTcAdvertisesCid) {
  reader_context_reset(reader_context_active());
  G_ISO_DEP_HAVE_TC = true;
  G_ISO_DEP_TC_BYTE = kTestLit0x02u;
  G_ISO_DEP_PCB_HAS_CID = false;
  EXPECT_TRUE(reader_security_key_iso_dep_probe_can_upgrade_cid());

  G_ISO_DEP_PCB_HAS_CID = true;
  EXPECT_FALSE(reader_security_key_iso_dep_probe_can_upgrade_cid());
}

TEST_F(NeroNfcReaderAppFixture, TxAddNadRequiresCidFraming) {
  const std::array<std::uint8_t, 4> kApdu = {0x00u, 0xA4u, 0x04u, 0x00u};

  reader_context_reset(reader_context_active());
  G_ISO_DEP_HAVE_TC = true;
  G_ISO_DEP_TC_BYTE = 0x01u;
  G_ISO_DEP_PCB_HAS_CID = false;
  G_ISO_DEP_PIC_FRAME_MAX = kTestLit256u;
  EXPECT_FALSE(
      reader_security_key_iso_dep_tx_add_nad(kApdu.size(), kApdu.data()));

  G_ISO_DEP_PCB_HAS_CID = true;
  EXPECT_TRUE(
      reader_security_key_iso_dep_tx_add_nad(kApdu.size(), kApdu.data()));

  const std::array<std::uint8_t, 1> kCtap = {0x80u};
  EXPECT_FALSE(
      reader_security_key_iso_dep_tx_add_nad(kCtap.size(), kCtap.data()));
}

TEST_F(NeroNfcReaderAppFixture,
       GetDataUidReturns6F00WhenResponseBufferTooSmall) {
  const uint8_t kApdu[] = {0xFFu, 0xCAu, 0x00u, 0x00u, 0x00u};
  uint8_t rsp[kTestLit2];
  for (uint8_t i = 0u; i < NFC_FRONTEND_ISO15693_UID_LEN; ++i) {
    (void)nero_nfc_store_u8(&G_UID15[0], NFC_FRONTEND_ISO15693_UID_LEN, i,
                            kTestLit0xABu);
  }
  G_TAG_KIND = READER_TAG_KIND_TYPE5;
  const uint16_t kRlen = reader_ccid_handle_get_data_apdu(
      &kApdu[0], static_cast<uint16_t>(sizeof(kApdu)), &rsp[0],
      static_cast<uint16_t>(sizeof(rsp)));
  EXPECT_EQ(kRlen, 2u);
  EXPECT_EQ(rsp[0], 0x6Fu);
  EXPECT_EQ(rsp[1], 0x00u);
}

TEST_F(NeroNfcReaderAppFixture,
       StorageGetDataDispatchesExtendedPcscIdentifiers) {
  const uint8_t kApdu[] = {0xFFu, 0xCAu, NFC_PCSC_GET_DATA_TYPE5_CC, 0x00u,
                           0x00u};
  uint8_t rsp[kTestLit8];

  G_TAG_KIND = READER_TAG_KIND_TYPE5;
  const uint16_t kRlen = reader_ccid_handle_get_data_apdu(
      &kApdu[0], static_cast<uint16_t>(sizeof(kApdu)), &rsp[0],
      static_cast<uint16_t>(sizeof(rsp)));

  ASSERT_EQ(kRlen, 2u);
  EXPECT_EQ(rsp[0], static_cast<uint8_t>(NFC_ISO7816_SW1_WRONG_DATA));
  EXPECT_EQ(rsp[1], static_cast<uint8_t>(NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED));
}

TEST_F(NeroNfcReaderAppFixture,
       Type2RawTransceiveGateAllowsReadsRejectsWrites) {
  reader_tags_utest_reset();
  reader_tags_utest_set_type2_storage_info(kTestLit144u, true, true);
  G_TAG_KIND = READER_TAG_KIND_TYPE2;

  const uint8_t kGetVersion[] = {
      static_cast<uint8_t>(CCID_RAW_T2_CMD_GET_VERSION)};
  const uint8_t kRead[] = {static_cast<uint8_t>(CCID_RAW_T2_CMD_READ),
                           static_cast<uint8_t>(NFC_STORAGE_TYPE2_CC_PAGE)};
  const uint8_t kFastRead[] = {
      static_cast<uint8_t>(CCID_RAW_T2_CMD_FAST_READ),
      static_cast<uint8_t>(NFC_STORAGE_TYPE2_CC_PAGE),
      static_cast<uint8_t>(NFC_STORAGE_TYPE2_CC_PAGE + 1u)};
  const uint8_t kWrite[] = {
      kTestLit0xA2u, static_cast<uint8_t>(NFC_STORAGE_TYPE2_FIRST_DATA_PAGE),
      kTestLit0x11u, kTestLit0x22u,
      kTestLit0x33u, kTestLit0x44u};

  EXPECT_TRUE(reader_ccid_type2_raw_transceive_allowed(
      &kGetVersion[0], static_cast<uint16_t>(sizeof(kGetVersion))));
  EXPECT_TRUE(reader_ccid_type2_raw_transceive_allowed(
      &kRead[0], static_cast<uint16_t>(sizeof(kRead))));
  EXPECT_TRUE(reader_ccid_type2_raw_transceive_allowed(
      &kFastRead[0], static_cast<uint16_t>(sizeof(kFastRead))));
  EXPECT_FALSE(reader_ccid_type2_raw_transceive_allowed(
      &kWrite[0], static_cast<uint16_t>(sizeof(kWrite))));
  EXPECT_FALSE(reader_ccid_type2_raw_transceive_allowed(NERO_NFC_NULL, 1u));

  G_TAG_KIND = READER_TAG_KIND_TYPE4;
  EXPECT_FALSE(reader_ccid_type2_raw_transceive_allowed(
      &kGetVersion[0], static_cast<uint16_t>(sizeof(kGetVersion))));
}

TEST_F(NeroNfcReaderAppFixture,
       Type5RawTransceiveGateAllowsReadsRejectsWrites) {
  reader_tags_utest_reset();
  reader_tags_utest_set_type5_info(NFC_TAG_T5T_CC_LEN_SHORT, kTestLit320u,
                                   kTestLit80u, true, true);
  G_TAG_KIND = READER_TAG_KIND_TYPE5;
  for (uint8_t i = 0u; i < NFC_FRONTEND_ISO15693_UID_LEN; ++i) {
    (void)nero_nfc_store_u8(&G_UID15[0], NFC_FRONTEND_ISO15693_UID_LEN, i,
                            static_cast<uint8_t>(kTestLit0x10u + i));
  }

  const uint8_t kInventory[] = {
      kTestLit0x01u, static_cast<uint8_t>(CCID_RAW_T5_CMD_INVENTORY)};
  /* ISO15693 addressed UID is little-endian vs G_UID15 MSB-first storage. */
  const uint8_t kReadSingle[] = {
      static_cast<uint8_t>(NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED),
      static_cast<uint8_t>(NFC_TAG_T5T_ISO15693_CMD_READ_SINGLE),
      kTestLit0x17u,
      kTestLit0x16u,
      kTestLit0x15u,
      kTestLit0x14u,
      kTestLit0x13u,
      kTestLit0x12u,
      kTestLit0x11u,
      kTestLit0x10u,
      0x00u};
  const uint8_t kWriteSingle[] = {
      static_cast<uint8_t>(NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED),
      static_cast<uint8_t>(NFC_TAG_T5T_ISO15693_CMD_WRITE_SINGLE),
      kTestLit0x17u,
      kTestLit0x16u,
      kTestLit0x15u,
      kTestLit0x14u,
      kTestLit0x13u,
      kTestLit0x12u,
      kTestLit0x11u,
      kTestLit0x10u,
      0x00u,
      kTestLit0x01u,
      kTestLit0x02u,
      kTestLit0x03u,
      kTestLit0x04u};

  EXPECT_TRUE(reader_ccid_type5_raw_transceive_allowed(
      &kInventory[0], static_cast<uint16_t>(sizeof(kInventory))));
  EXPECT_TRUE(reader_ccid_type5_raw_transceive_allowed(
      &kReadSingle[0], static_cast<uint16_t>(sizeof(kReadSingle))));
  EXPECT_FALSE(reader_ccid_type5_raw_transceive_allowed(
      &kWriteSingle[0], static_cast<uint16_t>(sizeof(kWriteSingle))));

  G_TAG_KIND = READER_TAG_KIND_TYPE2;
  EXPECT_FALSE(reader_ccid_type5_raw_transceive_allowed(
      &kInventory[0], static_cast<uint16_t>(sizeof(kInventory))));
}
