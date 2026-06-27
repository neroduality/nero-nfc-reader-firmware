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
#include "reader_security_key_ccid_codec.h"
#include "reader_security_key_iso_dep_session.h"
#include "reader_ccid_protocol.h"
#include "reader_ccid_bulk_codec.h"
#include "reader_ccid_internal.h"
#include "reader_iso_dep_apdu_relay.h"
#include "reader_iso_dep_ats.h"
#include "reader_iso_dep_frame.h"
#include "reader_iso_dep_timing.h"

#include "nfc_frontend.h"
#include "reader_context.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>

TEST(ReaderCcIdProtocol, EncodesT1ParametersResponse) {
  std::array<std::uint8_t, 20> buf{};
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
  std::array<std::uint8_t, 12> buf{};

  EXPECT_FALSE(reader_ccid_encode_params_response(
      buf.data(), buf.size(), 0x82u, 0x44u, 0x00u, 0x00u, 0x01u, 0x01u));
}

TEST(ReaderCcIdProtocol, RejectsNonT1SetParameters) {
  std::array<std::uint8_t, 10> frame{};
  frame[0] = 0x61u;

  /* [CCID1.10] §6.2.6 — bError is the byte offset of the first offending field. A
   * wrong dwLength (bytes 1..4) reports offset 0x01, regardless of bProtocolNum. */
  frame[7] = 0x01u; /* bProtocolNum = T1 (correct) */
  EXPECT_EQ(reader_ccid_param_error_for_request(frame.data(), frame.size(), 0x61u, 0x01u), 0x01u);
  EXPECT_EQ(reader_ccid_param_icc_level(frame.data(), frame.size(), 0x00u, 0x40u, 0x61u, 0x01u),
            0x40u);

  /* dwLength correct, bProtocolNum wrong: bError = offset of bProtocolNum (0x07). */
  nfc_ccid_u32_store_le(&frame[1], 7u);
  frame[7] = 0x00u;
  EXPECT_EQ(reader_ccid_param_error_for_request(frame.data(), frame.size(), 0x61u, 0x01u), 0x07u);

  /* All fields valid: no error. */
  frame[7] = 0x01u;
  EXPECT_EQ(reader_ccid_param_error_for_request(frame.data(), frame.size(), 0x61u, 0x01u), 0u);
  EXPECT_EQ(reader_ccid_param_icc_level(frame.data(), frame.size(), 0x00u, 0x40u, 0x61u, 0x01u),
            0x00u);

  /* abRFU[0] non-zero: bError = offset 0x08. */
  frame[8] = 0x01u;
  EXPECT_EQ(reader_ccid_param_error_for_request(frame.data(), frame.size(), 0x61u, 0x01u), 0x08u);

  /* abRFU[1] non-zero: bError = offset 0x09. */
  frame[8] = 0x00u;
  frame[9] = 0x01u;
  EXPECT_EQ(reader_ccid_param_error_for_request(frame.data(), frame.size(), 0x61u, 0x01u), 0x09u);
}

TEST(ReaderCcIdProtocol, EncodesDataRateClockResponse) {
  std::array<std::uint8_t, 18> buf{};
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
  std::array<std::uint8_t, 17> buf{};
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
  std::array<uint8_t, 32> work{};
  constexpr uint8_t kSlotMissing = 0x05u;

  const uint16_t failed_len = reader_ccid_encode_command_failed_response(
    work.data(), work.size(), (uint8_t)NFC_CCID_MSG_PC_TO_RDR_XFR, 0x03u,
    (uint8_t)NFC_CCID_ICC_ACTIVE, 0x01u);
  ASSERT_EQ(failed_len, NFC_CCID_BULK_HEADER_LEN);
  EXPECT_EQ(work[0], (uint8_t)NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
  EXPECT_EQ(work[6], 0x03u);
  EXPECT_EQ(work[8], 0x01u);

  const uint16_t absent_len = reader_ccid_encode_slot_absent_response(
    work.data(), work.size(), (uint8_t)NFC_CCID_MSG_PC_TO_RDR_SLOTSTATUS, 0x00u, 0x04u,
    kSlotMissing);
  ASSERT_EQ(absent_len, NFC_CCID_BULK_HEADER_LEN);
  EXPECT_EQ(work[0], (uint8_t)NFC_CCID_MSG_RDR_TO_PC_SLOTSTATUS);
  EXPECT_EQ(work[5], 0x00u);
  EXPECT_EQ(work[8], kSlotMissing);
}

TEST(ReaderSecurityKeyCcidCodec, CopiesAtsAsPcscAtrAndSelectsCtapTimeouts) {
  const uint8_t ats[] = {0x06u, 0x75u, 0x77u, 0x81u, 0x02u, 0x80u};
  std::array<uint8_t, 32> atr{};
  uint16_t atr_len = 0;

  ASSERT_TRUE(
    reader_security_key_copy_ats_as_pcsc_atr(ats, sizeof(ats), atr.data(), atr.size(), &atr_len));
  EXPECT_EQ(atr_len, 10u);
  EXPECT_EQ(atr[0], 0x3Bu);
  EXPECT_EQ(atr[1], 0x86u);

  EXPECT_EQ(reader_security_key_ctap_timeout_for_command(NFC_CTAP_CMD_GET_ASSERTION, 5000u, 500u), 5000u);
  EXPECT_EQ(reader_security_key_ctap_timeout_for_command(NFC_CTAP_CMD_GET_INFO, 5000u, 500u), 500u);

  std::array<uint8_t, 4> rsp{};
  EXPECT_EQ(reader_security_key_relay_failure_response(rsp.data(), rsp.size()), 2u);
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
  /* [ISO14443-4] §7.2 — the full FWT range must be honored, not truncated at 600 ms.
   * A 700 ms FWT yields 700+30 margin = 730 ms; FWI=14 (~4949 ms FWT) stays well
   * under the 5000 ms ceiling; an over-large FWT clamps to the WTX ceiling. */
  EXPECT_EQ(reader_iso_dep_link_response_timeout_ms(700000u), 730u);
  EXPECT_EQ(reader_iso_dep_link_response_timeout_ms(reader_iso_dep_fwt_us_from_fwi(14u)), 4980u);
  EXPECT_EQ(reader_iso_dep_link_response_timeout_ms(9000000u), ISO_DEP_WTX_TIMEOUT_MAX_MS);
}

TEST(ReaderIsoDepTiming, ComputesChunkBudget) {
  EXPECT_EQ(reader_iso_dep_apdu_chunk_budget(256u, 1u), 48u);
  EXPECT_EQ(reader_iso_dep_apdu_chunk_budget(100u, 10u), 48u);
  EXPECT_EQ(reader_iso_dep_apdu_chunk_budget(48u, 30u), 24u);
  EXPECT_EQ(reader_iso_dep_apdu_chunk_budget(16u, 1u), 48u);
}

TEST(ReaderIsoDepAts, RejectsShortAtsAndKeepsDefaults) {
  const std::array<std::uint8_t, 1> ats = {0x01u};
  reader_iso_dep_ats_profile_t profile{};

  EXPECT_FALSE(reader_iso_dep_parse_ats_profile(ats.data(), ats.size(), &profile));
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
  /* [ISO14443-4] T0=0x78 -> TA/TB/TC present (b5/b6/b7) and FSCI=8 (FSC 256). */
  const std::array<std::uint8_t, 7> ats = {0x07u, 0x78u, 0x11u, 0x80u,
                                           0x03u, 0xA1u, 0xA2u};
  reader_iso_dep_ats_profile_t profile{};

  ASSERT_TRUE(reader_iso_dep_parse_ats_profile(ats.data(), ats.size(), &profile));
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
  const std::array<std::uint8_t, 3> ats = {0x03u, 0x20u, 0xF0u};
  reader_iso_dep_ats_profile_t profile{};

  EXPECT_FALSE(reader_iso_dep_parse_ats_profile(ats.data(), ats.size(), &profile));
  EXPECT_EQ(profile.fwi, ISO_DEP_FWI_DEFAULT);
  EXPECT_EQ(profile.fwt_us, reader_iso_dep_fwt_us_from_fwi(ISO_DEP_FWI_DEFAULT));
}

TEST(ReaderIsoDepAts, UsesDefaultsWhenOptionalBytesAbsent) {
  const std::array<std::uint8_t, 3> ats = {0x03u, 0x00u, 0xFEu};
  reader_iso_dep_ats_profile_t profile{};

  ASSERT_TRUE(reader_iso_dep_parse_ats_profile(ats.data(), ats.size(), &profile));
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
  /* [ISO14443-4] T0=0x78 advertises TA/TB/TC and FSCI=8, but only TA is present. */
  const std::array<std::uint8_t, 3> ats = {0x03u, 0x78u, 0x11u};
  reader_iso_dep_ats_profile_t profile{};

  ASSERT_TRUE(reader_iso_dep_parse_ats_profile(ats.data(), ats.size(), &profile));
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
  const std::array<std::uint8_t, 4> cid_without_pcb_bit = {0x02u, 0x05u, 0x90u, 0x00u};
  const std::array<std::uint8_t, 5> silent_nad = {0x0Au, 0x05u, 0x00u, 0x90u, 0x00u};

  EXPECT_EQ(reader_iso_dep_rx_hdr_skip(0x02u), 1u);
  EXPECT_EQ(reader_iso_dep_rx_hdr_skip(0x0Au), 2u);
  EXPECT_EQ(reader_iso_dep_rx_hdr_skip(0x0Eu), 3u);
  EXPECT_EQ(reader_iso_dep_pick_inf_offset(cid_without_pcb_bit.data(),
                                           cid_without_pcb_bit.size(), true, 0x05u, false, 0u),
            2u);
  EXPECT_EQ(reader_iso_dep_pick_inf_offset(silent_nad.data(), silent_nad.size(), true, 0x05u,
                                           true, 0x01u),
            3u);
  EXPECT_EQ(reader_iso_dep_pick_inf_offset(silent_nad.data(), silent_nad.size(), false, 0u, true,
                                           0x01u),
            2u);
}

TEST(ReaderIsoDepFrame, ReadsNadByteWhenPresent) {
  const std::array<std::uint8_t, 3> cid_nad = {0x0Eu, 0x05u, 0x7Fu};
  constexpr std::uint8_t kDefaultNad = 0x00u;

  EXPECT_EQ(reader_iso_dep_rx_nad_byte(cid_nad.data(), cid_nad.size(), cid_nad[0], kDefaultNad),
            0x7Fu);
  EXPECT_EQ(reader_iso_dep_rx_nad_byte(cid_nad.data(), 2, cid_nad[0], kDefaultNad),
            kDefaultNad);
}

TEST(ReaderIsoDepFrame, MatchesRBlockAckNakAndCid) {
  const std::array<std::uint8_t, 2> ack_cid = {0xAAu, 0x05u};
  const std::array<std::uint8_t, 2> nak_cid = {0xBAu, 0x05u};
  const std::array<std::uint8_t, 2> wrong_cid = {0xAAu, 0x06u};
  std::uint8_t ack_block = 0xFFu;

  EXPECT_TRUE(reader_iso_dep_rx_is_chain_ack_for_block(ack_cid.data(), ack_cid.size(), 0u, true,
                                                       0x05u, &ack_block));
  EXPECT_EQ(ack_block, 0u);
  EXPECT_TRUE(reader_iso_dep_rx_is_chain_nak_for_block(nak_cid.data(), nak_cid.size(), 0u, true,
                                                       0x05u));
  EXPECT_FALSE(reader_iso_dep_rx_is_chain_ack_for_block(wrong_cid.data(), wrong_cid.size(), 0u,
                                                        true, 0x05u, NERO_NFC_NULL));
  EXPECT_FALSE(reader_iso_dep_rx_is_chain_ack_for_block(nak_cid.data(), nak_cid.size(), 0u, true,
                                                        0x05u, NERO_NFC_NULL));
  /* [ISO14443-4] §7.5.4 Rule 8 — R(ACK) block number must equal the chained I-block
   * (blk_sent); a toggled block number is rejected (no bespoke tolerance). */
  const std::array<std::uint8_t, 2> ack_toggled_block = {0xABu, 0x05u};
  EXPECT_FALSE(reader_iso_dep_rx_is_chain_ack_for_block(ack_toggled_block.data(),
                                                        ack_toggled_block.size(), 0u, true, 0x05u,
                                                        NERO_NFC_NULL));
  std::uint8_t ack_block1 = 0xFFu;
  const std::array<std::uint8_t, 2> ack_block1_match = {0xABu, 0x05u};
  EXPECT_TRUE(reader_iso_dep_rx_is_chain_ack_for_block(ack_block1_match.data(),
                                                       ack_block1_match.size(), 1u, true, 0x05u,
                                                       &ack_block1));
  EXPECT_EQ(ack_block1, 1u);
}

TEST(ReaderIsoDepFrame, ComputesWtxResponseTimeoutBounds) {
  const std::array<std::uint8_t, 2> wtx_min = {0xF2u, 0x01u};
  const std::array<std::uint8_t, 2> wtx_max = {0xF2u, 0x3Bu};

  EXPECT_EQ(reader_iso_dep_wtx_response_timeout_ms(4833u, wtx_min.data(), wtx_min.size(), 1u),
            80u);
  EXPECT_EQ(reader_iso_dep_wtx_response_timeout_ms(100000u, wtx_max.data(), wtx_max.size(), 1u),
            5000u);
  EXPECT_EQ(reader_iso_dep_wtx_response_timeout_ms(500000u, NERO_NFC_NULL, 0, 1u), 530u);
}

TEST(ReaderIsoDepFrame, ExtractsFinalIBlockInfWithoutTrimmingStatusTail) {
  const std::array<std::uint8_t, 4> frame = {0x02u, 0xA1u, 0x90u, 0x00u};
  std::uint16_t inf_len = 0u;
  std::uint8_t crc_tail_len = 0xFFu;

  ASSERT_TRUE(reader_iso_dep_i_block_inf_len(frame.data(), frame.size(), 1u, frame[0], &inf_len,
                                             &crc_tail_len));
  EXPECT_EQ(inf_len, 3u);
  EXPECT_EQ(crc_tail_len, 0u);
}

TEST(ReaderIsoDepFrame, ExtractsChainedIBlockInfAndTrimsRfCrcTail) {
  std::array<std::uint8_t, 5> frame = {0x12u, 0xA1u, 0x61u, 0x00u, 0x00u};
  const std::uint16_t crc = reader_iso_dep_crc_a(frame.data(), 3u);
  std::uint16_t inf_len = 0u;
  std::uint8_t crc_tail_len = 0u;

  frame[3] = (std::uint8_t)(crc & 0x00FFu);
  frame[4] = (std::uint8_t)(crc >> 8u);

  ASSERT_TRUE(reader_iso_dep_i_block_inf_len(frame.data(), frame.size(), 1u, frame[0], &inf_len,
                                             &crc_tail_len));
  EXPECT_EQ(inf_len, 2u);
  EXPECT_EQ(crc_tail_len, 2u);
}

TEST(ReaderIsoDepFrame, RejectsShortIBlockInfFrame) {
  const std::array<std::uint8_t, 2> frame = {0x02u, 0xA1u};
  std::uint16_t inf_len = 0xFFFFu;

  EXPECT_FALSE(reader_iso_dep_i_block_inf_len(frame.data(), frame.size(), 1u, frame[0], &inf_len,
                                              NERO_NFC_NULL));
  EXPECT_EQ(inf_len, 0u);
}

TEST(ReaderIsoDepFrame, BuildsChainedAckWithCidAndNad) {
  std::array<std::uint8_t, 4> ack{};
  std::uint8_t ack_len = 0u;

  ASSERT_TRUE(reader_iso_dep_build_chained_ack(ack.data(), ack.size(), 1u, true, 0x05u, true,
                                               0x7Fu, &ack_len));
  EXPECT_EQ(ack_len, 3u);
  EXPECT_EQ(ack[0], 0xAFu);
  EXPECT_EQ(ack[1], 0x05u);
  EXPECT_EQ(ack[2], 0x7Fu);
}

TEST(ReaderIsoDepFrame, RejectsUndersizedChainedAckBuffer) {
  std::array<std::uint8_t, 2> ack{};
  std::uint8_t ack_len = 0u;

  EXPECT_FALSE(reader_iso_dep_build_chained_ack(ack.data(), ack.size(), 1u, true, 0x05u, true,
                                                0x7Fu, &ack_len));
  EXPECT_EQ(ack_len, 0u);
}

TEST(ReaderIsoDepApduRelay, BuildsIBlockTxWithCidNadAndChaining) {
  const std::array<std::uint8_t, 4> apdu = {0x80u, 0x10u, 0x20u, 0x30u};
  std::array<std::uint8_t, 8> tx{};
  reader_iso_dep_i_block_tx_t tx_info{};

  ASSERT_TRUE(reader_iso_dep_build_i_block_tx(tx.data(), tx.size(), apdu.data(), apdu.size(), 0u,
                                              2u, true, 0x05u, true, 0x01u, 1u, &tx_info));
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
  const std::array<std::uint8_t, 3> apdu = {0x01u, 0x02u, 0x03u};
  std::array<std::uint8_t, 3> tx{};
  reader_iso_dep_i_block_tx_t tx_info{};

  EXPECT_FALSE(reader_iso_dep_build_i_block_tx(tx.data(), tx.size(), apdu.data(), apdu.size(), 0u,
                                               2u, true, 0x05u, false, 0u, 0u, &tx_info));
  EXPECT_EQ(tx_info.wire_len, 0u);
}

TEST(ReaderIsoDepApduRelay, BuildsWtxEchoPrefix) {
  const std::array<std::uint8_t, 3> rx = {0xFAu, 0x05u, 0x82u};
  std::array<std::uint8_t, 4> wtx{};
  std::uint8_t wtx_len = 0u;

  ASSERT_TRUE(reader_iso_dep_build_wtx_echo(wtx.data(), wtx.size(), rx.data(), rx.size(), 2u,
                                            &wtx_len));
  EXPECT_EQ(wtx_len, 3u);
  EXPECT_EQ(wtx[0], 0xFAu);
  EXPECT_EQ(wtx[1], 0x05u);
  EXPECT_EQ(wtx[2], 0x02u);
  EXPECT_FALSE(reader_iso_dep_build_wtx_echo(wtx.data(), 2u, rx.data(), rx.size(), 2u,
                                             &wtx_len));
  EXPECT_EQ(wtx_len, 0u);
}

TEST(ReaderIsoDepApduRelay, RejectsRfuWtxMultipliers) {
  std::array<std::uint8_t, 4> wtx{};
  std::uint8_t wtx_len = 0u;

  const std::array<std::uint8_t, 2> wtx_zero = {0xF2u, 0x00u};
  const std::array<std::uint8_t, 2> wtx_sixty = {0xF2u, 0x3Cu};
  const std::array<std::uint8_t, 2> wtx_sixty_three = {0xF2u, 0x3Fu};

  EXPECT_FALSE(reader_iso_dep_build_wtx_echo(wtx.data(), wtx.size(), wtx_zero.data(),
                                             wtx_zero.size(), 1u, &wtx_len));
  EXPECT_EQ(wtx_len, 0u);
  EXPECT_FALSE(reader_iso_dep_build_wtx_echo(wtx.data(), wtx.size(), wtx_sixty.data(),
                                             wtx_sixty.size(), 1u, &wtx_len));
  EXPECT_FALSE(reader_iso_dep_build_wtx_echo(wtx.data(), wtx.size(), wtx_sixty_three.data(),
                                             wtx_sixty_three.size(), 1u, &wtx_len));
}

TEST(ReaderIsoDepApduRelay, AppendsInfOrDropsOnCapacity) {
  const std::array<std::uint8_t, 3> inf = {0xA1u, 0x90u, 0x00u};
  std::array<std::uint8_t, 4> resp{};
  std::uint16_t total = 1u;
  bool appended = false;

  resp[0] = 0x7Fu;
  ASSERT_TRUE(
      reader_iso_dep_append_inf(resp.data(), resp.size(), &total, inf.data(), 2u, &appended));
  EXPECT_TRUE(appended);
  EXPECT_EQ(total, 3u);
  EXPECT_EQ(resp[0], 0x7Fu);
  EXPECT_EQ(resp[1], 0xA1u);
  EXPECT_EQ(resp[2], 0x90u);

  ASSERT_TRUE(
      reader_iso_dep_append_inf(resp.data(), resp.size(), &total, inf.data(), 3u, &appended));
  EXPECT_FALSE(appended);
  EXPECT_EQ(total, 3u);
}

TEST(ReaderIsoDepFrame, DetectsApduStatusWord) {
  const std::array<std::uint8_t, 3> success = {0x01u, 0x90u, 0x00u};
  const std::array<std::uint8_t, 3> continuation = {0x01u, 0x61u, 0x05u};
  const std::array<std::uint8_t, 3> ctap_getresponse = {0x01u, 0x91u, 0x00u};
  const std::array<std::uint8_t, 3> no_status = {0x01u, 0x60u, 0x00u};

  EXPECT_TRUE(reader_iso_dep_apdu_response_has_status_word(success.data(), success.size()));
  EXPECT_TRUE(
      reader_iso_dep_apdu_response_has_status_word(continuation.data(), continuation.size()));
  EXPECT_TRUE(
      reader_iso_dep_apdu_response_has_status_word(ctap_getresponse.data(), ctap_getresponse.size()));
  EXPECT_FALSE(reader_iso_dep_apdu_response_has_status_word(no_status.data(), no_status.size()));
  EXPECT_FALSE(reader_iso_dep_apdu_response_has_status_word(NERO_NFC_NULL, 0u));
}

TEST(ReaderIsoDepStatus, TrimsResidualCrcAfterSuccessStatus) {
  const std::array<std::uint8_t, 6> resp = {0x00u, 0xA1u, 0x90u,
                                            0x00u, 0x65u, 0x39u};

  EXPECT_EQ(reader_iso_dep_trim_crc_suffix(resp.data(), resp.size()), 4u);
}

TEST(ReaderIsoDepStatus, DetectsIso14443aCrcSuffix) {
  const std::array<std::uint8_t, 7> frame = {0x02u, 0x00u, 0xA1u, 0x90u,
                                             0x00u, 0x88u, 0x5Au};
  const std::array<std::uint8_t, 7> no_crc = {0x02u, 0x00u, 0xA1u, 0x90u,
                                              0x00u, 0x90u, 0x00u};

  EXPECT_TRUE(reader_iso_dep_has_crc_a_suffix(frame.data(), frame.size()));
  EXPECT_FALSE(reader_iso_dep_has_crc_a_suffix(no_crc.data(), no_crc.size()));
  EXPECT_EQ(
      reader_iso_dep_chained_crc_tail_len(0x12u, frame.data(), frame.size()),
      2u);
  EXPECT_EQ(
      reader_iso_dep_chained_crc_tail_len(0x02u, frame.data(), frame.size()),
      0u);
}

TEST(ReaderIsoDepStatus, TrimsResidualCrcThatLooksLikeCommandError) {
  const std::array<std::uint8_t, 6> resp = {0x00u, 0xA1u, 0x90u,
                                            0x00u, 0x69u, 0x01u};

  EXPECT_EQ(reader_iso_dep_trim_crc_suffix(resp.data(), resp.size()), 4u);
}

TEST(ReaderIsoDepStatus, TrimsResidualCrcAfterGetResponseStatus) {
  const std::array<std::uint8_t, 6> resp = {0x00u, 0xA1u, 0x61u,
                                            0x00u, 0x65u, 0x39u};

  EXPECT_EQ(reader_iso_dep_trim_crc_suffix(resp.data(), resp.size()), 4u);
}

TEST(ReaderIsoDepStatus, KeepsUnchainedGetResponseStatus) {
  const std::array<std::uint8_t, 4> resp = {0x00u, 0xA1u, 0x61u, 0x00u};

  EXPECT_EQ(reader_iso_dep_trim_crc_suffix(resp.data(), resp.size()),
            resp.size());
}

TEST(ReaderIsoDepStatus, KeepsCommandErrorWithoutPrecedingStatus) {
  const std::array<std::uint8_t, 4> resp = {0x01u, 0x02u, 0x69u, 0xFFu};

  EXPECT_EQ(reader_iso_dep_trim_crc_suffix(resp.data(), resp.size()),
            resp.size());
}

TEST(ReaderSecurityKeyIsoDepSession, RejectsShortRatsCommit) {
  const std::array<std::uint8_t, 1> rx = {0x06u};

  reader_context_reset(&g_reader);
  EXPECT_FALSE(reader_security_key_iso_dep_commit_rats_rx(1, rx.data(), 0x70u));
  EXPECT_EQ(g_block_num, 0u);
}

TEST(ReaderSecurityKeyIsoDepSession, CommitRatsStoresAtsAndResetsBlockNum) {
  /* [ISO14443-4] §5.2.5 — TL (byte 0) equals the ATS length including itself. */
  const std::array<std::uint8_t, 4> rx = {0x04u, 0x75u, 0x77u, 0x81u};

  reader_context_reset(&g_reader);
  g_block_num = 1u;
  ASSERT_TRUE(reader_security_key_iso_dep_commit_rats_rx(4, rx.data(), 0x70u));
  EXPECT_EQ(g_ats_len, 4u);
  EXPECT_EQ(g_ats_data[0], 0x04u);
  EXPECT_EQ(g_iso_dep_rats_param, 0x70u);
  EXPECT_EQ(g_block_num, 0u);
}

TEST(ReaderSecurityKeyIsoDepSession, CommitRatsUsesTlAndDropsTrailingBytes) {
  /* TL=0x03 with extra received bytes (e.g. CRC): only the TL-length ATS is kept. */
  const std::array<std::uint8_t, 5> rx = {0x03u, 0x75u, 0x77u, 0xAAu, 0xBBu};

  reader_context_reset(&g_reader);
  ASSERT_TRUE(reader_security_key_iso_dep_commit_rats_rx(5, rx.data(), 0x70u));
  EXPECT_EQ(g_ats_len, 3u);
  EXPECT_EQ(g_ats_data[0], 0x03u);
}

TEST(ReaderSecurityKeyIsoDepSession, CommitRatsRejectsTruncatedAtsByTl) {
  /* TL claims 6 bytes but only 4 were received: fail closed, do not relay. */
  const std::array<std::uint8_t, 4> rx = {0x06u, 0x75u, 0x77u, 0x81u};

  reader_context_reset(&g_reader);
  EXPECT_FALSE(reader_security_key_iso_dep_commit_rats_rx(4, rx.data(), 0x70u));
}

TEST(ReaderSecurityKeyIsoDepSession, ProbeCanUpgradeWhenTcAdvertisesCid) {
  reader_context_reset(&g_reader);
  g_iso_dep_have_tc = true;
  g_iso_dep_tc_byte = 0x02u;
  g_iso_dep_pcb_has_cid = false;
  EXPECT_TRUE(reader_security_key_iso_dep_probe_can_upgrade_cid());

  g_iso_dep_pcb_has_cid = true;
  EXPECT_FALSE(reader_security_key_iso_dep_probe_can_upgrade_cid());
}

TEST(ReaderSecurityKeyIsoDepSession, TxAddNadRequiresCidFraming) {
  const std::array<std::uint8_t, 4> apdu = {0x00u, 0xA4u, 0x04u, 0x00u};

  reader_context_reset(&g_reader);
  g_iso_dep_have_tc = true;
  g_iso_dep_tc_byte = 0x01u;
  g_iso_dep_pcb_has_cid = false;
  g_iso_dep_pic_frame_max = 256u;
  EXPECT_FALSE(reader_security_key_iso_dep_tx_add_nad(apdu.size(), apdu.data()));

  g_iso_dep_pcb_has_cid = true;
  EXPECT_TRUE(reader_security_key_iso_dep_tx_add_nad(apdu.size(), apdu.data()));

  const std::array<std::uint8_t, 1> ctap = {0x80u};
  EXPECT_FALSE(reader_security_key_iso_dep_tx_add_nad(ctap.size(), ctap.data()));
}

TEST(ReaderCcIdStorage, GetDataUidReturns6F00WhenResponseBufferTooSmall) {
  const uint8_t apdu[] = {0xFFu, 0xCAu, 0x00u, 0x00u, 0x00u};
  uint8_t rsp[2];
  for (uint8_t i = 0u; i < NFC_FRONTEND_ISO15693_UID_LEN; ++i) {
    g_uid15[i] = 0xABu;
  }
  g_tag_kind = READER_TAG_KIND_TYPE5;
  const uint16_t rlen =
    reader_ccid_handle_get_data_apdu(apdu, (uint16_t)sizeof(apdu), rsp, (uint16_t)sizeof(rsp));
  EXPECT_EQ(rlen, 2u);
  EXPECT_EQ(rsp[0], 0x6Fu);
  EXPECT_EQ(rsp[1], 0x00u);
}

TEST(ReaderCcIdStorage, StorageGetDataDispatchesExtendedPcscIdentifiers) {
  const uint8_t apdu[] = {0xFFu, 0xCAu, NFC_PCSC_GET_DATA_TYPE5_CC, 0x00u, 0x00u};
  uint8_t rsp[8];

  g_tag_kind = READER_TAG_KIND_TYPE5;
  const uint16_t rlen =
    reader_ccid_handle_get_data_apdu(apdu, (uint16_t)sizeof(apdu), rsp, (uint16_t)sizeof(rsp));

  ASSERT_EQ(rlen, 2u);
  EXPECT_EQ(rsp[0], (uint8_t)NFC_ISO7816_SW1_WRONG_DATA);
  EXPECT_EQ(rsp[1], (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
}
