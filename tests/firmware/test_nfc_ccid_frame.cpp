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
#include "ccid_usb_desc.h"
#include "nfc_ccid_frame.h"
#include "nfc_ctap_codec.h"

namespace {
enum {
  kTestLit0x01020304u = 0x01020304u,
  kTestLit0x02u = 0x02u,
  kTestLit0x03u = 0x03u,
  kTestLit0x04u = 0x04u,
  kTestLit0x05u = 0x05u,
  kTestLit0x07u = 0x07u,
  kTestLit0x08u = 0x08u,
  kTestLit0x23u = 0x23u,
  kTestLit0x42u = 0x42u,
  kTestLit0xA5A5A5A5u = 0xA5A5A5A5u,
  kTestLit0xA5u = 0xA5u,
  kTestLit0xAAu = 0xAAu,
  kTestLit0xBBu = 0xBBu,
  kTestLit0xFFu = 0xFFu,
  kTestLit10 = 10,
  kTestLit12 = 12,
  kTestLit16 = 16,
  kTestLit20 = 20,
  kTestLit20u = 20u,
  kTestLit4 = 4,
  kTestLit510u = 510u,
  kTestLit6 = 6,
  kTestLit8 = 8,
};
}  // namespace

#include <gtest/gtest.h>

#include <cstring>

namespace {
enum {
  kCtapSelectApduScratchCap = 192u,
  kCtapLongCborScratchCap = 134u,
};
}  // namespace

TEST(NfcCcidFrame, WorkBufferSizingMatchesFirmwareRelayCap) {
  EXPECT_EQ(NFC_CCID_WORK_BUF_SIZE, 2060u);
  EXPECT_EQ(NFC_CCID_MAX_XFR_PAYLOAD, 2050u);
  EXPECT_EQ(NFC_CCID_RSP_DATA_CAP, 510u);
  EXPECT_EQ(NFC_CCID_EXTENDED_RSP_BUF_SIZE, 2050u);
  EXPECT_EQ(NFC_CCID_BULK_HEADER_LEN + NFC_CCID_MAX_XFR_PAYLOAD,
            NFC_CCID_WORK_BUF_SIZE);
}

TEST(NfcCcidFrame, UsbDescriptorAdvertisesExtendedApduLimits) {
  EXPECT_EQ(NERO_CCID_DESC_MAX_MESSAGE_LENGTH, 2060u);
  EXPECT_EQ(NERO_CCID_DESC_DW_FEATURES & 0x00020000u, 0u);
  EXPECT_NE(NERO_CCID_DESC_DW_FEATURES & 0x00040000u, 0u);
  EXPECT_EQ(NERO_CCID_DESC_DEFAULT_CLOCK_KHZ, 13560u);
  EXPECT_EQ(NERO_CCID_DESC_MAX_CLOCK_KHZ, 13560u);
  EXPECT_EQ(NERO_CCID_DESC_DEFAULT_DATA_RATE_BPS, 106000u);
  EXPECT_EQ(NERO_CCID_DESC_MAX_DATA_RATE_BPS, 848000u);
}

TEST(NfcCcidFrame, DefinesCommercialReaderMaintenanceCommands) {
  EXPECT_EQ(NFC_CCID_MSG_PC_TO_RDR_ICC_POWER_ON, 0x62u);
  EXPECT_EQ(NFC_CCID_MSG_PC_TO_RDR_ICC_POWER_OFF, 0x63u);
  EXPECT_EQ(NFC_CCID_MSG_PC_TO_RDR_SLOTSTATUS, 0x65u);
  EXPECT_EQ(NFC_CCID_MSG_PC_TO_RDR_GET_PARAMETERS, 0x6Cu);
  EXPECT_EQ(NFC_CCID_MSG_PC_TO_RDR_RESET_PARAMETERS, 0x6Du);
  EXPECT_EQ(NFC_CCID_MSG_PC_TO_RDR_SET_PARAMETERS, 0x61u);
  EXPECT_EQ(NFC_CCID_MSG_PC_TO_RDR_ESCAPE, 0x6Bu);
  EXPECT_EQ(NFC_CCID_MSG_PC_TO_RDR_ABORT, 0x72u);
  EXPECT_EQ(NFC_CCID_MSG_RDR_TO_PC_DATABLOCK, 0x80u);
  EXPECT_EQ(NFC_CCID_MSG_RDR_TO_PC_PARAMETERS, 0x82u);
  EXPECT_EQ(NFC_CCID_MSG_RDR_TO_PC_ESCAPE, 0x83u);
  EXPECT_EQ(NFC_CCID_MSG_PC_TO_RDR_ICC_CLOCK, 0x6Eu);
  EXPECT_EQ(NFC_CCID_MSG_PC_TO_RDR_T0_APDU, 0x6Au);
  EXPECT_EQ(NFC_CCID_MSG_PC_TO_RDR_SECURE, 0x69u);
  EXPECT_EQ(NFC_CCID_MSG_PC_TO_RDR_MECHANICAL, 0x71u);
  EXPECT_EQ(NFC_CCID_MSG_PC_TO_RDR_SET_DATA_RATE_AND_CLOCK, 0x73u);
  EXPECT_EQ(NFC_CCID_MSG_RDR_TO_PC_DATA_RATE_AND_CLOCK, 0x84u);
  EXPECT_EQ(NFC_CCID_CONTROL_ABORT, 0x01u);
  EXPECT_EQ(NFC_CCID_CONTROL_GET_CLOCK_FREQUENCIES, 0x02u);
  EXPECT_EQ(NFC_CCID_CONTROL_GET_DATA_RATES, 0x03u);
}

TEST(NfcCcidFrame, MatchesCcidAbortControlRequest) {
  uint8_t slot = kTestLit0xFFu;
  uint8_t seq = kTestLit0xFFu;
  EXPECT_TRUE(nfc_ccid_control_abort_request_matches(
      0x21u, NFC_CCID_CONTROL_ABORT, 0x3400u, 0x0002u, 0x0000u, 0x02u, &slot,
      &seq));
  EXPECT_EQ(slot, 0x00u);
  EXPECT_EQ(seq, 0x34u);
}

TEST(NfcCcidFrame, MatchesCcidAbortControlRequestForBoundedSlot) {
  uint8_t slot = kTestLit0xFFu;
  uint8_t seq = kTestLit0xFFu;

  EXPECT_TRUE(nfc_ccid_control_abort_request_matches_slot(
      0x21u, NFC_CCID_CONTROL_ABORT, 0x3400u, 0x0002u, 0x0000u, 0x02u, 0u,
      &slot, &seq));
  EXPECT_EQ(slot, 0x00u);
  EXPECT_EQ(seq, 0x34u);

  slot = kTestLit0xAAu;
  seq = kTestLit0xBBu;
  EXPECT_FALSE(nfc_ccid_control_abort_request_matches_slot(
      0x21u, NFC_CCID_CONTROL_ABORT, 0x3401u, 0x0002u, 0x0000u, 0x02u, 0u,
      &slot, &seq));
  EXPECT_EQ(slot, 0u);
  EXPECT_EQ(seq, 0u);
}

TEST(NfcCcidFrame, RejectsNonAbortControlRequests) {
  uint8_t slot = kTestLit0xAAu;
  uint8_t seq = kTestLit0xBBu;
  EXPECT_FALSE(nfc_ccid_control_abort_request_matches(
      0xA1u, NFC_CCID_CONTROL_ABORT, 0x0100u, 0x0002u, 0x0000u, 0x02u, &slot,
      &seq));
  EXPECT_FALSE(nfc_ccid_control_abort_request_matches(
      0x21u, NFC_CCID_CONTROL_GET_DATA_RATES, 0x0100u, 0x0002u, 0x0000u, 0x02u,
      &slot, &seq));
  EXPECT_FALSE(nfc_ccid_control_abort_request_matches(
      0x21u, NFC_CCID_CONTROL_ABORT, 0x0100u, 0x0003u, 0x0000u, 0x02u, &slot,
      &seq));
  EXPECT_FALSE(nfc_ccid_control_abort_request_matches(
      0x21u, NFC_CCID_CONTROL_ABORT, 0x0100u, 0x0002u, 0x0001u, 0x02u, &slot,
      &seq));
  EXPECT_EQ(slot, 0u);
  EXPECT_EQ(seq, 0u);
}

TEST(NfcCcidFrame, U32LittleEndianRoundTrip) {
  uint8_t buf[kTestLit4]{};
  nfc_ccid_u32_store_le(&buf[0], kTestLit0x01020304u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&buf[0]), 0x01020304u);
}

TEST(NfcCcidFrame, U32HelpersIgnoreNullBuffers) {
  nfc_ccid_u32_store_le(NERO_NFC_NULL, kTestLit0x01020304u);
  EXPECT_EQ(nfc_ccid_u32_load_le(NERO_NFC_NULL), 0u);
}

TEST(NfcCcidFrame, ValidatesBulkFrameLength) {
  uint8_t frame[kTestLit20] = {NFC_CCID_MSG_PC_TO_RDR_XFR,
                               kTestLit0x04u,
                               0x00u,
                               0x00u,
                               0x00u,
                               0x00u,
                               kTestLit0x07u,
                               0x00u,
                               0x00u,
                               0x00u};
  uint32_t data_len = 0;

  ASSERT_TRUE(nfc_ccid_bulk_frame_validate(&frame[0], 14u, &data_len));
  EXPECT_EQ(data_len, 4u);
}

TEST(NfcCcidFrame, RejectsOversizedBulkPayload) {
  uint8_t frame[kTestLit16] = {NFC_CCID_MSG_PC_TO_RDR_XFR,
                               kTestLit0x03u,
                               kTestLit0x08u,
                               0x00u,
                               0x00u,
                               0x00u,
                               0x01u,
                               0x00u,
                               0x00u,
                               0x00u};
  EXPECT_FALSE(
      nfc_ccid_bulk_frame_validate(&frame[0], sizeof(frame), NERO_NFC_NULL));
}

TEST(NfcCcidFrame, RejectsTruncatedBulkFrame) {
  uint8_t frame[kTestLit12] = {NFC_CCID_MSG_PC_TO_RDR_XFR,
                               kTestLit0x08u,
                               0x00u,
                               0x00u,
                               0x00u,
                               0x00u,
                               kTestLit0x02u,
                               0x00u,
                               0x00u,
                               0x00u};
  EXPECT_FALSE(
      nfc_ccid_bulk_frame_validate(&frame[0], sizeof(frame), NERO_NFC_NULL));
}

TEST(NfcCcidFrame, ClearsDataLengthOnInvalidBulkFrame) {
  uint8_t frame[NFC_CCID_BULK_HEADER_LEN - 1u]{};
  uint32_t data_len = kTestLit0xA5A5A5A5u;

  EXPECT_FALSE(
      nfc_ccid_bulk_frame_validate(&frame[0], sizeof(frame), &data_len));
  EXPECT_EQ(data_len, 0u);
}

TEST(NfcCcidFrame, RejectsTrailingBulkBytesBeyondDwLength) {
  uint8_t frame[kTestLit12] = {NFC_CCID_MSG_PC_TO_RDR_XFR,
                               0x00u,
                               0x00u,
                               0x00u,
                               0x00u,
                               0x00u,
                               kTestLit0x02u,
                               0x00u,
                               0x00u,
                               0x00u};
  EXPECT_FALSE(
      nfc_ccid_bulk_frame_validate(&frame[0], sizeof(frame), NERO_NFC_NULL));
}

TEST(NfcCcidFrame, RejectsShortBulkHeader) {
  uint8_t frame[NFC_CCID_BULK_HEADER_LEN - 1u]{};
  EXPECT_FALSE(
      nfc_ccid_bulk_frame_validate(&frame[0], sizeof(frame), NERO_NFC_NULL));
}

TEST(NfcCcidFrame, EncodesSlotStatusReplyHeader) {
  uint8_t buf[kTestLit10]{};
  nfc_ccid_encode_slot_status(&buf[0], NFC_CCID_MSG_RDR_TO_PC_SLOTSTATUS,
                              kTestLit0x42u, NFC_CCID_ICC_ACTIVE, 0x00u);

  EXPECT_EQ(buf[0], NFC_CCID_MSG_RDR_TO_PC_SLOTSTATUS);
  EXPECT_EQ(buf[6], 0x42u);
  EXPECT_EQ(buf[7], NFC_CCID_ICC_ACTIVE);
  EXPECT_EQ(nfc_ccid_u32_load_le(&buf[1]), 0u);
}

TEST(NfcCcidFrame, EncodesDataBlockReplyHeader) {
  uint8_t buf[kTestLit10]{};
  nfc_ccid_encode_data_block_header(&buf[0], NFC_CCID_MSG_RDR_TO_PC_DATABLOCK,
                                    kTestLit0x03u, kTestLit20u,
                                    NFC_CCID_ICC_ACTIVE, 0u);

  EXPECT_EQ(buf[0], NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
  EXPECT_EQ(buf[6], 0x03u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&buf[1]), 20u);
  EXPECT_EQ(buf[9], 0u);
}

TEST(NfcCcidFrame, EncodesResponseChainingMarkers) {
  uint8_t buf[kTestLit10]{};
  nfc_ccid_encode_data_block_header(
      &buf[0], NFC_CCID_MSG_RDR_TO_PC_DATABLOCK, kTestLit0x05u, kTestLit510u,
      NFC_CCID_ICC_ACTIVE, NFC_CCID_XFR_LEVEL_CHAIN_BEGIN);
  EXPECT_EQ(buf[9], NFC_CCID_XFR_LEVEL_CHAIN_BEGIN);

  nfc_ccid_encode_data_block_header(
      &buf[0], NFC_CCID_MSG_RDR_TO_PC_DATABLOCK, kTestLit0x05u, kTestLit510u,
      NFC_CCID_ICC_ACTIVE, NFC_CCID_XFR_LEVEL_CHAIN_MIDDLE);
  EXPECT_EQ(buf[9], NFC_CCID_XFR_LEVEL_CHAIN_MIDDLE);

  nfc_ccid_encode_data_block_header(
      &buf[0], NFC_CCID_MSG_RDR_TO_PC_DATABLOCK, kTestLit0x05u, kTestLit20u,
      NFC_CCID_ICC_ACTIVE, NFC_CCID_XFR_LEVEL_CHAIN_END);
  EXPECT_EQ(buf[9], NFC_CCID_XFR_LEVEL_CHAIN_END);
}

TEST(NfcCcidFrame, DetectsHostResponseContinuationRequest) {
  uint8_t frame[kTestLit10]{};
  frame[0] = NFC_CCID_MSG_PC_TO_RDR_XFR;
  frame[kTestLit6] = kTestLit0x23u;
  frame[kTestLit8] = NFC_CCID_XFR_RESPONSE_CONTINUE;

  EXPECT_TRUE(nfc_ccid_xfr_frame_requests_response_continuation(&frame[0],
                                                                sizeof(frame)));

  frame[kTestLit8] = 0u;
  EXPECT_FALSE(nfc_ccid_xfr_frame_requests_response_continuation(
      &frame[0], sizeof(frame)));

  frame[0] = NFC_CCID_MSG_PC_TO_RDR_SLOTSTATUS;
  frame[kTestLit8] = NFC_CCID_XFR_RESPONSE_CONTINUE;
  EXPECT_FALSE(nfc_ccid_xfr_frame_requests_response_continuation(
      &frame[0], sizeof(frame)));
}

TEST(NfcCcidFrame, TimeExtensionThresholdMatchesFirmwarePolicy) {
  EXPECT_EQ(NFC_CCID_TIME_EXTENSION_APDU_LEN_THRESHOLD, 64u);
}

TEST(NfcCcidFrame, EncodesSpecCcidTimeExtensionDataBlock) {
  uint8_t buf[kTestLit10]{};

  nfc_ccid_encode_data_block_header(
      &buf[0], NFC_CCID_MSG_RDR_TO_PC_DATABLOCK, kTestLit0x42u, 0u,
      static_cast<uint8_t>(NFC_CCID_ICC_CMD_TIME_EXTENSION |
                           NFC_CCID_ICC_ACTIVE),
      NFC_CCID_XFR_LEVEL_SINGLE);
  buf[kTestLit8] = NFC_CCID_TIME_EXTENSION_BWT_MULTIPLIER;

  EXPECT_EQ(buf[0], NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
  EXPECT_EQ(nfc_ccid_u32_load_le(&buf[1]), 0u);
  EXPECT_EQ(buf[6], 0x42u);
  EXPECT_EQ(buf[7], NFC_CCID_ICC_CMD_TIME_EXTENSION);
  EXPECT_EQ(buf[8], NFC_CCID_TIME_EXTENSION_BWT_MULTIPLIER);
  EXPECT_EQ(buf[9], NFC_CCID_XFR_LEVEL_SINGLE);
}

TEST(NfcCcidFrame, XfrTimeExtensionPolicyMatchesWebAuthnFidoFlow) {
  const uint8_t kCbor[] = {0xA1u, 0x01u, 0x02u};
  uint8_t apdu[kCtapSelectApduScratchCap]{};
  uint16_t apdu_len = 0;

  ASSERT_TRUE(
      nfc_ctap_pack_select_fido_apdu(true, &apdu[0], sizeof(apdu), &apdu_len));
  EXPECT_TRUE(nfc_ccid_xfr_payload_needs_time_extension(&apdu[0], apdu_len));

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_GET_INFO, &kCbor[0], 1u,
                                      false, &apdu[0], sizeof(apdu),
                                      &apdu_len));
  EXPECT_FALSE(nfc_ccid_xfr_payload_needs_time_extension(&apdu[0], apdu_len));

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_CLIENT_PIN, &kCbor[0],
                                      sizeof(kCbor), false, &apdu[0],
                                      sizeof(apdu), &apdu_len));
  EXPECT_TRUE(nfc_ccid_xfr_payload_needs_time_extension(&apdu[0], apdu_len));

  uint8_t long_cbor[kCtapLongCborScratchCap]{};
  for (unsigned char& i : long_cbor) {
    i = kTestLit0xA5u;
  }
  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_CLIENT_PIN, &long_cbor[0],
                                      sizeof(long_cbor), false, &apdu[0],
                                      sizeof(apdu), &apdu_len));
  EXPECT_TRUE(nfc_ccid_xfr_payload_needs_time_extension(&apdu[0], apdu_len));

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_MAKE_CREDENTIAL, &kCbor[0],
                                      sizeof(kCbor), false, &apdu[0],
                                      sizeof(apdu), &apdu_len));
  EXPECT_TRUE(nfc_ccid_xfr_payload_needs_time_extension(&apdu[0], apdu_len));

  ASSERT_TRUE(nfc_ctap_pack_cbor_apdu(NFC_CTAP_CMD_GET_ASSERTION, &kCbor[0],
                                      sizeof(kCbor), false, &apdu[0],
                                      sizeof(apdu), &apdu_len));
  EXPECT_TRUE(nfc_ccid_xfr_payload_needs_time_extension(&apdu[0], apdu_len));
}
