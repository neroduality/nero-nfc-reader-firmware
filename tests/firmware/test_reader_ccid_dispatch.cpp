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

#include "reader_ccid.h"
#include "reader_ccid_internal.h"
#include "reader_ccid_utest.h"
#include "reader_context.h"
#include "reader_hal_utest.h"
#include "reader_security_key_utest_stub.h"

#include "nero_nfc_mem_util.h"
#include "nfc_ccid_frame.h"
#include "nfc_pcsc_contactless.h"
#include "nfc_storage_ndef.h"
#include "nfc_tag_geometry_limits.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <vector>

extern "C" {
void reader_tags_utest_reset(void);
void reader_tags_utest_set_type2_storage_info(uint16_t data_area_size, bool read_open,
                                              bool write_open);
void reader_tags_utest_set_type5_info(uint16_t cc_len, uint16_t data_area_size,
                                      uint16_t block_count, bool read_open, bool write_open);
void reader_tags_utest_set_type2_write_ok(bool ok);
void reader_tags_utest_set_type5_write_ok(bool ok);
void reader_tags_utest_set_type2_transceive_response(const uint8_t *rsp, uint16_t len);
uint16_t reader_tags_utest_type2_write_count(void);
uint16_t reader_tags_utest_type5_write_count(void);
uint16_t reader_tags_utest_type5_read_count(void);
uint16_t reader_tags_utest_type5_last_read_block(void);
uint16_t reader_tags_utest_type5_last_read_len(void);
uint16_t reader_tags_utest_type2_transceive_count(void);
uint16_t reader_tags_utest_type5_transceive_count(void);
}

class ReaderCcidDispatchTest : public ::testing::Test {
protected:
  static constexpr uint16_t kSwPayloadEnd =
    static_cast<uint16_t>(NFC_CCID_BULK_PAYLOAD_OFFSET) + static_cast<uint16_t>(NFC_ISO7816_SW_LEN);

  void SetUp() override {
    reader_ccid_utest_setup();
    reader_ccid_utest_reset();
    reader_tags_utest_reset();
  }

  static std::array<uint8_t, 10> make_bulk(uint8_t msg_type, uint8_t seq) {
    std::array<uint8_t, 10> frame{};
    frame[0] = msg_type;
    frame[6] = seq;
    return frame;
  }

  static std::vector<uint8_t> make_xfr(uint8_t seq, const std::vector<uint8_t> &payload) {
    std::vector<uint8_t> frame(NFC_CCID_BULK_HEADER_LEN, 0u);
    frame[0] = NFC_CCID_MSG_PC_TO_RDR_XFR;
    nfc_ccid_u32_store_le(&frame[1], static_cast<uint32_t>(payload.size()));
    frame[6] = seq;
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
  }

  static std::vector<uint8_t> make_xfr_chain(uint8_t seq, uint8_t level,
                                             const std::vector<uint8_t> &payload) {
    std::vector<uint8_t> frame = make_xfr(seq, payload);
    frame[NFC_CCID_BULK_LEVEL_PARAM2_OFFSET] = level;
    return frame;
  }

  static void power_on_storage_tag(reader_tag_kind_t kind) {
    reader_ccid_on_tag_detected(kind);
    auto power_on = make_bulk(NFC_CCID_MSG_PC_TO_RDR_ICC_POWER_ON, 0x70u);
    reader_ccid_utest_handle_bulk(power_on.data(), (uint16_t)power_on.size());
  }

  static void set_type5_uid_for_tests() {
    const std::array<uint8_t, NFC_FRONTEND_ISO15693_UID_LEN> uid = {
      0xE0u, 0x02u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u,
    };
    EXPECT_TRUE(nero_nfc_copy_bytes(g_uid15, NFC_FRONTEND_ISO15693_UID_LEN, 0u, uid.data(),
                                    static_cast<uint16_t>(uid.size())));
  }

  static std::vector<uint8_t> mismatched_type5_uid_lsb() {
    return {
      0x99u, 0x88u, 0x77u, 0x66u, 0x55u, 0x44u, 0x33u, 0x22u,
    };
  }

  static std::vector<uint8_t> make_select_ndef_app_apdu() {
    return {
      (uint8_t)NFC_ISO7816_CLA_ISO,
      (uint8_t)NFC_ISO7816_INS_SELECT,
      (uint8_t)NFC_ISO7816_P1_SELECT_BY_DF_NAME,
      (uint8_t)NFC_ISO7816_P2_SELECT_FIRST,
      (uint8_t)NFC_PCSC_NDEF_APP_AID_LEN,
      0xD2u,
      0x76u,
      0x00u,
      0x00u,
      0x85u,
      0x01u,
      0x01u,
      0x00u,
    };
  }

  static std::vector<uint8_t> make_acr122_direct_apdu(const std::vector<uint8_t> &pn53x) {
    std::vector<uint8_t> apdu = {
      (uint8_t)NFC_ISO7816_CLA_PROPRIETARY,
      (uint8_t)NFC_ISO7816_CLA_ISO,
      (uint8_t)NFC_ISO7816_CLA_ISO,
      (uint8_t)NFC_ISO7816_CLA_ISO,
      static_cast<uint8_t>(pn53x.size()),
    };
    apdu.insert(apdu.end(), pn53x.begin(), pn53x.end());
    return apdu;
  }
};

TEST_F(ReaderCcidDispatchTest, SlotStatusReportsNoIccWhenEmpty) {
  auto frame = make_bulk(NFC_CCID_MSG_PC_TO_RDR_SLOTSTATUS, 0x11u);
  reader_ccid_utest_handle_bulk(frame.data(), (uint16_t)frame.size());
  ASSERT_GE(reader_ccid_utest_last_send_len(), 10u);
  const uint8_t *rsp = reader_ccid_utest_last_send();
  EXPECT_EQ(rsp[0], NFC_CCID_MSG_RDR_TO_PC_SLOTSTATUS);
  EXPECT_EQ(rsp[6], 0x11u);
  EXPECT_EQ(rsp[7] & 0x03u, 0x02u);
}

TEST_F(ReaderCcidDispatchTest, SlotStatusReportsInactiveWhenTagPresent) {
  reader_ccid_on_tag_detected(READER_TAG_KIND_TYPE4);
  auto frame = make_bulk(NFC_CCID_MSG_PC_TO_RDR_SLOTSTATUS, 0x12u);
  reader_ccid_utest_handle_bulk(frame.data(), (uint16_t)frame.size());
  const uint8_t *rsp = reader_ccid_utest_last_send();
  EXPECT_EQ(rsp[0], NFC_CCID_MSG_RDR_TO_PC_SLOTSTATUS);
  EXPECT_EQ(rsp[7] & 0x03u, 0x01u);
}

TEST_F(ReaderCcidDispatchTest, IccPowerOnReturnsAtrForType4Tag) {
  reader_ccid_on_tag_detected(READER_TAG_KIND_TYPE4);
  auto frame = make_bulk(0x62u, 0x20u);
  reader_ccid_utest_handle_bulk(frame.data(), (uint16_t)frame.size());
  const uint8_t *rsp = reader_ccid_utest_last_send();
  EXPECT_EQ(rsp[0], NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
  EXPECT_GT(nfc_ccid_u32_load_le(&rsp[1]), 0u);
}

TEST_F(ReaderCcidDispatchTest, IccPowerOnWithoutCardRepliesDataBlockError) {
  /* [CCID1.10] Rev 1.10 §6.2.1 — IccPowerOn always answers with RDR_to_PC_DataBlock,
   * even on failure: dwLength=0, bmCommandStatus=failed, bError set. */
  auto frame = make_bulk(0x62u, 0x33u);
  reader_ccid_utest_handle_bulk(frame.data(), (uint16_t)frame.size());
  ASSERT_GE(reader_ccid_utest_last_send_len(), 10u);
  const uint8_t *rsp = reader_ccid_utest_last_send();
  EXPECT_EQ(rsp[0], NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
  EXPECT_EQ(rsp[6], 0x33u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&rsp[1]), 0u);
  EXPECT_EQ(rsp[7] & 0xC0u, 0x40u); /* bmCommandStatus = failed */
  EXPECT_EQ(rsp[7] & 0x03u, 0x02u); /* bmICCStatus = no ICC */
  EXPECT_EQ(rsp[8], 0xFEu);         /* bError = ICC mute */
}

TEST_F(ReaderCcidDispatchTest, IccPowerOnDoesNotSendPrematureTimeExtensionBeforeType4Atr) {
  reader_ccid_on_tag_detected(READER_TAG_KIND_TYPE4);
  auto frame = make_bulk(0x62u, 0x22u);
  reader_ccid_utest_handle_bulk(frame.data(), (uint16_t)frame.size());

  ASSERT_GE(reader_hal_utest_ccid_last_send_len(), 10u);
  const uint8_t *rsp = reader_ccid_utest_last_send();
  EXPECT_EQ(reader_hal_utest_ccid_send_count(), 1u);
  EXPECT_EQ(reader_hal_utest_ccid_time_extension_send_count(), 0u);
  EXPECT_EQ(rsp[0], NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
  EXPECT_EQ(rsp[6], 0x22u);
  EXPECT_EQ(rsp[7] & NFC_CCID_ICC_CMD_TIME_EXTENSION, 0u);
  EXPECT_GT(nfc_ccid_u32_load_le(&rsp[1]), 0u);
}

TEST_F(ReaderCcidDispatchTest, IccClockReturnsNotSupported) {
  reader_ccid_on_tag_detected(READER_TAG_KIND_TYPE4);
  auto frame = make_bulk(NFC_CCID_MSG_PC_TO_RDR_ICC_CLOCK, 0x21u);
  reader_ccid_utest_handle_bulk(frame.data(), (uint16_t)frame.size());
  const uint8_t *rsp = reader_ccid_utest_last_send();
  EXPECT_EQ(rsp[0], NFC_CCID_MSG_RDR_TO_PC_SLOTSTATUS);
  EXPECT_EQ(rsp[7] & 0x40u, 0x40u);
}

TEST_F(ReaderCcidDispatchTest, RejectsNonZeroSlot) {
  auto frame = make_bulk(NFC_CCID_MSG_PC_TO_RDR_SLOTSTATUS, 0x30u);
  frame[5] = 0x01u;
  reader_ccid_utest_handle_bulk(frame.data(), (uint16_t)frame.size());
  const uint8_t *rsp = reader_ccid_utest_last_send();
  EXPECT_EQ(rsp[0], NFC_CCID_MSG_RDR_TO_PC_SLOTSTATUS);
  EXPECT_EQ(rsp[8], 0x05u);
}

TEST_F(ReaderCcidDispatchTest, ActiveRemovalNotifiesAndTearsDownSession) {
  reader_ccid_on_tag_detected(READER_TAG_KIND_TYPE4);
  EXPECT_EQ(reader_hal_utest_ccid_notify_count(), 1u);
  EXPECT_TRUE(reader_hal_utest_ccid_last_notify_present());

  auto power_on = make_bulk(0x62u, 0x23u);
  reader_ccid_utest_handle_bulk(power_on.data(), (uint16_t)power_on.size());
  EXPECT_EQ(reader_ccid_icc_status(), NFC_CCID_ICC_ACTIVE);

  reader_ccid_on_tag_removed_from_field();
  EXPECT_EQ(reader_ccid_icc_status(), NFC_CCID_ICC_NO_ICC);
  EXPECT_EQ(reader_hal_utest_ccid_notify_count(), 2u);
  EXPECT_FALSE(reader_hal_utest_ccid_last_notify_present());
}

TEST_F(ReaderCcidDispatchTest, Type4ShortXfrDoesNotSendInitialTimeExtension) {
  reader_ccid_on_tag_detected(READER_TAG_KIND_TYPE4);
  auto power_on = make_bulk(0x62u, 0x24u);
  reader_ccid_utest_handle_bulk(power_on.data(), (uint16_t)power_on.size());
  ASSERT_EQ(reader_hal_utest_ccid_time_extension_send_count(), 0u);

  std::array<uint8_t, 14> frame{};
  frame[0] = NFC_CCID_MSG_PC_TO_RDR_XFR;
  frame[1] = 0x04u;
  frame[6] = 0x41u;
  frame[10] = 0x00u;
  frame[11] = 0xA4u;
  frame[12] = 0x00u;
  frame[13] = 0x00u;
  reader_ccid_utest_handle_bulk(frame.data(), (uint16_t)frame.size());

  const uint8_t *rsp = reader_ccid_utest_last_send();
  EXPECT_EQ(reader_hal_utest_ccid_time_extension_send_count(), 0u);
  EXPECT_EQ(rsp[0], NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
  EXPECT_EQ(rsp[6], 0x41u);
  EXPECT_EQ(rsp[7] & NFC_CCID_ICC_CMD_TIME_EXTENSION, 0u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&rsp[1]), 2u);
}

TEST_F(ReaderCcidDispatchTest, XfrBlockEmptyPayloadReachesApduDispatcher) {
  reader_ccid_on_tag_detected(READER_TAG_KIND_TYPE4);
  auto power_on = make_bulk(0x62u, 0x26u);
  reader_ccid_utest_handle_bulk(power_on.data(), (uint16_t)power_on.size());
  ASSERT_EQ(reader_hal_utest_ccid_time_extension_send_count(), 0u);

  std::array<uint8_t, 10> frame{};
  frame[0] = NFC_CCID_MSG_PC_TO_RDR_XFR;
  frame[6] = 0x43u;
  reader_ccid_utest_handle_bulk(frame.data(), (uint16_t)frame.size());

  const uint8_t *rsp = reader_ccid_utest_last_send();
  ASSERT_GE(reader_ccid_utest_last_send_len(), 12u);
  EXPECT_EQ(rsp[0], NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
  EXPECT_EQ(rsp[6], 0x43u);
  EXPECT_EQ(rsp[7] & NFC_CCID_ICC_CMD_TIME_EXTENSION, 0u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&rsp[1]), 2u);
  EXPECT_EQ(rsp[10], 0x6Fu);
  EXPECT_EQ(rsp[11], 0x00u);
}

TEST_F(ReaderCcidDispatchTest, Type4FfAcr122DirectDoesNotRelayInnerFidoSelect) {
  reader_ccid_on_tag_detected(READER_TAG_KIND_TYPE4);
  auto power_on = make_bulk(0x62u, 0x27u);
  reader_ccid_utest_handle_bulk(power_on.data(), (uint16_t)power_on.size());

  const std::vector<uint8_t> payload = {
    0xFFu, 0x00u, 0x00u, 0x00u, 0x11u, 0xD4u, 0x40u, 0x01u, 0x00u, 0xA4u, 0x04u,
    0x00u, 0x08u, 0xA0u, 0x00u, 0x00u, 0x06u, 0x47u, 0x2Fu, 0x00u, 0x01u, 0x00u,
  };
  std::vector<uint8_t> frame(10u, 0u);
  frame[0] = NFC_CCID_MSG_PC_TO_RDR_XFR;
  nfc_ccid_u32_store_le(&frame[1], (uint32_t)payload.size());
  frame[6] = 0x33u;
  frame.insert(frame.end(), payload.begin(), payload.end());

  reader_ccid_utest_handle_bulk(frame.data(), (uint16_t)frame.size());

  const uint8_t *rsp = reader_ccid_utest_last_send();
  ASSERT_GE(reader_ccid_utest_last_send_len(), 15u);
  EXPECT_EQ(reader_security_key_utest_last_apdu_rsp_cap(), 0u);
  EXPECT_EQ(rsp[0], NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
  EXPECT_EQ(rsp[6], 0x33u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&rsp[1]), 5u);
  EXPECT_EQ(rsp[10], 0xD5u);
  EXPECT_EQ(rsp[11], 0x41u);
  EXPECT_EQ(rsp[12], 0x01u);
  EXPECT_EQ(rsp[13], 0x90u);
  EXPECT_EQ(rsp[14], 0x00u);
}

TEST_F(ReaderCcidDispatchTest, Type2Pn53xTunnelRejectsRawWriteBeforeRf) {
  power_on_storage_tag(READER_TAG_KIND_TYPE2);

  const std::vector<uint8_t> type2_write = {
    (uint8_t)NFC_PN532_HOST_TO_PN532,
    (uint8_t)NFC_PN532_CMD_IN_DATA_EXCHANGE,
    0x01u,
    0xA2u,
    (uint8_t)NFC_STORAGE_TYPE2_FIRST_DATA_PAGE,
    0x11u,
    0x22u,
    0x33u,
    0x44u,
  };
  auto frame = make_xfr(0x34u, make_acr122_direct_apdu(type2_write));
  reader_ccid_utest_handle_bulk(frame.data(), static_cast<uint16_t>(frame.size()));

  const uint8_t *rsp = reader_ccid_utest_last_send();
  ASSERT_GE(reader_ccid_utest_last_send_len(), static_cast<uint16_t>(NFC_CCID_BULK_PAYLOAD_OFFSET + 5u));
  EXPECT_EQ(reader_tags_utest_type2_transceive_count(), 0u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&rsp[1]), 5u);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET], (uint8_t)NFC_PN532_PN532_TO_HOST);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 1u], (uint8_t)NFC_PN532_RSP_IN_DATA_EXCHANGE);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 2u], 0x01u);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 3u], (uint8_t)NFC_ISO7816_SW1_SUCCESS);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 4u], (uint8_t)NFC_ISO7816_SW2_SUCCESS);
}

TEST_F(ReaderCcidDispatchTest, Type5Pn53xTunnelRejectsRawWriteBeforeRf) {
  power_on_storage_tag(READER_TAG_KIND_TYPE5);

  const std::vector<uint8_t> type5_write_single = {
    (uint8_t)NFC_PN532_HOST_TO_PN532,
    (uint8_t)NFC_PN532_CMD_IN_COMMUNICATE_THRU,
    (uint8_t)NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED,
    (uint8_t)NFC_TAG_T5T_ISO15693_CMD_WRITE_SINGLE,
    0x00u,
    0x01u,
    0x02u,
    0x03u,
    0x04u,
  };
  auto frame = make_xfr(0x35u, make_acr122_direct_apdu(type5_write_single));
  reader_ccid_utest_handle_bulk(frame.data(), static_cast<uint16_t>(frame.size()));

  const uint8_t *rsp = reader_ccid_utest_last_send();
  ASSERT_GE(reader_ccid_utest_last_send_len(), static_cast<uint16_t>(NFC_CCID_BULK_PAYLOAD_OFFSET + 5u));
  EXPECT_EQ(reader_tags_utest_type5_transceive_count(), 0u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&rsp[1]), 5u);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET], (uint8_t)NFC_PN532_PN532_TO_HOST);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 1u], (uint8_t)NFC_PN532_RSP_IN_COMMUNICATE_THRU);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 2u], 0x01u);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 3u], (uint8_t)NFC_ISO7816_SW1_SUCCESS);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 4u], (uint8_t)NFC_ISO7816_SW2_SUCCESS);
}

TEST_F(ReaderCcidDispatchTest, Type5TransparentEscapeRejectsRawWriteBeforeRf) {
  power_on_storage_tag(READER_TAG_KIND_TYPE5);

  const std::vector<uint8_t> escape_write = {
    (uint8_t)NFC_ISO7816_CLA_PROPRIETARY,
    (uint8_t)NFC_PCSC_ESCAPE_TRANSPARENT_INS,
    0x00u,
    0x00u,
    0x07u,
    (uint8_t)NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED,
    (uint8_t)NFC_TAG_T5T_ISO15693_CMD_WRITE_SINGLE,
    0x00u,
    0x01u,
    0x02u,
    0x03u,
    0x04u,
  };
  auto frame = make_xfr(0x36u, escape_write);
  reader_ccid_utest_handle_bulk(frame.data(), static_cast<uint16_t>(frame.size()));

  const uint8_t *rsp = reader_ccid_utest_last_send();
  ASSERT_GE(reader_ccid_utest_last_send_len(), kSwPayloadEnd);
  EXPECT_EQ(reader_tags_utest_type5_transceive_count(), 0u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&rsp[1]), (uint32_t)NFC_ISO7816_SW_LEN);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET], (uint8_t)NFC_ISO7816_SW1_INS_NOT_SUPPORTED);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 1u], (uint8_t)NFC_ISO7816_SW2_SUCCESS);
}

TEST_F(ReaderCcidDispatchTest, Type5TransparentEscapeRejectsStayQuietBeforeRf) {
  power_on_storage_tag(READER_TAG_KIND_TYPE5);

  const std::vector<uint8_t> stay_quiet = {
    (uint8_t)NFC_ISO7816_CLA_PROPRIETARY,
    (uint8_t)NFC_PCSC_ESCAPE_TRANSPARENT_INS,
    0x00u,
    0x00u,
    0x02u,
    (uint8_t)NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED,
    0x02u,
  };
  auto frame = make_xfr(0x36u, stay_quiet);
  reader_ccid_utest_handle_bulk(frame.data(), static_cast<uint16_t>(frame.size()));

  const uint8_t *rsp = reader_ccid_utest_last_send();
  ASSERT_GE(reader_ccid_utest_last_send_len(), kSwPayloadEnd);
  EXPECT_EQ(reader_tags_utest_type5_transceive_count(), 0u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&rsp[1]), (uint32_t)NFC_ISO7816_SW_LEN);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET], (uint8_t)NFC_ISO7816_SW1_INS_NOT_SUPPORTED);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 1u], (uint8_t)NFC_ISO7816_SW2_SUCCESS);
}

TEST_F(ReaderCcidDispatchTest, Type5TransparentEscapeRejectsAddressedReadForOtherUidBeforeRf) {
  reader_tags_utest_set_type5_info(NFC_TAG_T5T_CC_LEN_SHORT, 320u, 81u, true, true);
  set_type5_uid_for_tests();
  power_on_storage_tag(READER_TAG_KIND_TYPE5);

  std::vector<uint8_t> escape_read = {
    (uint8_t)NFC_ISO7816_CLA_PROPRIETARY,
    (uint8_t)NFC_PCSC_ESCAPE_TRANSPARENT_INS,
    0x00u,
    0x00u,
    (uint8_t)(2u + NFC_FRONTEND_ISO15693_UID_LEN + 1u),
    (uint8_t)NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED,
    (uint8_t)NFC_TAG_T5T_ISO15693_CMD_READ_SINGLE,
  };
  const std::vector<uint8_t> uid_lsb = mismatched_type5_uid_lsb();
  escape_read.insert(escape_read.end(), uid_lsb.begin(), uid_lsb.end());
  escape_read.push_back(0x01u);

  auto frame = make_xfr(0x38u, escape_read);
  reader_ccid_utest_handle_bulk(frame.data(), static_cast<uint16_t>(frame.size()));

  const uint8_t *rsp = reader_ccid_utest_last_send();
  ASSERT_GE(reader_ccid_utest_last_send_len(), kSwPayloadEnd);
  EXPECT_EQ(reader_tags_utest_type5_transceive_count(), 0u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&rsp[1]), (uint32_t)NFC_ISO7816_SW_LEN);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET], (uint8_t)NFC_ISO7816_SW1_INS_NOT_SUPPORTED);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 1u], (uint8_t)NFC_ISO7816_SW2_SUCCESS);
}

TEST_F(ReaderCcidDispatchTest, Type5TransparentEscapeRejectsAddressedSysInfoForOtherUidBeforeRf) {
  set_type5_uid_for_tests();
  power_on_storage_tag(READER_TAG_KIND_TYPE5);

  std::vector<uint8_t> sys_info = {
    (uint8_t)NFC_ISO7816_CLA_PROPRIETARY,
    (uint8_t)NFC_PCSC_ESCAPE_TRANSPARENT_INS,
    0x00u,
    0x00u,
    (uint8_t)(2u + NFC_FRONTEND_ISO15693_UID_LEN),
    (uint8_t)NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED,
    (uint8_t)NFC_TAG_T5T_ISO15693_CMD_GET_SYS_INFO,
  };
  const std::vector<uint8_t> uid_lsb = mismatched_type5_uid_lsb();
  sys_info.insert(sys_info.end(), uid_lsb.begin(), uid_lsb.end());

  auto frame = make_xfr(0x39u, sys_info);
  reader_ccid_utest_handle_bulk(frame.data(), static_cast<uint16_t>(frame.size()));

  const uint8_t *rsp = reader_ccid_utest_last_send();
  ASSERT_GE(reader_ccid_utest_last_send_len(), kSwPayloadEnd);
  EXPECT_EQ(reader_tags_utest_type5_transceive_count(), 0u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&rsp[1]), (uint32_t)NFC_ISO7816_SW_LEN);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET], (uint8_t)NFC_ISO7816_SW1_INS_NOT_SUPPORTED);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 1u], (uint8_t)NFC_ISO7816_SW2_SUCCESS);
}

TEST_F(ReaderCcidDispatchTest, Type5Pn53xTunnelRejectsAddressedReadForOtherUidBeforeRf) {
  reader_tags_utest_set_type5_info(NFC_TAG_T5T_CC_LEN_SHORT, 320u, 81u, true, true);
  set_type5_uid_for_tests();
  power_on_storage_tag(READER_TAG_KIND_TYPE5);

  std::vector<uint8_t> type5_read = {
    (uint8_t)NFC_PN532_HOST_TO_PN532,
    (uint8_t)NFC_PN532_CMD_IN_COMMUNICATE_THRU,
    (uint8_t)NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED,
    (uint8_t)NFC_TAG_T5T_ISO15693_CMD_READ_SINGLE,
  };
  const std::vector<uint8_t> uid_lsb = mismatched_type5_uid_lsb();
  type5_read.insert(type5_read.end(), uid_lsb.begin(), uid_lsb.end());
  type5_read.push_back(0x01u);

  auto frame = make_xfr(0x3Au, make_acr122_direct_apdu(type5_read));
  reader_ccid_utest_handle_bulk(frame.data(), static_cast<uint16_t>(frame.size()));

  const uint8_t *rsp = reader_ccid_utest_last_send();
  ASSERT_GE(reader_ccid_utest_last_send_len(),
            static_cast<uint16_t>(NFC_CCID_BULK_PAYLOAD_OFFSET + 5u));
  EXPECT_EQ(reader_tags_utest_type5_transceive_count(), 0u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&rsp[1]), 5u);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET], (uint8_t)NFC_PN532_PN532_TO_HOST);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 1u], (uint8_t)NFC_PN532_RSP_IN_COMMUNICATE_THRU);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 2u], 0x01u);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 3u], (uint8_t)NFC_ISO7816_SW1_SUCCESS);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 4u], (uint8_t)NFC_ISO7816_SW2_SUCCESS);
}

TEST_F(ReaderCcidDispatchTest, Type2Pn53xTunnelRejectsOutOfBoundsRawReadBeforeRf) {
  reader_tags_utest_set_type2_storage_info(64u, true, true);
  power_on_storage_tag(READER_TAG_KIND_TYPE2);

  const std::vector<uint8_t> type2_read_page20 = {
    (uint8_t)NFC_PN532_HOST_TO_PN532,
    (uint8_t)NFC_PN532_CMD_IN_DATA_EXCHANGE,
    0x01u,
    (uint8_t)CCID_RAW_T2_CMD_READ,
    20u,
  };
  auto frame = make_xfr(0x37u, make_acr122_direct_apdu(type2_read_page20));
  reader_ccid_utest_handle_bulk(frame.data(), static_cast<uint16_t>(frame.size()));

  const uint8_t *rsp = reader_ccid_utest_last_send();
  ASSERT_GE(reader_ccid_utest_last_send_len(),
            static_cast<uint16_t>(NFC_CCID_BULK_PAYLOAD_OFFSET + 5u));
  EXPECT_EQ(reader_tags_utest_type2_transceive_count(), 0u);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET], (uint8_t)NFC_PN532_PN532_TO_HOST);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 1u], (uint8_t)NFC_PN532_RSP_IN_DATA_EXCHANGE);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 2u], 0x01u);
}

TEST_F(ReaderCcidDispatchTest, Type2GetDataVersionUsesNtagFingerprintWithoutNxpUid) {
  const uint8_t apdu[] = {0xFFu, 0xCAu, (uint8_t)NFC_PCSC_GET_DATA_TYPE2_VERSION, 0x00u, 0x00u};
  const uint8_t version[] = {0x00u, 0x04u, 0x04u, 0x02u, 0x01u, 0x00u, 0x13u, 0x03u};
  uint8_t rsp[16];

  reader_tags_utest_set_type2_storage_info(1016u, true, true);
  reader_tags_utest_set_type2_transceive_response(version, (uint16_t)sizeof(version));
  g_tag_kind = READER_TAG_KIND_TYPE2;
  g_uid14_len = 7u;
  g_uid14[0] = 0x53u;

  const uint16_t rlen =
    reader_ccid_handle_get_data_apdu(apdu, (uint16_t)sizeof(apdu), rsp, (uint16_t)sizeof(rsp));

  ASSERT_EQ(rlen, (uint16_t)(sizeof(version) + NFC_ISO7816_SW_LEN));
  EXPECT_TRUE(std::equal(std::begin(version), std::end(version), rsp));
  EXPECT_EQ(rsp[sizeof(version)], (uint8_t)NFC_ISO7816_SW1_SUCCESS);
  EXPECT_EQ(rsp[sizeof(version) + 1u], (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  EXPECT_EQ(reader_tags_utest_type2_transceive_count(), 1u);
}

TEST_F(ReaderCcidDispatchTest, Type2GetDataVersionDoesNotProbeType4Tag) {
  const uint8_t apdu[] = {0xFFu, 0xCAu, (uint8_t)NFC_PCSC_GET_DATA_TYPE2_VERSION, 0x00u, 0x00u};
  const uint8_t version[] = {0x00u, 0x04u, 0x04u, 0x02u, 0x01u, 0x00u, 0x13u, 0x03u};
  uint8_t rsp[16];

  reader_tags_utest_set_type2_storage_info(1016u, true, true);
  reader_tags_utest_set_type2_transceive_response(version, (uint16_t)sizeof(version));
  g_tag_kind = READER_TAG_KIND_TYPE4;

  const uint16_t rlen =
    reader_ccid_handle_get_data_apdu(apdu, (uint16_t)sizeof(apdu), rsp, (uint16_t)sizeof(rsp));

  ASSERT_EQ(rlen, (uint16_t)NFC_ISO7816_SW_LEN);
  EXPECT_EQ(rsp[0], (uint8_t)NFC_ISO7816_SW1_WRONG_DATA);
  EXPECT_EQ(rsp[1], (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
  EXPECT_EQ(reader_tags_utest_type2_transceive_count(), 0u);
}

TEST_F(ReaderCcidDispatchTest, StorageTagsRejectIsoType4NdefSelect) {
  const std::vector<uint8_t> select_ndef_app = make_select_ndef_app_apdu();
  const reader_tag_kind_t storage_kinds[] = {READER_TAG_KIND_TYPE2, READER_TAG_KIND_TYPE5};

  for (reader_tag_kind_t kind : storage_kinds) {
    reader_ccid_utest_reset();
    reader_ccid_on_tag_detected(kind);
    auto power_on = make_bulk(0x62u, 0x50u);
    reader_ccid_utest_handle_bulk(power_on.data(), (uint16_t)power_on.size());

    auto frame = make_xfr(0x51u, select_ndef_app);
    reader_ccid_utest_handle_bulk(frame.data(), static_cast<uint16_t>(frame.size()));

    const uint8_t *rsp = reader_ccid_utest_last_send();
    ASSERT_GE(reader_ccid_utest_last_send_len(),
              static_cast<uint16_t>(NFC_CCID_BULK_HEADER_LEN) +
                static_cast<uint16_t>(NFC_ISO7816_SW_LEN));
    EXPECT_EQ(rsp[0], NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
    EXPECT_EQ(rsp[6], 0x51u);
    EXPECT_EQ(nfc_ccid_u32_load_le(&rsp[1]), (uint32_t)NFC_ISO7816_SW_LEN);
    EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET], (uint8_t)NFC_ISO7816_SW1_INS_NOT_SUPPORTED);
    EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 1u], (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  }
}

TEST_F(ReaderCcidDispatchTest, Type4NdefSelectRelaysOnNonFidoType4Tag) {
  reader_security_key_utest_set_select_fido_probe_ok(false);
  power_on_storage_tag(READER_TAG_KIND_TYPE4);

  auto frame = make_xfr(0x75u, make_select_ndef_app_apdu());
  reader_ccid_utest_handle_bulk(frame.data(), static_cast<uint16_t>(frame.size()));

  const uint8_t *rsp = reader_ccid_utest_last_send();
  ASSERT_GE(reader_ccid_utest_last_send_len(), kSwPayloadEnd);
  EXPECT_EQ(nfc_ccid_u32_load_le(&rsp[1]), (uint32_t)NFC_ISO7816_SW_LEN);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET], (uint8_t)NFC_ISO7816_SW1_SUCCESS);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 1u], (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  EXPECT_GT(reader_security_key_utest_last_apdu_rsp_cap(), 0u);
}

TEST_F(ReaderCcidDispatchTest, Type4NdefSelectBlockedOnConfirmedSecurityKey) {
  reader_security_key_utest_set_select_fido_probe_ok(true);
  power_on_storage_tag(READER_TAG_KIND_TYPE4);
  ASSERT_EQ(reader_security_key_utest_last_apdu_rsp_cap(), 0u);

  auto frame = make_xfr(0x76u, make_select_ndef_app_apdu());
  reader_ccid_utest_handle_bulk(frame.data(), static_cast<uint16_t>(frame.size()));

  const uint8_t *rsp = reader_ccid_utest_last_send();
  ASSERT_GE(reader_ccid_utest_last_send_len(), kSwPayloadEnd);
  EXPECT_EQ(nfc_ccid_u32_load_le(&rsp[1]), (uint32_t)NFC_ISO7816_SW_LEN);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET],
            (uint8_t)NFC_ISO7816_SW1_CONDITIONS_NOT_SATISFIED);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 1u],
            (uint8_t)NFC_ISO7816_SW2_COMMAND_NOT_ALLOWED);
  EXPECT_EQ(reader_security_key_utest_last_apdu_rsp_cap(), 0u);
}

TEST_F(ReaderCcidDispatchTest, Type2UpdateBinaryRejectsWriteRestrictedTag) {
  reader_tags_utest_set_type2_storage_info(64u, true, false);
  reader_tags_utest_set_type2_write_ok(true);
  power_on_storage_tag(READER_TAG_KIND_TYPE2);

  const std::vector<uint8_t> update_page4 = {
    (uint8_t)NFC_ISO7816_CLA_PROPRIETARY, (uint8_t)NFC_ISO7816_INS_UPDATE_BINARY,
    0x00u,                                (uint8_t)NFC_STORAGE_TYPE2_FIRST_DATA_PAGE,
    0x04u,                                0xAAu,
    0xBBu,                                0xCCu,
    0xDDu,
  };
  auto frame = make_xfr(0x72u, update_page4);
  reader_ccid_utest_handle_bulk(frame.data(), static_cast<uint16_t>(frame.size()));

  const uint8_t *rsp = reader_ccid_utest_last_send();
  ASSERT_GE(reader_ccid_utest_last_send_len(), kSwPayloadEnd);
  EXPECT_EQ(nfc_ccid_u32_load_le(&rsp[1]), (uint32_t)NFC_ISO7816_SW_LEN);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET],
            (uint8_t)NFC_ISO7816_SW1_CONDITIONS_NOT_SATISFIED);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 1u],
            (uint8_t)NFC_ISO7816_SW2_CONDITIONS_NOT_SATISFIED);
  EXPECT_EQ(reader_tags_utest_type2_write_count(), 0u);
}

TEST_F(ReaderCcidDispatchTest, Type2UpdateBinaryRejectsPagePastDataArea) {
  reader_tags_utest_set_type2_storage_info(64u, true, true);
  reader_tags_utest_set_type2_write_ok(true);
  power_on_storage_tag(READER_TAG_KIND_TYPE2);

  const std::vector<uint8_t> update_page20 = {
    (uint8_t)NFC_ISO7816_CLA_PROPRIETARY, (uint8_t)NFC_ISO7816_INS_UPDATE_BINARY,
    0x00u,                                20u,
    0x04u,                                0xAAu,
    0xBBu,                                0xCCu,
    0xDDu,
  };
  auto frame = make_xfr(0x73u, update_page20);
  reader_ccid_utest_handle_bulk(frame.data(), static_cast<uint16_t>(frame.size()));

  const uint8_t *rsp = reader_ccid_utest_last_send();
  ASSERT_GE(reader_ccid_utest_last_send_len(), kSwPayloadEnd);
  EXPECT_EQ(nfc_ccid_u32_load_le(&rsp[1]), (uint32_t)NFC_ISO7816_SW_LEN);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET], (uint8_t)NFC_ISO7816_SW1_WRONG_P1P2);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 1u], (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  EXPECT_EQ(reader_tags_utest_type2_write_count(), 0u);
}

TEST_F(ReaderCcidDispatchTest, Type2UpdateBinaryAcceptsAlignedMultiPageWrite) {
  reader_tags_utest_set_type2_storage_info(64u, true, true);
  reader_tags_utest_set_type2_write_ok(true);
  power_on_storage_tag(READER_TAG_KIND_TYPE2);

  const std::vector<uint8_t> update_pages4And5 = {
    (uint8_t)NFC_ISO7816_CLA_PROPRIETARY, (uint8_t)NFC_ISO7816_INS_UPDATE_BINARY,
    0x00u,                                (uint8_t)NFC_STORAGE_TYPE2_FIRST_DATA_PAGE,
    0x08u,                                0xAAu,
    0xBBu,                                0xCCu,
    0xDDu,                                0x11u,
    0x22u,                                0x33u,
    0x44u,
  };
  auto frame = make_xfr(0x75u, update_pages4And5);
  reader_ccid_utest_handle_bulk(frame.data(), static_cast<uint16_t>(frame.size()));

  const uint8_t *rsp = reader_ccid_utest_last_send();
  ASSERT_GE(reader_ccid_utest_last_send_len(), kSwPayloadEnd);
  EXPECT_EQ(nfc_ccid_u32_load_le(&rsp[1]), (uint32_t)NFC_ISO7816_SW_LEN);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET], (uint8_t)NFC_ISO7816_SW1_SUCCESS);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 1u], (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  EXPECT_EQ(reader_tags_utest_type2_write_count(), 2u);
}

TEST_F(ReaderCcidDispatchTest, Type5ReadBinaryGenericByteOffsetMapsToBlock) {
  reader_tags_utest_set_type5_info(NFC_TAG_T5T_CC_LEN_SHORT, 320u, 81u, true, true);
  power_on_storage_tag(READER_TAG_KIND_TYPE5);

  const std::vector<uint8_t> read_from_tlv_start = {
    (uint8_t)NFC_ISO7816_CLA_PROPRIETARY,
    (uint8_t)NFC_ISO7816_INS_READ_BINARY,
    0x00u,
    (uint8_t)NFC_STORAGE_TYPE5_BLOCK_SIZE,
    0x08u,
  };
  auto frame = make_xfr(0x77u, read_from_tlv_start);
  reader_ccid_utest_handle_bulk(frame.data(), static_cast<uint16_t>(frame.size()));

  const uint8_t *rsp = reader_ccid_utest_last_send();
  ASSERT_GE(reader_ccid_utest_last_send_len(),
            static_cast<uint16_t>(NFC_CCID_BULK_PAYLOAD_OFFSET + 10u));
  EXPECT_EQ(nfc_ccid_u32_load_le(&rsp[1]), 10u);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 8u], (uint8_t)NFC_ISO7816_SW1_SUCCESS);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 9u], (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  EXPECT_EQ(reader_tags_utest_type5_read_count(), 1u);
  EXPECT_EQ(reader_tags_utest_type5_last_read_block(), 1u);
  EXPECT_EQ(reader_tags_utest_type5_last_read_len(), 8u);
}

TEST_F(ReaderCcidDispatchTest, Type5UpdateBinaryAcceptsValidCcRefresh) {
  reader_tags_utest_set_type5_info(NFC_TAG_T5T_CC_LEN_SHORT, 320u, 81u, true, true);
  reader_tags_utest_set_type5_write_ok(true);
  power_on_storage_tag(READER_TAG_KIND_TYPE5);

  const std::vector<uint8_t> update_block0 = {
    (uint8_t)NFC_ISO7816_CLA_PROPRIETARY,
    (uint8_t)NFC_ISO7816_INS_UPDATE_BINARY,
    (uint8_t)NFC_ISO7816_READ_BINARY_P1_BLOCK_IN_P2,
    0x00u,
    0x04u,
    (uint8_t)NFC_FORUM_CC_MAGIC,
    (uint8_t)NFC_T5T_CC_VERSION,
    0x10u,
    0x00u,
  };
  auto frame = make_xfr(0x74u, update_block0);
  reader_ccid_utest_handle_bulk(frame.data(), static_cast<uint16_t>(frame.size()));

  const uint8_t *rsp = reader_ccid_utest_last_send();
  ASSERT_GE(reader_ccid_utest_last_send_len(), kSwPayloadEnd);
  EXPECT_EQ(nfc_ccid_u32_load_le(&rsp[1]), (uint32_t)NFC_ISO7816_SW_LEN);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET], (uint8_t)NFC_ISO7816_SW1_SUCCESS);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 1u], (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  EXPECT_EQ(reader_tags_utest_type5_write_count(), 1u);
}

TEST_F(ReaderCcidDispatchTest, Type5UpdateBinaryRejectsInvalidCcRefresh) {
  reader_tags_utest_set_type5_info(NFC_TAG_T5T_CC_LEN_SHORT, 320u, 81u, true, true);
  reader_tags_utest_set_type5_write_ok(true);
  power_on_storage_tag(READER_TAG_KIND_TYPE5);

  const std::vector<uint8_t> update_block0 = {
    (uint8_t)NFC_ISO7816_CLA_PROPRIETARY,
    (uint8_t)NFC_ISO7816_INS_UPDATE_BINARY,
    (uint8_t)NFC_ISO7816_READ_BINARY_P1_BLOCK_IN_P2,
    0x00u,
    0x04u,
    0xAAu,
    0xBBu,
    0xCCu,
    0xDDu,
  };
  auto frame = make_xfr(0x75u, update_block0);
  reader_ccid_utest_handle_bulk(frame.data(), static_cast<uint16_t>(frame.size()));

  const uint8_t *rsp = reader_ccid_utest_last_send();
  ASSERT_GE(reader_ccid_utest_last_send_len(), kSwPayloadEnd);
  EXPECT_EQ(nfc_ccid_u32_load_le(&rsp[1]), (uint32_t)NFC_ISO7816_SW_LEN);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET], (uint8_t)NFC_ISO7816_SW1_WRONG_DATA);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 1u], (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  EXPECT_EQ(reader_tags_utest_type5_write_count(), 0u);
}

TEST_F(ReaderCcidDispatchTest, Type5UpdateBinaryAcceptsAlignedMultiBlockWrite) {
  reader_tags_utest_set_type5_info(NFC_TAG_T5T_CC_LEN_SHORT, 320u, 81u, true, true);
  reader_tags_utest_set_type5_write_ok(true);
  power_on_storage_tag(READER_TAG_KIND_TYPE5);

  const std::vector<uint8_t> update_blocks1And2 = {
    (uint8_t)NFC_ISO7816_CLA_PROPRIETARY,
    (uint8_t)NFC_ISO7816_INS_UPDATE_BINARY,
    (uint8_t)NFC_ISO7816_READ_BINARY_P1_BLOCK_IN_P2,
    0x01u,
    0x08u,
    0xAAu,
    0xBBu,
    0xCCu,
    0xDDu,
    0x11u,
    0x22u,
    0x33u,
    0x44u,
  };
  auto frame = make_xfr(0x76u, update_blocks1And2);
  reader_ccid_utest_handle_bulk(frame.data(), static_cast<uint16_t>(frame.size()));

  const uint8_t *rsp = reader_ccid_utest_last_send();
  ASSERT_GE(reader_ccid_utest_last_send_len(), kSwPayloadEnd);
  EXPECT_EQ(nfc_ccid_u32_load_le(&rsp[1]), (uint32_t)NFC_ISO7816_SW_LEN);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET], (uint8_t)NFC_ISO7816_SW1_SUCCESS);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 1u], (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  EXPECT_EQ(reader_tags_utest_type5_write_count(), 2u);
}

TEST_F(ReaderCcidDispatchTest, Type4XfrPassesStatusWordHeadroomToRelay) {
  reader_ccid_on_tag_detected(READER_TAG_KIND_TYPE4);
  auto power_on = make_bulk(0x62u, 0x25u);
  reader_ccid_utest_handle_bulk(power_on.data(), (uint16_t)power_on.size());

  std::array<uint8_t, 14> frame{};
  frame[0] = NFC_CCID_MSG_PC_TO_RDR_XFR;
  frame[1] = 0x04u;
  frame[6] = 0x42u;
  frame[10] = 0x00u;
  frame[11] = 0xA4u;
  frame[12] = 0x00u;
  frame[13] = 0x00u;
  reader_ccid_utest_handle_bulk(frame.data(), (uint16_t)frame.size());

  EXPECT_EQ(reader_security_key_utest_last_apdu_rsp_cap(), CCID_APDU_RSP_BUF_MAX + 2u);
}

TEST_F(ReaderCcidDispatchTest, AbortDuringXfrReturnsCommandAborted) {
  reader_ccid_on_tag_detected(READER_TAG_KIND_TYPE4);
  auto power_on = make_bulk(0x62u, 0x20u);
  reader_ccid_utest_handle_bulk(power_on.data(), (uint16_t)power_on.size());

  reader_hal_utest_ccid_set_abort_pending(true, 0u, 0u);
  std::array<uint8_t, 14> frame{};
  frame[0] = NFC_CCID_MSG_PC_TO_RDR_XFR;
  frame[1] = 0x04u;
  frame[6] = 0x40u;
  frame[10] = 0x00u;
  frame[11] = 0xA4u;
  frame[12] = 0x00u;
  frame[13] = 0x00u;
  reader_ccid_utest_handle_bulk(frame.data(), (uint16_t)frame.size());
  const uint8_t *rsp = reader_ccid_utest_last_send();
  EXPECT_EQ(rsp[0], NFC_CCID_MSG_RDR_TO_PC_SLOTSTATUS);
  EXPECT_EQ(rsp[8], 0xFFu);
}

TEST_F(ReaderCcidDispatchTest, AbortClearsPendingCommandChain) {
  reader_ccid_on_tag_detected(READER_TAG_KIND_TYPE4);
  auto power_on = make_bulk(0x62u, 0x28u);
  reader_ccid_utest_handle_bulk(power_on.data(), (uint16_t)power_on.size());

  auto chain_begin =
    make_xfr_chain(0x52u, (uint8_t)NFC_CCID_XFR_LEVEL_CHAIN_BEGIN, {0x00u, 0xA4u});
  reader_ccid_utest_handle_bulk(chain_begin.data(), static_cast<uint16_t>(chain_begin.size()));
  const uint8_t *rsp = reader_ccid_utest_last_send();
  ASSERT_GE(reader_ccid_utest_last_send_len(), static_cast<uint16_t>(NFC_CCID_BULK_HEADER_LEN));
  EXPECT_EQ(rsp[0], NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
  EXPECT_EQ(rsp[NFC_CCID_BULK_LEVEL_PARAM3_OFFSET], (uint8_t)NFC_CCID_XFR_RESPONSE_CONTINUE);

  auto abort = make_bulk(NFC_CCID_MSG_PC_TO_RDR_ABORT, 0x53u);
  reader_ccid_utest_handle_bulk(abort.data(), (uint16_t)abort.size());

  auto single = make_xfr(0x54u, {0x00u, 0xA4u, 0x04u, 0x00u});
  reader_ccid_utest_handle_bulk(single.data(), static_cast<uint16_t>(single.size()));
  rsp = reader_ccid_utest_last_send();
  ASSERT_GE(reader_ccid_utest_last_send_len(), kSwPayloadEnd);
  EXPECT_EQ(rsp[0], NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
  EXPECT_EQ(rsp[6], 0x54u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&rsp[1]), (uint32_t)NFC_ISO7816_SW_LEN);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET], (uint8_t)NFC_ISO7816_SW1_SUCCESS);
  EXPECT_EQ(rsp[NFC_CCID_BULK_PAYLOAD_OFFSET + 1u], (uint8_t)NFC_ISO7816_SW2_SUCCESS);
}
