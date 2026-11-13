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

#include "nero_nfc_reader_app_fixture.hpp"
#include "nfc_ctap_codec.h"
#include "reader_ccid.h"
#include "reader_ccid_internal.h"
#include "reader_ccid_utest.h"
#include "reader_ccid_xfr.h"
#include "reader_context.h"
#include "reader_hal_utest.h"
#include "reader_security_key_utest_stub.h"
#include "reader_tags_utest.h"
#include <span>

namespace {
enum {
  kTestLit0x01u = 0x01u,
  kTestLit0x02u = 0x02u,
  kTestLit0x03u = 0x03u,
  kTestLit0x04u = 0x04u,
  kTestLit0x05u = 0x05u,
  kTestLit0x0Fu = 0x0Fu,
  kTestLit0x11u = 0x11u,
  kTestLit0x12u = 0x12u,
  kTestLit0x20u = 0x20u,
  kTestLit0x21u = 0x21u,
  kTestLit0x22u = 0x22u,
  kTestLit0x23u = 0x23u,
  kTestLit0x24u = 0x24u,
  kTestLit0x25u = 0x25u,
  kTestLit0x26u = 0x26u,
  kTestLit0x27u = 0x27u,
  kTestLit0x28u = 0x28u,
  kTestLit0x30u = 0x30u,
  kTestLit0x31u = 0x31u,
  kTestLit0x32u = 0x32u,
  kTestLit0x33u = 0x33u,
  kTestLit0x34u = 0x34u,
  kTestLit0x35u = 0x35u,
  kTestLit0x36u = 0x36u,
  kTestLit0x37u = 0x37u,
  kTestLit0x38u = 0x38u,
  kTestLit0x39u = 0x39u,
  kTestLit0x3Au = 0x3Au,
  kTestLit0x40u = 0x40u,
  kTestLit0x41u = 0x41u,
  kTestLit0x42u = 0x42u,
  kTestLit0x43u = 0x43u,
  kTestLit0x44u = 0x44u,
  kTestLit0x50u = 0x50u,
  kTestLit0x51u = 0x51u,
  kTestLit0x52u = 0x52u,
  kTestLit0x53u = 0x53u,
  kTestLit0x54u = 0x54u,
  kTestLit0x55u = 0x55u,
  kTestLit0x62u = 0x62u,
  kTestLit0x66u = 0x66u,
  kTestLit0x70u = 0x70u,
  kTestLit0x72u = 0x72u,
  kTestLit0x73u = 0x73u,
  kTestLit0x74u = 0x74u,
  kTestLit0x75u = 0x75u,
  kTestLit0x76u = 0x76u,
  kTestLit0x77u = 0x77u,
  kTestLit0x85u = 0x85u,
  kTestLit0x88u = 0x88u,
  kTestLit0x80u = 0x80u,
  kTestLit0x99u = 0x99u,
  kTestLit0xA4u = 0xA4u,
  kTestLit0xA5u = 0xA5u,
  kTestLit0xD2u = 0xD2u,
  kTestLit10 = 10,
  kTestLit1016u = 1016u,
  kTestLit11 = 11,
  kTestLit12 = 12,
  kTestLit13 = 13,
  kTestLit14 = 14,
  kTestLit144u = 144u,
  kTestLit16 = 16,
  kTestLit2u = 2u,
  kTestLit320u = 320u,
  kTestLit5 = 5,
  kTestLit6 = 6,
  kTestLit64u = 64u,
  kTestLit7u = 7u,
  kTestLit81u = 81u,
};
}  // namespace

#include "nero_nfc_mem_util.h"
#include "nfc_ccid_frame.h"
#include "nfc_pcsc_contactless.h"
#include "nfc_storage_ndef.h"
#include "nfc_tag_geometry_limits.h"
#include "test_bounds.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <ranges>
#include <vector>

namespace {
std::span<const uint8_t> LastCcidSend() {
  const uint8_t* const data = reader_ccid_utest_last_send();
  const auto len = static_cast<size_t>(reader_ccid_utest_last_send_len());
  // Paren ctor: brace-init `{ptr,len}` is misread by cppcheck as size 2.
  const std::span<const uint8_t> span(data, len);
  return span;
}

constexpr uint16_t kSwPayloadEnd =
    static_cast<uint16_t>(NFC_CCID_BULK_PAYLOAD_OFFSET) +
    static_cast<uint16_t>(NFC_ISO7816_SW_LEN);

class ReaderCcidDispatchTest : public NeroNfcReaderAppFixture {
 protected:
  void SetUp() override {
    BindReaderApp();
    reader_ccid_utest_setup();
    reader_ccid_utest_reset();
    reader_tags_utest_reset();
  }

  static std::array<uint8_t, kTestLit10> MakeBulk(uint8_t msg_type,
                                                  uint8_t seq) {
    std::array<uint8_t, kTestLit10> frame{};
    frame.at(0) = msg_type;
    frame.at(kTestLit6) = seq;
    return frame;
  }

  static std::vector<uint8_t> MakeXfr(uint8_t seq,
                                      const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> frame(NFC_CCID_BULK_HEADER_LEN + payload.size(), 0u);
    frame.at(0) = NFC_CCID_MSG_PC_TO_RDR_XFR;
    nfc_ccid_u32_store_le(&frame.at(1), static_cast<uint32_t>(payload.size()));
    frame.at(kTestLit6) = seq;
    std::ranges::copy(payload, frame.begin() + static_cast<std::ptrdiff_t>(
                                                   NFC_CCID_BULK_HEADER_LEN));
    return frame;
  }

  static std::vector<uint8_t> MakeXfrChain(
      uint8_t seq, uint8_t level, const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> frame = MakeXfr(seq, payload);
    frame.at(NFC_CCID_BULK_LEVEL_PARAM2_OFFSET) = level;
    return frame;
  }

  static void PowerOnStorageTag(reader_tag_kind_t kind) {
    reader_ccid_on_tag_detected(kind);
    auto power_on =
        MakeBulk(NFC_CCID_MSG_PC_TO_RDR_ICC_POWER_ON, kTestLit0x70u);
    reader_ccid_utest_handle_bulk(power_on.data(),
                                  static_cast<uint16_t>(power_on.size()));
  }

  static void SetType5UidForTests() {
    const std::array<uint8_t, NFC_FRONTEND_ISO15693_UID_LEN> uid = {
        0xE0u, 0x02u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u,
    };
    EXPECT_TRUE(nero_nfc_copy_bytes(&G_UID15[0], NFC_FRONTEND_ISO15693_UID_LEN,
                                    0u, uid.data(),
                                    static_cast<uint16_t>(uid.size())));
  }

  static std::vector<uint8_t> MismatchedType5UidLsb() {
    return {
        kTestLit0x99u, kTestLit0x88u, kTestLit0x77u, kTestLit0x66u,
        kTestLit0x55u, kTestLit0x44u, kTestLit0x33u, kTestLit0x22u,
    };
  }

  static std::vector<uint8_t> MakeSelectNdefAppApdu() {
    return {
        static_cast<uint8_t>(NFC_ISO7816_CLA_ISO),
        static_cast<uint8_t>(NFC_ISO7816_INS_SELECT),
        static_cast<uint8_t>(NFC_ISO7816_P1_SELECT_BY_DF_NAME),
        static_cast<uint8_t>(NFC_ISO7816_P2_SELECT_FIRST),
        static_cast<uint8_t>(NFC_PCSC_NDEF_APP_AID_LEN),
        kTestLit0xD2u,
        kTestLit0x76u,
        0x00u,
        0x00u,
        kTestLit0x85u,
        0x01u,
        0x01u,
        0x00u,
    };
  }

  static std::vector<uint8_t> MakeSelectFidoAppApdu() {
    std::vector<uint8_t> apdu = {
        static_cast<uint8_t>(NFC_ISO7816_CLA_ISO),
        static_cast<uint8_t>(NFC_ISO7816_INS_SELECT),
        static_cast<uint8_t>(NFC_ISO7816_P1_SELECT_BY_DF_NAME),
        static_cast<uint8_t>(NFC_ISO7816_P2_SELECT_FIRST),
        static_cast<uint8_t>(NFC_CTAP_FIDO_AID_LEN),
    };
    apdu.insert(apdu.end(), std::begin(NFC_CTAP_FIDO_AID),
                std::end(NFC_CTAP_FIDO_AID));
    apdu.push_back(0x00u);
    return apdu;
  }

  static std::vector<uint8_t> MakeAcr122DirectApdu(
      const std::vector<uint8_t>& pn53x) {
    std::vector<uint8_t> apdu = {
        static_cast<uint8_t>(NFC_ISO7816_CLA_PROPRIETARY),
        static_cast<uint8_t>(NFC_ISO7816_CLA_ISO),
        static_cast<uint8_t>(NFC_ISO7816_CLA_ISO),
        static_cast<uint8_t>(NFC_ISO7816_CLA_ISO),
        static_cast<uint8_t>(pn53x.size()),
    };
    apdu.insert(apdu.end(), pn53x.begin(), pn53x.end());
    return apdu;
  }
};

}  // namespace

TEST_F(ReaderCcidDispatchTest, SlotStatusReportsNoIccWhenEmpty) {
  auto frame = MakeBulk(NFC_CCID_MSG_PC_TO_RDR_SLOTSTATUS, kTestLit0x11u);
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));
  ASSERT_GE(reader_ccid_utest_last_send_len(), 10u);
  const std::span<const uint8_t> rsp = LastCcidSend();
  EXPECT_EQ(nero_nfc_test::At(rsp, 0), NFC_CCID_MSG_RDR_TO_PC_SLOTSTATUS);
  EXPECT_EQ(nero_nfc_test::At(rsp, 6), 0x11u);
  EXPECT_EQ(nero_nfc_test::At(rsp, 7) & 0x03u, 0x02u);
}

TEST_F(ReaderCcidDispatchTest, SlotStatusReportsInactiveWhenTagPresent) {
  reader_ccid_on_tag_detected(READER_TAG_KIND_TYPE4);
  auto frame = MakeBulk(NFC_CCID_MSG_PC_TO_RDR_SLOTSTATUS, kTestLit0x12u);
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));
  const std::span<const uint8_t> rsp = LastCcidSend();
  EXPECT_EQ(nero_nfc_test::At(rsp, 0), NFC_CCID_MSG_RDR_TO_PC_SLOTSTATUS);
  EXPECT_EQ(nero_nfc_test::At(rsp, 7) & 0x03u, 0x01u);
}

TEST_F(ReaderCcidDispatchTest, IccPowerOnReturnsAtrForType4Tag) {
  reader_ccid_on_tag_detected(READER_TAG_KIND_TYPE4);
  auto frame = MakeBulk(kTestLit0x62u, kTestLit0x20u);
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));
  const std::span<const uint8_t> rsp = LastCcidSend();
  EXPECT_EQ(nero_nfc_test::At(rsp, 0), NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
  EXPECT_GT(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)), 0u);
}

TEST_F(ReaderCcidDispatchTest, IccPowerOnWithoutCardRepliesDataBlockError) {
  /* [CCID1.10] Rev 1.10 §6.2.1 -- IccPowerOn always answers with
   * RDR_to_PC_DataBlock, even on failure: dwLength=0, bmCommandStatus=failed,
   * bError set. */
  auto frame = MakeBulk(kTestLit0x62u, kTestLit0x33u);
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));
  ASSERT_GE(reader_ccid_utest_last_send_len(), 10u);
  const std::span<const uint8_t> rsp = LastCcidSend();
  EXPECT_EQ(nero_nfc_test::At(rsp, 0), NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
  EXPECT_EQ(nero_nfc_test::At(rsp, 6), 0x33u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)), 0u);
  EXPECT_EQ(nero_nfc_test::At(rsp, 7) & 0xC0u,
            0x40u); /* bmCommandStatus = failed */
  EXPECT_EQ(nero_nfc_test::At(rsp, 7) & 0x03u,
            0x02u);                            /* bmICCStatus = no ICC */
  EXPECT_EQ(nero_nfc_test::At(rsp, 8), 0xFEu); /* bError = ICC mute */
}

TEST_F(ReaderCcidDispatchTest,
       IccPowerOnReturnsAtrWithoutUndefinedTimeExtension) {
  reader_ccid_on_tag_detected(READER_TAG_KIND_TYPE4);
  auto frame = MakeBulk(kTestLit0x62u, kTestLit0x22u);
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  ASSERT_GE(reader_hal_utest_ccid_last_send_len(), 10u);
  const std::span<const uint8_t> rsp = LastCcidSend();
  EXPECT_EQ(reader_hal_utest_ccid_send_count(), 1u);
  EXPECT_EQ(reader_hal_utest_ccid_time_extension_send_count(), 0u);
  EXPECT_EQ(reader_security_key_utest_select_fido_probe_count(), 0u);
  EXPECT_EQ(nero_nfc_test::At(rsp, 0), NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
  EXPECT_EQ(nero_nfc_test::At(rsp, 6), 0x22u);
  EXPECT_EQ(nero_nfc_test::At(rsp, 7) & NFC_CCID_ICC_CMD_TIME_EXTENSION, 0u);
  EXPECT_GT(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)), 0u);
}

TEST_F(ReaderCcidDispatchTest, IccClockReturnsNotSupported) {
  reader_ccid_on_tag_detected(READER_TAG_KIND_TYPE4);
  auto frame = MakeBulk(NFC_CCID_MSG_PC_TO_RDR_ICC_CLOCK, kTestLit0x21u);
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));
  const std::span<const uint8_t> rsp = LastCcidSend();
  EXPECT_EQ(nero_nfc_test::At(rsp, 0), NFC_CCID_MSG_RDR_TO_PC_SLOTSTATUS);
  EXPECT_EQ(nero_nfc_test::At(rsp, 7) & 0x40u, 0x40u);
}

TEST_F(ReaderCcidDispatchTest, RejectsNonZeroSlot) {
  auto frame = MakeBulk(NFC_CCID_MSG_PC_TO_RDR_SLOTSTATUS, kTestLit0x30u);
  frame.at(kTestLit5) = 0x01u;
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));
  const std::span<const uint8_t> rsp = LastCcidSend();
  EXPECT_EQ(nero_nfc_test::At(rsp, 0), NFC_CCID_MSG_RDR_TO_PC_SLOTSTATUS);
  EXPECT_EQ(nero_nfc_test::At(rsp, 8), 0x05u);
}

TEST_F(ReaderCcidDispatchTest, HeaderCompleteLengthMismatchReturnsError) {
  auto frame = MakeBulk(NFC_CCID_MSG_PC_TO_RDR_SLOTSTATUS, kTestLit0x30u);
  frame.at(1) = 0x01u;
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(), NFC_CCID_BULK_HEADER_LEN);
  EXPECT_EQ(nero_nfc_test::At(rsp, 0), NFC_CCID_MSG_RDR_TO_PC_SLOTSTATUS);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_SEQ_OFFSET), kTestLit0x30u);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_LEVEL_PARAM_OFFSET) & 0x40u,
            0x40u);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_LEVEL_PARAM2_OFFSET), 0x01u);
}

TEST_F(ReaderCcidDispatchTest,
       HeaderCompleteXfrLengthMismatchReturnsDataBlockError) {
  auto frame = MakeBulk(NFC_CCID_MSG_PC_TO_RDR_XFR, kTestLit0x31u);
  frame.at(1) = 0x01u;
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(), NFC_CCID_BULK_HEADER_LEN);
  EXPECT_EQ(nero_nfc_test::At(rsp, 0), NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_SEQ_OFFSET), kTestLit0x31u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)), 0u);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_LEVEL_PARAM_OFFSET) & 0x40u,
            0x40u);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_LEVEL_PARAM2_OFFSET), 0x01u);
}

TEST_F(ReaderCcidDispatchTest, FailedChainSendClearsUnrecoverableState) {
  std::vector<uint8_t> data(NFC_CCID_RSP_DATA_CAP + 1u, kTestLit0xA5u);
  std::array<uint8_t, NFC_CCID_BULK_HEADER_LEN + NFC_CCID_RSP_DATA_CAP> work{};
  reader_hal_utest_ccid_set_send_ok(false);

  reader_ccid_send_xfr_data_response(work.data(), kTestLit0x30u, data.data(),
                                     static_cast<uint16_t>(data.size()));

  EXPECT_FALSE(G_CCID_CHAIN_ACTIVE);
  EXPECT_EQ(G_CCID_CHAIN_OFF, 0u);
}

TEST_F(ReaderCcidDispatchTest,
       SuccessfulChainedResponseAdvancesAndClearsAfterFinalChunk) {
  std::vector<uint8_t> data(NFC_CCID_RSP_DATA_CAP + 1u, kTestLit0xA5u);
  std::array<uint8_t, NFC_CCID_BULK_HEADER_LEN + NFC_CCID_RSP_DATA_CAP> work{};

  reader_ccid_send_xfr_data_response(work.data(), kTestLit0x31u, data.data(),
                                     static_cast<uint16_t>(data.size()));

  ASSERT_TRUE(G_CCID_CHAIN_ACTIVE);
  EXPECT_EQ(G_CCID_CHAIN_OFF, NFC_CCID_RSP_DATA_CAP);
  EXPECT_EQ(reader_hal_utest_ccid_send_count(), 1u);
  std::span<const uint8_t> rsp = LastCcidSend();
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_LEVEL_PARAM3_OFFSET),
            static_cast<uint8_t>(NFC_CCID_XFR_LEVEL_CHAIN_BEGIN));

  reader_ccid_send_xfr_chain_chunk(work.data(), kTestLit0x31u);

  EXPECT_FALSE(G_CCID_CHAIN_ACTIVE);
  EXPECT_EQ(G_CCID_CHAIN_OFF, 0u);
  EXPECT_EQ(reader_hal_utest_ccid_send_count(), 2u);
  rsp = LastCcidSend();
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_LEVEL_PARAM3_OFFSET),
            static_cast<uint8_t>(NFC_CCID_XFR_LEVEL_CHAIN_END));
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)), 1u);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
            kTestLit0xA5u);
}

TEST_F(ReaderCcidDispatchTest, ActiveRemovalNotifiesAndTearsDownSession) {
  reader_ccid_on_tag_detected(READER_TAG_KIND_TYPE4);
  EXPECT_EQ(reader_hal_utest_ccid_notify_count(), 1u);
  EXPECT_TRUE(reader_hal_utest_ccid_last_notify_present());

  auto power_on = MakeBulk(kTestLit0x62u, kTestLit0x23u);
  reader_ccid_utest_handle_bulk(power_on.data(),
                                static_cast<uint16_t>(power_on.size()));
  EXPECT_EQ(reader_ccid_icc_status(), NFC_CCID_ICC_ACTIVE);

  reader_ccid_on_tag_removed_from_field();
  EXPECT_EQ(reader_ccid_icc_status(), NFC_CCID_ICC_NO_ICC);
  EXPECT_EQ(reader_hal_utest_ccid_notify_count(), 2u);
  EXPECT_FALSE(reader_hal_utest_ccid_last_notify_present());
}

TEST_F(ReaderCcidDispatchTest, HostActivityDefersStorageRemovalProbe) {
  constexpr uint32_t kActivityStartMs = 100u;
  reader_ccid_utest_set_millis(kActivityStartMs);
  PowerOnStorageTag(READER_TAG_KIND_TYPE5);

  EXPECT_FALSE(reader_ccid_removal_probe_due(kActivityStartMs +
                                             CCID_REMOVE_DEFER_MS - 1u));
  EXPECT_TRUE(
      reader_ccid_removal_probe_due(kActivityStartMs + CCID_REMOVE_DEFER_MS));
}

TEST_F(ReaderCcidDispatchTest, RemovalProbeDeadlineIsSafeAcrossMillisWrap) {
  constexpr uint32_t kActivityStartMs =
      UINT32_MAX - (CCID_REMOVE_DEFER_MS / 2u);
  reader_ccid_utest_set_millis(kActivityStartMs);
  PowerOnStorageTag(READER_TAG_KIND_TYPE5);
  const uint32_t deadline = kActivityStartMs + CCID_REMOVE_DEFER_MS;

  EXPECT_FALSE(reader_ccid_removal_probe_due(deadline - 1u));
  EXPECT_TRUE(reader_ccid_removal_probe_due(deadline));
}

TEST_F(ReaderCcidDispatchTest, AbortRequestAppliesOnlyToSupportedSlotZero) {
  reader_hal_utest_ccid_set_abort_pending(true, 1u, kTestLit0x31u);
  EXPECT_FALSE(reader_ccid_abort_requested());

  reader_hal_utest_ccid_set_abort_pending(true, 0u, kTestLit0x31u);
  EXPECT_TRUE(reader_ccid_abort_requested());

  reader_hal_utest_ccid_set_abort_pending(false, 0u, kTestLit0x31u);
  EXPECT_FALSE(reader_ccid_abort_requested());
}

TEST_F(ReaderCcidDispatchTest, Type4ShortXfrAddsNoTimeExtensionAfterPowerOn) {
  reader_ccid_on_tag_detected(READER_TAG_KIND_TYPE4);
  auto power_on = MakeBulk(kTestLit0x62u, kTestLit0x24u);
  reader_ccid_utest_handle_bulk(power_on.data(),
                                static_cast<uint16_t>(power_on.size()));
  ASSERT_EQ(reader_hal_utest_ccid_time_extension_send_count(), 0u);
  ASSERT_EQ(reader_security_key_utest_time_extension_binding_count(), 3u);

  std::array<uint8_t, kTestLit14> frame{};
  frame.at(0) = NFC_CCID_MSG_PC_TO_RDR_XFR;
  frame.at(1) = kTestLit0x04u;
  frame.at(kTestLit6) = kTestLit0x41u;
  frame.at(kTestLit10) = 0x00u;
  frame.at(kTestLit11) = kTestLit0xA4u;
  frame.at(kTestLit12) = 0x00u;
  frame.at(kTestLit13) = 0x00u;
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  EXPECT_EQ(reader_hal_utest_ccid_time_extension_send_count(), 0u);
  EXPECT_EQ(reader_security_key_utest_time_extension_binding_count(), 5u);
  EXPECT_EQ(nero_nfc_test::At(rsp, 0), NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
  EXPECT_EQ(nero_nfc_test::At(rsp, 6), 0x41u);
  EXPECT_EQ(nero_nfc_test::At(rsp, 7) & NFC_CCID_ICC_CMD_TIME_EXTENSION, 0u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)), 2u);
}

TEST_F(ReaderCcidDispatchTest, XfrBlockEmptyPayloadReachesApduDispatcher) {
  reader_ccid_on_tag_detected(READER_TAG_KIND_TYPE4);
  auto power_on = MakeBulk(kTestLit0x62u, kTestLit0x26u);
  reader_ccid_utest_handle_bulk(power_on.data(),
                                static_cast<uint16_t>(power_on.size()));
  ASSERT_EQ(reader_hal_utest_ccid_time_extension_send_count(), 0u);

  std::array<uint8_t, kTestLit10> frame{};
  frame.at(0) = NFC_CCID_MSG_PC_TO_RDR_XFR;
  frame.at(kTestLit6) = kTestLit0x43u;
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(), 12u);
  EXPECT_EQ(nero_nfc_test::At(rsp, 0), NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
  EXPECT_EQ(nero_nfc_test::At(rsp, 6), 0x43u);
  EXPECT_EQ(nero_nfc_test::At(rsp, 7) & NFC_CCID_ICC_CMD_TIME_EXTENSION, 0u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)), 2u);
  EXPECT_EQ(nero_nfc_test::At(rsp, 10), 0x6Fu);
  EXPECT_EQ(nero_nfc_test::At(rsp, 11), 0x00u);
}

TEST_F(ReaderCcidDispatchTest, Type4FfAcr122DirectDoesNotRelayInnerFidoSelect) {
  reader_ccid_on_tag_detected(READER_TAG_KIND_TYPE4);
  auto power_on = MakeBulk(kTestLit0x62u, kTestLit0x27u);
  reader_ccid_utest_handle_bulk(power_on.data(),
                                static_cast<uint16_t>(power_on.size()));

  const std::vector<uint8_t> payload = {
      0xFFu, 0x00u, 0x00u, 0x00u, 0x11u, 0xD4u, 0x40u, 0x01u,
      0x00u, 0xA4u, 0x04u, 0x00u, 0x08u, 0xA0u, 0x00u, 0x00u,
      0x06u, 0x47u, 0x2Fu, 0x00u, 0x01u, 0x00u,
  };
  std::vector<uint8_t> frame = MakeXfr(kTestLit0x33u, payload);

  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(), 15u);
  EXPECT_EQ(reader_security_key_utest_last_apdu_rsp_cap(), 0u);
  EXPECT_EQ(nero_nfc_test::At(rsp, 0), NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
  EXPECT_EQ(nero_nfc_test::At(rsp, 6), 0x33u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)), 5u);
  EXPECT_EQ(nero_nfc_test::At(rsp, 10), 0xD5u);
  EXPECT_EQ(nero_nfc_test::At(rsp, 11), 0x41u);
  EXPECT_EQ(nero_nfc_test::At(rsp, 12), 0x01u);
  EXPECT_EQ(nero_nfc_test::At(rsp, 13), 0x90u);
  EXPECT_EQ(nero_nfc_test::At(rsp, 14), 0x00u);
}

TEST_F(ReaderCcidDispatchTest, Type4Pn53xExchangeAppendsOuterStatusWord) {
  PowerOnStorageTag(READER_TAG_KIND_TYPE4);

  const std::vector<uint8_t> payload = {
      static_cast<uint8_t>(NFC_PN532_HOST_TO_PN532),
      static_cast<uint8_t>(NFC_PN532_CMD_IN_DATA_EXCHANGE),
      0x01u,
      static_cast<uint8_t>(NFC_ISO7816_CLA_ISO),
      static_cast<uint8_t>(NFC_ISO7816_INS_SELECT),
      0x00u,
      0x00u,
  };
  auto frame = MakeXfr(kTestLit0x34u, MakeAcr122DirectApdu(payload));
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(),
            static_cast<uint16_t>(NFC_CCID_BULK_PAYLOAD_OFFSET + 7u));
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)), 7u);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
            static_cast<uint8_t>(NFC_PN532_PN532_TO_HOST));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 1u),
            static_cast<uint8_t>(NFC_PN532_RSP_IN_DATA_EXCHANGE));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 2u), 0x00u);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 3u),
            static_cast<uint8_t>(NFC_ISO7816_SW1_SUCCESS));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 4u),
            static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 5u),
            static_cast<uint8_t>(NFC_ISO7816_SW1_SUCCESS));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 6u),
            static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS));
}

TEST_F(ReaderCcidDispatchTest, Acr122GetFirmwareVersionReturnsAsciiString) {
  PowerOnStorageTag(READER_TAG_KIND_TYPE4);

  const std::vector<uint8_t> apdu = {
      static_cast<uint8_t>(NFC_ISO7816_CLA_PROPRIETARY),
      static_cast<uint8_t>(NFC_ISO7816_CLA_ISO),
      static_cast<uint8_t>(NFC_ACR122U_P1_GET_FIRMWARE_VERSION),
      static_cast<uint8_t>(NFC_ISO7816_P2_SELECT_FIRST),
      static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS),
  };
  auto frame = MakeXfr(kTestLit0x30u, apdu);
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(),
            static_cast<uint16_t>(NFC_CCID_BULK_PAYLOAD_OFFSET + 10u));
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)), 10u);
  EXPECT_EQ(std::memcmp(&nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
                        "ACR122U203", 10),
            0);
}

TEST_F(ReaderCcidDispatchTest, Pn53xGetFirmwareVersionReturnsIcRevision) {
  PowerOnStorageTag(READER_TAG_KIND_TYPE4);

  const std::vector<uint8_t> payload = {
      static_cast<uint8_t>(NFC_PN532_HOST_TO_PN532),
      static_cast<uint8_t>(NFC_PN532_CMD_GET_FIRMWARE_VERSION),
  };
  auto frame = MakeXfr(kTestLit0x31u, MakeAcr122DirectApdu(payload));
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(),
            static_cast<uint16_t>(NFC_CCID_BULK_PAYLOAD_OFFSET + 8u));
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)), 8u);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
            static_cast<uint8_t>(NFC_PN532_PN532_TO_HOST));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 1u),
            static_cast<uint8_t>(NFC_PN532_GET_FIRMWARE_VERSION_RSP_SUB));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 2u),
            static_cast<uint8_t>(NFC_PN532_FW_VERSION_IC));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 3u),
            static_cast<uint8_t>(NFC_PN532_FW_VERSION_VER));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 4u),
            static_cast<uint8_t>(NFC_PN532_FW_VERSION_REV));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 5u),
            static_cast<uint8_t>(NFC_PN532_FW_VERSION_SUPPORT));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 6u),
            static_cast<uint8_t>(NFC_ISO7816_SW1_SUCCESS));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 7u),
            static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS));
}

TEST_F(ReaderCcidDispatchTest, Pn53xInListPassiveEmptyWhenTypeaUnavailable) {
  PowerOnStorageTag(READER_TAG_KIND_TYPE4);

  const std::vector<uint8_t> payload = {
      static_cast<uint8_t>(NFC_PN532_HOST_TO_PN532),
      static_cast<uint8_t>(NFC_PN532_CMD_IN_LIST_PASSIVE_TARGET),
      static_cast<uint8_t>(NFC_PN532_SINGLE_TARGET),
      static_cast<uint8_t>(NFC_PN532_BRTY_106KBPS_TYPE_A),
  };
  auto frame = MakeXfr(kTestLit0x32u, MakeAcr122DirectApdu(payload));
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(),
            static_cast<uint16_t>(NFC_CCID_BULK_PAYLOAD_OFFSET + 5u));
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)), 5u);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
            static_cast<uint8_t>(NFC_PN532_PN532_TO_HOST));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 1u),
            static_cast<uint8_t>(NFC_PN532_RSP_IN_LIST_PASSIVE_TARGET));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 2u),
            static_cast<uint8_t>(NFC_PN532_STATUS_OK));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 3u),
            static_cast<uint8_t>(NFC_ISO7816_SW1_SUCCESS));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 4u),
            static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS));
}

TEST_F(ReaderCcidDispatchTest, Pn53xInListPassiveReturnsTypeaTargetFields) {
  PowerOnStorageTag(READER_TAG_KIND_TYPE4);

  constexpr uint8_t kSakIsoDep = kTestLit0x20u;
  const std::array<uint8_t, 4u> uid = {kTestLit0x04u, kTestLit0x11u,
                                       kTestLit0x22u, kTestLit0x33u};
  const std::array<uint8_t, 2u> atqa = {kTestLit0x04u, 0x00u};
  const std::array<uint8_t, 5u> ats = {kTestLit0x05u, kTestLit0x75u,
                                       kTestLit0x80u, kTestLit0x02u,
                                       kTestLit0x80u};
  reader_tags_utest_set_typea_info(uid.data(), static_cast<uint8_t>(uid.size()),
                                   atqa.data(), kSakIsoDep, ats.data(),
                                   static_cast<uint8_t>(ats.size()));

  const std::vector<uint8_t> payload = {
      static_cast<uint8_t>(NFC_PN532_HOST_TO_PN532),
      static_cast<uint8_t>(NFC_PN532_CMD_IN_LIST_PASSIVE_TARGET),
      static_cast<uint8_t>(NFC_PN532_SINGLE_TARGET),
      static_cast<uint8_t>(NFC_PN532_BRTY_106KBPS_TYPE_A),
  };
  auto frame = MakeXfr(kTestLit0x33u, MakeAcr122DirectApdu(payload));
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  constexpr uint16_t kPn53xPrefixLen = 2u;
  constexpr uint16_t kTargetHeaderLen = 6u; /* NbTg Tg ATQA SAK UIDLEN */
  constexpr uint16_t kExpectedPayloadLen =
      kPn53xPrefixLen + kTargetHeaderLen + static_cast<uint16_t>(uid.size()) +
      1u + static_cast<uint16_t>(ats.size()) +
      static_cast<uint16_t>(NFC_ISO7816_SW_LEN);
  ASSERT_GE(reader_ccid_utest_last_send_len(),
            static_cast<uint16_t>(NFC_CCID_BULK_PAYLOAD_OFFSET +
                                  kExpectedPayloadLen));
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)),
            kExpectedPayloadLen);
  const auto body = rsp.subspan(NFC_CCID_BULK_PAYLOAD_OFFSET);
  EXPECT_EQ(nero_nfc_test::At(body, 0),
            static_cast<uint8_t>(NFC_PN532_PN532_TO_HOST));
  EXPECT_EQ(nero_nfc_test::At(body, 1),
            static_cast<uint8_t>(NFC_PN532_RSP_IN_LIST_PASSIVE_TARGET));
  EXPECT_EQ(nero_nfc_test::At(body, 2),
            static_cast<uint8_t>(NFC_PN532_SINGLE_TARGET));
  EXPECT_EQ(nero_nfc_test::At(body, 3),
            static_cast<uint8_t>(NFC_PN532_SINGLE_TARGET));
  EXPECT_EQ(nero_nfc_test::At(body, 4), atqa.at(0));
  EXPECT_EQ(nero_nfc_test::At(body, 5), atqa.at(1));
  EXPECT_EQ(nero_nfc_test::At(body, 6), kSakIsoDep);
  EXPECT_EQ(nero_nfc_test::At(body, 7), static_cast<uint8_t>(uid.size()));
  EXPECT_TRUE(std::equal(uid.begin(), uid.end(), body.begin() + 8));
  EXPECT_EQ(nero_nfc_test::At(body, 12), static_cast<uint8_t>(ats.size()));
  EXPECT_TRUE(std::equal(ats.begin(), ats.end(), body.begin() + 13));
  EXPECT_EQ(nero_nfc_test::At(body, 18),
            static_cast<uint8_t>(NFC_ISO7816_SW1_SUCCESS));
  EXPECT_EQ(nero_nfc_test::At(body, 19),
            static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS));
}

TEST_F(ReaderCcidDispatchTest, Pn53xInDeselectReturnsOkStatus) {
  PowerOnStorageTag(READER_TAG_KIND_TYPE4);

  const std::vector<uint8_t> payload = {
      static_cast<uint8_t>(NFC_PN532_HOST_TO_PN532),
      static_cast<uint8_t>(NFC_PN532_CMD_IN_DESELECT),
      static_cast<uint8_t>(NFC_PN532_SINGLE_TARGET),
  };
  auto frame = MakeXfr(kTestLit0x39u, MakeAcr122DirectApdu(payload));
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(),
            static_cast<uint16_t>(NFC_CCID_BULK_PAYLOAD_OFFSET + 5u));
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)), 5u);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
            static_cast<uint8_t>(NFC_PN532_PN532_TO_HOST));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 1u),
            static_cast<uint8_t>(NFC_PN532_RSP_IN_DESELECT));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 2u),
            static_cast<uint8_t>(NFC_PN532_STATUS_OK));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 3u),
            static_cast<uint8_t>(NFC_ISO7816_SW1_SUCCESS));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 4u),
            static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS));
}

TEST_F(ReaderCcidDispatchTest, Type2Pn53xGetVersionAllowedThroughTunnel) {
  PowerOnStorageTag(READER_TAG_KIND_TYPE2);
  reader_tags_utest_set_type2_storage_info(kTestLit144u, true, true);
  const std::array<uint8_t, 8u> version = {
      0x00u,         kTestLit0x04u, kTestLit0x04u, kTestLit0x02u,
      kTestLit0x01u, 0x00u,         kTestLit0x0Fu, kTestLit0x03u};
  reader_tags_utest_set_type2_transceive_response(
      version.data(), static_cast<uint16_t>(version.size()));

  const std::vector<uint8_t> payload = {
      static_cast<uint8_t>(NFC_PN532_HOST_TO_PN532),
      static_cast<uint8_t>(NFC_PN532_CMD_IN_DATA_EXCHANGE),
      0x01u,
      static_cast<uint8_t>(CCID_RAW_T2_CMD_GET_VERSION),
  };
  auto frame = MakeXfr(kTestLit0x3Au, MakeAcr122DirectApdu(payload));
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(),
            static_cast<uint16_t>(NFC_CCID_BULK_PAYLOAD_OFFSET + 13u));
  EXPECT_EQ(reader_tags_utest_type2_transceive_count(), 1u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)), 13u);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
            static_cast<uint8_t>(NFC_PN532_PN532_TO_HOST));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 1u),
            static_cast<uint8_t>(NFC_PN532_RSP_IN_DATA_EXCHANGE));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 2u),
            static_cast<uint8_t>(NFC_PN532_STATUS_OK));
  EXPECT_EQ(
      std::memcmp(&nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 3u),
                  version.data(), version.size()),
      0);
}

TEST_F(ReaderCcidDispatchTest, Type2Pn53xTunnelRejectsRawWriteBeforeRf) {
  PowerOnStorageTag(READER_TAG_KIND_TYPE2);

  const std::vector<uint8_t> type2_write = {
      static_cast<uint8_t>(NFC_PN532_HOST_TO_PN532),
      static_cast<uint8_t>(NFC_PN532_CMD_IN_DATA_EXCHANGE),
      0x01u,
      0xA2u,
      static_cast<uint8_t>(NFC_STORAGE_TYPE2_FIRST_DATA_PAGE),
      0x11u,
      0x22u,
      0x33u,
      0x44u,
  };
  auto frame = MakeXfr(kTestLit0x34u, MakeAcr122DirectApdu(type2_write));
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(),
            static_cast<uint16_t>(NFC_CCID_BULK_PAYLOAD_OFFSET + 5u));
  EXPECT_EQ(reader_tags_utest_type2_transceive_count(), 0u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)), 5u);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
            static_cast<uint8_t>(NFC_PN532_PN532_TO_HOST));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 1u),
            static_cast<uint8_t>(NFC_PN532_RSP_IN_DATA_EXCHANGE));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 2u), 0x01u);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 3u),
            static_cast<uint8_t>(NFC_ISO7816_SW1_SUCCESS));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 4u),
            static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS));
}

TEST_F(ReaderCcidDispatchTest, Type5Pn53xTunnelRejectsRawWriteBeforeRf) {
  PowerOnStorageTag(READER_TAG_KIND_TYPE5);

  const std::vector<uint8_t> type5_write_single = {
      static_cast<uint8_t>(NFC_PN532_HOST_TO_PN532),
      static_cast<uint8_t>(NFC_PN532_CMD_IN_COMMUNICATE_THRU),
      static_cast<uint8_t>(NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED),
      static_cast<uint8_t>(NFC_TAG_T5T_ISO15693_CMD_WRITE_SINGLE),
      0x00u,
      0x01u,
      0x02u,
      0x03u,
      0x04u,
  };
  auto frame = MakeXfr(kTestLit0x35u, MakeAcr122DirectApdu(type5_write_single));
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(),
            static_cast<uint16_t>(NFC_CCID_BULK_PAYLOAD_OFFSET + 5u));
  EXPECT_EQ(reader_tags_utest_type5_transceive_count(), 0u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)), 5u);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
            static_cast<uint8_t>(NFC_PN532_PN532_TO_HOST));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 1u),
            static_cast<uint8_t>(NFC_PN532_RSP_IN_COMMUNICATE_THRU));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 2u), 0x01u);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 3u),
            static_cast<uint8_t>(NFC_ISO7816_SW1_SUCCESS));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 4u),
            static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS));
}

TEST_F(ReaderCcidDispatchTest, Type5TransparentEscapeRejectsRawWriteBeforeRf) {
  PowerOnStorageTag(READER_TAG_KIND_TYPE5);

  const std::vector<uint8_t> escape_write = {
      static_cast<uint8_t>(NFC_ISO7816_CLA_PROPRIETARY),
      static_cast<uint8_t>(NFC_PCSC_ESCAPE_TRANSPARENT_INS),
      0x00u,
      0x00u,
      0x07u,
      static_cast<uint8_t>(NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED),
      static_cast<uint8_t>(NFC_TAG_T5T_ISO15693_CMD_WRITE_SINGLE),
      0x00u,
      0x01u,
      0x02u,
      0x03u,
      0x04u,
  };
  auto frame = MakeXfr(kTestLit0x36u, escape_write);
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(), kSwPayloadEnd);
  EXPECT_EQ(reader_tags_utest_type5_transceive_count(), 0u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)),
            static_cast<uint32_t>(NFC_ISO7816_SW_LEN));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
            static_cast<uint8_t>(NFC_ISO7816_SW1_INS_NOT_SUPPORTED));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 1u),
            static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS));
}

TEST_F(ReaderCcidDispatchTest, Type5TransparentEscapeRejectsStayQuietBeforeRf) {
  PowerOnStorageTag(READER_TAG_KIND_TYPE5);

  const std::vector<uint8_t> stay_quiet = {
      static_cast<uint8_t>(NFC_ISO7816_CLA_PROPRIETARY),
      static_cast<uint8_t>(NFC_PCSC_ESCAPE_TRANSPARENT_INS),
      0x00u,
      0x00u,
      0x02u,
      static_cast<uint8_t>(NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED),
      0x02u,
  };
  auto frame = MakeXfr(kTestLit0x36u, stay_quiet);
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(), kSwPayloadEnd);
  EXPECT_EQ(reader_tags_utest_type5_transceive_count(), 0u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)),
            static_cast<uint32_t>(NFC_ISO7816_SW_LEN));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
            static_cast<uint8_t>(NFC_ISO7816_SW1_INS_NOT_SUPPORTED));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 1u),
            static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS));
}

TEST_F(ReaderCcidDispatchTest,
       Type5TransparentEscapeRejectsAddressedReadForOtherUidBeforeRf) {
  reader_tags_utest_set_type5_info(NFC_TAG_T5T_CC_LEN_SHORT, kTestLit320u,
                                   kTestLit81u, true, true);
  SetType5UidForTests();
  PowerOnStorageTag(READER_TAG_KIND_TYPE5);

  std::vector<uint8_t> escape_read = {
      static_cast<uint8_t>(NFC_ISO7816_CLA_PROPRIETARY),
      static_cast<uint8_t>(NFC_PCSC_ESCAPE_TRANSPARENT_INS),
      0x00u,
      0x00u,
      static_cast<uint8_t>(kTestLit2u + NFC_FRONTEND_ISO15693_UID_LEN + 1u),
      static_cast<uint8_t>(NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED),
      static_cast<uint8_t>(NFC_TAG_T5T_ISO15693_CMD_READ_SINGLE),
  };
  const std::vector<uint8_t> uid_lsb = MismatchedType5UidLsb();
  escape_read.insert(escape_read.end(), uid_lsb.begin(), uid_lsb.end());
  escape_read.push_back(0x01u);

  auto frame = MakeXfr(kTestLit0x38u, escape_read);
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(), kSwPayloadEnd);
  EXPECT_EQ(reader_tags_utest_type5_transceive_count(), 0u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)),
            static_cast<uint32_t>(NFC_ISO7816_SW_LEN));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
            static_cast<uint8_t>(NFC_ISO7816_SW1_INS_NOT_SUPPORTED));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 1u),
            static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS));
}

TEST_F(ReaderCcidDispatchTest,
       Type5TransparentEscapeRejectsAddressedSysInfoForOtherUidBeforeRf) {
  SetType5UidForTests();
  PowerOnStorageTag(READER_TAG_KIND_TYPE5);

  std::vector<uint8_t> sys_info = {
      static_cast<uint8_t>(NFC_ISO7816_CLA_PROPRIETARY),
      static_cast<uint8_t>(NFC_PCSC_ESCAPE_TRANSPARENT_INS),
      0x00u,
      0x00u,
      static_cast<uint8_t>(kTestLit2u + NFC_FRONTEND_ISO15693_UID_LEN),
      static_cast<uint8_t>(NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED),
      static_cast<uint8_t>(NFC_TAG_T5T_ISO15693_CMD_GET_SYS_INFO),
  };
  const std::vector<uint8_t> uid_lsb = MismatchedType5UidLsb();
  sys_info.insert(sys_info.end(), uid_lsb.begin(), uid_lsb.end());

  auto frame = MakeXfr(kTestLit0x39u, sys_info);
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(), kSwPayloadEnd);
  EXPECT_EQ(reader_tags_utest_type5_transceive_count(), 0u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)),
            static_cast<uint32_t>(NFC_ISO7816_SW_LEN));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
            static_cast<uint8_t>(NFC_ISO7816_SW1_INS_NOT_SUPPORTED));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 1u),
            static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS));
}

TEST_F(ReaderCcidDispatchTest,
       Type5Pn53xTunnelRejectsAddressedReadForOtherUidBeforeRf) {
  reader_tags_utest_set_type5_info(NFC_TAG_T5T_CC_LEN_SHORT, kTestLit320u,
                                   kTestLit81u, true, true);
  SetType5UidForTests();
  PowerOnStorageTag(READER_TAG_KIND_TYPE5);

  std::vector<uint8_t> type5_read = {
      static_cast<uint8_t>(NFC_PN532_HOST_TO_PN532),
      static_cast<uint8_t>(NFC_PN532_CMD_IN_COMMUNICATE_THRU),
      static_cast<uint8_t>(NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED),
      static_cast<uint8_t>(NFC_TAG_T5T_ISO15693_CMD_READ_SINGLE),
  };
  const std::vector<uint8_t> uid_lsb = MismatchedType5UidLsb();
  type5_read.insert(type5_read.end(), uid_lsb.begin(), uid_lsb.end());
  type5_read.push_back(0x01u);

  auto frame = MakeXfr(kTestLit0x3Au, MakeAcr122DirectApdu(type5_read));
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(),
            static_cast<uint16_t>(NFC_CCID_BULK_PAYLOAD_OFFSET + 5u));
  EXPECT_EQ(reader_tags_utest_type5_transceive_count(), 0u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)), 5u);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
            static_cast<uint8_t>(NFC_PN532_PN532_TO_HOST));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 1u),
            static_cast<uint8_t>(NFC_PN532_RSP_IN_COMMUNICATE_THRU));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 2u), 0x01u);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 3u),
            static_cast<uint8_t>(NFC_ISO7816_SW1_SUCCESS));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 4u),
            static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS));
}

TEST_F(ReaderCcidDispatchTest,
       Type2Pn53xTunnelRejectsOutOfBoundsRawReadBeforeRf) {
  reader_tags_utest_set_type2_storage_info(kTestLit64u, true, true);
  PowerOnStorageTag(READER_TAG_KIND_TYPE2);

  const std::vector<uint8_t> type2_read_page20 = {
      static_cast<uint8_t>(NFC_PN532_HOST_TO_PN532),
      static_cast<uint8_t>(NFC_PN532_CMD_IN_DATA_EXCHANGE),
      0x01u,
      static_cast<uint8_t>(CCID_RAW_T2_CMD_READ),
      20u,
  };
  auto frame = MakeXfr(kTestLit0x37u, MakeAcr122DirectApdu(type2_read_page20));
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(),
            static_cast<uint16_t>(NFC_CCID_BULK_PAYLOAD_OFFSET + 5u));
  EXPECT_EQ(reader_tags_utest_type2_transceive_count(), 0u);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
            static_cast<uint8_t>(NFC_PN532_PN532_TO_HOST));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 1u),
            static_cast<uint8_t>(NFC_PN532_RSP_IN_DATA_EXCHANGE));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 2u), 0x01u);
}

TEST_F(ReaderCcidDispatchTest,
       Type2GetDataVersionUsesNtagFingerprintWithoutNxpUid) {
  const uint8_t apdu[] = {0xFFu, 0xCAu,
                          static_cast<uint8_t>(NFC_PCSC_GET_DATA_TYPE2_VERSION),
                          0x00u, 0x00u};
  const uint8_t version[] = {0x00u, 0x04u, 0x04u, 0x02u,
                             0x01u, 0x00u, 0x13u, 0x03u};
  uint8_t rsp[kTestLit16];

  reader_tags_utest_set_type2_storage_info(kTestLit1016u, true, true);
  reader_tags_utest_set_type2_transceive_response(
      &version[0], static_cast<uint16_t>(sizeof(version)));
  G_TAG_KIND = READER_TAG_KIND_TYPE2;
  G_UID14_LEN = kTestLit7u;
  G_UID14[0] = kTestLit0x53u;

  const uint16_t rlen = reader_ccid_handle_get_data_apdu(
      &apdu[0], static_cast<uint16_t>(sizeof(apdu)), &rsp[0],
      static_cast<uint16_t>(sizeof(rsp)));

  ASSERT_EQ(rlen, static_cast<uint16_t>(sizeof(version) + NFC_ISO7816_SW_LEN));
  EXPECT_TRUE(std::equal(std::begin(version), std::end(version), &rsp[0]));
  EXPECT_EQ(rsp[sizeof(version)],
            static_cast<uint8_t>(NFC_ISO7816_SW1_SUCCESS));
  EXPECT_EQ(rsp[sizeof(version) + 1u],
            static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS));
  EXPECT_EQ(reader_tags_utest_type2_transceive_count(), 1u);
}

TEST_F(ReaderCcidDispatchTest, Type2GetDataVersionDoesNotProbeType4Tag) {
  const uint8_t apdu[] = {0xFFu, 0xCAu,
                          static_cast<uint8_t>(NFC_PCSC_GET_DATA_TYPE2_VERSION),
                          0x00u, 0x00u};
  const uint8_t version[] = {0x00u, 0x04u, 0x04u, 0x02u,
                             0x01u, 0x00u, 0x13u, 0x03u};
  uint8_t rsp[kTestLit16];

  reader_tags_utest_set_type2_storage_info(kTestLit1016u, true, true);
  reader_tags_utest_set_type2_transceive_response(
      &version[0], static_cast<uint16_t>(sizeof(version)));
  G_TAG_KIND = READER_TAG_KIND_TYPE4;

  const uint16_t rlen = reader_ccid_handle_get_data_apdu(
      &apdu[0], static_cast<uint16_t>(sizeof(apdu)), &rsp[0],
      static_cast<uint16_t>(sizeof(rsp)));

  ASSERT_EQ(rlen, static_cast<uint16_t>(NFC_ISO7816_SW_LEN));
  EXPECT_EQ(rsp[0], static_cast<uint8_t>(NFC_ISO7816_SW1_WRONG_DATA));
  EXPECT_EQ(rsp[1], static_cast<uint8_t>(NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED));
  EXPECT_EQ(reader_tags_utest_type2_transceive_count(), 0u);
}

TEST_F(ReaderCcidDispatchTest, StorageTagsRejectIsoType4NdefSelect) {
  const std::vector<uint8_t> select_ndef_app = MakeSelectNdefAppApdu();
  const reader_tag_kind_t storage_kinds[] = {READER_TAG_KIND_TYPE2,
                                             READER_TAG_KIND_TYPE5};

  for (reader_tag_kind_t const kind : storage_kinds) {
    reader_ccid_utest_reset();
    reader_ccid_on_tag_detected(kind);
    auto power_on = MakeBulk(kTestLit0x62u, kTestLit0x50u);
    reader_ccid_utest_handle_bulk(power_on.data(),
                                  static_cast<uint16_t>(power_on.size()));

    auto frame = MakeXfr(kTestLit0x51u, select_ndef_app);
    reader_ccid_utest_handle_bulk(frame.data(),
                                  static_cast<uint16_t>(frame.size()));

    const std::span<const uint8_t> rsp = LastCcidSend();
    ASSERT_GE(reader_ccid_utest_last_send_len(),
              static_cast<uint16_t>(NFC_CCID_BULK_HEADER_LEN) +
                  static_cast<uint16_t>(NFC_ISO7816_SW_LEN));
    EXPECT_EQ(nero_nfc_test::At(rsp, 0), NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
    EXPECT_EQ(nero_nfc_test::At(rsp, 6), 0x51u);
    EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)),
              static_cast<uint32_t>(NFC_ISO7816_SW_LEN));
    EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
              static_cast<uint8_t>(NFC_ISO7816_SW1_INS_NOT_SUPPORTED));
    EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 1u),
              static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS));
  }
}

TEST_F(ReaderCcidDispatchTest, Type4NdefSelectRelaysOnNonFidoType4Tag) {
  reader_security_key_utest_set_select_fido_probe_ok(false);
  PowerOnStorageTag(READER_TAG_KIND_TYPE4);

  auto frame = MakeXfr(kTestLit0x75u, MakeSelectNdefAppApdu());
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(), kSwPayloadEnd);
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)),
            static_cast<uint32_t>(NFC_ISO7816_SW_LEN));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
            static_cast<uint8_t>(NFC_ISO7816_SW1_SUCCESS));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 1u),
            static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS));
  EXPECT_GT(reader_security_key_utest_last_apdu_rsp_cap(), 0u);
}

TEST_F(ReaderCcidDispatchTest, Type4NdefSelectBlockedOnConfirmedSecurityKey) {
  PowerOnStorageTag(READER_TAG_KIND_TYPE4);
  ASSERT_EQ(reader_security_key_utest_last_apdu_rsp_cap(), 0u);

  auto fido_select = MakeXfr(kTestLit0x75u, MakeSelectFidoAppApdu());
  reader_ccid_utest_handle_bulk(fido_select.data(),
                                static_cast<uint16_t>(fido_select.size()));
  ASSERT_GT(reader_security_key_utest_last_apdu_rsp_cap(), 0u);

  auto frame = MakeXfr(kTestLit0x76u, MakeSelectNdefAppApdu());
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(), kSwPayloadEnd);
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)),
            static_cast<uint32_t>(NFC_ISO7816_SW_LEN));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
            static_cast<uint8_t>(NFC_ISO7816_SW1_CONDITIONS_NOT_SATISFIED));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 1u),
            static_cast<uint8_t>(NFC_ISO7816_SW2_COMMAND_NOT_ALLOWED));
}

TEST_F(ReaderCcidDispatchTest, FailedFidoSelectDoesNotBlockNdefApplication) {
  const std::array<uint8_t, NFC_ISO7816_SW_LEN> failure = {
      static_cast<uint8_t>(NFC_ISO7816_SW1_GENERAL_ERROR),
      static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS)};
  PowerOnStorageTag(READER_TAG_KIND_TYPE4);
  reader_security_key_utest_set_apdu_response(
      failure.data(), static_cast<uint16_t>(failure.size()));

  auto fido_select = MakeXfr(kTestLit0x75u, MakeSelectFidoAppApdu());
  reader_ccid_utest_handle_bulk(fido_select.data(),
                                static_cast<uint16_t>(fido_select.size()));

  const std::array<uint8_t, NFC_ISO7816_SW_LEN> success = {
      static_cast<uint8_t>(NFC_ISO7816_SW1_SUCCESS),
      static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS)};
  reader_security_key_utest_set_apdu_response(
      success.data(), static_cast<uint16_t>(success.size()));
  auto ndef_select = MakeXfr(kTestLit0x76u, MakeSelectNdefAppApdu());
  reader_ccid_utest_handle_bulk(ndef_select.data(),
                                static_cast<uint16_t>(ndef_select.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
            static_cast<uint8_t>(NFC_ISO7816_SW1_SUCCESS));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 1u),
            static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS));
}

TEST_F(ReaderCcidDispatchTest, Type2UpdateBinaryRejectsWriteRestrictedTag) {
  reader_tags_utest_set_type2_storage_info(kTestLit64u, true, false);
  reader_tags_utest_set_type2_write_ok(true);
  PowerOnStorageTag(READER_TAG_KIND_TYPE2);

  const std::vector<uint8_t> update_page4 = {
      static_cast<uint8_t>(NFC_ISO7816_CLA_PROPRIETARY),
      static_cast<uint8_t>(NFC_ISO7816_INS_UPDATE_BINARY),
      0x00u,
      static_cast<uint8_t>(NFC_STORAGE_TYPE2_FIRST_DATA_PAGE),
      0x04u,
      0xAAu,
      0xBBu,
      0xCCu,
      0xDDu,
  };
  auto frame = MakeXfr(kTestLit0x72u, update_page4);
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(), kSwPayloadEnd);
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)),
            static_cast<uint32_t>(NFC_ISO7816_SW_LEN));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
            static_cast<uint8_t>(NFC_ISO7816_SW1_CONDITIONS_NOT_SATISFIED));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 1u),
            static_cast<uint8_t>(NFC_ISO7816_SW2_CONDITIONS_NOT_SATISFIED));
  EXPECT_EQ(reader_tags_utest_type2_write_count(), 0u);
}

TEST_F(ReaderCcidDispatchTest, StorageUpdateBinarySendsTimeExtension) {
  reader_tags_utest_set_type2_storage_info(kTestLit64u, true, true);
  reader_tags_utest_set_type2_write_ok(true);
  PowerOnStorageTag(READER_TAG_KIND_TYPE2);

  const std::vector<uint8_t> update_page4 = {
      static_cast<uint8_t>(NFC_ISO7816_CLA_PROPRIETARY),
      static_cast<uint8_t>(NFC_ISO7816_INS_UPDATE_BINARY),
      0x00u,
      static_cast<uint8_t>(NFC_STORAGE_TYPE2_FIRST_DATA_PAGE),
      kTestLit0x04u,
      0xAAu,
      0xBBu,
      0xCCu,
      0xDDu,
  };
  auto frame = MakeXfr(kTestLit0x72u, update_page4);
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  EXPECT_EQ(reader_hal_utest_ccid_time_extension_send_count(), 1u);
  const std::span<const uint8_t> rsp = LastCcidSend();
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
            static_cast<uint8_t>(NFC_ISO7816_SW1_SUCCESS));
}

TEST_F(ReaderCcidDispatchTest, Type2WriteStopsBetweenPagesOnAbort) {
  reader_tags_utest_set_type2_storage_info(kTestLit64u, true, true);
  reader_tags_utest_set_type2_write_ok(true);
  reader_tags_utest_abort_after_type2_writes(1u);
  PowerOnStorageTag(READER_TAG_KIND_TYPE2);

  const std::vector<uint8_t> update_two_pages = {
      static_cast<uint8_t>(NFC_ISO7816_CLA_PROPRIETARY),
      static_cast<uint8_t>(NFC_ISO7816_INS_UPDATE_BINARY),
      0x00u,
      static_cast<uint8_t>(NFC_STORAGE_TYPE2_FIRST_DATA_PAGE),
      0x08u,
      0x01u,
      0x02u,
      0x03u,
      0x04u,
      0x05u,
      0x06u,
      0x07u,
      0x08u,
  };
  auto frame = MakeXfr(0u, update_two_pages);
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  EXPECT_EQ(reader_tags_utest_type2_write_count(), 1u);
  EXPECT_EQ(nero_nfc_test::At(rsp, 0), NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_LEVEL_PARAM_OFFSET) & 0x40u,
            0x40u);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_LEVEL_PARAM2_OFFSET), 0xFFu);
}

TEST_F(ReaderCcidDispatchTest, Type2UpdateBinaryRejectsPagePastDataArea) {
  reader_tags_utest_set_type2_storage_info(kTestLit64u, true, true);
  reader_tags_utest_set_type2_write_ok(true);
  PowerOnStorageTag(READER_TAG_KIND_TYPE2);

  const std::vector<uint8_t> update_page20 = {
      static_cast<uint8_t>(NFC_ISO7816_CLA_PROPRIETARY),
      static_cast<uint8_t>(NFC_ISO7816_INS_UPDATE_BINARY),
      0x00u,
      20u,
      0x04u,
      0xAAu,
      0xBBu,
      0xCCu,
      0xDDu,
  };
  auto frame = MakeXfr(kTestLit0x73u, update_page20);
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(), kSwPayloadEnd);
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)),
            static_cast<uint32_t>(NFC_ISO7816_SW_LEN));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
            static_cast<uint8_t>(NFC_ISO7816_SW1_WRONG_P1P2));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 1u),
            static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS));
  EXPECT_EQ(reader_tags_utest_type2_write_count(), 0u);
}

TEST_F(ReaderCcidDispatchTest, Type2UpdateBinaryAcceptsAlignedMultiPageWrite) {
  reader_tags_utest_set_type2_storage_info(kTestLit64u, true, true);
  reader_tags_utest_set_type2_write_ok(true);
  PowerOnStorageTag(READER_TAG_KIND_TYPE2);

  const std::vector<uint8_t> update_pages4_and5 = {
      static_cast<uint8_t>(NFC_ISO7816_CLA_PROPRIETARY),
      static_cast<uint8_t>(NFC_ISO7816_INS_UPDATE_BINARY),
      0x00u,
      static_cast<uint8_t>(NFC_STORAGE_TYPE2_FIRST_DATA_PAGE),
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
  auto frame = MakeXfr(kTestLit0x75u, update_pages4_and5);
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(), kSwPayloadEnd);
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)),
            static_cast<uint32_t>(NFC_ISO7816_SW_LEN));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
            static_cast<uint8_t>(NFC_ISO7816_SW1_SUCCESS));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 1u),
            static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS));
  EXPECT_EQ(reader_tags_utest_type2_write_count(), 2u);
}

TEST_F(ReaderCcidDispatchTest, Type5ReadBinaryGenericByteOffsetMapsToBlock) {
  reader_tags_utest_set_type5_info(NFC_TAG_T5T_CC_LEN_SHORT, kTestLit320u,
                                   kTestLit81u, true, true);
  PowerOnStorageTag(READER_TAG_KIND_TYPE5);

  const std::vector<uint8_t> read_from_tlv_start = {
      static_cast<uint8_t>(NFC_ISO7816_CLA_PROPRIETARY),
      static_cast<uint8_t>(NFC_ISO7816_INS_READ_BINARY),
      0x00u,
      static_cast<uint8_t>(NFC_STORAGE_TYPE5_BLOCK_SIZE),
      0x08u,
  };
  auto frame = MakeXfr(kTestLit0x77u, read_from_tlv_start);
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(),
            static_cast<uint16_t>(NFC_CCID_BULK_PAYLOAD_OFFSET + 10u));
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)), 10u);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 8u),
            static_cast<uint8_t>(NFC_ISO7816_SW1_SUCCESS));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 9u),
            static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS));
  EXPECT_EQ(reader_tags_utest_type5_read_count(), 1u);
  EXPECT_EQ(reader_tags_utest_type5_last_read_block(), 1u);
  EXPECT_EQ(reader_tags_utest_type5_last_read_len(), 8u);
  EXPECT_EQ(reader_hal_utest_ccid_time_extension_send_count(), 1u);
}

TEST_F(ReaderCcidDispatchTest, Type5UpdateBinaryAcceptsValidCcRefresh) {
  reader_tags_utest_set_type5_info(NFC_TAG_T5T_CC_LEN_SHORT, kTestLit320u,
                                   kTestLit81u, true, true);
  reader_tags_utest_set_type5_write_ok(true);
  PowerOnStorageTag(READER_TAG_KIND_TYPE5);

  const std::vector<uint8_t> update_block0 = {
      static_cast<uint8_t>(NFC_ISO7816_CLA_PROPRIETARY),
      static_cast<uint8_t>(NFC_ISO7816_INS_UPDATE_BINARY),
      static_cast<uint8_t>(NFC_ISO7816_READ_BINARY_P1_BLOCK_IN_P2),
      0x00u,
      0x04u,
      static_cast<uint8_t>(NFC_FORUM_CC_MAGIC),
      static_cast<uint8_t>(NFC_T5T_CC_VER_ACCESS),
      0x10u,
      0x00u,
  };
  auto frame = MakeXfr(kTestLit0x74u, update_block0);
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(), kSwPayloadEnd);
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)),
            static_cast<uint32_t>(NFC_ISO7816_SW_LEN));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
            static_cast<uint8_t>(NFC_ISO7816_SW1_SUCCESS));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 1u),
            static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS));
  EXPECT_EQ(reader_tags_utest_type5_write_count(), 1u);
}

TEST_F(ReaderCcidDispatchTest, Type5UpdateBinaryRejectsInvalidCcRefresh) {
  reader_tags_utest_set_type5_info(NFC_TAG_T5T_CC_LEN_SHORT, kTestLit320u,
                                   kTestLit81u, true, true);
  reader_tags_utest_set_type5_write_ok(true);
  PowerOnStorageTag(READER_TAG_KIND_TYPE5);

  const std::vector<uint8_t> update_block0 = {
      static_cast<uint8_t>(NFC_ISO7816_CLA_PROPRIETARY),
      static_cast<uint8_t>(NFC_ISO7816_INS_UPDATE_BINARY),
      static_cast<uint8_t>(NFC_ISO7816_READ_BINARY_P1_BLOCK_IN_P2),
      0x00u,
      0x04u,
      0xAAu,
      0xBBu,
      0xCCu,
      0xDDu,
  };
  auto frame = MakeXfr(kTestLit0x75u, update_block0);
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(), kSwPayloadEnd);
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)),
            static_cast<uint32_t>(NFC_ISO7816_SW_LEN));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
            static_cast<uint8_t>(NFC_ISO7816_SW1_WRONG_DATA));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 1u),
            static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS));
  EXPECT_EQ(reader_tags_utest_type5_write_count(), 0u);
}

TEST_F(ReaderCcidDispatchTest, Type5WriteStopsBetweenBlocksOnAbort) {
  reader_tags_utest_set_type5_info(NFC_TAG_T5T_CC_LEN_SHORT, kTestLit320u,
                                   kTestLit81u, true, true);
  reader_tags_utest_set_type5_write_ok(true);
  reader_tags_utest_abort_after_type5_writes(1u);
  PowerOnStorageTag(READER_TAG_KIND_TYPE5);

  const std::vector<uint8_t> update_two_blocks = {
      static_cast<uint8_t>(NFC_ISO7816_CLA_PROPRIETARY),
      static_cast<uint8_t>(NFC_ISO7816_INS_UPDATE_BINARY),
      static_cast<uint8_t>(NFC_ISO7816_READ_BINARY_P1_BLOCK_IN_P2),
      0x01u,
      0x08u,
      0x01u,
      0x02u,
      0x03u,
      0x04u,
      0x05u,
      0x06u,
      0x07u,
      0x08u,
  };
  auto frame = MakeXfr(0u, update_two_blocks);
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  EXPECT_EQ(reader_tags_utest_type5_write_count(), 1u);
  EXPECT_EQ(nero_nfc_test::At(rsp, 0), NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_LEVEL_PARAM_OFFSET) & 0x40u,
            0x40u);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_LEVEL_PARAM2_OFFSET), 0xFFu);
}

TEST_F(ReaderCcidDispatchTest, Type5UpdateBinaryAcceptsAlignedMultiBlockWrite) {
  reader_tags_utest_set_type5_info(NFC_TAG_T5T_CC_LEN_SHORT, kTestLit320u,
                                   kTestLit81u, true, true);
  reader_tags_utest_set_type5_write_ok(true);
  PowerOnStorageTag(READER_TAG_KIND_TYPE5);

  const std::vector<uint8_t> update_blocks1_and2 = {
      static_cast<uint8_t>(NFC_ISO7816_CLA_PROPRIETARY),
      static_cast<uint8_t>(NFC_ISO7816_INS_UPDATE_BINARY),
      static_cast<uint8_t>(NFC_ISO7816_READ_BINARY_P1_BLOCK_IN_P2),
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
  auto frame = MakeXfr(kTestLit0x76u, update_blocks1_and2);
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(), kSwPayloadEnd);
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)),
            static_cast<uint32_t>(NFC_ISO7816_SW_LEN));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
            static_cast<uint8_t>(NFC_ISO7816_SW1_SUCCESS));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 1u),
            static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS));
  EXPECT_EQ(reader_tags_utest_type5_write_count(), 2u);
}

TEST_F(ReaderCcidDispatchTest, Type4XfrPassesStatusWordHeadroomToRelay) {
  reader_ccid_on_tag_detected(READER_TAG_KIND_TYPE4);
  auto power_on = MakeBulk(kTestLit0x62u, kTestLit0x25u);
  reader_ccid_utest_handle_bulk(power_on.data(),
                                static_cast<uint16_t>(power_on.size()));

  std::array<uint8_t, kTestLit14> frame{};
  frame.at(0) = NFC_CCID_MSG_PC_TO_RDR_XFR;
  frame.at(1) = kTestLit0x04u;
  frame.at(kTestLit6) = kTestLit0x42u;
  frame.at(kTestLit10) = 0x00u;
  frame.at(kTestLit11) = kTestLit0xA4u;
  frame.at(kTestLit12) = 0x00u;
  frame.at(kTestLit13) = 0x00u;
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  EXPECT_EQ(reader_security_key_utest_last_apdu_rsp_cap(),
            CCID_APDU_RSP_BUF_MAX + 2u);
}

TEST_F(ReaderCcidDispatchTest, AbortDuringXfrReturnsCommandAborted) {
  reader_ccid_on_tag_detected(READER_TAG_KIND_TYPE4);
  auto power_on = MakeBulk(kTestLit0x62u, kTestLit0x20u);
  reader_ccid_utest_handle_bulk(power_on.data(),
                                static_cast<uint16_t>(power_on.size()));

  reader_hal_utest_ccid_set_abort_pending(true, 0u, 0u);
  std::array<uint8_t, kTestLit14> frame{};
  frame.at(0) = NFC_CCID_MSG_PC_TO_RDR_XFR;
  frame.at(1) = kTestLit0x04u;
  frame.at(kTestLit6) = kTestLit0x40u;
  frame.at(kTestLit10) = 0x00u;
  frame.at(kTestLit11) = kTestLit0xA4u;
  frame.at(kTestLit12) = 0x00u;
  frame.at(kTestLit13) = 0x00u;
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));
  const std::span<const uint8_t> rsp = LastCcidSend();
  EXPECT_EQ(nero_nfc_test::At(rsp, 0), NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
  EXPECT_EQ(nero_nfc_test::At(rsp, 8), 0xFFu);
}

TEST_F(ReaderCcidDispatchTest, AbortArrivingDuringXfrFailsOriginalCommand) {
  reader_ccid_on_tag_detected(READER_TAG_KIND_TYPE4);
  auto power_on = MakeBulk(kTestLit0x62u, kTestLit0x20u);
  reader_ccid_utest_handle_bulk(power_on.data(),
                                static_cast<uint16_t>(power_on.size()));
  reader_security_key_utest_set_abort_during_exchange(true);

  auto frame = MakeXfr(0u, {0x00u, kTestLit0xA4u, 0x00u, 0x00u});
  reader_ccid_utest_handle_bulk(frame.data(),
                                static_cast<uint16_t>(frame.size()));

  const std::span<const uint8_t> rsp = LastCcidSend();
  EXPECT_EQ(nero_nfc_test::At(rsp, 0), NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_SEQ_OFFSET), 0u);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_LEVEL_PARAM_OFFSET) & 0x40u,
            0x40u);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_LEVEL_PARAM2_OFFSET), 0xFFu);
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)), 0u);
}

TEST_F(ReaderCcidDispatchTest, AbortClearsPendingCommandChain) {
  reader_ccid_on_tag_detected(READER_TAG_KIND_TYPE4);
  auto power_on = MakeBulk(kTestLit0x62u, kTestLit0x28u);
  reader_ccid_utest_handle_bulk(power_on.data(),
                                static_cast<uint16_t>(power_on.size()));

  auto chain_begin = MakeXfrChain(
      kTestLit0x52u, static_cast<uint8_t>(NFC_CCID_XFR_LEVEL_CHAIN_BEGIN),
      {0x00u, kTestLit0xA4u});
  reader_ccid_utest_handle_bulk(chain_begin.data(),
                                static_cast<uint16_t>(chain_begin.size()));
  std::span<const uint8_t> rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(),
            static_cast<uint16_t>(NFC_CCID_BULK_HEADER_LEN));
  EXPECT_EQ(nero_nfc_test::At(rsp, 0), NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_LEVEL_PARAM3_OFFSET),
            static_cast<uint8_t>(NFC_CCID_XFR_RESPONSE_CONTINUE));

  auto abort = MakeBulk(NFC_CCID_MSG_PC_TO_RDR_ABORT, kTestLit0x53u);
  reader_ccid_utest_handle_bulk(abort.data(),
                                static_cast<uint16_t>(abort.size()));

  auto single =
      MakeXfr(kTestLit0x54u, {0x00u, kTestLit0xA4u, kTestLit0x04u, 0x00u});
  reader_ccid_utest_handle_bulk(single.data(),
                                static_cast<uint16_t>(single.size()));
  rsp = LastCcidSend();
  ASSERT_GE(reader_ccid_utest_last_send_len(), kSwPayloadEnd);
  EXPECT_EQ(nero_nfc_test::At(rsp, 0), NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
  EXPECT_EQ(nero_nfc_test::At(rsp, 6), 0x54u);
  EXPECT_EQ(nfc_ccid_u32_load_le(&nero_nfc_test::At(rsp, 1)),
            static_cast<uint32_t>(NFC_ISO7816_SW_LEN));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET),
            static_cast<uint8_t>(NFC_ISO7816_SW1_SUCCESS));
  EXPECT_EQ(nero_nfc_test::At(rsp, NFC_CCID_BULK_PAYLOAD_OFFSET + 1u),
            static_cast<uint8_t>(NFC_ISO7816_SW2_SUCCESS));
}
