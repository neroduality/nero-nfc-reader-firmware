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
#include "nfc_pcsc_contactless.h"

#include <gtest/gtest.h>

#include <cstring>

namespace {

unsigned XorTck(const uint8_t *atr, uint16_t len) {
  unsigned tck = 0;
  for (uint16_t i = 1; i < len; ++i) {
    tck ^= atr[i];
  }
  return tck;
}

} // namespace

TEST(NfcPcscContactless, StorageTagsUseT1ProtocolForPcsc) {
  EXPECT_EQ(nfc_pcsc_protocol_for_tag(NFC_TAG_KIND_TYPE2), NFC_PCSC_PROTOCOL_T1);
  EXPECT_EQ(nfc_pcsc_protocol_for_tag(NFC_TAG_KIND_TYPE4), NFC_PCSC_PROTOCOL_T1);
  EXPECT_EQ(nfc_pcsc_protocol_for_tag(NFC_TAG_KIND_TYPE5), NFC_PCSC_PROTOCOL_T1);
}

TEST(NfcPcscContactless, BuildsType2StorageAtrWithPcscRidAndCardName) {
  uint8_t atr[NFC_PCSC_STORAGE_ATR_LEN]{};
  uint16_t len = 0;

  ASSERT_TRUE(nfc_pcsc_copy_storage_card_atr(NFC_TAG_KIND_TYPE2, atr, sizeof(atr), &len));

  ASSERT_EQ(len, NFC_PCSC_STORAGE_ATR_LEN);
  EXPECT_EQ(atr[0], 0x3Bu);
  EXPECT_EQ(atr[1], 0x8Fu);
  EXPECT_EQ(atr[2], 0x80u);
  EXPECT_EQ(atr[3], 0x01u);
  EXPECT_EQ(atr[4], 0x80u);
  EXPECT_EQ(atr[5], 0x4Fu);
  EXPECT_EQ(atr[6], 0x0Cu);
  EXPECT_EQ(atr[7], 0xA0u);
  EXPECT_EQ(atr[8], 0x00u);
  EXPECT_EQ(atr[9], 0x00u);
  EXPECT_EQ(atr[10], 0x03u);
  EXPECT_EQ(atr[11], 0x06u);
  EXPECT_EQ(atr[12], 0x03u);
  EXPECT_EQ(atr[13], 0x00u);
  EXPECT_EQ(atr[14], 0x03u);
  EXPECT_EQ(XorTck(atr, len), 0u);
}

TEST(NfcPcscContactless, BuildsType5StorageAtrWithIso15693StandardCode) {
  uint8_t atr[NFC_PCSC_STORAGE_ATR_LEN]{};
  uint16_t len = 0;

  ASSERT_TRUE(nfc_pcsc_copy_storage_card_atr(NFC_TAG_KIND_TYPE5, atr, sizeof(atr), &len));

  ASSERT_EQ(len, NFC_PCSC_STORAGE_ATR_LEN);
  EXPECT_EQ(atr[12], 0x0Bu);
  EXPECT_EQ(atr[13], 0x00u);
  EXPECT_EQ(atr[14], 0x12u);
  EXPECT_EQ(XorTck(atr, len), 0u);
}

TEST(NfcPcscContactless, BuildsType4CcFileWithGenericTemplate) {
  uint8_t cc[NFC_PCSC_T4_CC_FILE_LEN]{};
  uint16_t len = 0u;

  ASSERT_TRUE(nfc_pcsc_build_type4_cc_file(0x0123u, true, true, cc, sizeof(cc), &len));
  EXPECT_EQ(len, NFC_PCSC_T4_CC_FILE_LEN);
  EXPECT_EQ(cc[1], (uint8_t)NFC_PCSC_T4_CC_FILE_LEN);
  EXPECT_EQ(cc[2], (uint8_t)NFC_PCSC_T4_CC_MAPPING_VERSION);
  EXPECT_EQ(cc[11], 0x01u);
  EXPECT_EQ(cc[12], 0x23u);
  EXPECT_EQ(cc[13], (uint8_t)NFC_PCSC_T4_READ_ACCESS_OPEN);
  EXPECT_EQ(cc[14], (uint8_t)NFC_PCSC_T4_READ_ACCESS_OPEN);

  ASSERT_TRUE(nfc_pcsc_build_type4_cc_file(0x0123u, true, false, cc, sizeof(cc), &len));
  EXPECT_EQ(cc[14], (uint8_t)NFC_PCSC_T4_READ_ACCESS_CLOSED);
  ASSERT_TRUE(nfc_pcsc_build_type4_cc_file(0x0123u, false, true, cc, sizeof(cc), &len));
  EXPECT_EQ(cc[13], (uint8_t)NFC_PCSC_T4_READ_ACCESS_CLOSED);
  EXPECT_FALSE(nfc_pcsc_build_type4_cc_file(0x0123u, true, true, cc,
                                            NFC_PCSC_T4_CC_FILE_LEN - 1u,
                                            &len));
}

TEST(NfcPcscContactless, ConvertsType4FileSizeAndMessageCapacity) {
  uint16_t message_size = 0u;
  uint16_t file_size = 0u;

  ASSERT_TRUE(nfc_pcsc_type4_max_message_size(0x0123u, &message_size));
  EXPECT_EQ(message_size, 0x0121u);
  EXPECT_TRUE(nfc_pcsc_type4_message_size_to_file_size(message_size, &file_size));
  EXPECT_EQ(file_size, 0x0123u);

  ASSERT_TRUE(nfc_pcsc_type4_max_message_size(0x0010u, &message_size));
  EXPECT_EQ(message_size, 0x000Eu);

  EXPECT_FALSE(nfc_pcsc_type4_max_message_size(1u, &message_size));
  EXPECT_FALSE(nfc_pcsc_type4_max_message_size(2u, NERO_NFC_NULL));
  EXPECT_FALSE(nfc_pcsc_type4_message_size_to_file_size(UINT16_MAX, &file_size));
}

TEST(NfcPcscContactless, ClearsOutputsOnRejectedCapacityHelpers) {
  uint16_t message_size = 0xBEEFu;
  uint16_t file_size = 0xBEEFu;

  EXPECT_FALSE(nfc_pcsc_type4_max_message_size(1u, &message_size));
  EXPECT_EQ(message_size, 0u);

  EXPECT_FALSE(nfc_pcsc_type4_message_size_to_file_size(UINT16_MAX, &file_size));
  EXPECT_EQ(file_size, 0u);
}

TEST(NfcPcscContactless, Type4ApduChunkCapsAreConsistent) {
  EXPECT_EQ(NFC_PCSC_T4_READ_BINARY_DATA_MAX, 254u);
  EXPECT_EQ(NFC_PCSC_T4_UPDATE_BINARY_DATA_MAX, 240u);
  EXPECT_EQ(NFC_PCSC_T4_UPDATE_BINARY_APDU_MAX, 245u);
  EXPECT_EQ(NFC_PCSC_ISO_DEP_APDU_RESP_MAX, 256u);
  EXPECT_EQ(NFC_PCSC_T4_READ_BINARY_DATA_MAX + 2u, NFC_PCSC_ISO_DEP_APDU_RESP_MAX);
  EXPECT_EQ(NFC_PCSC_T4_UPDATE_BINARY_APDU_MAX,
            5u + NFC_PCSC_T4_UPDATE_BINARY_DATA_MAX);
}

TEST(NfcPcscContactless, Iso7816ResponseSwOk) {
  const uint8_t ok[] = {0x00u, (uint8_t)NFC_ISO7816_SW1_SUCCESS, (uint8_t)NFC_ISO7816_SW2_SUCCESS};
  const uint8_t bad[] = {0x00u, 0x63u, 0x00u};
  const uint8_t wrong_len[] = {0x00u, (uint8_t)NFC_ISO7816_SW1_WRONG_LENGTH, 0x0Fu};
  const uint8_t more[] = {0x00u, (uint8_t)NFC_ISO7816_SW1_MORE_DATA, 0x05u};
  uint8_t sw1 = 0u;
  uint8_t sw2 = 0u;
  uint8_t le = 0u;

  EXPECT_TRUE(nfc_iso7816_response_sw_ok(ok, 3));
  EXPECT_FALSE(nfc_iso7816_response_sw_ok(bad, 3));
  EXPECT_FALSE(nfc_iso7816_response_sw_ok(NERO_NFC_NULL, 2));

  ASSERT_TRUE(nfc_iso7816_response_sw(ok, 3, &sw1, &sw2));
  EXPECT_EQ(sw1, (uint8_t)NFC_ISO7816_SW1_SUCCESS);
  EXPECT_EQ(sw2, (uint8_t)NFC_ISO7816_SW2_SUCCESS);

  ASSERT_TRUE(nfc_iso7816_response_wrong_length(wrong_len, 3, &le));
  EXPECT_EQ(le, 0x0Fu);
  EXPECT_FALSE(nfc_iso7816_response_wrong_length(ok, 3, NERO_NFC_NULL));

  ASSERT_TRUE(nfc_iso7816_response_more_data(more, 3, &le));
  EXPECT_EQ(le, 0x05u);
  EXPECT_FALSE(nfc_iso7816_response_more_data(ok, 3, NERO_NFC_NULL));
}

TEST(NfcPcscContactless, ClearsOutputsOnRejectedIso7816Responses) {
  const uint8_t ok[] = {0x00u, (uint8_t)NFC_ISO7816_SW1_SUCCESS, (uint8_t)NFC_ISO7816_SW2_SUCCESS};
  uint8_t sw1 = 0xA5u;
  uint8_t sw2 = 0xA5u;
  uint8_t le = 0xA5u;
  uint16_t rsp_len = 0xBEEFu;
  uint8_t rsp[1]{};

  EXPECT_FALSE(nfc_iso7816_response_sw(ok, 1, &sw1, &sw2));
  EXPECT_EQ(sw1, 0u);
  EXPECT_EQ(sw2, 0u);

  EXPECT_FALSE(nfc_iso7816_response_wrong_length(ok, sizeof(ok), &le));
  EXPECT_EQ(le, 0u);

  le = 0xA5u;
  EXPECT_FALSE(nfc_iso7816_response_more_data(ok, sizeof(ok), &le));
  EXPECT_EQ(le, 0u);

  EXPECT_FALSE(nfc_iso7816_append_sw(rsp, sizeof(rsp), sizeof(rsp), 0x90u, 0x00u, &rsp_len));
  EXPECT_EQ(rsp_len, 0u);
}

TEST(NfcPcscContactless, Iso7816ApduHelpers) {
  const uint8_t read_apdu[] = {0x00u, 0xB0u, 0x01u, 0x02u, 0x0Fu};
  const uint8_t update_apdu[] = {0x00u, 0xD6u, 0x00u, 0x00u, 0x02u, 0xAAu, 0xBBu};
  const uint8_t select_apdu[] = {0x00u, 0xA4u, 0x04u, 0x00u, 0x02u, 0xE1u, 0x03u, 0x00u};
  uint16_t offset = 0u;
  uint8_t le = 0u;
  uint8_t lc = 0u;
  const uint8_t *data = NERO_NFC_NULL;
  uint16_t rsp_len = 0u;
  uint8_t rsp[4] = {0xDEu, 0xADu, 0x00u, 0x00u};

  EXPECT_TRUE(nfc_iso7816_apdu_min_len(5u, 5u));
  EXPECT_FALSE(nfc_iso7816_apdu_min_len(4u, 5u));

  ASSERT_TRUE(nfc_iso7816_apdu_read_binary(read_apdu, sizeof(read_apdu), &offset, &le));
  EXPECT_EQ(offset, 0x0102u);
  EXPECT_EQ(le, 0x0Fu);

  ASSERT_TRUE(nfc_iso7816_apdu_update_binary(update_apdu, sizeof(update_apdu), &offset, &lc, &data));
  EXPECT_EQ(offset, 0u);
  EXPECT_EQ(lc, 2u);
  ASSERT_NE(data, NERO_NFC_NULL);
  EXPECT_EQ(data[0], 0xAAu);
  EXPECT_EQ(data[1], 0xBBu);

  ASSERT_TRUE(nfc_iso7816_apdu_lc(select_apdu, sizeof(select_apdu), &lc));
  EXPECT_EQ(lc, 2u);
  EXPECT_TRUE(nfc_iso7816_apdu_lc_body_ok(sizeof(update_apdu), 2u));
  EXPECT_TRUE(nfc_iso7816_apdu_lc_body_with_le_ok(sizeof(select_apdu), lc));
  data = nfc_iso7816_apdu_data_ptr(select_apdu, sizeof(select_apdu), lc);
  ASSERT_NE(data, NERO_NFC_NULL);
  EXPECT_EQ(data[0], 0xE1u);

  ASSERT_TRUE(nfc_iso7816_append_sw(rsp, sizeof(rsp), 2u, 0x90u, 0x00u, &rsp_len));
  EXPECT_EQ(rsp_len, 4u);
  EXPECT_EQ(rsp[2], 0x90u);
  EXPECT_EQ(rsp[3], 0x00u);
}

TEST(NfcPcscContactless, ClearsOutputsOnRejectedIso7816Apdus) {
  const uint8_t short_apdu[] = {0x00u, 0xB0u, 0x01u, 0x02u};
  const uint8_t update_bad_lc[] = {0x00u, 0xD6u, 0x00u, 0x00u, 0x02u, 0xAAu};
  uint16_t offset = 0xBEEFu;
  uint8_t le = 0xA5u;
  uint8_t lc = 0xA5u;
  const uint8_t *data = short_apdu;
  uint8_t apdu[4]{};
  uint8_t apdu_len = 0xA5u;

  EXPECT_FALSE(nfc_iso7816_apdu_lc(short_apdu, sizeof(short_apdu), &lc));
  EXPECT_EQ(lc, 0u);

  EXPECT_FALSE(nfc_iso7816_apdu_read_binary(short_apdu, sizeof(short_apdu), &offset, &le));
  EXPECT_EQ(offset, 0u);
  EXPECT_EQ(le, 0u);

  EXPECT_FALSE(nfc_iso7816_apdu_update_binary(update_bad_lc, sizeof(update_bad_lc), &offset, &lc,
                                              &data));
  EXPECT_EQ(offset, 0u);
  EXPECT_EQ(lc, 0u);
  EXPECT_EQ(data, NERO_NFC_NULL);

  EXPECT_FALSE(nfc_pcsc_build_t4_select_file_apdu(0xE103u, apdu, sizeof(apdu), &apdu_len));
  EXPECT_EQ(apdu_len, 0u);

  apdu_len = 0xA5u;
  EXPECT_FALSE(nfc_pcsc_build_t4_read_binary_apdu(0u, 2u, apdu, sizeof(apdu), &apdu_len));
  EXPECT_EQ(apdu_len, 0u);
}

TEST(NfcPcscContactless, RecognizesBothNdefApplicationAidVersions) {
  EXPECT_TRUE(nfc_pcsc_is_ndef_aid(NFC_PCSC_NDEF_APP_AID, NFC_PCSC_NDEF_APP_AID_LEN));
  EXPECT_TRUE(nfc_pcsc_is_ndef_aid(NFC_PCSC_NDEF_APP_AID_V0, NFC_PCSC_NDEF_APP_AID_LEN));
  const uint8_t other[] = {0xA0u, 0x00u, 0x00u, 0x06u, 0x47u, 0x2Fu, 0x00u, 0x01u};
  EXPECT_FALSE(nfc_pcsc_is_ndef_aid(other, sizeof(other)));
}

TEST(NfcPcscContactless, RejectsStorageAtrForType4Tag) {
  uint8_t atr[NFC_PCSC_STORAGE_ATR_LEN]{};
  uint16_t len = 0xBEEFu;
  EXPECT_FALSE(nfc_pcsc_copy_storage_card_atr(NFC_TAG_KIND_TYPE4, atr, sizeof(atr), &len));
  EXPECT_EQ(len, 0u);
}

TEST(NfcPcscContactless, StorageCardCodeRejectsNullOutputs) {
  EXPECT_FALSE(nfc_pcsc_storage_card_code_for_tag(NFC_TAG_KIND_TYPE2, NERO_NFC_NULL,
                                                  NERO_NFC_NULL, NERO_NFC_NULL));
}

TEST(NfcPcscContactless, ClearsOutputsOnRejectedStorageCardCode) {
  uint8_t standard = 0xA5u;
  uint8_t hi = 0xA5u;
  uint8_t lo = 0xA5u;

  EXPECT_FALSE(nfc_pcsc_storage_card_code_for_tag(NFC_TAG_KIND_TYPE4, &standard, &hi, &lo));
  EXPECT_EQ(standard, 0u);
  EXPECT_EQ(hi, 0u);
  EXPECT_EQ(lo, 0u);
}

TEST(NfcPcscContactless, Type2AndType5StorageCodesDiffer) {
  uint8_t std2 = 0;
  uint8_t hi2 = 0;
  uint8_t lo2 = 0;
  uint8_t std5 = 0;
  uint8_t hi5 = 0;
  uint8_t lo5 = 0;

  ASSERT_TRUE(nfc_pcsc_storage_card_code_for_tag(NFC_TAG_KIND_TYPE2, &std2, &hi2, &lo2));
  ASSERT_TRUE(nfc_pcsc_storage_card_code_for_tag(NFC_TAG_KIND_TYPE5, &std5, &hi5, &lo5));
  EXPECT_NE(std2, std5);
  EXPECT_NE(lo2, lo5);
}

TEST(NfcPcscContactless, AidMatchesRequiresExactLength) {
  const uint8_t short_aid[] = {0xD2u, 0x76u, 0x00u, 0x00u, 0x85u, 0x01u};
  EXPECT_FALSE(nfc_pcsc_aid_matches(short_aid, sizeof(short_aid), NFC_PCSC_NDEF_APP_AID,
                                    NFC_PCSC_NDEF_APP_AID_LEN));
}

TEST(NfcPcscContactless, NdefAppSelectVariantsCoverAidP2AndLeMatrix) {
  nfc_pcsc_ndef_app_select_variant_t variant{};
  bool saw_v1_p2_00_le = false;
  bool saw_v1_p2_0c_no_le = false;
  bool saw_v0_p2_00_le = false;
  bool saw_v0_p2_0c_no_le = false;

  for (uint8_t i = 0u; i < NFC_PCSC_NDEF_APP_SELECT_VARIANT_COUNT; ++i) {
    ASSERT_TRUE(nfc_pcsc_ndef_app_select_variant(i, &variant));
    EXPECT_EQ(variant.aid_len, NFC_PCSC_NDEF_APP_AID_LEN);
    if (variant.aid == NFC_PCSC_NDEF_APP_AID) {
      if ((variant.p2 == 0x00u) && variant.add_le_00) {
        saw_v1_p2_00_le = true;
      }
      if ((variant.p2 == 0x0Cu) && !variant.add_le_00) {
        saw_v1_p2_0c_no_le = true;
      }
    }
    if (variant.aid == NFC_PCSC_NDEF_APP_AID_V0) {
      if ((variant.p2 == 0x00u) && variant.add_le_00) {
        saw_v0_p2_00_le = true;
      }
      if ((variant.p2 == 0x0Cu) && !variant.add_le_00) {
        saw_v0_p2_0c_no_le = true;
      }
    }
  }
  EXPECT_FALSE(nfc_pcsc_ndef_app_select_variant(NFC_PCSC_NDEF_APP_SELECT_VARIANT_COUNT, &variant));
  EXPECT_EQ(variant.aid, NERO_NFC_NULL);
  EXPECT_EQ(variant.aid_len, 0u);
  EXPECT_TRUE(saw_v1_p2_00_le);
  EXPECT_TRUE(saw_v1_p2_0c_no_le);
  EXPECT_TRUE(saw_v0_p2_00_le);
  EXPECT_TRUE(saw_v0_p2_0c_no_le);
}

TEST(NfcPcscContactless, BuildsSelectAidApduWithOptionalLe) {
  uint8_t apdu[16]{};
  uint16_t apdu_len = 0u;
  const uint8_t aid[] = {0xD2u, 0x76u, 0x00u, 0x00u, 0x85u, 0x01u, 0x01u};
  const uint8_t expected[] = {0x00u, 0xA4u, 0x04u, 0x0Cu, 0x07u, 0xD2u, 0x76u, 0x00u,
                              0x00u, 0x85u, 0x01u, 0x01u, 0x00u};

  ASSERT_TRUE(nfc_pcsc_build_select_aid_apdu(aid, sizeof(aid), 0x0Cu, true, apdu, sizeof(apdu),
                                             &apdu_len));
  EXPECT_EQ(apdu_len, sizeof(expected));
  EXPECT_EQ(std::memcmp(apdu, expected, sizeof(expected)), 0);
  EXPECT_FALSE(nfc_pcsc_build_select_aid_apdu(aid, (uint8_t)(NFC_ISO7816_SELECT_AID_MAX + 1u),
                                                0x00u, false, apdu, sizeof(apdu), &apdu_len));
}

TEST(NfcPcscContactless, BuildsType4SelectFileApdu) {
  uint8_t apdu[NFC_PCSC_T4_SELECT_FILE_APDU_LEN]{};
  uint8_t apdu_len = 0u;
  const uint8_t expected[] = {0x00u, 0xA4u, 0x00u, 0x0Cu, 0x02u, 0xE1u, 0x03u};

  ASSERT_TRUE(nfc_pcsc_build_t4_select_file_apdu(NFC_PCSC_T4_CC_FILE_ID, apdu, sizeof(apdu),
                                                 &apdu_len));

  EXPECT_EQ(apdu_len, sizeof(expected));
  EXPECT_EQ(std::memcmp(apdu, expected, sizeof(expected)), 0);
  EXPECT_FALSE(nfc_pcsc_build_t4_select_file_apdu(NFC_PCSC_T4_CC_FILE_ID, apdu, 6u,
                                                  &apdu_len));
}

TEST(NfcPcscContactless, BuildsType4ReadBinaryApdu) {
  uint8_t apdu[NFC_PCSC_T4_READ_BINARY_APDU_LEN]{};
  uint8_t apdu_len = 0u;
  const uint8_t expected[] = {0x00u, 0xB0u, 0x01u, 0x02u, 0x0Fu};

  ASSERT_TRUE(nfc_pcsc_build_t4_read_binary_apdu(0x0102u, NFC_PCSC_T4_CC_FILE_LEN, apdu,
                                                sizeof(apdu), &apdu_len));

  EXPECT_EQ(apdu_len, sizeof(expected));
  EXPECT_EQ(std::memcmp(apdu, expected, sizeof(expected)), 0);
  EXPECT_FALSE(nfc_pcsc_build_t4_read_binary_apdu(0x0000u, NFC_PCSC_T4_NLEN_LEN, apdu, 4u,
                                                 &apdu_len));
}
