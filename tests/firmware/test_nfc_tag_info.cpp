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

#include "nfc_tag_info.h"
#include "nfc_tag_geometry_limits.h"
#include "nfc_ndef_tlv.h"

#include <cstring>

#include <gtest/gtest.h>

TEST(NfcTagInfoTest, Type2VersionRecognizesNtag213) {
  nfc_tag_type2_info_t info{};
  const uint8_t version[8] = {0x00u, 0x04u, 0x04u, 0x02u, 0x01u, 0x00u, 0x0Fu, 0x03u};

  nfc_tag_type2_apply_version(&info, version, sizeof(version));

  EXPECT_TRUE(info.version_valid);
  EXPECT_EQ(info.family, NFC_TAG_TYPE2_FAMILY_NTAG21X);
  EXPECT_STREQ(info.vendor_name, "NXP");
  EXPECT_STREQ(info.product_name, "NTAG213");
  EXPECT_EQ(info.max_user_page, 39u);
}

TEST(NfcTagInfoTest, Type2VersionRecognizesNtag216) {
  nfc_tag_type2_info_t info{};
  const uint8_t version[8] = {0x00u, 0x04u, 0x04u, 0x02u, 0x01u, 0x00u, 0x13u, 0x03u};

  nfc_tag_type2_apply_version(&info, version, sizeof(version));

  EXPECT_TRUE(info.version_valid);
  EXPECT_EQ(info.family, NFC_TAG_TYPE2_FAMILY_NTAG21X);
  EXPECT_STREQ(info.vendor_name, "NXP");
  EXPECT_STREQ(info.product_name, "NTAG216");
  EXPECT_EQ(info.max_user_page, 225u);
}

TEST(NfcTagInfoTest, Type2CcParsesCapabilityContainer) {
  nfc_tag_type2_info_t info{};
  const uint8_t cc[4] = {0xE1u, 0x10u, 0x6Du, 0x00u};

  nfc_tag_type2_apply_cc(&info, cc, sizeof(cc));

  EXPECT_TRUE(info.cc_valid);
  EXPECT_EQ(info.mapping_major, 1u);
  EXPECT_EQ(info.mapping_minor, 0u);
  EXPECT_EQ(info.data_area_size_bytes, 872u);
  EXPECT_TRUE(info.read_access_open);
  EXPECT_TRUE(info.write_access_open);
}

TEST(NfcTagInfoTest, Type2CcRejectsBadMagic) {
  nfc_tag_type2_info_t info{};
  const uint8_t cc[4] = {0x00u, 0x10u, 0x6Du, 0x00u};

  nfc_tag_type2_apply_cc(&info, cc, sizeof(cc));

  EXPECT_FALSE(info.cc_valid);
}

TEST(NfcTagInfoTest, Type2CcInvalidInputClearsPreviousValidity) {
  nfc_tag_type2_info_t info{};
  const uint8_t valid_cc[4] = {0xE1u, 0x10u, 0x12u, 0x00u};
  const uint8_t invalid_cc[4] = {0x00u, 0x10u, 0x12u, 0x00u};

  nfc_tag_type2_apply_cc(&info, valid_cc, sizeof(valid_cc));
  ASSERT_TRUE(info.cc_valid);

  nfc_tag_type2_apply_cc(&info, invalid_cc, sizeof(invalid_cc));
  EXPECT_FALSE(info.cc_valid);
  EXPECT_EQ(info.data_area_size_bytes, 0u);
  EXPECT_FALSE(info.read_access_open);
  EXPECT_FALSE(info.write_access_open);
}

TEST(NfcTagInfoTest, Type2St25TnFamilyUsesCcDerivedGeometry) {
  nfc_tag_type2_info_t st25tn512{};
  nfc_tag_type2_info_t st25tn01k{};
  nfc_tag_type2_info_t st25tn_unknown{};
  const uint8_t st25tn512_cc[4] = {0xE1u, 0x10u, 0x08u, 0x00u};
  const uint8_t st25tn01k_cc[4] = {0xE1u, 0x10u, 0x14u, 0x00u};

  nfc_tag_type2_apply_cc(&st25tn512, st25tn512_cc, sizeof(st25tn512_cc));
  nfc_tag_type2_apply_family_hint(&st25tn512, NFC_TAG_TYPE2_FAMILY_ST25TN);
  nfc_tag_type2_apply_cc(&st25tn01k, st25tn01k_cc, sizeof(st25tn01k_cc));
  nfc_tag_type2_apply_family_hint(&st25tn01k, NFC_TAG_TYPE2_FAMILY_ST25TN);
  nfc_tag_type2_apply_family_hint(&st25tn_unknown, NFC_TAG_TYPE2_FAMILY_ST25TN);

  EXPECT_EQ(st25tn512.max_user_page, 19u);
  EXPECT_STREQ(st25tn512.product_name, "ST25TN512");
  EXPECT_EQ(st25tn01k.max_user_page, 43u);
  EXPECT_STREQ(st25tn01k.product_name, "ST25TN01K");
  EXPECT_EQ(st25tn_unknown.max_user_page, 19u);
  EXPECT_STREQ(st25tn_unknown.product_name, "ST25TN-class");
}

TEST(NfcTagInfoTest, Type4CcParsesStandardFields) {
  nfc_tag_type4_info_t info{};
  const uint8_t cc[15] = {
    0x00u, 0x0Fu, 0x20u, 0x00u, 0x3Bu, 0x00u, 0x34u, 0x04u,
    0x06u, 0xE1u, 0x04u, 0x01u, 0xF4u, 0x00u, 0x00u,
  };

  ASSERT_TRUE(nfc_tag_type4_apply_cc(&info, cc, sizeof(cc)));
  EXPECT_EQ(info.mapping_major, 2u);
  EXPECT_EQ(info.mapping_minor, 0u);
  EXPECT_EQ(info.mle, 59u);
  EXPECT_EQ(info.mlc, 52u);
  EXPECT_EQ(info.ndef_file_id[0], 0xE1u);
  EXPECT_EQ(info.ndef_file_id[1], 0x04u);
  EXPECT_EQ(info.max_ndef_size, 500u);
  EXPECT_TRUE(info.read_access_open);
  EXPECT_TRUE(info.write_access_open);
}

TEST(NfcTagInfoTest, Type4CcAcceptsLongerControlFile) {
  nfc_tag_type4_info_t info{};
  const uint8_t cc[17] = {
    0x00u, 0x11u, 0x20u, 0x00u, 0x3Bu, 0x00u, 0x34u, 0x04u, 0x06u,
    0xE1u, 0x04u, 0x01u, 0xF4u, 0x00u, 0x00u, 0xAAu, 0x55u,
  };

  ASSERT_TRUE(nfc_tag_type4_apply_cc(&info, cc, sizeof(cc)));
  EXPECT_EQ(info.cc_len, 15u);
  EXPECT_EQ(info.ndef_file_id[0], 0xE1u);
  EXPECT_EQ(info.ndef_file_id[1], 0x04u);
  EXPECT_EQ(info.max_ndef_size, 500u);
}

TEST(NfcTagInfoTest, Type4CcParsesNtag424DnaFactoryControlFile) {
  // NXP NT4H2421Gx (NTAG 424 DNA) factory Capability Container: CCLEN=0017h
  // (23 bytes), Mapping Version 2.0, MLe=0100h, MLc=00FFh, an NDEF-File_Ctrl_TLV
  // (file E104h, 256 bytes, plain read+write) followed by a Proprietary-File_Ctrl_TLV
  // (file E105h, T=05h). The parser must accept the 23-byte CC and expose the NDEF
  // file as plain read/write so default tags can be read and written without
  // secure messaging.
  static_assert(NFC_TAG_NT4H424_DEFAULT_MLE == 0x0100u, "NT4H424 factory MLe");
  static_assert(NFC_TAG_NT4H424_DEFAULT_MLC == 0x00FFu, "NT4H424 factory MLc");
  nfc_tag_type4_info_t info{};
  const uint8_t cc[23] = {
    0x00u, 0x17u, 0x20u, NFC_TAG_NT4H424_DEFAULT_MLE_MSB, NFC_TAG_NT4H424_DEFAULT_MLE_LSB,
    NFC_TAG_NT4H424_DEFAULT_MLC_MSB, NFC_TAG_NT4H424_DEFAULT_MLC_LSB, 0x04u, 0x06u, 0xE1u, 0x04u,
    0x01u, 0x00u, 0x00u, 0x00u, 0x05u, 0x06u, 0xE1u, 0x05u, 0x00u, 0x80u, 0x82u, 0x83u,
  };

  ASSERT_TRUE(nfc_tag_type4_apply_cc(&info, cc, sizeof(cc)));
  EXPECT_EQ(info.cc_len, 15u);
  EXPECT_EQ(info.mapping_major, 2u);
  EXPECT_EQ(info.mapping_minor, 0u);
  EXPECT_EQ(info.mle, NFC_TAG_NT4H424_DEFAULT_MLE);
  EXPECT_EQ(info.mlc, NFC_TAG_NT4H424_DEFAULT_MLC);
  EXPECT_EQ(info.ndef_file_id[0], 0xE1u);
  EXPECT_EQ(info.ndef_file_id[1], 0x04u);
  EXPECT_EQ(info.max_ndef_size, 256u);
  EXPECT_TRUE(info.read_access_open);
  EXPECT_TRUE(info.write_access_open);
}

TEST(NfcTagInfoTest, Type4CcRejectsMalformedControlFile) {
  nfc_tag_type4_info_t info{};
  const uint8_t too_short[8] = {0x00u, 0x08u, 0x20u, 0x00u, 0x3Bu, 0x00u, 0x34u, 0x04u};
  const uint8_t bad_length[15] = {
    0x00u, 0x10u, 0x20u, 0x00u, 0x3Bu, 0x00u, 0x34u, 0x04u,
    0x06u, 0xE1u, 0x04u, 0x01u, 0xF4u, 0x00u, 0x00u,
  };

  EXPECT_FALSE(nfc_tag_type4_apply_cc(&info, too_short, sizeof(too_short)));
  EXPECT_FALSE(nfc_tag_type4_apply_cc(&info, bad_length, sizeof(bad_length)));
}

TEST(NfcTagInfoTest, Type4CcRejectsOutOfRangeMleMlc) {
  /* T4T 1.0 §7.2.1.7: MLe valid 000Fh..FFFFh, MLc valid 000Dh..FFFFh. */
  nfc_tag_type4_info_t info{};
  const uint8_t mle_too_small[15] = {
    0x00u, 0x0Fu, 0x20u, 0x00u, 0x0Eu, 0x00u, 0x34u, 0x04u,
    0x06u, 0xE1u, 0x04u, 0x01u, 0xF4u, 0x00u, 0x00u,
  };
  const uint8_t mlc_too_small[15] = {
    0x00u, 0x0Fu, 0x20u, 0x00u, 0x3Bu, 0x00u, 0x0Cu, 0x04u,
    0x06u, 0xE1u, 0x04u, 0x01u, 0xF4u, 0x00u, 0x00u,
  };

  EXPECT_FALSE(nfc_tag_type4_apply_cc(&info, mle_too_small, sizeof(mle_too_small)));
  EXPECT_FALSE(nfc_tag_type4_apply_cc(&info, mlc_too_small, sizeof(mlc_too_small)));
}

TEST(NfcTagInfoTest, Type4CcInvalidInputClearsPreviousValidity) {
  nfc_tag_type4_info_t info{};
  const uint8_t valid_cc[15] = {
    0x00u, 0x0Fu, 0x20u, 0x00u, 0x3Bu, 0x00u, 0x34u, 0x04u,
    0x06u, 0xE1u, 0x04u, 0x01u, 0xF4u, 0x00u, 0x00u,
  };
  const uint8_t invalid_cc[8] = {0x00u, 0x08u, 0x20u, 0x00u, 0x3Bu, 0x00u, 0x34u, 0x04u};

  ASSERT_TRUE(nfc_tag_type4_apply_cc(&info, valid_cc, sizeof(valid_cc)));
  ASSERT_TRUE(info.cc_valid);

  EXPECT_FALSE(nfc_tag_type4_apply_cc(&info, invalid_cc, sizeof(invalid_cc)));
  EXPECT_FALSE(info.cc_valid);
  EXPECT_EQ(info.max_ndef_size, 0u);
  EXPECT_FALSE(info.read_access_open);
  EXPECT_FALSE(info.write_access_open);
}

TEST(NfcTagInfoTest, Type5SystemInfoAndCcParseCommonFields) {
  nfc_tag_type5_info_t info{};
  const uint8_t cc[4] = {0xE1u, 0x40u, 0x14u, 0x00u};
  const uint8_t raw[15] = {
    0x00u, 0x0Fu, 0xE0u, 0x02u, 0xAAu, 0xBBu, 0xCCu, 0xDDu,
    0xEEu, 0xFFu, 0x12u, 0x34u, 0x4Fu, 0x03u, 0xA1u,
  };

  nfc_tag_type5_apply_cc(&info, cc, sizeof(cc));
  nfc_tag_type5_apply_system_info(&info, raw, sizeof(raw));

  EXPECT_TRUE(info.cc_valid);
  EXPECT_EQ(info.mapping_major, 1u);
  EXPECT_EQ(info.mapping_minor, 0u);
  EXPECT_EQ(info.data_area_size_bytes, 160u);
  EXPECT_TRUE(info.read_access_open);
  EXPECT_TRUE(info.write_access_open);
  EXPECT_TRUE(info.dsfid_valid);
  EXPECT_EQ(info.dsfid, 0x12u);
  EXPECT_TRUE(info.afi_valid);
  EXPECT_EQ(info.afi, 0x34u);
  EXPECT_EQ(info.block_count, 80u);
  EXPECT_EQ(info.block_size, 4u);
  EXPECT_TRUE(info.ic_ref_valid);
  EXPECT_EQ(info.ic_ref, 0xA1u);
}

TEST(NfcTagInfoTest, Type5SystemInfoClearsOmittedOptionalFields) {
  nfc_tag_type5_info_t info{};
  const uint8_t full_raw[15] = {
    0x00u, 0x0Fu, 0xE0u, 0x02u, 0xAAu, 0xBBu, 0xCCu, 0xDDu,
    0xEEu, 0xFFu, 0x12u, 0x34u, 0x4Fu, 0x03u, 0xA1u,
  };
  const uint8_t minimal_raw[10] = {
    0x00u, 0x00u, 0xE0u, 0x02u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu,
  };

  nfc_tag_type5_apply_system_info(&info, full_raw, sizeof(full_raw));
  ASSERT_TRUE(info.dsfid_valid);
  ASSERT_TRUE(info.afi_valid);
  ASSERT_NE(info.block_count, 0u);
  ASSERT_TRUE(info.ic_ref_valid);

  nfc_tag_type5_apply_system_info(&info, minimal_raw, sizeof(minimal_raw));
  EXPECT_FALSE(info.dsfid_valid);
  EXPECT_FALSE(info.afi_valid);
  EXPECT_EQ(info.block_count, 0u);
  EXPECT_EQ(info.block_size, 0u);
  EXPECT_FALSE(info.ic_ref_valid);
}

TEST(NfcTagInfoTest, Type5ExtendedCcUsesExtendedMlenBytes) {
  nfc_tag_type5_info_t info{};
  const uint8_t cc[8] = {0xE2u, 0x40u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u, 0x00u};

  nfc_tag_type5_apply_cc(&info, cc, sizeof(cc));

  EXPECT_TRUE(info.cc_valid);
  EXPECT_EQ(info.cc_len, sizeof(cc));
  EXPECT_EQ(info.data_area_size_bytes, 2048u);
}

TEST(NfcTagInfoTest, Type5ExtendedCcTriggeredByZeroMlenWithE1Magic) {
  /* T5T 1.0 §4.3.1.17: MLEN==0 selects the 8-byte CC regardless of magic. */
  nfc_tag_type5_info_t info{};
  const uint8_t cc[8] = {0xE1u, 0x40u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x40u};

  nfc_tag_type5_apply_cc(&info, cc, sizeof(cc));

  EXPECT_TRUE(info.cc_valid);
  EXPECT_EQ(info.cc_len, 8u);
  EXPECT_EQ(info.data_area_size_bytes, 512u);
}

TEST(NfcTagInfoTest, Type5FourByteCcWithE2MagicUsesByteTwo) {
  /* T5T 1.0 §4.3.1.17: a non-zero MLEN is always a 4-byte CC, even for E2h. */
  nfc_tag_type5_info_t info{};
  const uint8_t cc[4] = {0xE2u, 0x40u, 0x20u, 0x00u};

  nfc_tag_type5_apply_cc(&info, cc, sizeof(cc));

  EXPECT_TRUE(info.cc_valid);
  EXPECT_EQ(info.cc_len, 4u);
  EXPECT_EQ(info.data_area_size_bytes, 256u);
}

TEST(NfcTagInfoTest, Type5MlenOverflowUsesSystemInfoSize) {
  /*
   * T5T 1.0 §4.3.1.17 MLEN overflow: 4-byte CC with byte2==FFh and byte3 bit2
   * set defers the real size to (Extended) GetSystemInfo. ST25DV64KC reports
   * 2048 blocks x 4 bytes; minus the 4 CC bytes = 8188 bytes of T5T_Area.
   */
  nfc_tag_type5_info_t info{};
  const uint8_t cc[4] = {0xE1u, 0x40u, 0xFFu, 0x04u};
  /* Extended GetSystemInfo: flags, info=0F, UID(8), DSFID, AFI, NB_lsb, NB_msb,
   * block_size, IC ref. NB = 0x07FF -> 2048 blocks; block_size byte 0x03 -> 4. */
  const uint8_t ext[16] = {
    0x00u, 0x0Fu, 0xE0u, 0x02u, 0xAAu, 0xBBu, 0xCCu, 0xDDu,
    0xEEu, 0xFFu, 0xFFu, 0x03u, 0xFFu, 0x07u, 0x03u, 0x24u,
  };

  nfc_tag_type5_apply_cc(&info, cc, sizeof(cc));
  ASSERT_TRUE(info.cc_valid);
  ASSERT_EQ(info.data_area_size_bytes, 2040u);
  EXPECT_TRUE(nfc_tag_type5_cc_signals_mlen_overflow(&info));

  nfc_tag_type5_apply_system_info_ext(&info, ext, sizeof(ext));
  ASSERT_EQ(info.block_count, 2048u);
  ASSERT_EQ(info.block_size, 4u);

  nfc_tag_type5_resolve_mlen_overflow(&info);
  EXPECT_EQ(info.data_area_size_bytes, 8188u);
}

TEST(NfcTagInfoTest, Type5MlenOverflowIgnoredWithoutFlag) {
  nfc_tag_type5_info_t info{};
  const uint8_t cc[4] = {0xE1u, 0x40u, 0xFFu, 0x00u};
  const uint8_t ext[16] = {
    0x00u, 0x0Fu, 0xE0u, 0x02u, 0xAAu, 0xBBu, 0xCCu, 0xDDu,
    0xEEu, 0xFFu, 0xFFu, 0x03u, 0xFFu, 0x07u, 0x03u, 0x24u,
  };

  nfc_tag_type5_apply_cc(&info, cc, sizeof(cc));
  nfc_tag_type5_apply_system_info_ext(&info, ext, sizeof(ext));
  EXPECT_FALSE(nfc_tag_type5_cc_signals_mlen_overflow(&info));
  nfc_tag_type5_resolve_mlen_overflow(&info);
  EXPECT_EQ(info.data_area_size_bytes, 2040u);
}

TEST(NfcTagInfoTest, Type5CcInvalidInputClearsPreviousValidity) {
  nfc_tag_type5_info_t info{};
  const uint8_t valid_cc[4] = {0xE1u, 0x40u, 0x14u, 0x00u};
  const uint8_t invalid_zero_cc[4] = {0xE1u, 0x40u, 0x00u, 0x00u};

  nfc_tag_type5_apply_cc(&info, valid_cc, sizeof(valid_cc));
  ASSERT_TRUE(info.cc_valid);
  ASSERT_EQ(info.data_area_size_bytes, 160u);

  /* MLEN==0 but only 4 bytes available: the 8-byte CC cannot be completed. */
  nfc_tag_type5_apply_cc(&info, invalid_zero_cc, sizeof(invalid_zero_cc));
  EXPECT_FALSE(info.cc_valid);
  EXPECT_EQ(info.cc_len, 0u);
  EXPECT_EQ(info.data_area_size_bytes, 0u);
  EXPECT_FALSE(info.read_access_open);
  EXPECT_FALSE(info.write_access_open);
}

TEST(NfcTagInfoTest, Type5CcRejectsBadMagicAndIncompleteExtendedCc) {
  nfc_tag_type5_info_t bad_magic{};
  nfc_tag_type5_info_t short_extended{};
  nfc_tag_type5_info_t zero_size_extended{};
  const uint8_t bad_magic_cc[4] = {0x00u, 0x40u, 0x14u, 0x00u};
  /* MLEN==0 marks an 8-byte CC, but only 4 bytes are supplied. */
  const uint8_t short_extended_cc[4] = {0xE2u, 0x40u, 0x00u, 0x00u};
  /* 8-byte CC present but bytes 6..7 encode a zero T5T_Area size. */
  const uint8_t zero_size_extended_cc[8] = {0xE1u, 0x40u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u};

  nfc_tag_type5_apply_cc(&bad_magic, bad_magic_cc, sizeof(bad_magic_cc));
  nfc_tag_type5_apply_cc(&short_extended, short_extended_cc, sizeof(short_extended_cc));
  nfc_tag_type5_apply_cc(&zero_size_extended, zero_size_extended_cc, sizeof(zero_size_extended_cc));

  EXPECT_FALSE(bad_magic.cc_valid);
  EXPECT_FALSE(short_extended.cc_valid);
  EXPECT_FALSE(zero_size_extended.cc_valid);
}

TEST(NfcTagInfoTest, Type5St25TvFamilyAttribution) {
  nfc_tag_type5_info_t info{};
  const uint8_t uid[8] = {0xE0u, 0x02u, 0x24u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u};
  const uint8_t raw[15] = {
    0x00u, 0x0Cu, 0xE0u, 0x02u, 0x24u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x01u, 0x4Fu, 0x03u, 0x00u, 0x00u, 0x00u,
  };

  nfc_tag_type5_apply_system_info(&info, raw, sizeof(raw));

  EXPECT_STREQ(nfc_tag_type5_family_name(uid, sizeof(uid), &info), "ST25TV-class");
}

TEST(NfcTagInfoTest, Type5St25DvFamilyAttributionFromIcRef) {
  nfc_tag_type5_info_t info{};
  const uint8_t uid[8] = {0xE0u, 0x02u, 0x51u, 0x67u, 0x65u, 0xE0u, 0xCAu, 0x13u};
  const uint8_t raw[13] = {
    0x00u, 0x0Bu, 0x13u, 0xCAu, 0xE0u, 0x65u, 0x67u, 0x51u, 0x02u, 0xE0u, 0x00u, 0x00u, 0x51u,
  };

  nfc_tag_type5_apply_system_info(&info, raw, sizeof(raw));

  ASSERT_TRUE(info.ic_ref_valid);
  EXPECT_EQ(info.ic_ref, 0x51u);
  EXPECT_STREQ(nfc_tag_type5_family_name(uid, sizeof(uid), &info), "ST25DV-class");
}

TEST(NfcTagInfoTest, NdefTlvFindsMessageAfterNullAndUnknownTlvs) {
  const uint8_t area[] = {
    0x00u, 0xFDu, 0x02u, 0xAAu, 0xBBu, 0x03u, 0x03u, 0xD1u, 0x01u, 0x00u, 0xFEu,
  };
  nfc_ndef_tlv_t tlv{};

  ASSERT_EQ(nfc_ndef_find_message_tlv(area, sizeof(area), 0u, &tlv), NFC_NDEF_TLV_OK);
  EXPECT_EQ(tlv.type, NFC_NDEF_TLV_MESSAGE);
  EXPECT_EQ(tlv.header_offset, 5u);
  EXPECT_EQ(tlv.value_offset, 7u);
  EXPECT_EQ(tlv.value_len, 3u);
}

TEST(NfcTagInfoTest, NdefTlvSupportsExtendedLengthRoundTrip) {
  uint8_t ndef[300];
  uint8_t tlv_buf[305];
  uint16_t tlv_len = 0u;
  nfc_ndef_tlv_t tlv{};

  for (uint16_t i = 0u; i < sizeof(ndef); ++i) {
    ndef[i] = static_cast<uint8_t>(i & 0xFFu);
  }

  ASSERT_TRUE(nfc_ndef_build_message_tlv(ndef, sizeof(ndef), tlv_buf, sizeof(tlv_buf), &tlv_len));
  EXPECT_EQ(tlv_len, 305u);
  ASSERT_EQ(nfc_ndef_find_message_tlv(tlv_buf, tlv_len, 0u, &tlv), NFC_NDEF_TLV_OK);
  EXPECT_EQ(tlv.header_offset, 0u);
  EXPECT_EQ(tlv.value_offset, 4u);
  EXPECT_EQ(tlv.value_len, sizeof(ndef));
  EXPECT_EQ(memcmp(tlv_buf + tlv.value_offset, ndef, sizeof(ndef)), 0);
}

TEST(NfcTagInfoTest, NdefTlvReportsTruncatedValue) {
  const uint8_t area[] = {0x03u, 0x05u, 0xD1u};
  nfc_ndef_tlv_t tlv{};

  EXPECT_EQ(nfc_ndef_find_message_tlv(area, sizeof(area), 0u, &tlv), NFC_NDEF_TLV_TRUNCATED);
}
