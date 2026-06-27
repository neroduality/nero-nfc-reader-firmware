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

#pragma once

#include "nero_nfc_attrs.h"
#include "nero_nfc_mem_util.h"
#include "nfc_tag_geometry_limits.h"
#include "nfc_tag_info.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Manifest prefixes in this contactless PC/SC/ISO7816 contract:
 *   [ISO7816-3] ATR framing bytes used for PC/SC storage ATR synthesis.
 *   [ISO7816-4] APDU fields, status words, and command opcodes.
 *   [PCSC-P3] contactless storage ATR and transparent exchange identifiers. */
enum {
  NFC_PCSC_PROTOCOL_T0 = 0x00u,
  NFC_PCSC_PROTOCOL_T1 = 0x01u,
  NFC_PCSC_STORAGE_RID_LEN = 5u,
  NFC_PCSC_STORAGE_ATR_LEN = 20u,
  NFC_PCSC_NDEF_APP_AID_LEN = NFC_TAG_T4T_NDEF_APP_AID_LEN,
  NFC_PCSC_T4_SELECT_FILE_APDU_LEN = 7u,
  NFC_PCSC_T4_READ_BINARY_APDU_LEN = 5u,
  NFC_PCSC_T4_CC_FILE_ID = NFC_TAG_T4T_CC_FILE_ID,
  NFC_PCSC_T4_CC_FILE_LEN = 15u,
  NFC_PCSC_T4_NLEN_LEN = 2u,
  /* Type 4 short READ BINARY: Le data fits in FSD=256 minus 2-byte SW. */
  NFC_PCSC_T4_READ_BINARY_DATA_MAX = 254u,
  /*
   * Type 4 UPDATE BINARY command data cap (Lc). Unlike READ, payload travels in
   * the C-APDU on the outbound ISO-DEP frame. At FSC=256 the 5-byte UPDATE
   * header plus ISO-DEP I-block overhead (PCB, optional CID/NAD) must fit with
   * Lc bytes, so the safe single-chunk data cap is below the read-side 254-byte
   * response limit. CC MLc may reduce this further at runtime.
   */
  NFC_PCSC_T4_UPDATE_BINARY_DATA_MAX = 240u,
  NFC_PCSC_T4_UPDATE_BINARY_APDU_MAX = 245u,
  /* Stack buffer for ISO-DEP transceive at FSDI=7 (256-byte PICC frame). */
  NFC_PCSC_ISO_DEP_APDU_RESP_MAX = 256u,
  /* ISO-DEP transceive scratch with small margin above resp + SW. */
  NFC_PCSC_ISO_DEP_APDU_RESP_STACK = 260u,
  /* NFC Forum Type 4 Tag — 15-byte CC file (mapping v2.0) helper defaults. */
  NFC_PCSC_T4_CC_MAPPING_VERSION = 0x20u,
  NFC_PCSC_T4_CC_DEFAULT_MLE = 0x003Bu,
  NFC_PCSC_T4_CC_DEFAULT_MLC = 0x0034u,
  NFC_PCSC_T4_NDEF_FC_TLV_TAG = 0x04u,
  NFC_PCSC_T4_NDEF_FC_TLV_LEN = 0x06u,
  NFC_PCSC_T4_NDEF_FILE_ID_MSB = 0xE1u,
  NFC_PCSC_T4_NDEF_FILE_ID_LSB = 0x04u,
  NFC_PCSC_T4_READ_ACCESS_OPEN = 0x00u,
  NFC_PCSC_T4_READ_ACCESS_CLOSED = 0xFFu,
  NFC_PCSC_STORAGE_RID_0 = 0xA0u, /* [PCSC-P3] §3.1.3 contactless storage RID byte 0 */
  NFC_PCSC_STORAGE_RID_1 = 0x00u,
  NFC_PCSC_STORAGE_RID_2 = 0x00u,
  NFC_PCSC_STORAGE_RID_3 = 0x03u,
  NFC_PCSC_STORAGE_RID_4 = 0x06u,
  /* ISO/IEC 7816-4 status words — single source for CCID APDU responses and
     relay paths. */
  NFC_ISO7816_SW1_SUCCESS = 0x90u,
  NFC_ISO7816_SW2_SUCCESS = 0x00u,
  NFC_ISO7816_SW1_MORE_DATA = 0x61u,
  NFC_ISO7816_SW1_MORE_DATA_VENDOR = 0x91u, /* proprietary "more data"/keep-alive SW1 */
  NFC_ISO7816_SW1_WRONG_LENGTH = 0x6Cu,
  NFC_ISO7816_SW1_VERIFICATION_FAILED = 0x63u,
  NFC_ISO7816_SW1_GENERAL_ERROR = 0x6Fu,
  NFC_ISO7816_SW_SUCCESS = 0x9000u, /* combined SW1||SW2 success word */
  NFC_ISO7816_INS_SELECT = 0xA4u,
  NFC_ISO7816_INS_READ_BINARY = 0xB0u,
  NFC_ISO7816_INS_UPDATE_BINARY = 0xD6u,
  NFC_ISO7816_INS_GET_DATA = 0xCAu,
  NFC_ISO7816_INS_GET_RESPONSE = 0xC0u,
  /* [DERIVED] Firmware-local SELECT-by-AID cap, not the ISO7816 short-Lc maximum. */
  NFC_ISO7816_SELECT_AID_MAX = 16u,
  /* ISO/IEC 7816-4 class bytes — short-form C-APDU CLA. */
  NFC_ISO7816_CLA_ISO = 0x00u,
  NFC_ISO7816_CLA_PROPRIETARY = 0xFFu,
  NFC_ISO7816_CLA_PROPRIETARY_SHORT = 0x80u,
  /* ISO/IEC 7816-4 SELECT P1 — select by DF name (AID). */
  NFC_ISO7816_P1_SELECT_BY_DF_NAME = 0x04u,
  /* ISO/IEC 7816-4 status-word and APDU geometry helpers. */
  NFC_ISO7816_SW_STATUS_WORD_LEN = 2u,
  /* [DERIVED] Byte mask helper; intentionally not a standalone SPEC entry. */
  NFC_ISO7816_BYTE_MASK = 0xFFu,
  /* ISO/IEC 7816-3 ATR layout for PC/SC ATS-as-ATR synthesis. */
  NFC_ISO7816_ATR_TS = 0x3Bu,
  NFC_ISO7816_ATR_T0_HIST_LEN_MASK = 0x80u,
  NFC_ISO7816_ATR_TD1_T1 = 0x01u,
  NFC_ISO7816_ATR_FIXED_PREFIX_LEN = 3u,
  NFC_ISO7816_ATR_TS_TCK_OVERHEAD = 4u,
  /* [DERIVED] Status-classification helpers; SW byte values are traced separately. */
  NFC_ISO7816_SW1_HIGH_BYTE_MASK = 0xFF00u,
  NFC_ISO7816_SW1_WARNING_MIN = 0x62u,
  NFC_ISO7816_SW1_WARNING_MAX = 0x6Fu,
  NFC_ISO7816_SW_WARNING_MIN = 0x6200u,
  NFC_ISO7816_SW_WARNING_MAX = 0x6FFFu,
  NFC_ISO7816_SW1_MORE_DATA_PATTERN = 0x6100u,
  NFC_ISO7816_SW1_MORE_DATA_VENDOR_PATTERN = 0x9100u,
  /* [DERIVED] Parser mask for CTAP P1 high-bit handling, not an ISO7816 literal. */
  NFC_ISO7816_P1_IGNORE_MSB_MASK = 0x7Fu,
  NFC_ISO7816_SHORT_LC_MAX = 255u,
  NFC_ISO7816_MIN_CMD_APDU_LEN = 4u,
  /* [DERIVED] APDU parser guard length, not a standalone SPEC entry. */
  NFC_ISO7816_MIN_EXTENDED_APDU_LEN = 8u,
  NFC_ISO7816_MIN_RESPONSE_WITH_SW_LEN = 2u,
  /* [DERIVED] Response parser guard lengths; SW trailer width is traced separately. */
  NFC_ISO7816_MIN_RESPONSE_WITH_BODY_LEN = 3u,
  NFC_ISO7816_MIN_RESPONSE_WITH_STATUS_LEN = 4u,
  NFC_ISO7816_APDU_LE_ONLY_LEN = 5u,
  /* ISO/IEC 7816-4 SELECT P2 — first or only occurrence vs next occurrence. */
  NFC_ISO7816_P2_SELECT_FIRST = 0x00u,
  NFC_ISO7816_P2_SELECT_NO_FCI = 0x0Cu,
  /* ISO/IEC 7816-4 GET DATA — P2 default (no template qualifier). */
  NFC_ISO7816_GET_DATA_P2_DEFAULT = 0x00u,
  /* ISO/IEC 7816-4 short C-APDU field indices (CLA=0, INS=1). */
  NFC_ISO7816_APDU_IDX_CLA = 0u,
  NFC_ISO7816_APDU_IDX_INS = 1u,
  NFC_ISO7816_APDU_IDX_P1 = 2u,
  NFC_ISO7816_APDU_IDX_P2 = 3u,
  NFC_ISO7816_APDU_IDX_LC = 4u,
  /* ISO/IEC 7816-4 short C-APDU with empty body and Le only. */
  NFC_ISO7816_SHORT_APDU_HDR_LEN = 5u,
  /* [DERIVED] Short APDU case-4 parser prefix, not a standalone SPEC entry. */
  NFC_ISO7816_APDU_LC_BODY_WITH_LE_PREFIX = 6u,
  /* Contactless reader wrong-length SW1 (distinct from 7816-4 0x6C). */
  NFC_ISO7816_SW1_WRONG_LENGTH_ALT = 0x67u,
  /* [PCSC-P3] §3.3.3 — Escape command for transparent ISO15693 exchange. */
  NFC_PCSC_ESCAPE_TRANSPARENT_INS = 0xC2u,
  /* [PCSC-P3] §3.1.3 — contactless storage card standard identifiers. */
  NFC_PCSC_STORAGE_STANDARD_ISO14443A = 0x03u,
  NFC_PCSC_STORAGE_STANDARD_ISO15693 = 0x0Bu,
  NFC_PCSC_STORAGE_CARD_TYPE2 = 0x03u,
  NFC_PCSC_STORAGE_CARD_TYPE5 = 0x12u,
  /* [ISO7816-4] Table 5 (SW1) / Table 6 (SW2) — status words for storage-card
     APDU responses. */
  NFC_ISO7816_SW1_WRONG_DATA = 0x6Au,
  NFC_ISO7816_SW1_WRONG_P1P2 = 0x6Bu,
  NFC_ISO7816_SW1_INS_NOT_SUPPORTED = 0x6Du,
  NFC_ISO7816_SW1_CLASS_NOT_SUPPORTED = 0x6Eu,
  NFC_ISO7816_SW1_CONDITIONS_NOT_SATISFIED = 0x69u,
  NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED = 0x81u,
  NFC_ISO7816_SW2_FILE_NOT_FOUND = 0x82u,
  NFC_ISO7816_SW2_WRONG_PARAMS = 0x86u,
  NFC_ISO7816_SW2_REF_DATA_NOT_FOUND = 0x88u,
  NFC_ISO7816_SW2_CONDITIONS_NOT_SATISFIED = 0x85u,
  /* [DERIVED] Host-defined SW2 when command not allowed (no
     assigned Table 6 code). */
  NFC_ISO7816_SW2_COMMAND_NOT_ALLOWED = 0xFFu,
  /* [ISO7816-4] Table 39 — SELECT by file identifier (P1). */
  NFC_ISO7816_P1_SELECT_BY_FILE_ID = 0x00u,
  /* [ISO7816-4] §7.4.1 — file identifier is two bytes on the wire. */
  NFC_ISO7816_LC_SELECT_FILE_ID = 2u,
  /* [ISO7816-4] §5.1.3 — SW1-SW2 response trailer width (bytes). */
  NFC_ISO7816_SW_LEN = 2u,
  /* [ISO7816-4] §7 — APDU encode/decode high-byte shift (host helper). */
  NFC_ISO7816_U16_HIGH_BYTE_SHIFT = 8u,
  /* [ISO7816-4] §7 — APDU low-byte mask (host helper). */
  NFC_ISO7816_LOW_BYTE_MASK = 0xFFu,
  /* [ISO7816-4] READ BINARY — P1=FFh, block number in P2 (Type 5 PC/SC
     convention). */
  NFC_ISO7816_READ_BINARY_P1_BLOCK_IN_P2 = 0xFFu,
  /* [PCSC-P3] §3.2.2.3.2 GET DATA P1 tag-data identifiers. */
  NFC_PCSC_GET_DATA_UID = 0x00u,
  NFC_PCSC_GET_DATA_ATS = 0x01u,
  NFC_PCSC_GET_DATA_SAK = 0x02u,
  NFC_PCSC_GET_DATA_ATQA = 0x03u,
  NFC_PCSC_GET_DATA_TYPE2_VERSION = 0x04u,
  NFC_PCSC_GET_DATA_NTAG_SIGNATURE = 0x05u,
  NFC_PCSC_GET_DATA_TYPE5_SYS_INFO = 0x06u,
  NFC_PCSC_GET_DATA_TYPE2_CC = 0x07u,
  NFC_PCSC_GET_DATA_TYPE2_AUTH0 = 0x08u,
  NFC_PCSC_GET_DATA_TYPE5_CC = 0x0Au,
  NFC_PCSC_GET_DATA_TYPE4_CC = 0x09u,
  NFC_PCSC_GET_DATA_P1_MAX = 0x0Au,
  NFC_PCSC_GET_DATA_SAK_RSP_LEN = 1u,
  NFC_PCSC_GET_DATA_ATQA_RSP_LEN = 2u,
  NFC_PCSC_GET_DATA_AUTH0_RSP_LEN = 1u,

  /* PN532 host-command frame bytes used by the ACR122U-style direct APDU path.
   */
  NFC_PN532_HOST_TO_PN532 = 0xD4u,
  NFC_PN532_PN532_TO_HOST = 0xD5u,
  NFC_PN532_CMD_GET_FIRMWARE_VERSION = 0x02u,
  NFC_PN532_CMD_IN_DATA_EXCHANGE = 0x40u,
  NFC_PN532_RSP_IN_DATA_EXCHANGE = 0x41u,
  NFC_PN532_CMD_IN_COMMUNICATE_THRU = 0x42u,
  NFC_PN532_RSP_IN_COMMUNICATE_THRU = 0x43u,
  NFC_PN532_CMD_IN_DESELECT = 0x44u,
  NFC_PN532_RSP_IN_DESELECT = 0x45u,
  NFC_PN532_CMD_IN_LIST_PASSIVE_TARGET = 0x4Au,
  NFC_PN532_RSP_IN_LIST_PASSIVE_TARGET = 0x4Bu,
  NFC_PN532_CMD_READ_REGISTER = 0x52u,
  NFC_PN532_RSP_READ_REGISTER = 0x53u,
  NFC_PN532_BRTY_106KBPS_TYPE_A = 0x00u,
  NFC_PN532_SINGLE_TARGET = 0x01u,
  NFC_PN532_STATUS_OK = 0x00u,
  NFC_PN532_STATUS_ERROR = 0x01u,
  NFC_PN532_STATUS_TIMEOUT = 0x27u,
  NFC_PN532_GET_FIRMWARE_VERSION_RSP_SUB = 0x03u,
  NFC_PN532_FW_VERSION_IC = 0x32u,
  NFC_PN532_FW_VERSION_VER = 0x01u,
  NFC_PN532_FW_VERSION_REV = 0x06u,
  NFC_PN532_FW_VERSION_SUPPORT = 0x07u,

  /* ACR122U API v2.02 pseudo-APDU INS byte: FF 00 48 00 00. */
  NFC_ACR122U_INS_GET_FIRMWARE_VERSION = 0x48u,
};

NERO_NFC_STATIC_ASSERT(NFC_PCSC_T4_READ_BINARY_DATA_MAX + NFC_ISO7816_SW_LEN ==
                         NFC_PCSC_ISO_DEP_APDU_RESP_MAX,
                       "Type 4 READ BINARY data + SW fits ISO-DEP FSC max");
NERO_NFC_STATIC_ASSERT(NFC_PCSC_T4_UPDATE_BINARY_APDU_MAX ==
                         (NFC_ISO7816_SHORT_APDU_HDR_LEN + NFC_PCSC_T4_UPDATE_BINARY_DATA_MAX),
                       "Type 4 UPDATE BINARY APDU size is header + data cap");
NERO_NFC_STATIC_ASSERT(NFC_PCSC_ISO_DEP_APDU_RESP_STACK >=
                         NFC_PCSC_ISO_DEP_APDU_RESP_MAX + NFC_ISO7816_SW_LEN,
                       "ISO-DEP stack buffer must hold max response + SW");

static const uint8_t NFC_PCSC_STORAGE_RID[NFC_PCSC_STORAGE_RID_LEN] = {
  (uint8_t)NFC_PCSC_STORAGE_RID_0, (uint8_t)NFC_PCSC_STORAGE_RID_1, (uint8_t)NFC_PCSC_STORAGE_RID_2,
  (uint8_t)NFC_PCSC_STORAGE_RID_3, (uint8_t)NFC_PCSC_STORAGE_RID_4,
};

/* NFC Forum Type 4 Tag — NDEF Application AID (D2 76 00 00 85 01 01). */
static const uint8_t NFC_PCSC_NDEF_APP_AID[NFC_PCSC_NDEF_APP_AID_LEN] = {
  0xD2u, 0x76u, 0x00u, 0x00u, 0x85u, 0x01u, 0x01u,
};

static const uint8_t NFC_PCSC_NDEF_APP_AID_V0[NFC_PCSC_NDEF_APP_AID_LEN] = {
  0xD2u, 0x76u, 0x00u, 0x00u, 0x85u, 0x01u, 0x00u,
};

static inline uint8_t nfc_pcsc_protocol_for_tag(nfc_tag_kind_t tag_kind) {
  (void)tag_kind;
  return NFC_PCSC_PROTOCOL_T1;
}

NERO_NFC_NODISCARD static inline bool
nfc_pcsc_type4_max_message_size(uint16_t max_ndef_file_size, uint16_t *max_message_size_out) {
  if (max_message_size_out != NERO_NFC_NULL) {
    *max_message_size_out = 0u;
  }
  if ((max_message_size_out == NERO_NFC_NULL) ||
      (max_ndef_file_size < (uint16_t)NFC_PCSC_T4_NLEN_LEN)) {
    return false;
  }
  *max_message_size_out = (uint16_t)(max_ndef_file_size - (uint16_t)NFC_PCSC_T4_NLEN_LEN);
  return true;
}

NERO_NFC_NODISCARD static inline bool
nfc_pcsc_type4_message_size_to_file_size(uint16_t max_message_size,
                                         uint16_t *max_ndef_file_size_out) {
  if (max_ndef_file_size_out != NERO_NFC_NULL) {
    *max_ndef_file_size_out = 0u;
  }
  if (max_ndef_file_size_out == NERO_NFC_NULL) {
    return false;
  }
  return nero_nfc_try_add_u16(max_message_size, (uint16_t)NFC_PCSC_T4_NLEN_LEN,
                              max_ndef_file_size_out);
}

NERO_NFC_NODISCARD static inline bool nfc_pcsc_storage_card_code_for_tag(nfc_tag_kind_t tag_kind,
                                                                         uint8_t *standard_out,
                                                                         uint8_t *card_hi_out,
                                                                         uint8_t *card_lo_out) {
  if (standard_out != NERO_NFC_NULL) {
    *standard_out = 0u;
  }
  if (card_hi_out != NERO_NFC_NULL) {
    *card_hi_out = 0u;
  }
  if (card_lo_out != NERO_NFC_NULL) {
    *card_lo_out = 0u;
  }
  if ((standard_out == NERO_NFC_NULL) || (card_hi_out == NERO_NFC_NULL) ||
      (card_lo_out == NERO_NFC_NULL)) {
    return false;
  }
  switch (tag_kind) {
  case NFC_TAG_KIND_TYPE2:
    *standard_out = (uint8_t)NFC_PCSC_STORAGE_STANDARD_ISO14443A;
    *card_hi_out = 0x00u;
    *card_lo_out = (uint8_t)NFC_PCSC_STORAGE_CARD_TYPE2;
    return true;
  case NFC_TAG_KIND_TYPE5:
    *standard_out = (uint8_t)NFC_PCSC_STORAGE_STANDARD_ISO15693;
    *card_hi_out = 0x00u;
    *card_lo_out = (uint8_t)NFC_PCSC_STORAGE_CARD_TYPE5;
    return true;
  case NFC_TAG_KIND_NONE:
  case NFC_TAG_KIND_TYPE4:
  default:
    break;
  }
  return false;
}

NERO_NFC_NODISCARD static inline bool nfc_pcsc_copy_storage_card_atr(nfc_tag_kind_t tag_kind,
                                                                     uint8_t *dst, uint16_t dst_cap,
                                                                     uint16_t *alen_io) {
  static const uint8_t kPrefix[] = {0x3Bu, 0x8Fu, 0x80u, 0x01u}; /* ISO 7816-3 TS/T0/TD1 */
  static const uint8_t kHistoryTemplate[15] = {
    0x80u,
    0x4Fu,
    0x0Cu,
    (uint8_t)NFC_PCSC_STORAGE_RID_0,
    (uint8_t)NFC_PCSC_STORAGE_RID_1,
    (uint8_t)NFC_PCSC_STORAGE_RID_2,
    (uint8_t)NFC_PCSC_STORAGE_RID_3,
    (uint8_t)NFC_PCSC_STORAGE_RID_4,
    0x00u,
    0x00u,
    0x00u,
    0x00u,
    0x00u,
    0x00u,
    0x00u,
  };
  uint8_t history[15];
  uint8_t standard = 0u;
  uint8_t card_name_hi = 0u;
  uint8_t card_name_lo = 0u;
  uint8_t tck = 0u;
  uint16_t pos = 0u;

  if (alen_io != NERO_NFC_NULL) {
    *alen_io = 0u;
  }
  if ((dst == NERO_NFC_NULL) || (alen_io == NERO_NFC_NULL) ||
      (dst_cap < NFC_PCSC_STORAGE_ATR_LEN) ||
      !nfc_pcsc_storage_card_code_for_tag(tag_kind, &standard, &card_name_hi, &card_name_lo)) {
    return false;
  }
  if (!nero_nfc_copy_bytes(history, sizeof(history), 0u, kHistoryTemplate,
                           sizeof(kHistoryTemplate))) {
    return false;
  }
  history[8] = standard;
  history[9] = card_name_hi;
  history[10] = card_name_lo;

  if (!nero_nfc_copy_bytes(dst, dst_cap, 0u, kPrefix, sizeof(kPrefix))) {
    return false;
  }
  pos = (uint16_t)sizeof(kPrefix);
  if (!nero_nfc_copy_bytes(dst, dst_cap, pos, history, sizeof(history))) {
    return false;
  }
  pos = (uint16_t)(pos + sizeof(history));
  for (uint16_t i = 1u; i < pos; ++i) {
    tck ^= dst[i];
  }
  dst[pos++] = tck;
  *alen_io = pos;
  return true;
}

NERO_NFC_NODISCARD static inline bool nfc_pcsc_aid_matches(const uint8_t *aid, uint8_t aid_len,
                                                           const uint8_t *expect,
                                                           uint8_t expect_len) {
  return (aid != NERO_NFC_NULL) && (expect != NERO_NFC_NULL) && (aid_len == expect_len) &&
         (memcmp(aid, expect, expect_len) == 0);
}

NERO_NFC_NODISCARD static inline bool nfc_pcsc_is_ndef_aid(const uint8_t *aid, uint8_t aid_len) {
  return nfc_pcsc_aid_matches(aid, aid_len, NFC_PCSC_NDEF_APP_AID,
                              (uint8_t)NFC_PCSC_NDEF_APP_AID_LEN) ||
         nfc_pcsc_aid_matches(aid, aid_len, NFC_PCSC_NDEF_APP_AID_V0,
                              (uint8_t)NFC_PCSC_NDEF_APP_AID_LEN);
}

enum { NFC_PCSC_NDEF_APP_SELECT_VARIANT_COUNT = 8u };

#ifdef __cplusplus
struct nfc_pcsc_ndef_app_select_variant_t {
#else
typedef struct {
#endif
  const uint8_t *aid;
  uint8_t aid_len;
  uint8_t p2;
  bool add_le_00;
#ifdef __cplusplus
};
#else
} nfc_pcsc_ndef_app_select_variant_t;
#endif

NERO_NFC_NODISCARD static inline bool
nfc_pcsc_ndef_app_select_variant(uint8_t index, nfc_pcsc_ndef_app_select_variant_t *variant_out) {
  static const struct {
    const uint8_t *aid;
    uint8_t p2;
    bool add_le_00;
  } kVariants[NFC_PCSC_NDEF_APP_SELECT_VARIANT_COUNT] = {
    {NFC_PCSC_NDEF_APP_AID, (uint8_t)NFC_ISO7816_P2_SELECT_FIRST, true},
    {NFC_PCSC_NDEF_APP_AID, (uint8_t)NFC_ISO7816_P2_SELECT_FIRST, false},
    {NFC_PCSC_NDEF_APP_AID, (uint8_t)NFC_ISO7816_P2_SELECT_NO_FCI, true},
    {NFC_PCSC_NDEF_APP_AID, (uint8_t)NFC_ISO7816_P2_SELECT_NO_FCI, false},
    {NFC_PCSC_NDEF_APP_AID_V0, (uint8_t)NFC_ISO7816_P2_SELECT_FIRST, true},
    {NFC_PCSC_NDEF_APP_AID_V0, (uint8_t)NFC_ISO7816_P2_SELECT_FIRST, false},
    {NFC_PCSC_NDEF_APP_AID_V0, (uint8_t)NFC_ISO7816_P2_SELECT_NO_FCI, true},
    {NFC_PCSC_NDEF_APP_AID_V0, (uint8_t)NFC_ISO7816_P2_SELECT_NO_FCI, false},
  };

  if (variant_out != NERO_NFC_NULL) {
    variant_out->aid = NERO_NFC_NULL;
    variant_out->aid_len = 0u;
    variant_out->p2 = 0u;
    variant_out->add_le_00 = false;
  }
  if ((variant_out == NERO_NFC_NULL) ||
      (index >= (uint8_t)NFC_PCSC_NDEF_APP_SELECT_VARIANT_COUNT)) {
    return false;
  }
  variant_out->aid = kVariants[index].aid;
  variant_out->aid_len = (uint8_t)NFC_PCSC_NDEF_APP_AID_LEN;
  variant_out->p2 = kVariants[index].p2;
  variant_out->add_le_00 = kVariants[index].add_le_00;
  return true;
}

NERO_NFC_NODISCARD static inline bool nfc_pcsc_build_t4_select_file_apdu(uint16_t file_id,
                                                                         uint8_t *apdu,
                                                                         uint8_t apdu_cap,
                                                                         uint8_t *apdu_len_out) {
  if (apdu_len_out != NERO_NFC_NULL) {
    *apdu_len_out = 0u;
  }
  if ((apdu == NERO_NFC_NULL) || (apdu_len_out == NERO_NFC_NULL) ||
      (apdu_cap < (uint8_t)NFC_PCSC_T4_SELECT_FILE_APDU_LEN)) {
    return false;
  }
  apdu[0] = (uint8_t)NFC_ISO7816_CLA_ISO;
  apdu[1] = (uint8_t)NFC_ISO7816_INS_SELECT;
  apdu[2] = (uint8_t)NFC_ISO7816_P1_SELECT_BY_FILE_ID;
  apdu[3] = (uint8_t)NFC_ISO7816_P2_SELECT_NO_FCI;
  apdu[4] = (uint8_t)NFC_ISO7816_LC_SELECT_FILE_ID;
  apdu[5] = (uint8_t)(file_id >> (uint16_t)NFC_ISO7816_U16_HIGH_BYTE_SHIFT);
  apdu[6] = (uint8_t)(file_id & (uint16_t)NFC_ISO7816_LOW_BYTE_MASK);
  *apdu_len_out = (uint8_t)NFC_PCSC_T4_SELECT_FILE_APDU_LEN;
  return true;
}

NERO_NFC_NODISCARD static inline bool nfc_pcsc_build_t4_read_binary_apdu(uint16_t offset,
                                                                         uint8_t le, uint8_t *apdu,
                                                                         uint8_t apdu_cap,
                                                                         uint8_t *apdu_len_out) {
  if (apdu_len_out != NERO_NFC_NULL) {
    *apdu_len_out = 0u;
  }
  if ((apdu == NERO_NFC_NULL) || (apdu_len_out == NERO_NFC_NULL) ||
      (apdu_cap < (uint8_t)NFC_PCSC_T4_READ_BINARY_APDU_LEN)) {
    return false;
  }
  apdu[0] = (uint8_t)NFC_ISO7816_CLA_ISO;
  apdu[1] = (uint8_t)NFC_ISO7816_INS_READ_BINARY;
  apdu[2] = (uint8_t)(offset >> (uint16_t)NFC_ISO7816_U16_HIGH_BYTE_SHIFT);
  apdu[3] = (uint8_t)(offset & (uint16_t)NFC_ISO7816_LOW_BYTE_MASK);
  apdu[4] = le;
  *apdu_len_out = (uint8_t)NFC_PCSC_T4_READ_BINARY_APDU_LEN;
  return true;
}

/* NFC Forum Type 4 Tag — build a 15-byte CC file with variable NDEF file size.
 * [T4T-ISO14443-4] minimum CC length is 15 bytes; NTAG424 delivery CC is 23
 * bytes with proprietary TLV, so this helper emits only the generic Type 4 NDEF
 * File Control TLV template. CC bytes 13/14 are NDEF file read/write access
 * (0x00 open, 0xFF closed). */
NERO_NFC_NODISCARD static inline bool nfc_pcsc_build_type4_cc_file(uint16_t max_ndef_file_size,
                                                                   bool read_access_open,
                                                                   bool write_access_open,
                                                                   uint8_t *dst, uint16_t dst_cap,
                                                                   uint16_t *len_out) {
  if (len_out != NERO_NFC_NULL) {
    *len_out = 0u;
  }
  if ((dst == NERO_NFC_NULL) || (len_out == NERO_NFC_NULL) || (dst_cap < NFC_PCSC_T4_CC_FILE_LEN)) {
    return false;
  }
  dst[0] = 0x00u;
  dst[1] = (uint8_t)NFC_PCSC_T4_CC_FILE_LEN;
  dst[2] = (uint8_t)NFC_PCSC_T4_CC_MAPPING_VERSION;
  dst[3] = (uint8_t)(NFC_PCSC_T4_CC_DEFAULT_MLE >> (uint16_t)NFC_ISO7816_U16_HIGH_BYTE_SHIFT);
  dst[4] = (uint8_t)(NFC_PCSC_T4_CC_DEFAULT_MLE & (uint16_t)NFC_ISO7816_LOW_BYTE_MASK);
  dst[5] = (uint8_t)(NFC_PCSC_T4_CC_DEFAULT_MLC >> (uint16_t)NFC_ISO7816_U16_HIGH_BYTE_SHIFT);
  dst[6] = (uint8_t)(NFC_PCSC_T4_CC_DEFAULT_MLC & (uint16_t)NFC_ISO7816_LOW_BYTE_MASK);
  dst[7] = (uint8_t)NFC_PCSC_T4_NDEF_FC_TLV_TAG;
  dst[8] = (uint8_t)NFC_PCSC_T4_NDEF_FC_TLV_LEN;
  dst[9] = (uint8_t)NFC_PCSC_T4_NDEF_FILE_ID_MSB;
  dst[10] = (uint8_t)NFC_PCSC_T4_NDEF_FILE_ID_LSB;
  dst[11] = (uint8_t)(max_ndef_file_size >> (uint16_t)NFC_ISO7816_U16_HIGH_BYTE_SHIFT);
  dst[12] = (uint8_t)(max_ndef_file_size & (uint16_t)NFC_ISO7816_LOW_BYTE_MASK);
  dst[13] = read_access_open ? (uint8_t)NFC_PCSC_T4_READ_ACCESS_OPEN
                             : (uint8_t)NFC_PCSC_T4_READ_ACCESS_CLOSED;
  dst[14] = write_access_open ? (uint8_t)NFC_PCSC_T4_READ_ACCESS_OPEN
                              : (uint8_t)NFC_PCSC_T4_READ_ACCESS_CLOSED;
  *len_out = (uint16_t)NFC_PCSC_T4_CC_FILE_LEN;
  return true;
}

NERO_NFC_NODISCARD static inline bool nfc_iso7816_apdu_min_len(uint16_t apdu_len, uint16_t need) {
  return apdu_len >= need;
}

NERO_NFC_NODISCARD static inline bool nfc_iso7816_apdu_lc(const uint8_t *apdu, uint16_t apdu_len,
                                                          uint8_t *lc_out) {
  if (lc_out != NERO_NFC_NULL) {
    *lc_out = 0u;
  }
  if ((apdu == NERO_NFC_NULL) || (lc_out == NERO_NFC_NULL) ||
      !nero_nfc_span_ok((size_t)NFC_ISO7816_MIN_CMD_APDU_LEN, 1u, apdu_len)) {
    return false;
  }
  *lc_out = apdu[4];
  return true;
}

NERO_NFC_NODISCARD static inline bool nfc_iso7816_apdu_lc_body_ok(uint16_t apdu_len, uint8_t lc) {
  uint16_t need = 0u;
  return nero_nfc_try_add_u16((uint16_t)NFC_ISO7816_SHORT_APDU_HDR_LEN, lc, &need) &&
         (apdu_len == need);
}

NERO_NFC_NODISCARD static inline bool nfc_iso7816_apdu_lc_body_with_le_ok(uint16_t apdu_len,
                                                                          uint8_t lc) {
  uint16_t need = 0u;
  return nero_nfc_try_add_u16((uint16_t)NFC_ISO7816_APDU_LC_BODY_WITH_LE_PREFIX, lc, &need) &&
         (apdu_len == need);
}

NERO_NFC_NODISCARD static inline const uint8_t *
nfc_iso7816_apdu_data_ptr(const uint8_t *apdu, uint16_t apdu_len, uint8_t lc) {
  if ((apdu == NERO_NFC_NULL) ||
      !nero_nfc_span_ok((size_t)NFC_ISO7816_SHORT_APDU_HDR_LEN, lc, apdu_len)) {
    return NERO_NFC_NULL;
  }
  return apdu + (uint16_t)NFC_ISO7816_SHORT_APDU_HDR_LEN;
}

NERO_NFC_NODISCARD static inline bool nfc_iso7816_apdu_read_binary(const uint8_t *apdu,
                                                                   uint16_t apdu_len,
                                                                   uint16_t *offset_out,
                                                                   uint8_t *le_out) {
  if (offset_out != NERO_NFC_NULL) {
    *offset_out = 0u;
  }
  if (le_out != NERO_NFC_NULL) {
    *le_out = 0u;
  }
  if ((apdu == NERO_NFC_NULL) || (offset_out == NERO_NFC_NULL) || (le_out == NERO_NFC_NULL) ||
      (apdu_len != (uint16_t)NFC_PCSC_T4_READ_BINARY_APDU_LEN)) {
    return false;
  }
  *offset_out =
    (uint16_t)(((uint16_t)apdu[2] << (uint16_t)NFC_ISO7816_U16_HIGH_BYTE_SHIFT) | apdu[3]);
  *le_out = apdu[4];
  return true;
}

NERO_NFC_NODISCARD static inline bool
nfc_iso7816_apdu_update_binary(const uint8_t *apdu, uint16_t apdu_len, uint16_t *offset_out,
                               uint8_t *lc_out, const uint8_t **data_out) {
  uint8_t lc = 0u;
  uint16_t need = 0u;

  if (offset_out != NERO_NFC_NULL) {
    *offset_out = 0u;
  }
  if (lc_out != NERO_NFC_NULL) {
    *lc_out = 0u;
  }
  if (data_out != NERO_NFC_NULL) {
    *data_out = NERO_NFC_NULL;
  }
  if ((apdu == NERO_NFC_NULL) || (offset_out == NERO_NFC_NULL) || (lc_out == NERO_NFC_NULL) ||
      (data_out == NERO_NFC_NULL) || !nfc_iso7816_apdu_lc(apdu, apdu_len, &lc) ||
      !nero_nfc_try_add_u16((uint16_t)NFC_ISO7816_SHORT_APDU_HDR_LEN, lc, &need) ||
      (apdu_len != need) || (lc == 0u)) {
    return false;
  }
  *offset_out =
    (uint16_t)(((uint16_t)apdu[2] << (uint16_t)NFC_ISO7816_U16_HIGH_BYTE_SHIFT) | apdu[3]);
  *lc_out = lc;
  *data_out = apdu + (uint16_t)NFC_ISO7816_SHORT_APDU_HDR_LEN;
  return true;
}

NERO_NFC_NODISCARD static inline bool
nfc_pcsc_build_select_aid_apdu(const uint8_t *aid, uint8_t aid_len, uint8_t p2, bool add_le_00,
                               uint8_t *apdu, uint16_t apdu_cap, uint16_t *apdu_len_out) {
  uint16_t len = 0u;

  if (apdu_len_out != NERO_NFC_NULL) {
    *apdu_len_out = 0u;
  }
  if ((aid == NERO_NFC_NULL) || (apdu == NERO_NFC_NULL) || (apdu_len_out == NERO_NFC_NULL) ||
      (aid_len == 0u) || (aid_len > (uint8_t)NFC_ISO7816_SELECT_AID_MAX)) {
    return false;
  }
  if (!nero_nfc_try_add_u16((uint16_t)NFC_ISO7816_SHORT_APDU_HDR_LEN, aid_len, &len) ||
      (add_le_00 && !nero_nfc_try_add_u16(len, 1u, &len)) || (len > apdu_cap)) {
    return false;
  }
  apdu[0] = (uint8_t)NFC_ISO7816_CLA_ISO;
  apdu[1] = (uint8_t)NFC_ISO7816_INS_SELECT;
  apdu[2] = (uint8_t)NFC_ISO7816_P1_SELECT_BY_DF_NAME;
  apdu[3] = p2;
  apdu[4] = aid_len;
  if (!nero_nfc_copy_bytes(apdu, apdu_cap, (uint16_t)NFC_ISO7816_SHORT_APDU_HDR_LEN, aid,
                           aid_len)) {
    return false;
  }
  if (add_le_00) {
    apdu[(uint16_t)NFC_ISO7816_SHORT_APDU_HDR_LEN + aid_len] = (uint8_t)NFC_ISO7816_CLA_ISO;
  }
  *apdu_len_out = len;
  return true;
}

NERO_NFC_NODISCARD static inline bool nfc_iso7816_response_sw(const uint8_t *resp, int rlen,
                                                              uint8_t *sw1_out, uint8_t *sw2_out) {
  if (sw1_out != NERO_NFC_NULL) {
    *sw1_out = 0u;
  }
  if (sw2_out != NERO_NFC_NULL) {
    *sw2_out = 0u;
  }
  if ((resp == NERO_NFC_NULL) || (sw1_out == NERO_NFC_NULL) || (sw2_out == NERO_NFC_NULL) ||
      (rlen < 2)) {
    return false;
  }
  *sw1_out = resp[rlen - 2];
  *sw2_out = resp[rlen - 1];
  return true;
}

NERO_NFC_NODISCARD static inline bool
nfc_iso7816_response_wrong_length(const uint8_t *resp, int rlen, uint8_t *correct_le_out) {
  uint8_t sw1 = 0u;
  uint8_t sw2 = 0u;

  if (correct_le_out != NERO_NFC_NULL) {
    *correct_le_out = 0u;
  }
  if (!nfc_iso7816_response_sw(resp, rlen, &sw1, &sw2) ||
      (sw1 != (uint8_t)NFC_ISO7816_SW1_WRONG_LENGTH)) {
    return false;
  }
  if (correct_le_out != NERO_NFC_NULL) {
    *correct_le_out = sw2;
  }
  return true;
}

NERO_NFC_NODISCARD static inline bool nfc_iso7816_response_more_data(const uint8_t *resp, int rlen,
                                                                     uint8_t *remaining_out) {
  uint8_t sw1 = 0u;
  uint8_t sw2 = 0u;

  if (remaining_out != NERO_NFC_NULL) {
    *remaining_out = 0u;
  }
  if (!nfc_iso7816_response_sw(resp, rlen, &sw1, &sw2) ||
      (sw1 != (uint8_t)NFC_ISO7816_SW1_MORE_DATA)) {
    return false;
  }
  if (remaining_out != NERO_NFC_NULL) {
    *remaining_out = sw2;
  }
  return true;
}

NERO_NFC_NODISCARD static inline bool nfc_iso7816_append_sw(uint8_t *dst, uint16_t dst_cap,
                                                            uint16_t data_len, uint8_t sw1,
                                                            uint8_t sw2, uint16_t *out_len) {
  size_t response_len = 0u;

  if (out_len != NERO_NFC_NULL) {
    *out_len = 0u;
  }
  if ((dst == NERO_NFC_NULL) || (out_len == NERO_NFC_NULL) ||
      !nero_nfc_try_add_size((size_t)data_len, (size_t)NFC_ISO7816_SW_LEN, &response_len) ||
      (response_len > (size_t)dst_cap) ||
      !nero_nfc_span_ok((size_t)data_len, (size_t)NFC_ISO7816_SW_LEN, dst_cap)) {
    return false;
  }
  dst[data_len] = sw1;
  dst[data_len + 1u] = sw2;
  *out_len = (uint16_t)response_len;
  return true;
}

NERO_NFC_NODISCARD static inline bool nfc_iso7816_response_sw_ok(const uint8_t *resp, int rlen) {
  uint8_t sw1 = 0u;
  uint8_t sw2 = 0u;

  return nfc_iso7816_response_sw(resp, rlen, &sw1, &sw2) &&
         (sw1 == (uint8_t)NFC_ISO7816_SW1_SUCCESS) && (sw2 == (uint8_t)NFC_ISO7816_SW2_SUCCESS);
}

#ifdef __cplusplus
}
#endif
