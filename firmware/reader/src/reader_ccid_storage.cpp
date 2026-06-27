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

/*
 * reader_ccid_storage.cpp — PC/SC Part 3 storage-card APDU handlers.
 */

#if defined(NERO_CCID_USB_BUILD)

#include "reader_ccid_internal.h"

#include "reader_ccid.h"

#include "nfc_ccid_frame.h"

#include "nero_nfc_limits.h"
#include "nero_nfc_mem_util.h"
#include "nfc_pcsc_contactless.h"
#include "nfc_storage_ndef.h"

#include "reader_ccid_bulk_codec.h"
#include "reader_ccid_protocol.h"
#include "reader_context.h"
#include "reader_hal.h"
#include "reader_security_key.h"
#include "reader_tags_internal.h"

#if defined(NERO_HOST_UNIT_TEST_HOOKS)
#include "reader_ccid_utest.h"
#include "reader_hal_utest.h"
#endif

#include <algorithm>
#include <cstdint>
#include <cstring>

namespace {

enum {
  kIso7816UpdateBinaryMinHdrLen = 4u,
  kIso15693AddressFlag = 0x20u,
  kIso15693HeaderLen = 2u,
  kIso15693UidLen = NFC_FRONTEND_ISO15693_UID_LEN,
  kIso15693ShortBlockFieldLen = 1u,
  kIso15693ShortMultipleBlockFieldLen = 2u,
  kIso15693ExtBlockFieldLen = 2u,
  kIso15693ExtMultipleBlockFieldLen = 4u,
  kIso15693ExtCountLsbRelOffset = 2u,
  kIso15693ExtCountMsbRelOffset = 3u,
  kIso7816ShortLeZeroBytes = 256u,
  kType2RawFastReadLastPageOffset = 2u,
  kType2RawReadSigCmdLen = 2u,
};

} /* namespace */

uint16_t reader_ccid_append_status(uint8_t *dst, uint16_t data_len, uint16_t dst_cap, uint8_t sw1,
                                   uint8_t sw2) {
  uint16_t out_len = 0u;

  if (!nfc_iso7816_append_sw(dst, dst_cap, data_len, sw1, sw2, &out_len)) {
    return 0u;
  }
  return out_len;
}

static uint16_t reader_ccid_get_data_contactless(uint8_t p1, uint8_t *rsp, uint16_t rsp_cap) {
  reader_tag_typea_info_t typea;

  switch (p1) {
  case (uint8_t)NFC_PCSC_GET_DATA_UID:
    if (g_tag_kind == READER_TAG_KIND_TYPE5) {
      if (!nero_nfc_copy_bytes(rsp, rsp_cap, 0u, g_uid15, NFC_FRONTEND_ISO15693_UID_LEN)) {
        return reader_ccid_apdu_failure_response(rsp, rsp_cap);
      }
      return reader_ccid_append_success_status(rsp, NFC_FRONTEND_ISO15693_UID_LEN, rsp_cap);
    }
    if (!reader_tags_get_typea_info(&typea) ||
        !nero_nfc_copy_bytes(rsp, rsp_cap, 0u, typea.uid, typea.uid_len)) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                       (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
    }
    return reader_ccid_append_success_status(rsp, typea.uid_len, rsp_cap);
  case (uint8_t)NFC_PCSC_GET_DATA_ATS:
    if (!reader_tags_get_typea_info(&typea)) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                       (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
    }
    if (typea.ats_len != 0u) {
      if (!nero_nfc_copy_bytes(rsp, rsp_cap, 0u, typea.ats, typea.ats_len)) {
        return reader_ccid_apdu_failure_response(rsp, rsp_cap);
      }
      return reader_ccid_append_success_status(rsp, typea.ats_len, rsp_cap);
    }
    return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                     (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
  case (uint8_t)NFC_PCSC_GET_DATA_SAK:
    if (!reader_tags_get_typea_info(&typea) ||
        rsp_cap < (uint16_t)(NFC_PCSC_GET_DATA_SAK_RSP_LEN + NFC_ISO7816_SW_LEN)) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                       (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
    }
    rsp[0] = typea.sak;
    return reader_ccid_append_success_status(rsp, NFC_PCSC_GET_DATA_SAK_RSP_LEN, rsp_cap);
  case (uint8_t)NFC_PCSC_GET_DATA_ATQA:
    if (!reader_tags_get_typea_info(&typea) || !typea.atqa_valid ||
        rsp_cap < (uint16_t)(NFC_PCSC_GET_DATA_ATQA_RSP_LEN + NFC_ISO7816_SW_LEN)) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                       (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
    }
    rsp[0] = typea.atqa[0];
    rsp[1] = typea.atqa[1];
    return reader_ccid_append_success_status(rsp, NFC_PCSC_GET_DATA_ATQA_RSP_LEN, rsp_cap);
  default:
    return 0u;
  }
}

static uint16_t reader_ccid_get_data_type2(uint8_t p1, uint8_t *rsp, uint16_t rsp_cap) {
  reader_tag_type2_info_t type2;

  switch (p1) {
  case (uint8_t)NFC_PCSC_GET_DATA_TYPE2_VERSION: {
    const uint8_t get_version[NFC_TAG_T2T_GET_VERSION_CMD_LEN] = {
      (uint8_t)CCID_RAW_T2_CMD_GET_VERSION};
    uint8_t version[NFC_TAG_NTAG_VER_REPLY_LEN];
    int version_len;
    if ((g_tag_kind != READER_TAG_KIND_TYPE2) || !reader_tags_get_type2_storage_info(&type2) ||
        !type2.cc_valid) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                       (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
    }
    version_len = reader_tags_type2_transceive(get_version, (uint16_t)sizeof(get_version), version,
                                               (uint16_t)sizeof(version));
    if (version_len < (int)NFC_TAG_NTAG_VER_REPLY_LEN) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                       (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
    }
    nfc_tag_type2_apply_version(&type2, version, (uint8_t)NFC_TAG_NTAG_VER_REPLY_LEN);
    if (type2.family != NFC_TAG_TYPE2_FAMILY_NTAG21X) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                       (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
    }
    if (!nero_nfc_copy_bytes(rsp, rsp_cap, 0u, version, (uint16_t)NFC_TAG_NTAG_VER_REPLY_LEN)) {
      return reader_ccid_apdu_failure_response(rsp, rsp_cap);
    }
    return reader_ccid_append_success_status(rsp, (uint16_t)NFC_TAG_NTAG_VER_REPLY_LEN, rsp_cap);
  }
  case (uint8_t)NFC_PCSC_GET_DATA_NTAG_SIGNATURE: {
    const uint8_t read_sig[kType2RawReadSigCmdLen] = {(uint8_t)CCID_RAW_T2_CMD_READ_SIG, 0x00u};
    uint8_t signature[NFC_TAG_NTAG_SIG_REPLY_LEN];
    int sig_len;
    if ((g_uid14_len == 0u) || (g_uid14[0] != NFC_TAG_MFR_CODE_NXP)) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                       (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
    }
    sig_len = reader_tags_type2_transceive(read_sig, (uint16_t)sizeof(read_sig), signature,
                                           (uint16_t)sizeof(signature));
    if (sig_len < (int)sizeof(signature)) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                       (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
    }
    if (!nero_nfc_copy_bytes(rsp, rsp_cap, 0u, signature, (uint16_t)sizeof(signature))) {
      return reader_ccid_apdu_failure_response(rsp, rsp_cap);
    }
    return reader_ccid_append_success_status(rsp, (uint16_t)sizeof(signature), rsp_cap);
  }
  case (uint8_t)NFC_PCSC_GET_DATA_TYPE2_CC:
    if (!reader_tags_get_type2_storage_info(&type2) || !type2.cc_valid) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                       (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
    }
    if (!nero_nfc_copy_bytes(rsp, rsp_cap, 0u, type2.cc, (uint16_t)sizeof(type2.cc))) {
      return reader_ccid_apdu_failure_response(rsp, rsp_cap);
    }
    return reader_ccid_append_success_status(rsp, (uint16_t)sizeof(type2.cc), rsp_cap);
  case (uint8_t)NFC_PCSC_GET_DATA_TYPE2_AUTH0: {
    const uint8_t get_version[NFC_TAG_T2T_GET_VERSION_CMD_LEN] = {
      (uint8_t)CCID_RAW_T2_CMD_GET_VERSION};
    uint8_t version[NFC_TAG_NTAG_VER_REPLY_LEN];
    uint8_t cfg[NFC_TAG_T2T_READ_RESP_BYTES];
    int version_len;
    int cfg_len;
    if ((g_uid14_len == 0u) || (g_uid14[0] != NFC_TAG_MFR_CODE_NXP) ||
        (rsp_cap < (uint16_t)(NFC_PCSC_GET_DATA_AUTH0_RSP_LEN + NFC_ISO7816_SW_LEN))) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                       (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
    }
    version_len = reader_tags_type2_transceive(get_version, (uint16_t)sizeof(get_version), version,
                                               (uint16_t)sizeof(version));
    if (version_len < (int)NFC_TAG_NTAG_VER_REPLY_LEN) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                       (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
    }
    nero_nfc_zero_bytes(&type2, sizeof(type2));
    nfc_tag_type2_apply_version(&type2, version, (uint8_t)NFC_TAG_NTAG_VER_REPLY_LEN);
    if (type2.max_user_page == 0u) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                       (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
    }
    cfg_len = reader_tags_ntag_read_page(
      (uint8_t)(type2.max_user_page + NFC_TAG_NTAG_AUTH0_PAGE_OFFSET), cfg);
    if (cfg_len < (int)NFC_TAG_T2T_PAGE_SIZE_BYTES) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                       (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
    }
    rsp[0] = cfg[NFC_TAG_NTAG_CFG_AUTH0_BYTE_INDEX];
    return reader_ccid_append_success_status(rsp, NFC_PCSC_GET_DATA_AUTH0_RSP_LEN, rsp_cap);
  }
  default:
    return 0u;
  }
}

static uint16_t reader_ccid_get_data_type45(uint8_t p1, uint8_t *rsp, uint16_t rsp_cap) {
  reader_tag_type5_info_t type5;

  switch (p1) {
  case (uint8_t)NFC_PCSC_GET_DATA_TYPE5_SYS_INFO:
    if (!reader_tags_get_type5_info(&type5) || type5.raw_len == 0u) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                       (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
    }
    if (!nero_nfc_copy_bytes(rsp, rsp_cap, 0u, type5.raw, type5.raw_len)) {
      return reader_ccid_apdu_failure_response(rsp, rsp_cap);
    }
    return reader_ccid_append_success_status(rsp, type5.raw_len, rsp_cap);
  case (uint8_t)NFC_PCSC_GET_DATA_TYPE4_CC: {
    reader_tag_type4_info_t type4;

    if (!reader_tags_get_type4_info(&type4) || !type4.cc_valid || type4.cc_len == 0u) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                       (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
    }
    if (!nero_nfc_copy_bytes(rsp, rsp_cap, 0u, type4.cc, type4.cc_len)) {
      return reader_ccid_apdu_failure_response(rsp, rsp_cap);
    }
    return reader_ccid_append_success_status(rsp, type4.cc_len, rsp_cap);
  }
  case (uint8_t)NFC_PCSC_GET_DATA_TYPE5_CC:
    if (!reader_tags_get_type5_info(&type5) || !type5.cc_valid || type5.cc_len == 0u) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                       (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
    }
    if (!nero_nfc_copy_bytes(rsp, rsp_cap, 0u, type5.cc, type5.cc_len)) {
      return reader_ccid_apdu_failure_response(rsp, rsp_cap);
    }
    return reader_ccid_append_success_status(rsp, type5.cc_len, rsp_cap);
  default:
    return 0u;
  }
}

uint16_t reader_ccid_handle_get_data_apdu(const uint8_t *apdu, uint16_t apdu_len, uint8_t *rsp,
                                          uint16_t rsp_cap) {
  if ((apdu == NERO_NFC_NULL) || (rsp == NERO_NFC_NULL) ||
      !nfc_iso7816_apdu_min_len(apdu_len, NFC_ISO7816_SHORT_APDU_HDR_LEN) ||
      (rsp_cap < (uint16_t)NFC_ISO7816_SW_LEN)) {
    return 0u;
  }
  if (apdu_len != NFC_ISO7816_SHORT_APDU_HDR_LEN) {
    return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_LENGTH_ALT,
                                     (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  }
  if (apdu[NFC_ISO7816_APDU_IDX_P2] != (uint8_t)NFC_ISO7816_GET_DATA_P2_DEFAULT) {
    return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                     (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
  }

  const uint8_t p1 = apdu[NFC_ISO7816_APDU_IDX_P1];
  uint16_t response = reader_ccid_get_data_contactless(p1, rsp, rsp_cap);
  if (response != 0u) {
    return response;
  }
  response = reader_ccid_get_data_type2(p1, rsp, rsp_cap);
  if (response != 0u) {
    return response;
  }
  response = reader_ccid_get_data_type45(p1, rsp, rsp_cap);
  if (response != 0u) {
    return response;
  }
  return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                   (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
}

uint16_t reader_ccid_handle_escape_transparent_apdu(const uint8_t *apdu, uint16_t apdu_len,
                                                    uint8_t *rsp, uint16_t rsp_cap) {
  uint8_t lc;
  const uint8_t *body;
  int rlen;

  if ((apdu == NERO_NFC_NULL) || (rsp == NERO_NFC_NULL) ||
      !nfc_iso7816_apdu_min_len(apdu_len, NFC_ISO7816_SHORT_APDU_HDR_LEN) ||
      (rsp_cap < (uint16_t)NFC_ISO7816_SW_LEN)) {
    return 0u;
  }
  if ((apdu[0] != (uint8_t)NFC_ISO7816_CLA_PROPRIETARY) ||
      (apdu[1] != (uint8_t)NFC_PCSC_ESCAPE_TRANSPARENT_INS) ||
      (g_tag_kind != READER_TAG_KIND_TYPE5)) {
    return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_INS_NOT_SUPPORTED,
                                     (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  }
  if (!nfc_iso7816_apdu_lc(apdu, apdu_len, &lc) || (lc == 0u) ||
      !nfc_iso7816_apdu_lc_body_ok(apdu_len, lc)) {
    return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_LENGTH_ALT,
                                     (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  }
  body = nfc_iso7816_apdu_data_ptr(apdu, apdu_len, lc);
  if (body == NERO_NFC_NULL) {
    return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_LENGTH_ALT,
                                     (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  }
  if (!reader_ccid_type5_raw_transceive_allowed(body, lc)) {
    return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_INS_NOT_SUPPORTED,
                                     (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  }
  rlen = reader_tags_type5_transceive(body, lc, rsp, (uint16_t)(rsp_cap - NFC_ISO7816_SW_LEN));
  if (rlen < 0) {
    return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_VERIFICATION_FAILED,
                                     (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  }
  return reader_ccid_append_success_status(rsp, (uint16_t)rlen, rsp_cap);
}

static bool storage_read_binary_fields(const uint8_t *apdu, uint16_t apdu_len, uint16_t *offset_out,
                                       uint8_t *le_out) {
  if (offset_out != NERO_NFC_NULL) {
    *offset_out = 0u;
  }
  if (le_out != NERO_NFC_NULL) {
    *le_out = 0u;
  }
  if ((offset_out == NERO_NFC_NULL) || (le_out == NERO_NFC_NULL) ||
      !nfc_iso7816_apdu_read_binary(apdu, apdu_len, offset_out, le_out)) {
    return false;
  }
  if ((g_tag_kind == READER_TAG_KIND_TYPE5) &&
      (apdu[NFC_ISO7816_APDU_IDX_P1] == (uint8_t)NFC_ISO7816_READ_BINARY_P1_BLOCK_IN_P2)) {
    if (!nero_nfc_span_ok(NFC_ISO7816_APDU_IDX_P2, 1u, apdu_len)) {
      return false;
    }
    *offset_out = apdu[NFC_ISO7816_APDU_IDX_P2];
  } else if (g_tag_kind == READER_TAG_KIND_TYPE5) {
    if ((*offset_out % (uint16_t)NFC_STORAGE_TYPE5_BLOCK_SIZE) != 0u) {
      return false;
    }
    *offset_out = (uint16_t)(*offset_out / (uint16_t)NFC_STORAGE_TYPE5_BLOCK_SIZE);
  }
  return true;
}

static bool storage_update_binary_offset(const uint8_t *apdu, uint16_t apdu_len,
                                         uint16_t parsed_offset, uint16_t *offset_out) {
  if (offset_out == NERO_NFC_NULL) {
    return false;
  }
  *offset_out = parsed_offset;
  if ((apdu == NERO_NFC_NULL) || (g_tag_kind != READER_TAG_KIND_TYPE5)) {
    return true;
  }
  if ((apdu[NFC_ISO7816_APDU_IDX_P1] == (uint8_t)NFC_ISO7816_READ_BINARY_P1_BLOCK_IN_P2) &&
      nfc_iso7816_apdu_min_len(apdu_len, kIso7816UpdateBinaryMinHdrLen)) {
    *offset_out = apdu[NFC_ISO7816_APDU_IDX_P2];
    return true;
  }
  if ((parsed_offset % (uint16_t)NFC_STORAGE_TYPE5_BLOCK_SIZE) != 0u) {
    return false;
  }
  *offset_out = (uint16_t)(parsed_offset / (uint16_t)NFC_STORAGE_TYPE5_BLOCK_SIZE);
  return true;
}

static bool storage_type2_read_span_ok(const reader_tag_type2_info_t *type2, uint16_t page,
                                       uint16_t len) {
  if ((type2 == NERO_NFC_NULL) || !type2->cc_valid) {
    return false;
  }
  return nfc_storage_type2_read_span_ok(type2->data_area_size_bytes, page, len);
}

static bool storage_type2_update_span_ok(const reader_tag_type2_info_t *type2, uint16_t page,
                                         uint8_t len) {
  if ((type2 == NERO_NFC_NULL) || !type2->cc_valid || !type2->write_access_open) {
    return false;
  }
  return nfc_storage_type2_write_span_ok(type2->data_area_size_bytes, page, len);
}

static bool storage_type5_read_span_ok(const reader_tag_type5_info_t *type5, uint16_t block,
                                       uint16_t len) {
  uint16_t cc_bytes;
  uint8_t block_size;

  if ((type5 == NERO_NFC_NULL) || !type5->cc_valid) {
    return false;
  }
  block_size = (type5->block_size == 0u) ? ST25_T5_USER_BLOCK_SIZE : type5->block_size;
  cc_bytes = reader_tags_type5_cc_byte_len(type5);
  return nfc_storage_type5_read_span_ok(cc_bytes, type5->data_area_size_bytes, block_size,
                                        type5->block_count, block, len);
}

static bool storage_type5_update_span_ok(const reader_tag_type5_info_t *type5, uint16_t block,
                                         uint8_t len) {
  uint16_t cc_bytes;
  uint8_t block_size;

  if ((type5 == NERO_NFC_NULL) || !type5->cc_valid || !type5->write_access_open) {
    return false;
  }
  block_size = (type5->block_size == 0u) ? ST25_T5_USER_BLOCK_SIZE : type5->block_size;
  cc_bytes = reader_tags_type5_cc_byte_len(type5);
  return nfc_storage_type5_write_span_ok(cc_bytes, type5->data_area_size_bytes, block_size,
                                         type5->block_count, block, len);
}

static bool raw_type5_uid_lsb_matches_active(const uint8_t *uid_lsb) {
  if (uid_lsb == NERO_NFC_NULL) {
    return false;
  }
  for (uint8_t i = 0u; i < (uint8_t)kIso15693UidLen; ++i) {
    if (uid_lsb[i] != g_uid15[kIso15693UidLen - 1u - i]) {
      return false;
    }
  }
  return true;
}

static bool raw_type5_addressed_uid_allowed(const uint8_t *tx, uint16_t tx_len,
                                            uint16_t uid_offset) {
  return (tx != NERO_NFC_NULL) && nero_nfc_span_ok(uid_offset, kIso15693UidLen, tx_len) &&
         raw_type5_uid_lsb_matches_active(tx + uid_offset);
}

static bool raw_type5_fixed_command_allowed(const uint8_t *tx, uint16_t tx_len, uint16_t base_len) {
  if ((tx == NERO_NFC_NULL) || (tx_len < base_len)) {
    return false;
  }
  if ((tx[0] & kIso15693AddressFlag) != 0u) {
    return (tx_len == (uint16_t)(base_len + kIso15693UidLen)) &&
           raw_type5_addressed_uid_allowed(tx, tx_len, base_len);
  }
  return tx_len == base_len;
}

static bool raw_type5_block_payload_offset(const uint8_t *tx, uint16_t tx_len,
                                           uint16_t *offset_out) {
  uint16_t offset = kIso15693HeaderLen;

  if (offset_out != NERO_NFC_NULL) {
    *offset_out = 0u;
  }
  if ((tx == NERO_NFC_NULL) || (offset_out == NERO_NFC_NULL) || (tx_len < kIso15693HeaderLen)) {
    return false;
  }
  if ((tx[0] & kIso15693AddressFlag) != 0u) {
    if (!raw_type5_addressed_uid_allowed(tx, tx_len, offset)) {
      return false;
    }
    offset = (uint16_t)(offset + kIso15693UidLen);
  }
  *offset_out = offset;
  return true;
}

static bool raw_type5_read_span_allowed(uint16_t block, uint16_t byte_len) {
  reader_tag_type5_info_t type5;

  if ((byte_len == 0u) || !reader_tags_get_type5_info(&type5) || !type5.cc_valid ||
      !type5.read_access_open) {
    return false;
  }
  return storage_type5_read_span_ok(&type5, block, byte_len);
}

static bool raw_type5_read_command_allowed(const uint8_t *tx, uint16_t tx_len, bool extended,
                                           bool multiple) {
  uint16_t offset = 0u;
  uint16_t block = 0u;
  uint16_t count = 1u;

  if (!raw_type5_block_payload_offset(tx, tx_len, &offset)) {
    return false;
  }
  if (extended) {
    const uint16_t field_len =
      multiple ? (uint16_t)kIso15693ExtMultipleBlockFieldLen : (uint16_t)kIso15693ExtBlockFieldLen;
    uint8_t field[kIso15693ExtMultipleBlockFieldLen];
    if (!nero_nfc_span_ok(offset, field_len, tx_len) || tx_len != (uint16_t)(offset + field_len) ||
        !nero_nfc_copy_bytes(field, sizeof(field), 0u, tx + offset, field_len)) {
      return false;
    }
    block =
      (uint16_t)((uint16_t)field[0] | ((uint16_t)field[1] << NFC_ISO7816_U16_HIGH_BYTE_SHIFT));
    if (multiple) {
      const uint16_t count_field = (uint16_t)((uint16_t)field[kIso15693ExtCountLsbRelOffset] |
                                              ((uint16_t)field[kIso15693ExtCountMsbRelOffset]
                                               << NFC_ISO7816_U16_HIGH_BYTE_SHIFT));
      if (count_field == UINT16_MAX) {
        return false;
      }
      count = (uint16_t)(count_field + 1u);
    }
  } else {
    const uint16_t field_len = multiple ? (uint16_t)kIso15693ShortMultipleBlockFieldLen
                                        : (uint16_t)kIso15693ShortBlockFieldLen;
    uint8_t field[kIso15693ShortMultipleBlockFieldLen];
    if (!nero_nfc_span_ok(offset, field_len, tx_len) || tx_len != (uint16_t)(offset + field_len) ||
        !nero_nfc_copy_bytes(field, sizeof(field), 0u, tx + offset, field_len)) {
      return false;
    }
    block = field[0];
    if (multiple) {
      count = (uint16_t)(field[1] + 1u);
    }
  }
  if (multiple && (count > (uint16_t)NFC_TAG_T5T_ISO15693_READ_MULTIPLE_BLOCKS_MAX)) {
    return false;
  }
  if (count > (uint16_t)(UINT16_MAX / NFC_STORAGE_TYPE5_BLOCK_SIZE)) {
    return false;
  }
  return raw_type5_read_span_allowed(block,
                                     (uint16_t)(count * (uint16_t)NFC_STORAGE_TYPE5_BLOCK_SIZE));
}

bool reader_ccid_type2_raw_transceive_allowed(const uint8_t *tx, uint16_t tx_len) {
  reader_tag_type2_info_t type2;

  if ((tx == NERO_NFC_NULL) || (tx_len == 0u) || (g_tag_kind != READER_TAG_KIND_TYPE2)) {
    return false;
  }
  switch (tx[0]) {
  case CCID_RAW_T2_CMD_READ:
    if ((tx_len != (uint16_t)NFC_TAG_T2T_READ_CMD_LEN) ||
        !reader_tags_get_type2_storage_info(&type2) || !type2.cc_valid || !type2.read_access_open) {
      return false;
    }
    return storage_type2_read_span_ok(&type2, tx[1], NFC_TAG_T2T_READ_RESP_BYTES);
  case CCID_RAW_T2_CMD_FAST_READ: {
    uint16_t len;
    const uint16_t first_page = tx[1];
    const uint16_t last_page = tx[kType2RawFastReadLastPageOffset];
    if ((tx_len != (uint16_t)NFC_TAG_T2T_FAST_READ_CMD_LEN) || (last_page < first_page) ||
        !reader_tags_get_type2_storage_info(&type2) || !type2.cc_valid || !type2.read_access_open) {
      return false;
    }
    const uint16_t page_count = (uint16_t)((last_page - first_page) + 1);
    len = (uint16_t)(page_count * (uint16_t)NFC_TAG_T2T_PAGE_SIZE_BYTES);
    return storage_type2_read_span_ok(&type2, first_page, len);
  }
  case CCID_RAW_T2_CMD_GET_VERSION:
    return tx_len == (uint16_t)NFC_TAG_T2T_GET_VERSION_CMD_LEN;
  case CCID_RAW_T2_CMD_READ_SIG:
    return tx_len == (uint16_t)kType2RawReadSigCmdLen;
  default:
    return false;
  }
}

bool reader_ccid_type5_raw_transceive_allowed(const uint8_t *tx, uint16_t tx_len) {
  if ((tx == NERO_NFC_NULL) || (tx_len < kIso15693HeaderLen) ||
      (g_tag_kind != READER_TAG_KIND_TYPE5)) {
    return false;
  }
  switch (tx[1]) {
  case CCID_RAW_T5_CMD_INVENTORY:
    return tx_len >= kIso15693HeaderLen;
  case NFC_TAG_T5T_ISO15693_CMD_READ_SINGLE:
    return raw_type5_read_command_allowed(tx, tx_len, false, false);
  case NFC_TAG_T5T_ISO15693_CMD_READ_MULTIPLE:
  case CCID_RAW_T5_CMD_GET_MULTIPLE_BLOCK_SECURITY_STATUS:
    return raw_type5_read_command_allowed(tx, tx_len, false, true);
  case NFC_TAG_T5T_ISO15693_CMD_EXT_READ_SINGLE:
    return raw_type5_read_command_allowed(tx, tx_len, true, false);
  case NFC_TAG_T5T_ISO15693_CMD_EXT_READ_MULTIPLE:
  case CCID_RAW_T5_CMD_EXT_GET_MULTIPLE_BLOCK_SECURITY_STATUS:
    return raw_type5_read_command_allowed(tx, tx_len, true, true);
  case NFC_TAG_T5T_ISO15693_CMD_GET_SYS_INFO:
    return raw_type5_fixed_command_allowed(tx, tx_len, (uint16_t)kIso15693HeaderLen);
  case NFC_TAG_T5T_ISO15693_CMD_EXT_GET_SYS_INFO:
    return raw_type5_fixed_command_allowed(tx, tx_len, (uint16_t)(kIso15693HeaderLen + 1u));
  default:
    return false;
  }
}

static uint16_t storage_read_binary_remaining_bytes(uint16_t offset) {
  uint16_t total = 0u;

  if (g_tag_kind == READER_TAG_KIND_TYPE2) {
    reader_tag_type2_info_t type2;
    uint16_t byte_offset = 0u;
    if (!reader_tags_get_type2_storage_info(&type2) || !type2.cc_valid || !type2.read_access_open) {
      return 0u;
    }
    if (offset < (uint16_t)NFC_STORAGE_TYPE2_CC_PAGE) {
      return 0u;
    }
    if (!nero_nfc_try_add_u16((uint16_t)NFC_TAG_T2T_PAGE_SIZE_BYTES, type2.data_area_size_bytes,
                              &total)) {
      return 0u;
    }
    offset = (uint16_t)(offset - (uint16_t)NFC_STORAGE_TYPE2_CC_PAGE);
    if (offset > (uint16_t)(UINT16_MAX / NFC_TAG_T2T_PAGE_SIZE_BYTES)) {
      return 0u;
    }
    byte_offset = (uint16_t)(offset * (uint16_t)NFC_TAG_T2T_PAGE_SIZE_BYTES);
    offset = byte_offset;
  } else if (g_tag_kind == READER_TAG_KIND_TYPE5) {
    reader_tag_type5_info_t type5;

    if (!reader_tags_get_type5_info(&type5) || !type5.cc_valid || !type5.read_access_open) {
      return 0u;
    }
    const uint16_t cc_bytes = reader_tags_type5_cc_byte_len(&type5);
    if (cc_bytes == 0u) {
      return 0u;
    }
    if (!nero_nfc_try_add_u16(cc_bytes, type5.data_area_size_bytes, &total)) {
      return 0u;
    }
    if (offset > (uint16_t)(UINT16_MAX / ST25_T5_USER_BLOCK_SIZE)) {
      return 0u;
    }
    offset = (uint16_t)(offset * ST25_T5_USER_BLOCK_SIZE);
  } else {
    return 0u;
  }
  if (offset >= total) {
    return 0u;
  }
  return (uint16_t)(total - offset);
}

uint16_t reader_ccid_handle_read_binary_apdu(const uint8_t *apdu, uint16_t apdu_len, uint8_t *rsp,
                                             uint16_t rsp_cap) {
  uint16_t offset;
  uint16_t req_len;
  size_t rsp_need = 0u;
  int rlen;
  uint8_t le = 0u;

  if ((apdu == NERO_NFC_NULL) || (rsp == NERO_NFC_NULL) ||
      (rsp_cap < (uint16_t)NFC_ISO7816_SW_LEN)) {
    return 0u;
  }
  if (!storage_read_binary_fields(apdu, apdu_len, &offset, &le)) {
    return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_LENGTH_ALT,
                                     (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  }
  if (le == 0u) {
    const uint16_t remaining = storage_read_binary_remaining_bytes(offset);
    req_len = (remaining != 0u) ? remaining : (uint16_t)kIso7816ShortLeZeroBytes;
    if (req_len > (uint16_t)kIso7816ShortLeZeroBytes) {
      req_len = (uint16_t)kIso7816ShortLeZeroBytes;
    }
  } else {
    req_len = (uint16_t)le;
  }
  if (!nero_nfc_try_add_size((size_t)req_len, (size_t)NFC_ISO7816_SW_LEN, &rsp_need) ||
      (rsp_need > (size_t)rsp_cap)) {
    req_len = (uint16_t)(rsp_cap - (uint16_t)NFC_ISO7816_SW_LEN);
  }
  if (g_tag_kind == READER_TAG_KIND_TYPE2) {
    reader_tag_type2_info_t type2;
    if (!reader_tags_get_type2_storage_info(&type2) || !type2.cc_valid) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                       (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
    }
    if (!type2.read_access_open) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap,
                                       (uint8_t)NFC_ISO7816_SW1_CONDITIONS_NOT_SATISFIED,
                                       (uint8_t)NFC_ISO7816_SW2_CONDITIONS_NOT_SATISFIED);
    }
    if (!storage_type2_read_span_ok(&type2, offset, req_len)) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_P1P2,
                                       (uint8_t)NFC_ISO7816_SW2_SUCCESS);
    }
    rlen = reader_tags_type2_read_binary(offset, rsp, req_len);
  } else if (g_tag_kind == READER_TAG_KIND_TYPE5) {
    reader_tag_type5_info_t type5;
    if (!reader_tags_get_type5_info(&type5) || !type5.cc_valid) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                       (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
    }
    if (!type5.read_access_open) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap,
                                       (uint8_t)NFC_ISO7816_SW1_CONDITIONS_NOT_SATISFIED,
                                       (uint8_t)NFC_ISO7816_SW2_CONDITIONS_NOT_SATISFIED);
    }
    if (!storage_type5_read_span_ok(&type5, offset, req_len)) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_P1P2,
                                       (uint8_t)NFC_ISO7816_SW2_SUCCESS);
    }
    rlen = reader_tags_type5_read_binary(offset, rsp, req_len);
  } else {
    return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                     (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
  }
  if (rlen < 0) {
    return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_VERIFICATION_FAILED,
                                     (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  }
  return reader_ccid_append_success_status(rsp, (uint16_t)rlen, rsp_cap);
}

uint16_t reader_ccid_handle_update_binary_apdu(const uint8_t *apdu, uint16_t apdu_len, uint8_t *rsp,
                                               uint16_t rsp_cap) {
  uint16_t offset;
  uint8_t lc;
  const uint8_t *data = NERO_NFC_NULL;
  bool ok = false;

  if ((apdu == NERO_NFC_NULL) || (rsp == NERO_NFC_NULL) ||
      (rsp_cap < (uint16_t)NFC_ISO7816_SW_LEN)) {
    return 0u;
  }
  if (!nfc_iso7816_apdu_update_binary(apdu, apdu_len, &offset, &lc, &data)) {
    return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_LENGTH_ALT,
                                     (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  }
  if (!storage_update_binary_offset(apdu, apdu_len, offset, &offset)) {
    return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_P1P2,
                                     (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  }
  /*
   * Type 2 page addressing is single-byte (offset 0..0xFF, [T2T-ISO14443-A]
   * section 5.1); reject any wider offset that a Type 4 UPDATE BINARY APDU
   * might carry.
   */
  if ((g_tag_kind == READER_TAG_KIND_TYPE2) && (offset > NFC_BYTE_VALUE_MAX)) {
    return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_P1P2,
                                     (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  }
  if (g_tag_kind == READER_TAG_KIND_TYPE2) {
    reader_tag_type2_info_t type2;
    if (!reader_tags_get_type2_storage_info(&type2) || !type2.cc_valid) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                       (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
    }
    if (!type2.write_access_open) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap,
                                       (uint8_t)NFC_ISO7816_SW1_CONDITIONS_NOT_SATISFIED,
                                       (uint8_t)NFC_ISO7816_SW2_CONDITIONS_NOT_SATISFIED);
    }
    if (!storage_type2_update_span_ok(&type2, offset, lc)) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_P1P2,
                                       (uint8_t)NFC_ISO7816_SW2_SUCCESS);
    }
    ok = true;
    for (uint8_t off = 0u; off < lc; off = (uint8_t)(off + NFC_STORAGE_TYPE2_UNIT_SIZE)) {
      const uint16_t page = (uint16_t)(offset + (off / NFC_STORAGE_TYPE2_UNIT_SIZE));
      if ((page > NFC_BYTE_VALUE_MAX) || !reader_tags_type2_write_page((uint8_t)page, data + off)) {
        ok = false;
        break;
      }
    }
  } else if (g_tag_kind == READER_TAG_KIND_TYPE5) {
    reader_tag_type5_info_t type5;
    if (!reader_tags_get_type5_info(&type5) || !type5.cc_valid) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                       (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
    }
    if (!type5.write_access_open) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap,
                                       (uint8_t)NFC_ISO7816_SW1_CONDITIONS_NOT_SATISFIED,
                                       (uint8_t)NFC_ISO7816_SW2_CONDITIONS_NOT_SATISFIED);
    }
    if ((offset == 0u) && (lc == (uint8_t)NFC_TAG_T5T_CC_LEN_SHORT)) {
      nfc_tag_type5_info_t new_cc;
      nero_nfc_zero_bytes(&new_cc, sizeof(new_cc));
      nfc_tag_type5_apply_cc(&new_cc, data, lc);
      if (!new_cc.cc_valid) {
        return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                         (uint8_t)NFC_ISO7816_SW2_SUCCESS);
      }
      ok = reader_tags_type5_write_block(0u, data, lc);
      return reader_ccid_append_status(rsp, 0u, rsp_cap,
                                       ok ? (uint8_t)NFC_ISO7816_SW1_SUCCESS
                                          : (uint8_t)NFC_ISO7816_SW1_VERIFICATION_FAILED,
                                       (uint8_t)NFC_ISO7816_SW2_SUCCESS);
    }
    if (!storage_type5_update_span_ok(&type5, offset, lc)) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_P1P2,
                                       (uint8_t)NFC_ISO7816_SW2_SUCCESS);
    }
    ok = true;
    for (uint8_t off = 0u; off < lc; off = (uint8_t)(off + NFC_STORAGE_TYPE5_BLOCK_SIZE)) {
      if (!reader_tags_type5_write_block((uint16_t)(offset + (off / NFC_STORAGE_TYPE5_BLOCK_SIZE)),
                                         data + off, NFC_STORAGE_TYPE5_BLOCK_SIZE)) {
        ok = false;
        break;
      }
    }
  } else {
    return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_DATA,
                                     (uint8_t)NFC_ISO7816_SW2_FUNC_NOT_SUPPORTED);
  }
  return reader_ccid_append_status(rsp, 0u, rsp_cap,
                                   ok ? (uint8_t)NFC_ISO7816_SW1_SUCCESS
                                      : (uint8_t)NFC_ISO7816_SW1_VERIFICATION_FAILED,
                                   (uint8_t)NFC_ISO7816_SW2_SUCCESS);
}

#endif /* NERO_CCID_USB_BUILD */
