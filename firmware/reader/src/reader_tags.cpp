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

#include "reader_tags.h"
#include "reader_tags_internal.h"

#include "nfc_frontend.h"
#include "nfc_ndef_tlv.h"
#include "nfc_pcsc_contactless.h"
#include "nero_nfc_mem_util.h"
#include "nfc_storage_ndef.h"
#include "nfc_tag_geometry_limits.h"
#include "reader_context.h"
#include "reader_frontend.h"
#include "reader_hal.h"
#include "reader_output.h"
#include "reader_protocol.h"

#include "reader_tags_ndef_decode.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

uint8_t reader_tags_ndef_buf[READER_NDEF_BUF_MAX];

static uint8_t g_type2_fast_read_uid[NFC_TAG_TYPEA_UID_MAX];
static uint8_t g_type2_fast_read_uid_len;
static bool g_type2_fast_read_disabled;
static uint8_t g_type5_read_multiple_uid[NFC_FRONTEND_ISO15693_UID_LEN];
static bool g_type5_read_multiple_disabled;

static void reader_tags_type2_refresh_fast_read_cache(void) {
  if ((g_type2_fast_read_uid_len == g_uid14_len) &&
      ((g_uid14_len == 0u) || (memcmp(g_type2_fast_read_uid, g_uid14, g_uid14_len) == 0))) {
    return;
  }
  g_type2_fast_read_uid_len = g_uid14_len;
  g_type2_fast_read_disabled = false;
  if (g_uid14_len != 0u) {
    (void)nero_nfc_copy_bytes(g_type2_fast_read_uid, sizeof(g_type2_fast_read_uid), 0u, g_uid14,
                              g_uid14_len);
  }
}

static bool reader_tags_type2_fast_read_allowed(void) {
  reader_tags_type2_refresh_fast_read_cache();
  return !g_type2_fast_read_disabled && (g_uid14_len != 0u) && (g_uid14[0] == NFC_TAG_MFR_CODE_NXP);
}

static void reader_tags_type5_refresh_read_multiple_cache(void) {
  if (memcmp(g_type5_read_multiple_uid, g_uid15, NFC_FRONTEND_ISO15693_UID_LEN) == 0) {
    return;
  }
  g_type5_read_multiple_disabled = false;
  (void)nero_nfc_copy_bytes(g_type5_read_multiple_uid, sizeof(g_type5_read_multiple_uid), 0u,
                            g_uid15, NFC_FRONTEND_ISO15693_UID_LEN);
}

static bool reader_tags_type5_read_multiple_allowed(void) {
  reader_tags_type5_refresh_read_multiple_cache();
  return !g_type5_read_multiple_disabled;
}

static int reader_tags_type2_get_version(uint8_t *out, uint8_t out_cap) {
  const uint8_t cmd[1] = {NFC_FRONTEND_NTAG_CMD_GET_VERSION};
  uint8_t scratch[NFC_TAG_NTAG_GET_VERSION_RX_BUF_MAX];
  uint8_t *dst = (out != NERO_NFC_NULL) ? out : scratch;
  uint8_t cap = (out != NERO_NFC_NULL) ? out_cap : (uint8_t)sizeof(scratch);
  int ver_len = reader_protocol_transceive14(cmd, NFC_TAG_T2T_GET_VERSION_CMD_LEN, dst, cap, true,
                                             NFC_TAG_T2T_READ_TIMEOUT_MS, false, false);

  if (ver_len < (int)NFC_TAG_NTAG_VER_REPLY_LEN) {
    (void)reader_protocol_activate_iso14443a();
  }
  return ver_len;
}

static int reader_tags_type2_read_signature(uint8_t *out, uint8_t out_cap) {
  const uint8_t cmd[NFC_TAG_T2T_READ_CMD_LEN] = {NFC_FRONTEND_NTAG_CMD_READ_SIG, 0x00u};
  int sig_len = reader_protocol_transceive14(cmd, sizeof(cmd), out, out_cap, true,
                                             NFC_TAG_T2T_READ_SIG_TIMEOUT_MS, false, false);
  if (sig_len < (int)NFC_TAG_NTAG_SIG_REPLY_LEN) {
    (void)reader_protocol_activate_iso14443a();
  }
  return sig_len;
}
/*
 * [T5T-ISO15693] section 10.3.4 — addressed Get System Info (command 0x2B).
 * Response is parsed by nfc_tag_type5_apply_system_info() in nfc_tag_info.h.
 */
static int reader_tags_iso15693_get_system_info_raw(uint8_t *buf, uint8_t buf_cap) {
  uint8_t cmd[NFC_TAG_T5T_ISO15693_CMD_BUF_MAX];
  uint8_t n = 0u;

  if ((buf == NERO_NFC_NULL) || (buf_cap == 0u) ||
      !nero_nfc_span_ok(
        0u, NFC_TAG_T5T_ISO15693_SYS_INFO_CMD_HEADER_LEN + NFC_FRONTEND_ISO15693_UID_LEN,
        sizeof(cmd))) {
    return -1;
  }

  if (!nero_nfc_span_ok((size_t)n, 1u, sizeof(cmd))) {
    return -1;
  }
  cmd[n++] = NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED;
  if (!nero_nfc_span_ok((size_t)n, 1u, sizeof(cmd))) {
    return -1;
  }
  cmd[n++] = NFC_TAG_T5T_ISO15693_CMD_GET_SYS_INFO;
  for (uint8_t i = 0u; i < NFC_FRONTEND_ISO15693_UID_LEN; i++) {
    if (!nero_nfc_span_ok((size_t)n, 1u, sizeof(cmd))) {
      return -1;
    }
    cmd[n++] = g_uid15[NFC_FRONTEND_ISO15693_UID_LEN - 1u - i];
  }
  return reader_protocol_iso15693_transceive(cmd, n, buf, buf_cap,
                                             NFC_TAG_T5T_ISO15693_TRANSCEIVE_TIMEOUT_MS);
}

/*
 * [T5T-ISO15693] section 10.3.4 / [T5T-ISO15693-ST25DV] section 7.6.23 — Extended Get System Info
 * (command 0x3B). Used when [T5T-ISO15693] section 4.3.1.17 MLEN-overflow is signaled
 * in the CC, because standard Get System Info cannot report more than 256 blocks.
 */
static int reader_tags_iso15693_get_system_info_ext_raw(uint8_t *buf, uint8_t buf_cap) {
  uint8_t cmd[NFC_TAG_T5T_ISO15693_CMD_BUF_MAX];
  uint8_t n = 0u;

  if ((buf == NERO_NFC_NULL) || (buf_cap == 0u) ||
      !nero_nfc_span_ok(0u,
                        NFC_TAG_ST25DV_EXT_SYS_INFO_CMD_HEADER_LEN + NFC_FRONTEND_ISO15693_UID_LEN,
                        sizeof(cmd))) {
    return -1;
  }
  cmd[n++] =
    (uint8_t)(NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED | NFC_TAG_T5T_ISO15693_FLAG_PROTOCOL_EXTENSION);
  cmd[n++] = NFC_TAG_T5T_ISO15693_CMD_EXT_GET_SYS_INFO;
  cmd[n++] = NFC_TAG_ST25DV_EXT_SYS_INFO_REQUEST_FIELDS;
  for (uint8_t i = 0u; i < NFC_FRONTEND_ISO15693_UID_LEN; i++) {
    if (!nero_nfc_span_ok((size_t)n, 1u, sizeof(cmd))) {
      return -1;
    }
    cmd[n++] = g_uid15[NFC_FRONTEND_ISO15693_UID_LEN - 1u - i];
  }
  return reader_protocol_iso15693_transceive(cmd, n, buf, buf_cap,
                                             NFC_TAG_T5T_ISO15693_TRANSCEIVE_TIMEOUT_MS);
}

static bool reader_tags_type2_last_page(const reader_tag_type2_info_t *type2,
                                        uint16_t *last_page_out) {
  if (last_page_out != NERO_NFC_NULL) {
    *last_page_out = 0u;
  }
  if ((type2 == NERO_NFC_NULL) || (last_page_out == NERO_NFC_NULL) || !type2->cc_valid ||
      (type2->data_area_size_bytes == 0u)) {
    return false;
  }
  return nfc_storage_type2_last_page(type2->data_area_size_bytes, last_page_out);
}

static bool reader_tags_type2_read_cap(const reader_tag_type2_info_t *type2, uint16_t *cap_out) {
  uint16_t last_page;
  uint16_t pages;

  if (cap_out != NERO_NFC_NULL) {
    *cap_out = 0u;
  }
  if ((cap_out == NERO_NFC_NULL) || !reader_tags_type2_last_page(type2, &last_page) ||
      (last_page < NFC_TAG_T2T_CC_PAGE_INDEX)) {
    return false;
  }
  pages = (uint16_t)(last_page - NFC_TAG_T2T_CC_PAGE_INDEX + 1u);
  *cap_out = (uint16_t)(pages * NFC_TAG_T2T_PAGE_SIZE_BYTES);
  return true;
}

bool reader_tags_iso15693_inventory_step(void) {
  return reader_tags_iso15693_inventory_step_impl();
}

extern "C" bool reader_tags_get_typea_info(reader_tag_typea_info_t *info) {
  if (info == NERO_NFC_NULL || g_uid14_len == 0u) {
    return false;
  }

  nero_nfc_zero_bytes(info, sizeof(*info));
  if (!nero_nfc_copy_bytes(info->uid, sizeof(info->uid), 0u, g_uid14, g_uid14_len)) {
    return false;
  }
  info->uid_len = g_uid14_len;
  info->sak = g_sak;
  info->atqa_valid = g_atqa_valid;
  if (g_atqa_valid) {
    info->atqa[0] = g_atqa[0];
    info->atqa[1] = g_atqa[1];
  }
  if ((g_ats_len != 0u) &&
      !nero_nfc_copy_bytes(info->ats, sizeof(info->ats), 0u, g_ats_data, g_ats_len)) {
    return false;
  }
  info->ats_len = g_ats_len;
  return true;
}

extern "C" bool reader_tags_get_type2_info(reader_tag_type2_info_t *info) {
  uint8_t page3[NFC_TAG_T2T_READ_RESP_BYTES];
  int page_len;
  int version_len;

  if (info == NERO_NFC_NULL || g_uid14_len == 0u ||
      ((g_sak & NFC_TAG_T4T_SAK_ISO14443_4_BIT) != 0u)) {
    return false;
  }

  nero_nfc_zero_bytes(info, sizeof(*info));
  version_len = reader_tags_type2_get_version(info->version, (uint8_t)sizeof(info->version));
  if (version_len > 0) {
    info->version_len =
      (uint8_t)((version_len > (int)NFC_TAG_NTAG_VER_REPLY_LEN) ? (int)NFC_TAG_NTAG_VER_REPLY_LEN
                                                                : version_len);
    nfc_tag_type2_apply_version(info, info->version, info->version_len);
  }
  page_len = reader_tags_ntag_read_page(NFC_TAG_T2T_CC_PAGE_INDEX, page3);
  if (page_len >= (int)NFC_TAG_T2T_PAGE_SIZE_BYTES) {
    nfc_tag_type2_apply_cc(info, page3, NFC_TAG_T2T_PAGE_SIZE_BYTES);
  }
  if ((info->family == NFC_TAG_TYPE2_FAMILY_UNKNOWN) && (g_uid14_len != 0u) &&
      (g_uid14[0] == NFC_TAG_MFR_CODE_ST) && info->cc_valid &&
      (info->cc[0] == NFC_FORUM_CC_MAGIC)) {
    nfc_tag_type2_apply_family_hint(info, NFC_TAG_TYPE2_FAMILY_ST25TN);
  }
  if (info->family == NFC_TAG_TYPE2_FAMILY_NTAG21X) {
    uint8_t signature[NFC_TAG_NTAG_SIG_REPLY_LEN];
    int sig_len = reader_tags_type2_read_signature(signature, sizeof(signature));

    if (sig_len >= (int)sizeof(signature)) {
      nfc_tag_type2_apply_signature(info, signature, (uint8_t)sizeof(signature));
    }
    if (info->max_user_page != 0u) {
      uint8_t cfg[NFC_TAG_T2T_READ_RESP_BYTES];
      uint8_t auth0_page = (uint8_t)(info->max_user_page + NFC_TAG_NTAG_AUTH0_PAGE_OFFSET);
      int cfg_len = reader_tags_ntag_read_page(auth0_page, cfg);
      if (cfg_len >= (int)NFC_TAG_T2T_PAGE_SIZE_BYTES) {
        nfc_tag_type2_apply_auth0(info, cfg[NFC_TAG_NTAG_CFG_AUTH0_BYTE_INDEX]);
      }
    }
  }
  return true;
}

extern "C" bool reader_tags_get_type2_storage_info(reader_tag_type2_info_t *info) {
  uint8_t page3[NFC_TAG_T2T_READ_RESP_BYTES];
  int page_len;

  if (info == NERO_NFC_NULL || g_uid14_len == 0u ||
      ((g_sak & NFC_TAG_T4T_SAK_ISO14443_4_BIT) != 0u)) {
    return false;
  }

  nero_nfc_zero_bytes(info, sizeof(*info));
  page_len = reader_tags_ntag_read_page(NFC_TAG_T2T_CC_PAGE_INDEX, page3);
  if (page_len < (int)NFC_TAG_T2T_PAGE_SIZE_BYTES) {
    return false;
  }
  nfc_tag_type2_apply_cc(info, page3, NFC_TAG_T2T_PAGE_SIZE_BYTES);
  if ((info->family == NFC_TAG_TYPE2_FAMILY_UNKNOWN) && (g_uid14_len != 0u) &&
      (g_uid14[0] == NFC_TAG_MFR_CODE_ST) && info->cc_valid &&
      (info->cc[0] == NFC_FORUM_CC_MAGIC)) {
    nfc_tag_type2_apply_family_hint(info, NFC_TAG_TYPE2_FAMILY_ST25TN);
  }
  return info->cc_valid;
}

extern "C" bool reader_tags_get_type4_info(reader_tag_type4_info_t *info) {
  uint8_t ndef_file_hi = 0u;
  uint8_t ndef_file_lo = 0u;

  if (info == NERO_NFC_NULL || g_uid14_len == 0u ||
      ((g_sak & NFC_TAG_T4T_SAK_ISO14443_4_BIT) == 0u)) {
    return false;
  }
  return reader_tags_type4_load_info(info, &ndef_file_hi, &ndef_file_lo, false);
}

extern "C" bool reader_tags_get_type5_info(reader_tag_type5_info_t *info) {
  uint8_t sys_info[NFC_TAG_T5T_SYS_INFO_RAW_FIELD_MAX];
  uint8_t page0[NFC_TAG_T5T_CC_LEN_SHORT];
  int sys_len;
  int page_len;

  if (info == NERO_NFC_NULL) {
    return false;
  }
  nero_nfc_zero_bytes(info, sizeof(*info));
  page_len = reader_tags_iso15693_user_read(0u, page0, sizeof(page0));
  if (page_len >= (int)NFC_TAG_T5T_CC_LEN_SHORT) {
    uint8_t cc[NFC_TAG_T5T_CC_LEN_EXTENDED];
    const bool ndef_magic =
      (page0[0] == NFC_FORUM_CC_MAGIC) || (page0[0] == NFC_T5T_CC_MAGIC_8BYTE);
    const uint16_t declared_cc_len =
      nfc_storage_type5_declared_cc_len_from_first_block(page0, (uint16_t)sizeof(page0));
    if (!nero_nfc_copy_bytes(cc, sizeof(cc), 0u, page0, sizeof(page0))) {
      return false;
    }
    if (ndef_magic && declared_cc_len == (uint16_t)NFC_TAG_T5T_CC_LEN_EXTENDED) {
      uint8_t page1[NFC_TAG_T5T_CC_LEN_SHORT];
      int page1_len = reader_tags_iso15693_user_read(1u, page1, sizeof(page1));
      if (page1_len >= (int)NFC_TAG_T5T_CC_LEN_SHORT &&
          nero_nfc_copy_bytes(cc, sizeof(cc), NFC_TAG_T5T_CC_LEN_SHORT, page1, sizeof(page1))) {
        nfc_tag_type5_apply_cc(info, cc, sizeof(cc));
      } else {
        nfc_tag_type5_apply_cc(info, cc, sizeof(page0));
      }
    } else {
      nfc_tag_type5_apply_cc(info, cc, sizeof(page0));
    }
  }

  sys_len = reader_tags_iso15693_get_system_info_raw(sys_info, sizeof(sys_info));
  if (sys_len < (int)NFC_TAG_T5T_ISO15693_SYS_INFO_MIN_REPLY_LEN ||
      (sys_info[0] & NFC_TAG_T5T_ISO15693_RESP_FLAG_ERROR) != 0u) {
    return true;
  }
  nfc_tag_type5_apply_system_info(
    info, sys_info, (uint8_t)((sys_len > (int)sizeof(info->raw)) ? sizeof(info->raw) : sys_len));

  if (nfc_tag_type5_cc_signals_mlen_overflow(info)) {
    uint8_t ext_info[NFC_TAG_T5T_ISO15693_SYS_INFO_RAW_BUF_MAX];
    int ext_len = reader_tags_iso15693_get_system_info_ext_raw(ext_info, sizeof(ext_info));
    if ((ext_len >= (int)NFC_TAG_ST25DV_EXT_SYS_INFO_MIN_REPLY_LEN) &&
        ((ext_info[0] & NFC_TAG_T5T_ISO15693_RESP_FLAG_ERROR) == 0u)) {
      nfc_tag_type5_apply_system_info_ext(
        info, ext_info,
        (uint8_t)((ext_len > (int)sizeof(info->raw)) ? sizeof(info->raw) : ext_len));
    }
  }
  nfc_tag_type5_resolve_mlen_overflow(info);
  return true;
}

extern "C" bool reader_tags_get_tag_info(reader_tag_info_t *info) {
  if (info == NERO_NFC_NULL) {
    return false;
  }
  nero_nfc_zero_bytes(info, sizeof(*info));
  if ((g_uid14_len != 0u) && ((g_sak & NFC_TAG_T4T_SAK_ISO14443_4_BIT) == 0u)) {
    info->kind = NFC_TAG_KIND_TYPE2;
    return reader_tags_get_typea_info(&info->common.typea) &&
           reader_tags_get_type2_info(&info->detail.type2);
  }
  if ((g_uid14_len != 0u) && ((g_sak & NFC_TAG_T4T_SAK_ISO14443_4_BIT) != 0u)) {
    info->kind = NFC_TAG_KIND_TYPE4;
    return reader_tags_get_typea_info(&info->common.typea) &&
           reader_tags_get_type4_info(&info->detail.type4);
  }
  if (g_uid15[0] != 0u) {
    info->kind = NFC_TAG_KIND_TYPE5;
    return nero_nfc_copy_bytes(info->common.type5_uid, sizeof(info->common.type5_uid), 0u, g_uid15,
                               NFC_FRONTEND_ISO15693_UID_LEN) &&
           reader_tags_get_type5_info(&info->detail.type5);
  }
  return false;
}

typedef bool (*reader_tags_storage_write_unit_fn_t)(uint16_t unit, const uint8_t *data,
                                                    uint8_t data_len);

static bool reader_tags_write_storage_tlv_units(const uint8_t *tlv, uint16_t tlv_len,
                                                uint16_t first_unit, uint8_t unit_size,
                                                reader_tags_storage_write_unit_fn_t write_unit) {
  uint16_t units_needed = 0u;

  if ((tlv == NERO_NFC_NULL) || (unit_size == 0u) || (unit_size > NFC_STORAGE_TYPE5_BLOCK_SIZE) ||
      (write_unit == NERO_NFC_NULL) ||
      !nfc_storage_ceil_units_u16(tlv_len, unit_size, &units_needed) || (units_needed == 0u)) {
    return false;
  }
  for (uint16_t unit_index = 0u; unit_index < units_needed; unit_index++) {
    uint8_t unit_data[NFC_STORAGE_TYPE5_BLOCK_SIZE] = {0u, 0u, 0u, 0u};
    const uint16_t off = (uint16_t)(unit_index * unit_size);
    const uint16_t left = (uint16_t)(tlv_len - off);
    const uint16_t chunk = (left > unit_size) ? unit_size : left;
    const uint16_t unit = (uint16_t)(first_unit + unit_index);

    if (((chunk != 0u) &&
         !nero_nfc_copy_bytes(unit_data, sizeof(unit_data), 0u, tlv + off, chunk)) ||
        !write_unit(unit, unit_data, unit_size)) {
      return false;
    }
  }
  return true;
}

static bool reader_tags_type2_write_unit(uint16_t unit, const uint8_t *data, uint8_t data_len) {
  if ((data == NERO_NFC_NULL) || (data_len != NFC_STORAGE_TYPE2_UNIT_SIZE) || (unit > UINT8_MAX)) {
    return false;
  }
  return reader_tags_type2_write_page((uint8_t)unit, data);
}

static bool reader_tags_type5_write_unit(uint16_t unit, const uint8_t *data, uint8_t data_len) {
  return reader_tags_type5_write_block(unit, data, data_len);
}

extern "C" int reader_tags_load_type2_ndef_message(uint8_t *dst, uint16_t dst_cap) {
  reader_tag_type2_info_t type2;
  uint8_t raw[READER_TYPE2_RAW_READ_MAX];
  uint16_t raw_len;
  uint16_t raw_cap;
  int got;
  nfc_ndef_tlv_t tlv;

  if ((dst == NERO_NFC_NULL) || (dst_cap == 0u) || !reader_tags_get_type2_storage_info(&type2) ||
      !type2.cc_valid || !type2.read_access_open || (type2.data_area_size_bytes == 0u)) {
    return -1;
  }
  if (!reader_tags_type2_read_cap(&type2, &raw_cap) ||
      !nero_nfc_try_add_u16(READER_TYPE2_CC_PREFIX_BYTES, type2.data_area_size_bytes, &raw_len)) {
    return -1;
  }
  if (raw_len > sizeof(raw)) {
    raw_len = (uint16_t)sizeof(raw);
  }
  if (raw_len > raw_cap) {
    raw_len = raw_cap;
  }
  got = reader_tags_type2_read_binary(NFC_TAG_T2T_CC_PAGE_INDEX, raw, raw_len);
  if (got < (int)NFC_TAG_T2T_PAGE_SIZE_BYTES) {
    return -1;
  }
  if (nfc_ndef_find_message_tlv(raw, (uint16_t)got, READER_TYPE2_CC_PREFIX_BYTES, &tlv) !=
      NFC_NDEF_TLV_OK) {
    return -1;
  }
  if (tlv.value_len > dst_cap) {
    return -1;
  }
  if ((tlv.value_len != 0u) &&
      !nero_nfc_copy_bytes(dst, dst_cap, 0u, raw + tlv.value_offset, tlv.value_len)) {
    return -1;
  }
  return (int)tlv.value_len;
}

extern "C" int reader_tags_load_type5_ndef_message(uint8_t *dst, uint16_t dst_cap) {
  reader_tag_type5_info_t type5;
  uint8_t raw[READER_NDEF_BUF_MAX];
  uint16_t cc_len;
  uint16_t raw_len;
  int got;
  nfc_ndef_tlv_t tlv;

  if ((dst == NERO_NFC_NULL) || (dst_cap == 0u) || !reader_tags_get_type5_info(&type5) ||
      !type5.cc_valid || !type5.read_access_open || (type5.data_area_size_bytes == 0u)) {
    return -1;
  }
  cc_len = reader_tags_type5_cc_byte_len(&type5);
  if (cc_len == 0u) {
    return -1;
  }
  if (!nero_nfc_try_add_u16(cc_len, type5.data_area_size_bytes, &raw_len)) {
    return -1;
  }
  if (raw_len > sizeof(raw)) {
    raw_len = (uint16_t)sizeof(raw);
  }
  got = reader_tags_type5_read_binary(0u, raw, raw_len);
  if (got < (int)cc_len) {
    return -1;
  }
  if (nfc_ndef_find_message_tlv(raw, (uint16_t)got, cc_len, &tlv) != NFC_NDEF_TLV_OK) {
    return -1;
  }
  if (tlv.value_len > dst_cap) {
    return -1;
  }
  if ((tlv.value_len != 0u) &&
      !nero_nfc_copy_bytes(dst, dst_cap, 0u, raw + tlv.value_offset, tlv.value_len)) {
    return -1;
  }
  return (int)tlv.value_len;
}

extern "C" bool reader_tags_write_type2_ndef_message(const uint8_t *ndef, uint16_t ndef_len) {
  reader_tag_type2_info_t type2;
  uint8_t tlv[READER_TYPE2_RAW_READ_MAX];
  uint16_t tlv_len = 0u;
  uint16_t last_page;
  uint16_t pages_needed;
  size_t last_page_needed = 0u;

  if (((ndef_len != 0u) && (ndef == NERO_NFC_NULL)) ||
      !reader_tags_get_type2_storage_info(&type2) || !type2.cc_valid || !type2.write_access_open ||
      (type2.data_area_size_bytes == 0u)) {
    return false;
  }
  if (!nfc_ndef_build_message_tlv(ndef, ndef_len, tlv,
                                  (uint16_t)((type2.data_area_size_bytes > sizeof(tlv))
                                               ? sizeof(tlv)
                                               : type2.data_area_size_bytes),
                                  &tlv_len)) {
    return false;
  }
  if (!nfc_storage_ceil_units_u16(tlv_len, NFC_STORAGE_TYPE2_UNIT_SIZE, &pages_needed) ||
      (pages_needed == 0u) || !reader_tags_type2_last_page(&type2, &last_page) ||
      !nero_nfc_try_add_size(READER_TYPE2_CC_PREFIX_BYTES, (size_t)pages_needed - 1u,
                             &last_page_needed) ||
      (last_page_needed > last_page)) {
    return false;
  }
  return reader_tags_write_storage_tlv_units(tlv, tlv_len, NFC_STORAGE_TYPE2_FIRST_DATA_PAGE,
                                             NFC_STORAGE_TYPE2_UNIT_SIZE,
                                             reader_tags_type2_write_unit);
}

extern "C" bool reader_tags_write_type5_ndef_message(const uint8_t *ndef, uint16_t ndef_len) {
  reader_tag_type5_info_t type5;
  uint8_t tlv[READER_NDEF_BUF_MAX];
  uint16_t tlv_len = 0u;
  uint16_t start_block;
  uint16_t blocks_needed;
  uint16_t first_data_block = 0u;
  uint16_t last_data_block = 0u;
  uint16_t cc_len;
  uint8_t block_size;

  if (((ndef_len != 0u) && (ndef == NERO_NFC_NULL)) || !reader_tags_get_type5_info(&type5) ||
      !type5.cc_valid || !type5.write_access_open || (type5.data_area_size_bytes == 0u)) {
    return false;
  }
  block_size = (type5.block_size == 0u) ? ST25_T5_USER_BLOCK_SIZE : type5.block_size;
  if (block_size != ST25_T5_USER_BLOCK_SIZE) {
    return false;
  }
  if (!nfc_ndef_build_message_tlv(ndef, ndef_len, tlv,
                                  (uint16_t)((type5.data_area_size_bytes > sizeof(tlv))
                                               ? sizeof(tlv)
                                               : type5.data_area_size_bytes),
                                  &tlv_len)) {
    return false;
  }
  cc_len = reader_tags_type5_cc_byte_len(&type5);
  if (!nfc_storage_type5_data_blocks(cc_len, type5.data_area_size_bytes, block_size,
                                     type5.block_count, &first_data_block, &last_data_block) ||
      !nfc_storage_ceil_units_u16(tlv_len, NFC_STORAGE_TYPE5_BLOCK_SIZE, &blocks_needed) ||
      (blocks_needed == 0u)) {
    return false;
  }
  start_block = first_data_block;
  if (((uint32_t)start_block + (uint32_t)blocks_needed - 1u) > last_data_block) {
    return false;
  }
  return reader_tags_write_storage_tlv_units(
    tlv, tlv_len, start_block, NFC_STORAGE_TYPE5_BLOCK_SIZE, reader_tags_type5_write_unit);
}

extern "C" int reader_tags_type2_transceive(const uint8_t *tx, uint16_t tx_len, uint8_t *rx,
                                            uint16_t rx_max) {
  int rlen;

  if ((tx == NERO_NFC_NULL) || (tx_len == 0u) || (rx == NERO_NFC_NULL) || (rx_max == 0u)) {
    return -1;
  }
  rlen = reader_protocol_transceive14(tx, tx_len, rx, rx_max, true, NFC_TAG_T2T_READ_TIMEOUT_MS,
                                      false, false);
  if ((tx[0] == NFC_FRONTEND_NTAG_CMD_GET_VERSION) && (rlen < (int)NFC_TAG_NTAG_VER_REPLY_LEN)) {
    (void)reader_protocol_activate_iso14443a();
  }
  return rlen;
}

extern "C" bool reader_tags_type2_write_page(uint8_t page, const uint8_t *data) {
  if (data == NERO_NFC_NULL) {
    return false;
  }
  for (uint8_t attempt = 0u; attempt < NFC_TAG_READER_TYPE2_WRITE_ATTEMPTS; ++attempt) {
    uint8_t verify[NFC_TAG_T2T_READ_RESP_BYTES];
    bool write_ack;

    if (attempt != 0u && !reader_protocol_activate_iso14443a()) {
      continue;
    }
    write_ack = reader_tags_ntag_write_page(page, data);
    reader_hal_delay_ms(write_ack ? NFC_TAG_T2T_WRITE_VERIFY_SETTLE_MS
                                  : NFC_TAG_T2T_WRITE_FAIL_SETTLE_MS);
    if ((reader_tags_ntag_read_page(page, verify) >= (int)NFC_TAG_T2T_PAGE_SIZE_BYTES) &&
        (memcmp(verify, data, NFC_TAG_T2T_PAGE_SIZE_BYTES) == 0)) {
      return true;
    }
    (void)reader_protocol_activate_iso14443a();
  }
  return false;
}

extern "C" int reader_tags_type2_read_binary(uint16_t page, uint8_t *buf, uint16_t len) {
  uint16_t copied = 0u;

  if ((buf == NERO_NFC_NULL) || (len == 0u)) {
    return -1;
  }
  if ((len >= (uint16_t)NFC_TAG_T2T_READ_RESP_BYTES) && (page <= (uint16_t)UINT8_MAX) &&
      reader_tags_type2_fast_read_allowed()) {
    const uint16_t pages = (uint16_t)(len / (uint16_t)NFC_TAG_T2T_PAGE_SIZE_BYTES);
    const uint16_t fast_len = (uint16_t)(pages * (uint16_t)NFC_TAG_T2T_PAGE_SIZE_BYTES);
    const uint16_t last_page = (uint16_t)(page + pages - 1u);

    if ((pages != 0u) && (last_page <= (uint16_t)UINT8_MAX)) {
      if (reader_tags_ntag_fast_read((uint8_t)page, (uint8_t)last_page, buf, fast_len) >=
          (int)fast_len) {
        copied = fast_len;
        page = (uint16_t)(page + pages);
      } else {
        g_type2_fast_read_disabled = true;
      }
    }
  }

  while (copied < len) {
    uint8_t page_buf[NFC_TAG_T2T_READ_RESP_BYTES];
    uint16_t chunk =
      (uint16_t)((len - copied) > (uint16_t)sizeof(page_buf) ? (uint16_t)sizeof(page_buf)
                                                             : (len - copied));
    int rlen;

    /* [T2T-ISO14443-A] page address is a single byte on the RF wire; refuse to read past the
     * one-byte page space instead of silently wrapping to a low (config) page. */
    if (page > (uint16_t)UINT8_MAX) {
      return (copied == 0u) ? -1 : (int)copied;
    }
    rlen = reader_tags_ntag_read_page((uint8_t)page, page_buf);

    if (rlen < (int)chunk) {
      return (copied == 0u) ? -1 : (int)copied;
    }
    if (!nero_nfc_copy_bytes(buf, len, copied, page_buf, chunk)) {
      return (copied == 0u) ? -1 : (int)copied;
    }
    copied = (uint16_t)(copied + chunk);
    page = (uint16_t)(page + NFC_TAG_T2T_READ_RESP_PAGES);
  }
  return (int)copied;
}

extern "C" int reader_tags_type5_transceive(const uint8_t *tx, uint16_t tx_len, uint8_t *rx,
                                            uint16_t rx_max) {
  if ((tx == NERO_NFC_NULL) || (tx_len == 0u) || (rx == NERO_NFC_NULL) || (rx_max == 0u)) {
    return -1;
  }
  return reader_protocol_iso15693_transceive(tx, tx_len, rx, rx_max,
                                             NFC_TAG_T5T_ISO15693_TRANSCEIVE_TIMEOUT_MS);
}

extern "C" bool reader_tags_type5_write_block(uint16_t block, const uint8_t *data,
                                              uint8_t data_len) {
  uint8_t verify[NFC_TAG_T5T_ISO15693_SYS_INFO_UID_FIELD_LEN];

  if ((data == NERO_NFC_NULL) || (data_len == 0u) || (data_len > sizeof(verify))) {
    return false;
  }
  if (!reader_tags_iso15693_user_write(block, data, data_len)) {
    return false;
  }
  reader_hal_delay_ms(NFC_TAG_T5T_RF_WRITE_SETTLE_MS);
  if (reader_tags_iso15693_user_read(block, verify, data_len) < (int)data_len) {
    return false;
  }
  return memcmp(verify, data, data_len) == 0;
}

extern "C" int reader_tags_type5_read_binary(uint16_t block, uint8_t *buf, uint16_t len) {
  uint16_t copied = 0u;

  if ((buf == NERO_NFC_NULL) || (len == 0u)) {
    return -1;
  }

  while (copied < len) {
    uint8_t block_buf[ST25_T5_USER_BLOCK_SIZE];
    const uint16_t full_blocks =
      (uint16_t)((len - copied) / (uint16_t)NFC_STORAGE_TYPE5_BLOCK_SIZE);
    if ((full_blocks > 1u) && reader_tags_type5_read_multiple_allowed()) {
      const uint16_t blocks =
        (full_blocks > (uint16_t)NFC_TAG_T5T_ISO15693_READ_MULTIPLE_BLOCKS_MAX)
          ? (uint16_t)NFC_TAG_T5T_ISO15693_READ_MULTIPLE_BLOCKS_MAX
          : full_blocks;
      const uint16_t chunk_len = (uint16_t)(blocks * (uint16_t)NFC_STORAGE_TYPE5_BLOCK_SIZE);

      if (nero_nfc_span_ok(copied, chunk_len, len) &&
          reader_tags_iso15693_user_read_multiple(block, blocks, buf + copied, chunk_len) >=
            (int)chunk_len) {
        copied = (uint16_t)(copied + chunk_len);
        block = (uint16_t)(block + blocks);
        continue;
      }
      g_type5_read_multiple_disabled = true;
    }
    uint16_t chunk = (uint16_t)((len - copied) > (uint16_t)ST25_T5_USER_BLOCK_SIZE
                                  ? (uint16_t)ST25_T5_USER_BLOCK_SIZE
                                  : (len - copied));
    int rlen = reader_tags_iso15693_user_read(block, block_buf, sizeof(block_buf));

    if (rlen < (int)chunk) {
      return (copied == 0u) ? -1 : (int)copied;
    }
    if (!nero_nfc_copy_bytes(buf, len, copied, block_buf, chunk)) {
      return (copied == 0u) ? -1 : (int)copied;
    }
    copied = (uint16_t)(copied + chunk);
    block++;
  }
  return (int)copied;
}

/* ── Browser auto-open (URL allow-list enforced) ──────────────── */
