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

// Minimal stubs for reader_ccid.cpp storage-tag paths during host unit tests.

#include "reader_tags.h"
#include "nero_nfc_mem_util.h"
#include "nero_nfc_null.h"
#include "nfc_storage_ndef.h"
#include "nfc_tag_info.h"
#include "reader_hal_utest.h"

static bool g_typea_valid;
static reader_tag_typea_info_t g_typea_info;
static bool g_type2_storage_valid;
static reader_tag_type2_info_t g_type2_storage_info;
static bool g_type5_info_valid;
static reader_tag_type5_info_t g_type5_info;
static bool g_type2_write_ok;
static bool g_type5_write_ok;
static uint16_t g_type2_write_count;
static uint16_t g_abort_after_type2_writes;
static uint16_t g_type5_write_count;
static uint16_t g_abort_after_type5_writes;
static uint16_t g_type5_read_count;
static uint16_t g_type5_last_read_block;
static uint16_t g_type5_last_read_len;
static uint16_t g_type2_transceive_count;
static uint16_t g_type5_transceive_count;
static uint8_t g_type2_transceive_response[NFC_TAG_NTAG_VER_REPLY_LEN];
static uint16_t g_type2_transceive_response_len;

void reader_tags_utest_reset(void) {
  g_typea_valid = false;
  nero_nfc_zero_bytes(&g_typea_info, sizeof(g_typea_info));
  g_type2_storage_valid = false;
  nero_nfc_zero_bytes(&g_type2_storage_info, sizeof(g_type2_storage_info));
  g_type5_info_valid = false;
  nero_nfc_zero_bytes(&g_type5_info, sizeof(g_type5_info));
  g_type2_write_ok = false;
  g_type5_write_ok = false;
  g_type2_write_count = 0u;
  g_abort_after_type2_writes = 0u;
  g_type5_write_count = 0u;
  g_abort_after_type5_writes = 0u;
  g_type5_read_count = 0u;
  g_type5_last_read_block = 0u;
  g_type5_last_read_len = 0u;
  g_type2_transceive_count = 0u;
  g_type5_transceive_count = 0u;
  nero_nfc_zero_bytes(g_type2_transceive_response,
                      sizeof(g_type2_transceive_response));
  g_type2_transceive_response_len = 0u;
}

void reader_tags_utest_set_typea_info(const uint8_t* uid, uint8_t uid_len,
                                      const uint8_t* atqa, uint8_t sak,
                                      const uint8_t* ats, uint8_t ats_len) {
  g_typea_valid = false;
  nero_nfc_zero_bytes(&g_typea_info, sizeof(g_typea_info));
  if ((uid == NERO_NFC_NULL) || (atqa == NERO_NFC_NULL) || (uid_len == 0u) ||
      (uid_len > NFC_TAG_TYPEA_UID_MAX) ||
      ((ats_len != 0u) && (ats == NERO_NFC_NULL)) ||
      (ats_len > NFC_ISO14443_ATS_MAX) ||
      !nero_nfc_copy_bytes(g_typea_info.uid, sizeof(g_typea_info.uid), 0u, uid,
                           uid_len) ||
      !nero_nfc_copy_bytes(g_typea_info.atqa, sizeof(g_typea_info.atqa), 0u,
                           atqa, NFC_TAG_TYPEA_ATQA_LEN)) {
    return;
  }
  g_typea_info.uid_len = uid_len;
  g_typea_info.atqa_valid = true;
  g_typea_info.sak = sak;
  if ((ats_len != 0u) &&
      !nero_nfc_copy_bytes(g_typea_info.ats, sizeof(g_typea_info.ats), 0u, ats,
                           ats_len)) {
    return;
  }
  g_typea_info.ats_len = ats_len;
  g_typea_valid = true;
}

void reader_tags_utest_set_type2_storage_info(uint16_t data_area_size,
                                              bool read_open, bool write_open) {
  g_type2_storage_valid = true;
  nero_nfc_zero_bytes(&g_type2_storage_info, sizeof(g_type2_storage_info));
  g_type2_storage_info.cc_valid = true;
  g_type2_storage_info.cc[NFC_TAG_T2T_CC_MAGIC_INDEX] = NFC_FORUM_CC_MAGIC;
  g_type2_storage_info.cc[NFC_TAG_T2T_CC_VER_INDEX] = NFC_T2T_CC_VERSION;
  g_type2_storage_info.cc[NFC_TAG_T2T_CC_MLEN_INDEX] =
      (uint8_t)(data_area_size / NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES);
  g_type2_storage_info.cc[NFC_TAG_T2T_CC_ACCESS_INDEX] = 0u;
  g_type2_storage_info.data_area_size_bytes = data_area_size;
  g_type2_storage_info.read_access_open = read_open;
  g_type2_storage_info.write_access_open = write_open;
}

void reader_tags_utest_set_type5_info(uint16_t cc_len, uint16_t data_area_size,
                                      uint16_t block_count, bool read_open,
                                      bool write_open) {
  g_type5_info_valid = true;
  nero_nfc_zero_bytes(&g_type5_info, sizeof(g_type5_info));
  g_type5_info.cc_valid = true;
  g_type5_info.cc_len = (uint8_t)cc_len;
  g_type5_info.cc[NFC_TAG_T2T_CC_MAGIC_INDEX] = NFC_FORUM_CC_MAGIC;
  g_type5_info.cc[NFC_TAG_T5T_CC_VER_ACCESS_BYTE_INDEX] = NFC_T5T_CC_VER_ACCESS;
  g_type5_info.cc[NFC_TAG_T5T_CC_MLEN_BYTE_INDEX] =
      (uint8_t)(data_area_size / NFC_TAG_T5T_AREA_SIZE_UNIT_BYTES);
  g_type5_info.cc[NFC_TAG_T5T_CC_FLAGS_BYTE_INDEX] = 0u;
  g_type5_info.data_area_size_bytes = data_area_size;
  g_type5_info.block_size = NFC_STORAGE_TYPE5_BLOCK_SIZE;
  g_type5_info.block_count = block_count;
  g_type5_info.read_access_open = read_open;
  g_type5_info.write_access_open = write_open;
}

void reader_tags_utest_set_type2_write_ok(bool ok) { g_type2_write_ok = ok; }

void reader_tags_utest_abort_after_type2_writes(uint16_t count) {
  g_abort_after_type2_writes = count;
}

void reader_tags_utest_set_type5_write_ok(bool ok) { g_type5_write_ok = ok; }

void reader_tags_utest_abort_after_type5_writes(uint16_t count) {
  g_abort_after_type5_writes = count;
}

void reader_tags_utest_set_type2_transceive_response(const uint8_t* rsp,
                                                     uint16_t len) {
  if ((rsp == NERO_NFC_NULL) ||
      (len > (uint16_t)sizeof(g_type2_transceive_response)) ||
      !nero_nfc_copy_bytes(g_type2_transceive_response,
                           sizeof(g_type2_transceive_response), 0u, rsp, len)) {
    g_type2_transceive_response_len = 0u;
    return;
  }
  g_type2_transceive_response_len = len;
}

uint16_t reader_tags_utest_type2_write_count(void) {
  return g_type2_write_count;
}

uint16_t reader_tags_utest_type5_write_count(void) {
  return g_type5_write_count;
}

uint16_t reader_tags_utest_type5_read_count(void) { return g_type5_read_count; }

uint16_t reader_tags_utest_type5_last_read_block(void) {
  return g_type5_last_read_block;
}

uint16_t reader_tags_utest_type5_last_read_len(void) {
  return g_type5_last_read_len;
}

uint16_t reader_tags_utest_type2_transceive_count(void) {
  return g_type2_transceive_count;
}

uint16_t reader_tags_utest_type5_transceive_count(void) {
  return g_type5_transceive_count;
}

bool reader_tags_get_typea_info(reader_tag_typea_info_t* info) {
  if (info != NERO_NFC_NULL) {
    if (g_typea_valid) {
      *info = g_typea_info;
    } else {
      nero_nfc_zero_bytes(info, sizeof(*info));
    }
  }
  return g_typea_valid;
}

bool reader_tags_get_type2_info(reader_tag_type2_info_t* info) {
  if (info != NERO_NFC_NULL) {
    nero_nfc_zero_bytes(info, sizeof(*info));
  }
  return false;
}

bool reader_tags_get_type2_storage_info(reader_tag_type2_info_t* info) {
  if (info != NERO_NFC_NULL) {
    if (g_type2_storage_valid) {
      *info = g_type2_storage_info;
    } else {
      nero_nfc_zero_bytes(info, sizeof(*info));
    }
  }
  return g_type2_storage_valid;
}

bool reader_tags_get_type4_info(reader_tag_type4_info_t* info) {
  if (info != NERO_NFC_NULL) {
    nero_nfc_zero_bytes(info, sizeof(*info));
  }
  return false;
}

bool reader_tags_get_type5_info(reader_tag_type5_info_t* info) {
  if (info != NERO_NFC_NULL) {
    if (g_type5_info_valid) {
      *info = g_type5_info;
    } else {
      nero_nfc_zero_bytes(info, sizeof(*info));
    }
  }
  return g_type5_info_valid;
}

int reader_tags_load_type5_ndef_message(uint8_t* dst, uint16_t dst_cap) {
  if ((dst != NERO_NFC_NULL) && (dst_cap > 0u)) {
    dst[0] = 0u;
  }
  return 0;
}

bool reader_tags_write_type2_ndef_message(const uint8_t* ndef,
                                          uint16_t ndef_len) {
  (void)ndef;
  (void)ndef_len;
  return false;
}

bool reader_tags_write_type5_ndef_message(const uint8_t* ndef,
                                          uint16_t ndef_len) {
  (void)ndef;
  (void)ndef_len;
  return false;
}

int reader_tags_type2_transceive(const uint8_t* tx, uint16_t tx_len,
                                 uint8_t* rx, uint16_t rx_max) {
  (void)tx;
  (void)tx_len;
  g_type2_transceive_count++;
  if ((rx == NERO_NFC_NULL) || (g_type2_transceive_response_len == 0u) ||
      (rx_max < g_type2_transceive_response_len) ||
      !nero_nfc_copy_bytes(rx, rx_max, 0u, g_type2_transceive_response,
                           g_type2_transceive_response_len)) {
    return 0;
  }
  return (int)g_type2_transceive_response_len;
}

int reader_tags_ntag_read_page(uint8_t page, uint8_t* buffer) {
  static const uint8_t K_ZERO[1] = {0u};

  (void)page;
  if ((buffer == NERO_NFC_NULL) ||
      !nero_nfc_copy_bytes(buffer, NFC_TAG_T2T_PAGE_SIZE_BYTES, 0u, K_ZERO,
                           sizeof(K_ZERO))) {
    return -1;
  }
  return 0;
}

bool reader_tags_type2_write_page(uint8_t page, const uint8_t* data) {
  (void)page;
  (void)data;
  g_type2_write_count++;
  if ((g_abort_after_type2_writes != 0u) &&
      (g_type2_write_count >= g_abort_after_type2_writes)) {
    reader_hal_utest_ccid_set_abort_pending(true, 0u, 0u);
  }
  return g_type2_write_ok;
}

int reader_tags_type2_read_binary(uint16_t page, uint8_t* buf,
                                  uint16_t buf_cap) {
  (void)page;
  if (buf == NERO_NFC_NULL) {
    return -1;
  }
  nero_nfc_zero_bytes(buf, buf_cap);
  return (int)buf_cap;
}

int reader_tags_type5_transceive(const uint8_t* tx, uint16_t tx_len,
                                 uint8_t* rx, uint16_t rx_max) {
  (void)tx;
  (void)tx_len;
  if ((rx != NERO_NFC_NULL) && (rx_max > 0u)) {
    rx[0] = 0u;
  }
  g_type5_transceive_count++;
  return 0;
}

bool reader_tags_type5_write_block(uint16_t block, const uint8_t* data,
                                   uint8_t data_len) {
  (void)block;
  (void)data;
  (void)data_len;
  g_type5_write_count++;
  if ((g_abort_after_type5_writes != 0u) &&
      (g_type5_write_count >= g_abort_after_type5_writes)) {
    reader_hal_utest_ccid_set_abort_pending(true, 0u, 0u);
  }
  return g_type5_write_ok;
}

int reader_tags_type5_read_binary(uint16_t block, uint8_t* buf,
                                  uint16_t buf_cap) {
  if (buf == NERO_NFC_NULL) {
    return -1;
  }
  g_type5_read_count++;
  g_type5_last_read_block = block;
  g_type5_last_read_len = buf_cap;
  nero_nfc_zero_bytes(buf, buf_cap);
  return (int)buf_cap;
}

int reader_tags_load_type2_ndef_message(uint8_t* dst, uint16_t dst_cap) {
  if ((dst != NERO_NFC_NULL) && (dst_cap > 0u)) {
    dst[0] = 0u;
  }
  return 0;
}
