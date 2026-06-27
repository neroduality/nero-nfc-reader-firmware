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
#include "nero_nfc_limits.h"
#include "nero_nfc_mem_util.h"
#include "nero_nfc_null.h"
#include "nfc_tag_geometry_limits.h"
#include "nfc_tag_info.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
  NFC_STORAGE_TYPE2_CC_PAGE = 3u,
  NFC_STORAGE_TYPE2_FIRST_DATA_PAGE = 4u,
  NFC_STORAGE_TYPE2_UNIT_SIZE = 4u,
  NFC_STORAGE_TYPE5_BLOCK_SIZE = 4u,
  NFC_STORAGE_BLOCK_CEIL_BIAS = 3u,
};

NERO_NFC_NODISCARD static inline bool
nfc_storage_ceil_units_u16(uint16_t byte_len, uint8_t unit_size, uint16_t *units_out) {
  if (units_out != NERO_NFC_NULL) {
    *units_out = 0u;
  }
  if ((units_out == NERO_NFC_NULL) || (unit_size == 0u)) {
    return false;
  }
  *units_out = (uint16_t)(((uint32_t)byte_len + (uint32_t)unit_size - 1u) / (uint32_t)unit_size);
  return true;
}

static inline uint16_t nfc_storage_cap_scan_bytes(uint16_t data_area_size, uint16_t scan_max) {
  return (data_area_size > scan_max) ? scan_max : data_area_size;
}

NERO_NFC_NODISCARD static inline bool nfc_storage_type2_last_page(uint16_t data_area_size,
                                                                  uint16_t *last_page_out) {
  uint16_t pages = 0u;

  if (last_page_out != NERO_NFC_NULL) {
    *last_page_out = 0u;
  }
  if ((last_page_out == NERO_NFC_NULL) || (data_area_size == 0u) ||
      !nfc_storage_ceil_units_u16(data_area_size, NFC_STORAGE_TYPE2_UNIT_SIZE, &pages) ||
      (pages == 0u)) {
    return false;
  }
  *last_page_out = (uint16_t)(NFC_STORAGE_TYPE2_CC_PAGE + pages);
  if (*last_page_out > (uint16_t)NERO_NFC_TYPE2_STORAGE_MAX_PAGE) {
    *last_page_out = (uint16_t)NERO_NFC_TYPE2_STORAGE_MAX_PAGE;
  }
  return true;
}

NERO_NFC_NODISCARD static inline bool nfc_storage_type2_read_span_ok(uint16_t data_area_size,
                                                                     uint16_t page, uint16_t len) {
  uint16_t pages = 0u;
  uint16_t last_page = 0u;
  size_t end_page = 0u;

  if ((len == 0u) || !nfc_storage_type2_last_page(data_area_size, &last_page) ||
      !nfc_storage_ceil_units_u16(len, NFC_STORAGE_TYPE2_UNIT_SIZE, &pages) || (pages == 0u)) {
    return false;
  }
  if ((page < NFC_STORAGE_TYPE2_CC_PAGE) ||
      !nero_nfc_try_add_size((size_t)page, (size_t)pages - 1u, &end_page)) {
    return false;
  }
  return end_page <= last_page;
}

NERO_NFC_NODISCARD static inline bool nfc_storage_type2_update_page_ok(uint16_t page, uint8_t len) {
  return (len == NFC_STORAGE_TYPE2_UNIT_SIZE) && (page >= NFC_STORAGE_TYPE2_FIRST_DATA_PAGE) &&
         (page <= (uint16_t)NERO_NFC_TYPE2_STORAGE_MAX_PAGE);
}

NERO_NFC_NODISCARD static inline bool nfc_storage_type2_write_span_ok(uint16_t data_area_size,
                                                                      uint16_t page, uint16_t len) {
  if ((len == 0u) || ((len % NFC_STORAGE_TYPE2_UNIT_SIZE) != 0u) ||
      (page < NFC_STORAGE_TYPE2_FIRST_DATA_PAGE)) {
    return false;
  }
  return nfc_storage_type2_read_span_ok(data_area_size, page, len);
}

static inline uint16_t nfc_storage_type2_read_unit_limit(uint16_t first_unit, uint8_t unit_size,
                                                         uint16_t tlv_start_offset,
                                                         uint16_t data_area_size,
                                                         uint16_t scan_max) {
  uint16_t units = 0u;
  const uint16_t scan_bytes = nfc_storage_cap_scan_bytes(data_area_size, scan_max);

  if (unit_size == 0u) {
    return 0u;
  }
  if (((uint32_t)tlv_start_offset + (uint32_t)scan_bytes) > UINT16_MAX) {
    return 0u;
  }
  if (!nfc_storage_ceil_units_u16((uint16_t)(tlv_start_offset + scan_bytes), unit_size, &units)) {
    return 0u;
  }
  if (first_unit <= (uint16_t)NERO_NFC_TYPE2_STORAGE_MAX_PAGE) {
    const uint16_t max_units =
      (uint16_t)((uint32_t)NERO_NFC_TYPE2_STORAGE_MAX_PAGE - (uint32_t)first_unit + 1u);
    if (units > max_units) {
      units = max_units;
    }
  }
  return units;
}

static inline uint16_t nfc_storage_type5_cc_len_or_default(uint16_t parsed_cc_len,
                                                           const uint8_t *cc, uint16_t cc_len) {
  if (parsed_cc_len != 0u) {
    return parsed_cc_len;
  }
  /*
   * [T5T-ISO15693] section 4.3.1.17 — MLEN (CC byte 2) == 0 marks NFC_TAG_T5T_CC_LEN_EXTENDED;
   * only claim extended length when that many bytes are available.
   */
  if ((cc != NERO_NFC_NULL) && (cc_len >= NFC_TAG_T5T_CC_LEN_EXTENDED) &&
      (cc[NFC_TAG_T5T_CC_MLEN_BYTE_INDEX] == 0u)) {
    return NFC_TAG_T5T_CC_LEN_EXTENDED;
  }
  return NFC_TAG_T5T_CC_LEN_SHORT;
}

static inline uint16_t nfc_storage_type5_declared_cc_len_from_first_block(const uint8_t *cc,
                                                                          uint16_t cc_len) {
  if ((cc == NERO_NFC_NULL) || (cc_len < NFC_TAG_T5T_CC_LEN_SHORT) ||
      !nero_nfc_span_ok(NFC_TAG_T5T_CC_MLEN_BYTE_INDEX, 1u, cc_len)) {
    return 0u;
  }
  /*
   * [T5T-ISO15693] section 4.3.1.17 — MLEN (CC byte 2) == 0 declares an
   * 8-byte CC. This helper is for deciding whether block 1 must be read before
   * calling nfc_tag_type5_apply_cc().
   */
  return (cc[NFC_TAG_T5T_CC_MLEN_BYTE_INDEX] == 0u) ? NFC_TAG_T5T_CC_LEN_EXTENDED
                                                    : NFC_TAG_T5T_CC_LEN_SHORT;
}

NERO_NFC_NODISCARD static inline bool
nfc_storage_type5_data_blocks(uint16_t cc_bytes, uint16_t data_area_size, uint8_t block_size,
                              uint16_t block_count, uint16_t *first_data_block_out,
                              uint16_t *last_data_block_out) {
  uint16_t data_blocks = 0u;
  size_t last_block = 0u;

  if (first_data_block_out != NERO_NFC_NULL) {
    *first_data_block_out = 0u;
  }
  if (last_data_block_out != NERO_NFC_NULL) {
    *last_data_block_out = 0u;
  }
  if ((first_data_block_out == NERO_NFC_NULL) || (last_data_block_out == NERO_NFC_NULL) ||
      (cc_bytes == 0u) || (data_area_size == 0u) || (block_size != NFC_STORAGE_TYPE5_BLOCK_SIZE) ||
      ((cc_bytes % NFC_STORAGE_TYPE5_BLOCK_SIZE) != 0u)) {
    return false;
  }
  if (!nfc_storage_ceil_units_u16(data_area_size, NFC_STORAGE_TYPE5_BLOCK_SIZE, &data_blocks) ||
      (data_blocks == 0u)) {
    return false;
  }
  *first_data_block_out = (uint16_t)(cc_bytes / NFC_STORAGE_TYPE5_BLOCK_SIZE);
  if (!nero_nfc_try_add_size((size_t)*first_data_block_out, (size_t)data_blocks - 1u,
                             &last_block) ||
      (last_block > UINT16_MAX)) {
    return false;
  }
  if ((block_count != 0u) && (last_block >= block_count)) {
    last_block = (size_t)(block_count - 1u);
  }
  *last_data_block_out = (uint16_t)last_block;
  return *first_data_block_out <= *last_data_block_out;
}

static inline uint16_t nfc_storage_type5_read_block_limit(uint16_t tlv_start_offset,
                                                          uint16_t data_area_size,
                                                          uint16_t read_max) {
  if (tlv_start_offset >= read_max) {
    return 0u;
  }
  const uint16_t max_data_area = (uint16_t)(read_max - tlv_start_offset);
  const uint16_t scan_data = nfc_storage_cap_scan_bytes(data_area_size, max_data_area);
  if (((uint32_t)tlv_start_offset + (uint32_t)scan_data) > UINT16_MAX) {
    return 0u;
  }
  return (
    uint16_t)(((uint32_t)tlv_start_offset + (uint32_t)scan_data + NFC_STORAGE_BLOCK_CEIL_BIAS) /
              NFC_STORAGE_TYPE5_BLOCK_SIZE);
}

NERO_NFC_NODISCARD static inline bool
nfc_storage_type5_read_span_ok(uint16_t cc_bytes, uint16_t data_area_size, uint8_t block_size,
                               uint16_t block_count, uint16_t block, uint16_t len) {
  uint16_t first_data_block = 0u;
  uint16_t last_data_block = 0u;
  uint16_t blocks = 0u;
  size_t end_block = 0u;

  if ((len == 0u) ||
      !nfc_storage_type5_data_blocks(cc_bytes, data_area_size, block_size, block_count,
                                     &first_data_block, &last_data_block) ||
      !nfc_storage_ceil_units_u16(len, NFC_STORAGE_TYPE5_BLOCK_SIZE, &blocks) || (blocks == 0u)) {
    return false;
  }
  (void)first_data_block;
  if (!nero_nfc_try_add_size((size_t)block, (size_t)blocks - 1u, &end_block)) {
    return false;
  }
  return end_block <= last_data_block;
}

NERO_NFC_NODISCARD static inline bool
nfc_storage_type5_write_span_ok(uint16_t cc_bytes, uint16_t data_area_size, uint8_t block_size,
                                uint16_t block_count, uint16_t block, uint16_t len) {
  uint16_t first_data_block = 0u;
  uint16_t last_data_block = 0u;
  uint16_t blocks = 0u;
  size_t end_block = 0u;

  if ((len == 0u) || ((len % NFC_STORAGE_TYPE5_BLOCK_SIZE) != 0u) ||
      !nfc_storage_type5_data_blocks(cc_bytes, data_area_size, block_size, block_count,
                                     &first_data_block, &last_data_block) ||
      !nfc_storage_ceil_units_u16(len, NFC_STORAGE_TYPE5_BLOCK_SIZE, &blocks) || (blocks == 0u) ||
      !nero_nfc_try_add_size((size_t)block, (size_t)blocks - 1u, &end_block)) {
    return false;
  }
  return (block >= first_data_block) && (end_block <= last_data_block);
}

#ifdef __cplusplus
}
#endif
