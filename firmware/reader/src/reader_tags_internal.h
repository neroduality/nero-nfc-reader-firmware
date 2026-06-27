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

#include "nero_nfc_mem_util.h"
#include "nero_nfc_limits.h"
#include "nfc_tag_geometry_limits.h"
#include "reader_tags.h"

#include "nero_nfc_attrs.h"

#include <stdbool.h>
#include <stdint.h>

#define READER_NDEF_BUF_MAX NERO_NFC_READER_NDEF_BUF_MAX
/* [T5T-ISO15693] section 4.2 — ISO/IEC 15693 user block size is NFC_TAG_T2T_PAGE_SIZE_BYTES. */
#define ST25_T5_USER_BLOCK_SIZE NFC_TAG_T2T_PAGE_SIZE_BYTES
/*
 * Type 2 CC bytes (4) + largest supported user data-area read. The 912 B window
 * spans the NTAG216 user area (NTAG21x datasheet: 888 user bytes) plus headroom;
 * parsed CC MLEN and per-IC page caps still bound real tag access.
 */
#define READER_TYPE2_CC_PREFIX_BYTES NFC_TAG_T2T_PAGE_SIZE_BYTES
#define READER_TYPE2_DATA_AREA_READ_MAX NFC_TAG_T2T_HOST_NDEF_SCAN_MAX
#define READER_TYPE2_RAW_READ_MAX (READER_TYPE2_CC_PREFIX_BYTES + READER_TYPE2_DATA_AREA_READ_MAX)
/* Page-3..max_page dump buffer for interactive NTAG reads (see type2_max_read_page). */
#define READER_TYPE2_TAG_DUMP_MAX READER_TYPE2_DATA_AREA_READ_MAX

NERO_NFC_STATIC_ASSERT(READER_TYPE2_RAW_READ_MAX == 916u,
                       "Type 2 raw read cap must match CC prefix + data area");
NERO_NFC_STATIC_ASSERT(READER_TYPE2_TAG_DUMP_MAX == 912u,
                       "Type 2 tag dump cap must match data-area read max");

static inline uint16_t reader_tags_type5_cc_byte_len(const reader_tag_type5_info_t *type5) {
  if ((type5 == NERO_NFC_NULL) || !type5->cc_valid) {
    return 0u;
  }
  if (type5->cc_len != 0u) {
    return type5->cc_len;
  }
  /* [T5T-ISO15693] section 4.3.1.17 — MLEN (CC byte 2) == 0 marks NFC_TAG_T5T_CC_LEN_EXTENDED. */
  return (type5->cc[2] == 0u) ? NFC_TAG_T5T_CC_LEN_EXTENDED : NFC_TAG_T5T_CC_LEN_SHORT;
}

static inline uint16_t reader_tags_type5_tlv_start_block(const reader_tag_type5_info_t *type5) {
  const uint16_t cc_bytes = reader_tags_type5_cc_byte_len(type5);
  if ((cc_bytes == 0u) || (ST25_T5_USER_BLOCK_SIZE == 0u)) {
    return 0u;
  }
  return (uint16_t)(cc_bytes / ST25_T5_USER_BLOCK_SIZE);
}

extern uint8_t reader_tags_ndef_buf[READER_NDEF_BUF_MAX];

void reader_tags_reset_detected_urls(void);
void reader_tags_print_ndef_records(const uint8_t *data, uint16_t len);
void reader_tags_parse_ndef_tlv_area(const uint8_t *data, uint16_t len, uint16_t start_offset);

#ifdef __cplusplus
extern "C" {
#endif

int reader_tags_ntag_read_page(uint8_t page, uint8_t *buffer);

#ifdef __cplusplus
}
#endif

int reader_tags_ntag_fast_read(uint8_t first_page, uint8_t last_page, uint8_t *buffer,
                               uint16_t buffer_len);
NERO_NFC_NODISCARD bool reader_tags_ntag_write_page(uint8_t page, const uint8_t *data);
int reader_tags_iso15693_user_read_multiple(uint16_t first_block, uint16_t block_count,
                                            uint8_t *buf, uint16_t buf_len);
NERO_NFC_NODISCARD bool reader_tags_type4_load_info(reader_tag_type4_info_t *info,
                                                    uint8_t *ndef_file_hi_out,
                                                    uint8_t *ndef_file_lo_out, bool log_errors);

NERO_NFC_NODISCARD bool reader_tags_iso15693_inventory_step_impl(void);
int reader_tags_iso15693_user_read(uint16_t block, uint8_t *buf, uint8_t buf_len);
NERO_NFC_NODISCARD bool reader_tags_iso15693_user_write(uint16_t block, const uint8_t *data,
                                                        uint8_t data_len);
