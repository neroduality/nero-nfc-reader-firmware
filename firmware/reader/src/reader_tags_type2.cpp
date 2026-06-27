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
/*
 * reader_tags_type2.cpp — NFC Forum Type 2 tag read path.
 */

#include "reader_tags.h"
#include "reader_tags_internal.h"

#include "nfc_frontend.h"
#include "nfc_byte_tutorial.h"
#include "nfc_ndef_tlv.h"
#include "nfc_pcsc_contactless.h"
#include "nero_nfc_mem_util.h"
#include "nfc_tag_geometry_limits.h"
#include "nfc_tag_info_print.h"
#include "reader_context.h"
#include "reader_frontend.h"
#include "reader_hal.h"
#include "reader_output.h"
#include "reader_protocol.h"

#include "reader_tags_ndef_decode.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "nero_nfc_format.h"

static constexpr uint16_t kType2FastReadRespBytesMax = 192u;

extern "C" int reader_tags_ntag_read_page(uint8_t page, uint8_t *buffer) {
  const uint8_t cmd[NFC_TAG_T2T_READ_CMD_LEN] = {NFC_FRONTEND_NTAG_CMD_READ, page};
  if (buffer == NERO_NFC_NULL) {
    return -1;
  }
  return reader_protocol_transceive14(cmd, NFC_TAG_T2T_READ_CMD_LEN, buffer,
                                      NFC_TAG_T2T_READ_RESP_BYTES, true,
                                      NFC_TAG_T2T_READ_TIMEOUT_MS, false, false);
}

int reader_tags_ntag_fast_read(uint8_t first_page, uint8_t last_page, uint8_t *buffer,
                               uint16_t buffer_len) {
  uint16_t page_count;
  uint16_t expected;
  uint16_t copied = 0u;
  uint16_t page = first_page;
  const uint16_t chunk_page_limit =
    (uint16_t)(kType2FastReadRespBytesMax / NFC_TAG_T2T_PAGE_SIZE_BYTES);

  if ((buffer == NERO_NFC_NULL) || (last_page < first_page)) {
    return -1;
  }
  page_count = (uint16_t)((uint16_t)last_page - (uint16_t)first_page + 1u);
  expected = (uint16_t)(page_count * NFC_TAG_T2T_PAGE_SIZE_BYTES);
  if ((expected == 0u) || (expected > buffer_len)) {
    return -1;
  }
  while (page <= (uint16_t)last_page) {
    uint16_t remaining_pages = (uint16_t)((uint16_t)last_page - page + 1u);
    uint16_t chunk_pages =
      (remaining_pages > chunk_page_limit) ? chunk_page_limit : remaining_pages;
    uint8_t chunk_last = (uint8_t)(page + chunk_pages - 1u);
    uint16_t chunk_len = (uint16_t)(chunk_pages * NFC_TAG_T2T_PAGE_SIZE_BYTES);
    const uint8_t fast_read_request[NFC_TAG_T2T_FAST_READ_CMD_LEN] = {
      NFC_FRONTEND_NTAG_CMD_FAST_READ, (uint8_t)page, chunk_last};
    int rlen = reader_protocol_transceive14(fast_read_request, NFC_TAG_T2T_FAST_READ_CMD_LEN,
                                            &buffer[copied], chunk_len, true,
                                            NFC_TAG_T2T_READ_TIMEOUT_MS, false, false);

    if (rlen < (int)chunk_len) {
      (void)reader_protocol_activate_iso14443a();
      return -1;
    }
    copied = (uint16_t)(copied + chunk_len);
    page = (uint16_t)(page + chunk_pages);
  }
  return (int)copied;
}

bool reader_tags_ntag_write_page(uint8_t page, const uint8_t *data) {
  if (data == NERO_NFC_NULL) {
    return false;
  }
  if (!nero_nfc_span_ok(NFC_TAG_T2T_PAGE_BYTE3, 1u, NFC_TAG_T2T_PAGE_SIZE_BYTES)) {
    return false;
  }
  uint8_t cmd[NFC_TAG_T2T_WRITE_CMD_LEN];
  cmd[0] = NFC_FRONTEND_NTAG_CMD_WRITE;
  cmd[1] = page;
  if (!nero_nfc_copy_bytes(cmd, sizeof(cmd), NFC_TAG_T2T_WRITE_CMD_DATA_OFFSET, data,
                           NFC_TAG_T2T_PAGE_SIZE_BYTES)) {
    return false;
  }
  uint8_t rx[NFC_TAG_T2T_PAGE_SIZE_BYTES];
  int rlen = reader_protocol_transceive14(cmd, NFC_TAG_T2T_WRITE_CMD_LEN, rx, sizeof(rx), true,
                                          NFC_TAG_T2T_WRITE_ACK_TIMEOUT_MS, false, true);

  /*
   * [T2T-ISO14443-A] section 5.2 — WRITE is acknowledged only by the 4-bit ACK 1010b (0Ah).
   */
  return (rlen >= 1) && ((rx[0] & NFC_TAG_T2T_ACK_NIBBLE_MASK) == NFC_TAG_T2T_ACK_NIBBLE);
}

static uint16_t type2_max_read_page(const reader_tag_type2_info_t *info) {
  if (info == NERO_NFC_NULL) {
    return NFC_TAG_T2T_FALLBACK_LAST_PAGE;
  }
  if (info->cc_valid && (info->data_area_size_bytes != 0u)) {
    const uint16_t pages_from_cc =
      (uint16_t)(NFC_TAG_T2T_CC_PAGE_INDEX +
                 ((info->data_area_size_bytes + NFC_TAG_T2T_PAGE_SIZE_BYTES - 1u) /
                  NFC_TAG_T2T_PAGE_SIZE_BYTES));

    return (pages_from_cc > NFC_TAG_NTAG216_LAST_PAGE) ? NFC_TAG_NTAG216_LAST_PAGE : pages_from_cc;
  }
  if (info->max_user_page != 0u) {
    return info->max_user_page;
  }
  return NFC_TAG_T2T_FALLBACK_LAST_PAGE;
}

static void reader_tags_parse_type2_tlv(const uint8_t *data, uint16_t len) {
  if (len < READER_TYPE2_CC_PREFIX_BYTES) {
    return;
  }
  if (data[0] != NFC_FORUM_CC_MAGIC) {
    return;
  }
  reader_tags_parse_ndef_tlv_area(data, len, READER_TYPE2_CC_PREFIX_BYTES);
}

static bool reader_tags_type2_tlv_complete(const uint8_t *data, uint16_t len) {
  nfc_ndef_tlv_t tlv;

  if ((data == NERO_NFC_NULL) || (len <= READER_TYPE2_CC_PREFIX_BYTES) ||
      (data[0] != NFC_FORUM_CC_MAGIC)) {
    return false;
  }
  if (nfc_ndef_find_message_tlv(data, len, READER_TYPE2_CC_PREFIX_BYTES, &tlv) == NFC_NDEF_TLV_OK) {
    return true;
  }
  for (uint16_t i = READER_TYPE2_CC_PREFIX_BYTES; i < len; ++i) {
    if (data[i] == NFC_NDEF_TLV_TERMINATOR) {
      return true;
    }
  }
  return false;
}

static uint16_t reader_tags_type2_needed_pages(const uint8_t *data, uint16_t len,
                                               uint16_t max_page) {
  uint16_t pos = READER_TYPE2_CC_PREFIX_BYTES;

  if ((data == NERO_NFC_NULL) || (len <= READER_TYPE2_CC_PREFIX_BYTES) ||
      (data[0] != NFC_FORUM_CC_MAGIC)) {
    return 0u;
  }
  while (pos < len) {
    const uint16_t tlv_start = pos;
    const uint8_t type = data[pos++];
    uint16_t value_len;
    uint32_t need_bytes;

    if (type == NFC_NDEF_TLV_NULL) {
      continue;
    }
    if (type == NFC_NDEF_TLV_TERMINATOR) {
      return (uint16_t)((tlv_start + NFC_TAG_T2T_PAGE_SIZE_BYTES) / NFC_TAG_T2T_PAGE_SIZE_BYTES);
    }
    if (pos >= len) {
      return 0u;
    }
    if (data[pos] == NFC_NDEF_TLV_EXTENDED_LEN) {
      if (!nero_nfc_span_ok(pos, NFC_NDEF_TLV_EXTENDED_LEN_FIELD_BYTES, len)) {
        return 0u;
      }
      value_len = (uint16_t)(((uint16_t)data[pos + NFC_NDEF_TLV_EXTENDED_LEN_MSB_OFFSET]
                              << NFC_NDEF_TLV_LEN_SHIFT) |
                             data[pos + NFC_NDEF_TLV_EXTENDED_LEN_LSB_OFFSET]);
      pos = (uint16_t)(pos + NFC_NDEF_TLV_EXTENDED_LEN_FIELD_BYTES);
    } else {
      value_len = data[pos++];
    }
    if (type != NFC_NDEF_TLV_MESSAGE) {
      pos = (uint16_t)(pos + value_len);
      continue;
    }
    need_bytes = (uint32_t)pos + (uint32_t)value_len;
    if (need_bytes > (uint32_t)READER_TYPE2_TAG_DUMP_MAX) {
      need_bytes = (uint32_t)READER_TYPE2_TAG_DUMP_MAX;
    }
    {
      uint16_t pages =
        (uint16_t)((need_bytes + NFC_TAG_T2T_PAGE_SIZE_BYTES - 1u) / NFC_TAG_T2T_PAGE_SIZE_BYTES);
      const uint16_t max_pages = (uint16_t)(max_page - NFC_TAG_T2T_CC_PAGE_INDEX + 1u);
      return (pages > max_pages) ? max_pages : pages;
    }
  }
  return 0u;
}

void reader_tags_read_ntag_tag(void) {
  reader_tag_typea_info_t typea;
  reader_tag_type2_info_t type2;
  uint16_t max_page;
  uint8_t tag_data[READER_TYPE2_TAG_DUMP_MAX];
  uint16_t total = 0u;

  reader_tags_reset_detected_urls();
  if (!reader_tags_get_typea_info(&typea) || !reader_tags_get_type2_info(&type2)) {
    nero_nfc_log_line("\r\n  Failed to extract Type 2 tag information");
    return;
  }

  nero_nfc_log_line("\r\n╔════════════════════════════════════════╗");
  nero_nfc_log_line("║         NTAG / TYPE 2 TAG              ║");
  nero_nfc_log_line("╚════════════════════════════════════════╝");
  nfc_tag_print_type2_debug(nero_nfc_log_putc, &typea, &type2);
  if (!type2.cc_valid || (type2.data_area_size_bytes == 0u)) {
    nero_nfc_log_line("  Type 2 CC invalid or empty data area; cannot parse NDEF");
    return;
  }
  if (!type2.read_access_open) {
    nero_nfc_log_line("  Type 2 read access restricted; cannot parse NDEF");
    return;
  }
  max_page = type2_max_read_page(&type2);

  if ((type2.family == NFC_TAG_TYPE2_FAMILY_NTAG21X) && (max_page <= (uint16_t)UINT8_MAX)) {
    uint8_t first_read[NFC_TAG_T2T_READ_RESP_BYTES];
    if (reader_tags_ntag_read_page(NFC_TAG_T2T_CC_PAGE_INDEX, first_read) >=
        (int)NFC_TAG_T2T_READ_RESP_BYTES) {
      if (nero_nfc_copy_bytes(tag_data, sizeof(tag_data), 0u, first_read, sizeof(first_read))) {
        total = NFC_TAG_T2T_READ_RESP_BYTES;
      }
      const uint16_t needed_pages = reader_tags_type2_needed_pages(tag_data, total, max_page);
      if (needed_pages > NFC_TAG_T2T_READ_RESP_PAGES) {
        const uint16_t fast_len = (uint16_t)(needed_pages * NFC_TAG_T2T_PAGE_SIZE_BYTES);
        if ((fast_len <= sizeof(tag_data)) &&
            (reader_tags_ntag_fast_read(NFC_TAG_T2T_CC_PAGE_INDEX,
                                        (uint8_t)(NFC_TAG_T2T_CC_PAGE_INDEX + needed_pages - 1u),
                                        tag_data, fast_len) >= (int)fast_len)) {
          total = fast_len;
        }
      }
    }
  }

  if (total == 0u) {
    for (uint16_t page = NFC_TAG_T2T_CC_PAGE_INDEX; page <= max_page;
         page = (uint16_t)(page + NFC_TAG_T2T_READ_RESP_PAGES)) {
      uint8_t buffer[NFC_TAG_T2T_READ_RESP_BYTES];
      int rlen = reader_tags_ntag_read_page((uint8_t)page, buffer);
      uint8_t pages_to_copy = NFC_TAG_T2T_READ_RESP_PAGES;

      if (rlen < (int)NFC_TAG_T2T_PAGE_SIZE_BYTES) {
        nero_nfc_log_write("  Read failed at page ");
        do {
          char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
          (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(page));
          nero_nfc_log_write(ndc);
        } while (0);
        nero_nfc_log_write("\r\n");
        break;
      }
      if ((uint16_t)(page + (NFC_TAG_T2T_READ_RESP_PAGES - 1u)) > max_page) {
        pages_to_copy = (uint8_t)(max_page - page + 1u);
      }
      for (uint8_t p = 0u; p < pages_to_copy; p++) {
        if (total + NFC_TAG_T2T_PAGE_SIZE_BYTES <= sizeof(tag_data)) {
          if (!nero_nfc_copy_bytes(tag_data, sizeof(tag_data), total,
                                   &buffer[p * NFC_TAG_T2T_PAGE_SIZE_BYTES],
                                   NFC_TAG_T2T_PAGE_SIZE_BYTES)) {
            break;
          }
          total = (uint16_t)(total + NFC_TAG_T2T_PAGE_SIZE_BYTES);
        }
      }
      if (reader_tags_type2_tlv_complete(tag_data, total)) {
        break;
      }
    }
  }
  if (total >= NFC_TAG_T2T_MIN_NDEF_DUMP_BYTES) {
    nero_nfc_log_line("\r\n  ── Byte-level explainer (read-back) ──");
    nfc_tutorial_t2t_read_cmd(nero_nfc_log_putc, NFC_TAG_T2T_CC_PAGE_INDEX);
    if (total > NFC_TAG_T2T_READ_RESP_BYTES) {
      nfc_tutorial_t2t_fast_read_cmd(
        nero_nfc_log_putc, NFC_TAG_T2T_CC_PAGE_INDEX,
        (uint8_t)(NFC_TAG_T2T_CC_PAGE_INDEX + ((total / NFC_TAG_T2T_PAGE_SIZE_BYTES) - 1u)));
    }
    nfc_tutorial_t2t_cc(nero_nfc_log_putc, tag_data);
    nfc_tutorial_ndef_tlv(nero_nfc_log_putc, &tag_data[READER_TYPE2_CC_PREFIX_BYTES],
                          (uint16_t)(total - READER_TYPE2_CC_PREFIX_BYTES));
    reader_tags_parse_type2_tlv(tag_data, total);
  }
}
