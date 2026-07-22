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
 * reader_tags_type5.c — ISO15693 Type 5 tag read path.
 */

#include "nero_nfc_null.h"
#include "nfc_tag_geometry_limits.h"
#include "nfc_tag_info_print.h"
#include "reader_tags.h"
#include "reader_tags_internal.h"

#include "nero_nfc_frontend.h"
#include "nero_nfc_mem_util.h"
#include "nfc_byte_tutorial.h"
#include "nfc_ndef_tlv.h"
#include "nfc_pcsc_contactless.h"
#include "reader_context.h"
#include "reader_hal.h"
#include "reader_output.h"
#include "reader_protocol.h"

#include "reader_tags_ndef_decode.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

enum {
  READER_TYPE5_READ_MULTIPLE_CMD_MAX = 14u,
  READER_TYPE5_READ_MULTIPLE_SHORT_FIELD_LEN = 2u,
  READER_TYPE5_READ_MULTIPLE_EXT_FIELD_LEN = 4u,
};

static bool reader_tags_type5_cmd_append(uint8_t* cmd, uint16_t cmd_cap,
                                         uint16_t* pos, const uint8_t* src,
                                         uint16_t len) {
  if ((cmd == NERO_NFC_NULL) || (pos == NERO_NFC_NULL) ||
      (src == NERO_NFC_NULL)) {
    return false;
  }
  if (!nero_nfc_copy_bytes(cmd, cmd_cap, *pos, src, len)) {
    return false;
  }
  *pos = (uint16_t)(*pos + len);
  return true;
}

static int reader_type5_transceive(void* context, const uint8_t* tx,
                                   uint16_t tx_len, uint8_t* rx,
                                   uint16_t rx_max, uint16_t timeout_ms) {
  (void)context;
  return reader_protocol_iso15693_transceive(tx, tx_len, rx, rx_max,
                                             timeout_ms);
}

bool reader_tags_iso15693_inventory_step_impl(void) {
  return nfc_frontend_iso15693_inventory(reader_type5_transceive,
                                         READER_FRONTEND, G_UID15);
}

/*
 * Reads a single user-memory block across Type 5 ICs we support.
 * [T5T-ISO15693-ST25TV] DS13304 section 6.4.3 — ReadSingleBlock (opcode 0x20,
 * 1-byte address). [T5T-ISO15693-ST25DV] DS13519 section 7.6.6 — Read Single
 * Block accepts 0x20 for blocks 0..0xFF; extended 0x30 form is used above
 * NFC_TAG_T5T_ISO15693_BLOCK_ADDR_1BYTE_MAX.
 */
int reader_tags_iso15693_user_read(uint16_t block, uint8_t* buf,
                                   uint8_t buf_len) {
  if (block <= NFC_TAG_T5T_ISO15693_BLOCK_ADDR_1BYTE_MAX) {
    int r = nfc_frontend_iso15693_read_block(reader_type5_transceive,
                                             READER_FRONTEND, G_UID15,
                                             (uint8_t)(block), buf, buf_len);
    if (r >= 0) {
      return r;
    }
    /* Fall through to extended form on tags that only honour 0x30 — rare,
     * but keeps us robust against future ST25DV* memory configurations. */
  }
  return nfc_frontend_iso15693_ext_read_block(
      reader_type5_transceive, READER_FRONTEND, G_UID15, block, buf, buf_len);
}

int reader_tags_iso15693_user_read_multiple(uint16_t first_block,
                                            uint16_t block_count, uint8_t* buf,
                                            uint16_t buf_cap) {
  uint8_t cmd[READER_TYPE5_READ_MULTIPLE_CMD_MAX];
  uint8_t rx[1u + (NFC_TAG_T5T_ISO15693_READ_MULTIPLE_BLOCKS_MAX *
                   ST25_T5_USER_BLOCK_SIZE)];
  uint16_t want;
  uint16_t count_field;
  bool extended;
  uint16_t n = 0u;
  int rlen;

  if ((buf == NERO_NFC_NULL) || (block_count == 0u) ||
      (block_count >
       (uint16_t)(NFC_TAG_T5T_ISO15693_READ_MULTIPLE_BLOCKS_MAX)) ||
      (block_count > (uint16_t)(UINT16_MAX / ST25_T5_USER_BLOCK_SIZE))) {
    return -1;
  }
  want = (uint16_t)(block_count * (uint16_t)(ST25_T5_USER_BLOCK_SIZE));
  if (buf_cap < want) {
    return -1;
  }
  count_field = (uint16_t)(block_count - 1u);
  extended =
      (first_block > (uint16_t)(NFC_TAG_T5T_ISO15693_BLOCK_ADDR_1BYTE_MAX)) ||
      (count_field > (uint16_t)(NFC_TAG_T5T_ISO15693_BLOCK_ADDR_1BYTE_MAX));
  const uint8_t flags =
      extended ? (uint8_t)(NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED |
                           NFC_TAG_T5T_ISO15693_FLAG_PROTOCOL_EXTENSION)
               : (uint8_t)(NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED);
  const uint8_t opcode =
      extended ? (uint8_t)(NFC_TAG_T5T_ISO15693_CMD_EXT_READ_MULTIPLE)
               : (uint8_t)(NFC_TAG_T5T_ISO15693_CMD_READ_MULTIPLE);
  uint8_t uid_lsb[NFC_FRONTEND_ISO15693_UID_LEN];
  uint8_t block_fields[READER_TYPE5_READ_MULTIPLE_EXT_FIELD_LEN];

  if (!reader_tags_type5_cmd_append(cmd, sizeof(cmd), &n, &flags, 1u) ||
      !reader_tags_type5_cmd_append(cmd, sizeof(cmd), &n, &opcode, 1u)) {
    return -1;
  }
  for (size_t i = 0u; i < NFC_FRONTEND_ISO15693_UID_LEN; i++) {
    uid_lsb[i] = G_UID15[NFC_FRONTEND_ISO15693_UID_LEN - 1u - i];
  }
  if (!reader_tags_type5_cmd_append(cmd, sizeof(cmd), &n, uid_lsb,
                                    sizeof(uid_lsb))) {
    return -1;
  }
  if (extended) {
    block_fields[0] = (uint8_t)(first_block & NFC_ISO7816_LOW_BYTE_MASK);
    block_fields[1] = (uint8_t)(first_block >> NFC_ISO7816_U16_HIGH_BYTE_SHIFT);
    block_fields[READER_TYPE5_READ_MULTIPLE_SHORT_FIELD_LEN] =
        (uint8_t)(count_field & NFC_ISO7816_LOW_BYTE_MASK);
    block_fields[READER_TYPE5_READ_MULTIPLE_SHORT_FIELD_LEN + 1u] =
        (uint8_t)(count_field >> NFC_ISO7816_U16_HIGH_BYTE_SHIFT);
    if (!reader_tags_type5_cmd_append(
            cmd, sizeof(cmd), &n, block_fields,
            (uint16_t)(READER_TYPE5_READ_MULTIPLE_EXT_FIELD_LEN))) {
      return -1;
    }
  } else {
    block_fields[0] = (uint8_t)(first_block);
    block_fields[1] = (uint8_t)(count_field);
    if (!reader_tags_type5_cmd_append(
            cmd, sizeof(cmd), &n, block_fields,
            (uint16_t)(READER_TYPE5_READ_MULTIPLE_SHORT_FIELD_LEN))) {
      return -1;
    }
  }

  rlen = reader_protocol_iso15693_transceive(
      cmd, n, rx, (uint16_t)(sizeof(rx)),
      NFC_TAG_T5T_ISO15693_TRANSCEIVE_TIMEOUT_MS);
  if ((rlen < (int)(1u + want)) ||
      ((rx[0] & (uint8_t)(NFC_TAG_T5T_ISO15693_RESP_FLAG_ERROR)) != 0u)) {
    return -1;
  }
  if (!nero_nfc_copy_bytes(buf, buf_cap, 0u, &rx[1], want)) {
    return -1;
  }
  return (int)(want);
}

bool reader_tags_iso15693_user_write(uint16_t block, const uint8_t* data,
                                     uint8_t data_len) {
  if (block <= NFC_TAG_T5T_ISO15693_BLOCK_ADDR_1BYTE_MAX) {
    bool ok = nfc_frontend_iso15693_write_block(
        reader_type5_transceive, READER_FRONTEND, G_UID15, (uint8_t)(block),
        data, data_len);
    if (ok) {
      return true;
    }
  }
  return nfc_frontend_iso15693_ext_write_block(
      reader_type5_transceive, READER_FRONTEND, G_UID15, block, data, data_len);
}

/*
 * Reads up to READER_NDEF_BUF_MAX bytes from Type 5 user memory starting at
 * block 0 (which holds the Capability Container) and dumps any NDEF message
 * found inside the TLV payload. Uses the context-owned NDEF buffer
 * buffer.
 */
static bool read_type5_tlv_area(const reader_tag_type5_info_t* type5,
                                uint16_t* total_out,
                                uint16_t* start_offset_out) {
  uint8_t* const buf = READER_TAGS_NDEF_BUF;
  const uint16_t buf_size = READER_NDEF_BUF_MAX;
  uint16_t total = 0u;
  uint16_t bytes_to_read;
  uint16_t blocks_needed;
  uint16_t start_offset;

  if (total_out != NERO_NFC_NULL) {
    *total_out = 0u;
  }
  if (start_offset_out != NERO_NFC_NULL) {
    *start_offset_out = 0u;
  }
  if ((type5 == NERO_NFC_NULL) || (total_out == NERO_NFC_NULL) ||
      (start_offset_out == NERO_NFC_NULL) || !type5->cc_valid ||
      !type5->read_access_open || (type5->data_area_size_bytes == 0u)) {
    return false;
  }
  start_offset = reader_tags_type5_cc_byte_len(type5);
  if (!nero_nfc_try_add_u16(start_offset, type5->data_area_size_bytes,
                            &bytes_to_read)) {
    return false;
  }
  bytes_to_read = ((bytes_to_read) < (buf_size) ? (bytes_to_read) : (buf_size));
  blocks_needed = (uint16_t)((bytes_to_read + (ST25_T5_USER_BLOCK_SIZE - 1u)) /
                             ST25_T5_USER_BLOCK_SIZE);

  reader_tags_reset_detected_urls();

  for (uint16_t block = 0u; block < blocks_needed;) {
    uint8_t tmp[NFC_TAG_T5T_ISO15693_READ_MULTIPLE_BLOCKS_MAX *
                ST25_T5_USER_BLOCK_SIZE];
    const uint16_t remaining_blocks = (uint16_t)(blocks_needed - block);
    const uint16_t blocks =
        (remaining_blocks >
         (uint16_t)(NFC_TAG_T5T_ISO15693_READ_MULTIPLE_BLOCKS_MAX))
            ? (uint16_t)(NFC_TAG_T5T_ISO15693_READ_MULTIPLE_BLOCKS_MAX)
            : remaining_blocks;
    const uint16_t chunk_len =
        (uint16_t)(blocks * (uint16_t)(ST25_T5_USER_BLOCK_SIZE));
    int r = reader_tags_type5_read_binary(block, tmp, chunk_len);

    if (r < (int)(chunk_len)) {
      return false;
    }
    if (!nero_nfc_copy_bytes(buf, buf_size, total, tmp, chunk_len)) {
      return false;
    }
    if (!nero_nfc_try_add_u16(total, chunk_len, &total)) {
      return false;
    }
    block = (uint16_t)(block + blocks);
    if (total > start_offset) {
      nfc_ndef_tlv_t tlv;
      nfc_ndef_tlv_status_t const status =
          nfc_ndef_find_message_tlv(buf, total, start_offset, &tlv);
      if (status == NFC_NDEF_TLV_OK) {
        break;
      }
      for (uint16_t i = start_offset; i < total; ++i) {
        if (buf[i] == NFC_NDEF_TLV_TERMINATOR) {
          block = blocks_needed;
          break;
        }
      }
    }
  }
  *total_out = total;
  *start_offset_out = start_offset;
  return true;
}

void reader_tags_read_dynamic_or_static_type5(void) {
  reader_tag_type5_info_t type5;
  uint16_t total = 0u;
  uint16_t start_offset = 0u;

  nero_nfc_log_line("\r\n╔════════════════════════════════════════╗");
  nero_nfc_log_line("║      TYPE 5 / ISO 15693 TAG            ║");
  nero_nfc_log_line("╚════════════════════════════════════════╝");
  if (reader_tags_get_type5_info(&type5)) {
    nfc_tag_print_type5_debug(nero_nfc_log_putc, G_UID15,
                              NFC_FRONTEND_ISO15693_UID_LEN, &type5);
  }

  if (read_type5_tlv_area(&type5, &total, &start_offset) &&
      total >= start_offset) {
    nero_nfc_log_line("\r\n  ── Byte-level explainer (read-back) ──");
    {
      const uint16_t blocks_read =
          (uint16_t)(((unsigned)total + (unsigned)ST25_T5_USER_BLOCK_SIZE -
                      1u) /
                     (unsigned)ST25_T5_USER_BLOCK_SIZE);
      if (blocks_read > 1u) {
        nfc_tutorial_t5t_read_multiple_cmd(nero_nfc_log_putc, G_UID15, 0u,
                                           blocks_read);
      } else {
        nfc_tutorial_t5t_read_cmd(nero_nfc_log_putc, G_UID15, 0u);
      }
    }
    nfc_tutorial_t5t_cc(nero_nfc_log_putc, READER_TAGS_NDEF_BUF,
                        (uint8_t)(start_offset));
    nfc_tutorial_ndef_tlv(nero_nfc_log_putc,
                          &READER_TAGS_NDEF_BUF[start_offset],
                          (uint16_t)(total - start_offset));
    reader_tags_parse_ndef_tlv_area(READER_TAGS_NDEF_BUF, total, start_offset);
  } else {
    nero_nfc_log_line("  NDEF message: 0 bytes");
  }
}
