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
 * writer_tag_write_type5.cpp — ISO15693 Type 5 NDEF write path.
 */

#include "writer_tag_write_internal.h"

#include "writer_app_state.h"
#include "writer_frontend.h"
#include "writer_hal.h"
#include "writer_payload.h"

#include "nfc_byte_tutorial.h"
#include "nfc_frontend.h"
#include "nfc_tag_info.h"
#include "nero_nfc_mem_util.h"

#include <stdbool.h>
#include <stdint.h>
#include "nero_nfc_format.h"

/*
 * Local writer heuristic (not a spec value): keep a comfortable MLEN floor so a
 * freshly written short URL leaves headroom for later re-writes. Expressed in
 * the CC's 8-byte MLEN units.
 */
enum { kWriterType5MinMlenUnits = 8u };

static const uint8_t kWriterType5ShortCcTemplate[NFC_TAG_T5T_CC_LEN_SHORT] = {
  NFC_FORUM_CC_MAGIC, NFC_T5T_CC_VERSION, 0x00u, 0x00u};

static int iso15693_transceive_glue(const uint8_t *tx, uint16_t tx_len, uint8_t *rx,
                                    uint16_t rx_max, uint16_t timeout_ms) {
  if (((tx == NERO_NFC_NULL) && (tx_len != 0u)) || (rx == NERO_NFC_NULL)) {
    return -1;
  }
  return writer_frontend_iso15693_transceive(tx, tx_len, rx, rx_max, timeout_ms);
}

bool writer_tag_write_type5_inventory_step(void) {
  return nfc_frontend_iso15693_inventory(iso15693_transceive_glue, writer_app_uid15);
}

/*
 * Standard 1-byte addressed read/write — works on every NFC Forum Type 5
 * Capability Container (block 0..0xFF). ST25TV02KC only implements this form;
 * ST25DV* implements both 1-byte and 2-byte addressed forms but our short
 * URL NDEF lives well below block 0xFF, so 1-byte is sufficient.
 */
static int iso15693_read(uint8_t block, uint8_t *buf, uint8_t buf_len) {
  return nfc_frontend_iso15693_read_block(iso15693_transceive_glue, writer_app_uid15, block, buf,
                                          buf_len);
}

static bool iso15693_write(uint8_t block, const uint8_t *data, uint8_t data_len) {
  uint8_t rb[NFC_TAG_T5T_ISO15693_SYS_INFO_UID_FIELD_LEN];

  if ((data == NERO_NFC_NULL) || (data_len == 0u) || (data_len > sizeof(rb))) {
    return false;
  }

  /*
   * Some ST25TV write responses are easy to miss in stream mode after the
   * EEPROM programming delay. The tag content is authoritative, so always
   * verify by reading the block back after the write cycle. ST25DV/ST25TV
   * data sheets specify a typical RF write time of 5 ms per block; 8 ms leaves
   * margin before the verifying read.
   */
  (void)nfc_frontend_iso15693_write_block(iso15693_transceive_glue, writer_app_uid15, block, data,
                                          data_len);
  writer_hal_delay_ms(NFC_TAG_T5T_RF_WRITE_SETTLE_MS);
  if (iso15693_read(block, rb, data_len) < (int)data_len) {
    return false;
  }
  for (uint8_t i = 0u; i < data_len; i++) {
    if (!nero_nfc_span_ok((size_t)i, 1u, (size_t)data_len) || rb[i] != data[i]) {
      return false;
    }
  }
  return true;
}

static bool writer_type5_write_unit(uint16_t unit, const uint8_t *data, uint8_t data_len) {
  if ((data == NERO_NFC_NULL) || (data_len != NFC_STORAGE_TYPE5_BLOCK_SIZE) || (unit > UINT8_MAX)) {
    return false;
  }
  return iso15693_write((uint8_t)unit, data, data_len);
}

/*
 * Type 5 NDEF layout ([T5T-ISO15693] section 4.3.1 one-byte-address CC):
 *   block 0 (CC): E1 40 <MLEN> 00
 *   block 1+ : 03 <len> D1 01 <plen> 55 04 <suffix> FE 00...
 *   block 2+ : NDEF TLV when the tag already uses an 8-byte extended CC
 *
 * CC magic E1h is the NFC Forum one-byte block-address mode per [T5T-ISO15693] section 4.3.1.
 * MLEN counts T5T_Area size in NFC_TAG_T5T_AREA_SIZE_UNIT_BYTES units.
 * GetSystemInfo block count when available comes from [T5T-ISO15693] section 10.3.4 /
 * [T5T-ISO15693-ST25DV] section 7.6.23 (ST25TV02KC per [T5T-ISO15693-ST25TV] DS13304 does not
 * implement it).
 */
bool writer_tag_write_type5_impl(void) {
  uint8_t tlv[WRITER_NDEF_MAX_BYTES];
  uint16_t total = writer_payload_build_tlv(&writer_app_payload, tlv, sizeof(tlv));
  uint8_t mlen;
  uint16_t nb_blocks = 0u;
  uint8_t blk_size = NFC_STORAGE_TYPE5_BLOCK_SIZE;
  uint16_t blocks_needed;
  uint8_t cc_block[NFC_TAG_T5T_CC_LEN_EXTENDED] = {
    NFC_FORUM_CC_MAGIC, NFC_T5T_CC_VERSION, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u};
  uint16_t cc_len = NFC_TAG_T5T_CC_LEN_SHORT;
  uint16_t first_data_block = 1u;
  bool write_cc = true;

  if (!writer_payload_configured(&writer_app_payload)) {
    nero_nfc_log_write(
      "  ERROR: no payload configured — enter url/text/wifi/ndef-hex/... first\r\n");
    return false;
  }
  if (total == 0u) {
    nero_nfc_log_line("  ERROR: NDEF too large for buffer");
    return false;
  }

  /*
   * Probe tag geometry. [T5T-ISO15693] section 10.3.4 Get System Info is mandatory on
   * compliant VICCs (including ST25TV02KC); if a non-compliant VICC does not
   * answer, fall back to a conservative block size.
   */
  if (!nfc_frontend_iso15693_get_system_info(iso15693_transceive_glue, writer_app_uid15, &nb_blocks,
                                             &blk_size)) {
    blk_size = NFC_STORAGE_TYPE5_BLOCK_SIZE;
  }
  if (blk_size != NFC_STORAGE_TYPE5_BLOCK_SIZE) {
    nero_nfc_log_line("  ERROR: only 4-byte block tags supported");
    return false;
  }
  {
    uint8_t existing_cc[NFC_TAG_T5T_CC_LEN_EXTENDED];
    int existing_cc_len = iso15693_read(0u, existing_cc, NFC_STORAGE_TYPE5_BLOCK_SIZE);
    if (existing_cc_len >= (int)NFC_TAG_T5T_CC_LEN_SHORT) {
      nfc_tag_type5_info_t cc_info;
      const bool ndef_magic =
        (existing_cc[0] == NFC_FORUM_CC_MAGIC) || (existing_cc[0] == NFC_T5T_CC_MAGIC_8BYTE);
      const uint16_t declared_cc_len = nfc_storage_type5_declared_cc_len_from_first_block(
        existing_cc, (uint16_t)NFC_TAG_T5T_CC_LEN_SHORT);
      if (ndef_magic && declared_cc_len == (uint16_t)NFC_TAG_T5T_CC_LEN_EXTENDED) {
        int cc_tail_len = iso15693_read(1u, existing_cc + NFC_STORAGE_TYPE5_BLOCK_SIZE,
                                        NFC_STORAGE_TYPE5_BLOCK_SIZE);
        existing_cc_len = (cc_tail_len >= (int)NFC_TAG_T5T_CC_LEN_SHORT)
                            ? (int)NFC_TAG_T5T_CC_LEN_EXTENDED
                            : (int)NFC_TAG_T5T_CC_LEN_SHORT;
      }
      nero_nfc_zero_bytes(&cc_info, sizeof(cc_info));
      nfc_tag_type5_apply_cc(&cc_info, existing_cc, (uint8_t)existing_cc_len);
      if (cc_info.cc_valid && !cc_info.write_access_open) {
        nero_nfc_log_line("  ERROR: Type 5 tag reports write access restricted");
        return false;
      }
      if (cc_info.cc_valid) {
        cc_len = (uint16_t)existing_cc_len;
        first_data_block = (uint16_t)(cc_len / NFC_STORAGE_TYPE5_BLOCK_SIZE);
        if (!nero_nfc_copy_bytes(cc_block, sizeof(cc_block), 0u, existing_cc, cc_len)) {
          return false;
        }
      }
    }
  }

  /*
   * MLEN is in 8-byte units. We need ceil(total / 8) at minimum, and cap
   * against (nb_blocks - 1) * 4 / 8 (block 0 is the CC, not user data).
   */
  mlen =
    (uint8_t)((total + NFC_TAG_T5T_AREA_SIZE_UNIT_BYTES - 1u) / NFC_TAG_T5T_AREA_SIZE_UNIT_BYTES);
  if (mlen < kWriterType5MinMlenUnits) {
    mlen = kWriterType5MinMlenUnits; /* keep a comfortable headroom for future re-writes */
  }
  if (nb_blocks > first_data_block) {
    uint16_t avail_bytes =
      (uint16_t)((nb_blocks - first_data_block) * NFC_STORAGE_TYPE5_BLOCK_SIZE);
    uint16_t mlen_max = (uint16_t)(avail_bytes / NFC_TAG_T5T_AREA_SIZE_UNIT_BYTES);
    if (mlen_max > UINT8_MAX) {
      mlen_max = UINT8_MAX;
    }
    if (mlen > mlen_max) {
      mlen = (uint8_t)mlen_max;
    }
  }
  if (cc_len == (uint16_t)NFC_TAG_T5T_CC_LEN_EXTENDED) {
    write_cc = false;
  } else if (((cc_block[0] == NFC_FORUM_CC_MAGIC) || (cc_block[0] == NFC_T5T_CC_MAGIC_8BYTE)) &&
             (cc_block[NFC_TAG_T5T_CC_MLEN_BYTE_INDEX] >= mlen)) {
    write_cc = false;
  } else {
    if ((cc_block[0] != NFC_FORUM_CC_MAGIC) && (cc_block[0] != NFC_T5T_CC_MAGIC_8BYTE)) {
      if (!nero_nfc_copy_bytes(cc_block, sizeof(cc_block), 0u, kWriterType5ShortCcTemplate,
                               sizeof(kWriterType5ShortCcTemplate))) {
        return false;
      }
    }
    cc_block[NFC_TAG_T5T_CC_MLEN_BYTE_INDEX] = mlen;
    cc_len = NFC_TAG_T5T_CC_LEN_SHORT;
    first_data_block = 1u;
  }

  if (!nfc_storage_ceil_units_u16(total, NFC_STORAGE_TYPE5_BLOCK_SIZE, &blocks_needed) ||
      (blocks_needed == 0u)) {
    nero_nfc_log_line("  ERROR: invalid Type 5 NDEF storage length");
    return false;
  }
  if (nb_blocks != 0u) {
    uint16_t last_data_block = 0u;
    const uint32_t data_area_raw =
      (nb_blocks > first_data_block)
        ? ((uint32_t)(nb_blocks - first_data_block) * NFC_STORAGE_TYPE5_BLOCK_SIZE)
        : 0u;
    if (data_area_raw > UINT16_MAX) {
      nero_nfc_log_line("  ERROR: Type 5 geometry exceeds supported writer range");
      return false;
    }
    const uint16_t data_area_size = (uint16_t)data_area_raw;
    if (!nfc_storage_type5_data_blocks(cc_len, data_area_size, blk_size, nb_blocks,
                                       &first_data_block, &last_data_block) ||
        (((uint32_t)first_data_block + (uint32_t)blocks_needed - 1u) > last_data_block)) {
      nero_nfc_log_line("  ERROR: NDEF too big for this tag");
      return false;
    }
  }
  if (((uint32_t)first_data_block + (uint32_t)blocks_needed) >
      (NFC_TAG_T5T_ISO15693_BLOCK_ADDR_1BYTE_MAX + 1u)) {
    nero_nfc_log_line("  ERROR: NDEF would exceed 1-byte addressing range");
    return false;
  }

  {
    nero_nfc_log_write("\r\n  ── Writing NDEF (Type 5) ──\r\n  CC: ");
    for (uint8_t i = 0u; i < cc_len; i++) {
      nero_nfc_log_hex_u8(cc_block[i]);
      nero_nfc_log_putc(' ');
    }
    nero_nfc_log_write("\r\n");
    nero_nfc_log_write("  Bytes (");
    do {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(total));
      nero_nfc_log_write(ndc);
    } while (0);
    nero_nfc_log_write("): ");
    for (uint16_t i = 0u; i < total; i++) {
      nero_nfc_log_hex_u8(tlv[i]);
      nero_nfc_log_putc(' ');
    }
    nero_nfc_log_write("\r\n");

    nero_nfc_log_line("\r\n  ── Byte-level explainer (write) ──");
    nfc_tutorial_t5t_cc(nero_nfc_log_putc, cc_block, (uint8_t)cc_len);
    if (write_cc) {
      nfc_tutorial_t5t_write_cmd(nero_nfc_log_putc, NERO_NFC_NULL, 0u, cc_block,
                                 NFC_STORAGE_TYPE5_BLOCK_SIZE);
    } else {
      nfc_tutorial_t5t_write_cmd(nero_nfc_log_putc, NERO_NFC_NULL, (uint8_t)first_data_block, tlv,
                                 NFC_STORAGE_TYPE5_BLOCK_SIZE);
    }
    nfc_tutorial_ndef_tlv(nero_nfc_log_putc, tlv, total);

    if (write_cc && !iso15693_write(0u, cc_block, NFC_STORAGE_TYPE5_BLOCK_SIZE)) {
      nero_nfc_log_line("  CC write FAILED");
      return false;
    }
  }

  if (!writer_tag_write_storage_tlv_units(tlv, total, first_data_block,
                                          NFC_STORAGE_TYPE5_BLOCK_SIZE, "Block",
                                          writer_type5_write_unit)) {
    return false;
  }
  nero_nfc_log_line("\r\n  *** SUCCESS - Wrote NDEF message ***\r\n");
  return true;
}
