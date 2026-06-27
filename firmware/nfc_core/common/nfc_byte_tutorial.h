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

/*
 * nfc_byte_tutorial.h — byte-level annotated dumps for the serial (CDC) console.
 *
 * These helpers print each protocol byte next to its meaning so an operator can
 * follow a complete write-then-read round on Type 2 (NFC Forum T2T) and Type 5
 * (NFC Forum T5T / ISO/IEC 15693) tags. They are diagnostic output only: they
 * never mutate tag state and never change the read/write decision paths.
 *
 * Citation key (matches nfc_tag_geometry_limits.h; normative values in
 * docs/spec-traceability.yaml, checked by make lint):
 *   [T2T-ISO14443-A]   NFC Forum Type 2 Tag Technical Specification 1.0
 *   [T5T-ISO15693]   NFC Forum Type 5 Tag Technical Specification 1.0 over ISO/IEC 15693-3
 *   [T4T-ISO14443-4]   NFC Forum Type 4 Tag Technical Specification 1.0
 *   [ISO7816-4] ISO/IEC 7816-4 (SELECT / READ BINARY / UPDATE BINARY)
 *   [T2T-ISO14443-A-NTAG21x]  NXP NTAG213/215/216 data sheet Rev. 3.2
 *   [T4T-ISO14443-4-NT4H424] NXP NTAG 424 DNA data sheet Rev. 3.0
 */

#include "nfc_ndef_tlv.h"
#include "nfc_print_utils.h"
#include "nfc_tag_geometry_limits.h"
#include "nfc_tag_info.h"
#include "nfc_frontend.h"
#include "nfc_pcsc_contactless.h"
#include "nero_nfc_mem_util.h"
#include "nero_nfc_null.h"

#include <stdint.h>

#define NFC_TUTORIAL_UINT8_SHIFT 8u
#define NFC_TUTORIAL_U16_FIELD_LEN 2u
#define NFC_TUTORIAL_T5T_CC_MLEN_U16_OFF 6u
#define NFC_TUTORIAL_NDEF_TLV_MIN_LEN 2u
#define NFC_TUTORIAL_NDEF_TLV_EXT_MIN_LEN 4u
#define NFC_TUTORIAL_NDEF_TLV_VALUE_OFF_SHORT 2u
#define NFC_TUTORIAL_NDEF_TLV_VALUE_OFF_EXT 4u
#define NFC_TUTORIAL_NDEF_TLV_LEN_FIELD_LEN 2u
#define NFC_TUTORIAL_T2T_WRITE_FRAME_PAGE_INDEX 1u
#define NFC_TUTORIAL_T2T_WRITE_DATA_BASE NFC_TAG_T2T_WRITE_CMD_DATA_OFFSET
#define NFC_TUTORIAL_T2T_FAST_READ_LAST_PAGE_INDEX 2u
#define NFC_TUTORIAL_NDEF_TLV_EXT_LEN_MSB 2u
#define NFC_TUTORIAL_NDEF_TLV_EXT_LEN_LSB 3u

static inline void nfc_tutorial_byte_line(nero_nfc_emit_fn_t emit, uint8_t value,
                                          const char *meaning) {
  if (emit == NERO_NFC_NULL) {
    return;
  }
  nero_nfc_emit_write(emit, "      ");
  nero_nfc_emit_hex_u8(emit, value);
  nero_nfc_emit_write(emit, "  ");
  nero_nfc_emit_write(emit, meaning);
  nero_nfc_emit_write(emit, "\r\n");
}

static inline void nfc_tutorial_hex_row(nero_nfc_emit_fn_t emit, const char *label,
                                        const uint8_t *data, uint16_t len) {
  if ((emit == NERO_NFC_NULL) || (label == NERO_NFC_NULL)) {
    return;
  }
  nero_nfc_emit_write(emit, "    ");
  nero_nfc_emit_write(emit, label);
  if (data != NERO_NFC_NULL) {
    for (uint16_t i = 0u; i < len; ++i) {
      emit(' ');
      nero_nfc_emit_hex_u8(emit, data[i]);
    }
  }
  nero_nfc_emit_write(emit, "\r\n");
}

/* Decoded T2T_Area / T5T_Area size in bytes from an MLEN unit count (×8). */
static inline void nfc_tutorial_print_area_bytes(nero_nfc_emit_fn_t emit, uint16_t mlen_units) {
  nero_nfc_emit_write(emit, "NDEF data area = ");
  nero_nfc_emit_dec_u32(emit, (uint32_t)mlen_units * NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES);
  nero_nfc_emit_write(emit, " bytes (");
  nero_nfc_emit_dec_u32(emit, mlen_units);
  nero_nfc_emit_write(emit, " x 8)");
}

/* --- NFC Forum Type 2 (T2T) --- */

/* CC at page NFC_TAG_T2T_CC_PAGE_INDEX. [T2T-ISO14443-A] section 4.4 — E1h magic, MLEN, RWA. */
static inline void nfc_tutorial_t2t_cc(nero_nfc_emit_fn_t emit, const uint8_t *cc) {
  if ((emit == NERO_NFC_NULL) || (cc == NERO_NFC_NULL)) {
    return;
  }
  if (!nero_nfc_span_ok(NFC_TAG_T2T_CC_ACCESS_INDEX, 1u, NFC_TAG_T2T_PAGE_SIZE_BYTES)) {
    return;
  }
  nfc_tutorial_hex_row(emit, "[T2T CC @ page 3]", cc, NFC_TAG_T2T_PAGE_SIZE_BYTES);
  nfc_tutorial_byte_line(emit, cc[0],
                         (cc[0] == (uint8_t)NFC_FORUM_CC_MAGIC)
                           ? "magic E1h: NFC Forum T2T, NDEF present ([T2T-ISO14443-A] section 4.4)"
                           : "magic: NOT E1h -> not an NDEF T2T");
  nero_nfc_emit_write(emit, "      ");
  nero_nfc_emit_hex_u8(emit, cc[1]);
  nero_nfc_emit_write(emit, "  mapping version ");
  nero_nfc_emit_dec_u32(emit,
                        (uint32_t)(cc[NFC_TAG_T2T_CC_VER_INDEX] >> NFC_TAG_CC_MAPPING_MAJOR_SHIFT));
  emit('.');
  nero_nfc_emit_dec_u32(emit, (uint32_t)(cc[NFC_TAG_T2T_CC_VER_INDEX] & NFC_TAG_CC_NIBBLE_MASK));
  nero_nfc_emit_write(emit, "\r\n");
  nero_nfc_emit_write(emit, "      ");
  nero_nfc_emit_hex_u8(emit, cc[NFC_TAG_T2T_CC_MLEN_INDEX]);
  nero_nfc_emit_write(emit, "  MLEN=0x");
  nero_nfc_emit_hex_u8(emit, cc[NFC_TAG_T2T_CC_MLEN_INDEX]);
  nero_nfc_emit_write(emit, " -> ");
  nfc_tutorial_print_area_bytes(emit, cc[NFC_TAG_T2T_CC_MLEN_INDEX]);
  nero_nfc_emit_write(emit, "\r\n");
  nero_nfc_emit_write(emit, "      ");
  nero_nfc_emit_hex_u8(emit, cc[NFC_TAG_T2T_CC_ACCESS_INDEX]);
  nero_nfc_emit_write(emit, "  access: read=");
  nero_nfc_emit_write(emit,
                      ((cc[NFC_TAG_T2T_CC_ACCESS_INDEX] & NFC_TAG_CC_ACCESS_HIGH_NIBBLE_MASK) == 0u)
                        ? "open"
                        : "restricted");
  nero_nfc_emit_write(emit, " write=");
  nero_nfc_emit_write(emit, ((cc[NFC_TAG_T2T_CC_ACCESS_INDEX] & NFC_TAG_T2T_ACK_NIBBLE_MASK) == 0u)
                              ? "open"
                              : "restricted");
  nero_nfc_emit_write(emit, "  (T2T section 4.4 RWA)\r\n");
}

/* [T2T-ISO14443-A-NTAG21x] section 10.2 / [T2T-ISO14443-A] section 5.1 — READ (30h) returns
 * NFC_TAG_T2T_READ_RESP_BYTES.
 */
static inline void nfc_tutorial_t2t_read_cmd(nero_nfc_emit_fn_t emit, uint8_t page) {
  const uint8_t frame[NFC_TAG_T2T_READ_CMD_LEN] = {NFC_FRONTEND_NTAG_CMD_READ, page};
  if (emit == NERO_NFC_NULL) {
    return;
  }
  nfc_tutorial_hex_row(emit, "[T2T READ cmd]", frame, sizeof(frame));
  nfc_tutorial_byte_line(emit, frame[0], "30h READ opcode (returns 16 bytes = 4 pages)");
  nfc_tutorial_byte_line(emit, frame[1], "start page address");
}

static inline void nfc_tutorial_t2t_fast_read_cmd(nero_nfc_emit_fn_t emit, uint8_t first_page,
                                                  uint8_t last_page) {
  const uint8_t frame[NFC_TAG_T2T_FAST_READ_CMD_LEN] = {NFC_FRONTEND_NTAG_CMD_FAST_READ, first_page,
                                                        last_page};
  if (emit == NERO_NFC_NULL) {
    return;
  }
  nfc_tutorial_hex_row(emit, "[T2T FAST_READ cmd]", frame, sizeof(frame));
  nfc_tutorial_byte_line(emit, frame[0], "3Ah FAST_READ opcode (returns pages in one response)");
  nfc_tutorial_byte_line(emit, frame[1], "first page address");
  nfc_tutorial_byte_line(emit, frame[NFC_TUTORIAL_T2T_FAST_READ_LAST_PAGE_INDEX],
                         "last page address");
}

/* [T2T-ISO14443-A-NTAG21x] section 10.4 / [T2T-ISO14443-A] section 5.2 — WRITE (A2h) one
 * NFC_TAG_T2T_PAGE_SIZE_BYTES page. */
static inline void nfc_tutorial_t2t_write_cmd(nero_nfc_emit_fn_t emit, uint8_t page,
                                              const uint8_t *data) {
  uint8_t frame[NFC_TAG_T2T_WRITE_CMD_LEN];
  if ((emit == NERO_NFC_NULL) || (data == NERO_NFC_NULL)) {
    return;
  }
  frame[0] = NFC_FRONTEND_NTAG_CMD_WRITE;
  frame[NFC_TUTORIAL_T2T_WRITE_FRAME_PAGE_INDEX] = page;
  frame[NFC_TUTORIAL_T2T_WRITE_DATA_BASE] = data[0];
  frame[NFC_TUTORIAL_T2T_WRITE_DATA_BASE + 1u] = data[1];
  frame[NFC_TUTORIAL_T2T_WRITE_DATA_BASE + NFC_TAG_T2T_PAGE_BYTE2] = data[NFC_TAG_T2T_PAGE_BYTE2];
  frame[NFC_TUTORIAL_T2T_WRITE_DATA_BASE + NFC_TAG_T2T_PAGE_BYTE3] = data[NFC_TAG_T2T_PAGE_BYTE3];
  nfc_tutorial_hex_row(emit, "[T2T WRITE cmd]", frame, sizeof(frame));
  nfc_tutorial_byte_line(emit, frame[0], "A2h WRITE opcode (one 4-byte page)");
  nfc_tutorial_byte_line(emit, frame[1], "target page address");
  nfc_tutorial_hex_row(emit, "  payload (4 data bytes):", &frame[NFC_TUTORIAL_T2T_WRITE_DATA_BASE],
                       NFC_TAG_T2T_PAGE_SIZE_BYTES);
}

/* --- NFC Forum Type 5 (T5T) / ISO 15693 --- */

/* CC at block 0. [T5T-ISO15693] section 4.3.1 — magic E1h/E2h, version+access, MLEN. */
static inline void nfc_tutorial_t5t_cc(nero_nfc_emit_fn_t emit, const uint8_t *cc_block,
                                       uint8_t cc_len) {
  uint16_t mlen_units;
  if ((emit == NERO_NFC_NULL) || (cc_block == NERO_NFC_NULL) ||
      (cc_len < NFC_TAG_T5T_CC_LEN_SHORT)) {
    return;
  }
  nfc_tutorial_hex_row(emit, "[T5T CC @ block 0]", cc_block, cc_len);
  nfc_tutorial_byte_line(
    emit, cc_block[0],
    (cc_block[0] == (uint8_t)NFC_T5T_CC_MAGIC_8BYTE)
      ? "magic E2h: T5T, 2-byte block address mode ([T5T-ISO15693] section 4.3.1)"
      : "magic E1h: T5T, 1-byte block address mode ([T5T-ISO15693] section 4.3.1)");
  {
    nero_nfc_emit_write(emit, "      ");
    nero_nfc_emit_hex_u8(emit, cc_block[1]);
    nero_nfc_emit_write(emit, "  ver ");
    nero_nfc_emit_dec_u32(
      emit, (uint32_t)(cc_block[NFC_TAG_T2T_CC_VER_INDEX] >> NFC_TAG_T5T_CC_MAPPING_MAJOR_SHIFT));
    emit('.');
    nero_nfc_emit_dec_u32(
      emit, (uint32_t)((cc_block[NFC_TAG_T2T_CC_VER_INDEX] >> NFC_TAG_T5T_CC_MAPPING_MINOR_SHIFT) &
                       NFC_TAG_T5T_CC_MAPPING_MINOR_MASK));
    nero_nfc_emit_write(emit, ", read=");
    nero_nfc_emit_write(
      emit, ((cc_block[1] & NFC_TAG_T5T_CC_ACCESS_READ_MASK) == 0u) ? "open" : "restricted");
    nero_nfc_emit_write(emit, " write=");
    nero_nfc_emit_write(
      emit, ((cc_block[1] & NFC_TAG_T5T_CC_ACCESS_WRITE_MASK) == 0u) ? "open" : "restricted");
    nero_nfc_emit_write(emit, "\r\n");
  }
  if ((cc_block[NFC_TAG_T5T_CC_MLEN_BYTE_INDEX] != 0u) || (cc_len < NFC_TAG_T5T_CC_LEN_EXTENDED)) {
    mlen_units = cc_block[NFC_TAG_T5T_CC_MLEN_BYTE_INDEX];
    nero_nfc_emit_write(emit, "      ");
    nero_nfc_emit_hex_u8(emit, cc_block[NFC_TAG_T5T_CC_MLEN_BYTE_INDEX]);
    nero_nfc_emit_write(emit, "  MLEN (4-byte CC) -> ");
    nfc_tutorial_print_area_bytes(emit, mlen_units);
    nero_nfc_emit_write(emit, "  ([T5T-ISO15693] section 4.3.1.17)\r\n");
    nfc_tutorial_byte_line(emit, cc_block[NFC_TAG_T5T_CC_FLAGS_BYTE_INDEX],
                           "feature flags (special frame / lock block / overflow)");
  } else {
    if (!nero_nfc_span_ok((size_t)NFC_TUTORIAL_T5T_CC_MLEN_U16_OFF,
                          (size_t)NFC_TUTORIAL_U16_FIELD_LEN, cc_len)) {
      return;
    }
    mlen_units = (uint16_t)(((uint16_t)cc_block[NFC_TUTORIAL_T5T_CC_MLEN_U16_OFF]
                             << NFC_TUTORIAL_UINT8_SHIFT) |
                            cc_block[NFC_TUTORIAL_T5T_CC_MLEN_U16_OFF + 1u]);
    nfc_tutorial_byte_line(
      emit, cc_block[NFC_TAG_T5T_CC_MLEN_BYTE_INDEX],
      "MLEN=00h -> extended CC: size in bytes 6..7 ([T5T-ISO15693] section 4.3.1.17)");
    nfc_tutorial_byte_line(emit, cc_block[NFC_TAG_T5T_CC_FLAGS_BYTE_INDEX], "feature flags");
    nfc_tutorial_hex_row(emit,
                         "  bytes 6..7 (16-bit MLEN):", &cc_block[NFC_TUTORIAL_T5T_CC_MLEN_U16_OFF],
                         NFC_TUTORIAL_U16_FIELD_LEN);
    nero_nfc_emit_write(emit, "      ");
    nfc_tutorial_print_area_bytes(emit, mlen_units);
    nero_nfc_emit_write(emit, "\r\n");
  }
}

/* [T5T-ISO15693] section 10.3 — ReadSingleBlock (20h), addressed mode. */
static inline void nfc_tutorial_t5t_read_cmd(nero_nfc_emit_fn_t emit, const uint8_t *uid_lsb,
                                             uint8_t block) {
  if (emit == NERO_NFC_NULL) {
    return;
  }
  nfc_tutorial_byte_line(emit, NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED,
                         "request flags: Addressed + high data rate ([T5T-ISO15693] section 7.3)");
  nfc_tutorial_byte_line(emit, NFC_TAG_T5T_ISO15693_CMD_READ_SINGLE,
                         "20h ReadSingleBlock opcode ([T5T-ISO15693] section 10.3.1)");
  if (uid_lsb != NERO_NFC_NULL) {
    nfc_tutorial_hex_row(emit, "  UID (8 bytes, LSB first):", uid_lsb,
                         NFC_TAG_T5T_ISO15693_SYS_INFO_UID_FIELD_LEN);
  }
  nfc_tutorial_byte_line(emit, block, "block number to read (4 bytes returned)");
}

static inline void nfc_tutorial_t5t_read_multiple_cmd(nero_nfc_emit_fn_t emit,
                                                      const uint8_t *uid_lsb, uint16_t first_block,
                                                      uint16_t block_count) {
  if (emit == NERO_NFC_NULL) {
    return;
  }
  nfc_tutorial_byte_line(emit, NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED,
                         "request flags: Addressed + high data rate ([T5T-ISO15693] section 7.3)");
  nfc_tutorial_byte_line(emit,
                         (first_block > NFC_TAG_T5T_ISO15693_BLOCK_ADDR_1BYTE_MAX)
                           ? NFC_TAG_T5T_ISO15693_CMD_EXT_READ_MULTIPLE
                           : NFC_TAG_T5T_ISO15693_CMD_READ_MULTIPLE,
                         "ReadMultipleBlocks opcode (23h, or 33h extended addressing)");
  if (uid_lsb != NERO_NFC_NULL) {
    nfc_tutorial_hex_row(emit, "  UID (8 bytes, LSB first):", uid_lsb,
                         NFC_TAG_T5T_ISO15693_SYS_INFO_UID_FIELD_LEN);
  }
  nero_nfc_emit_write(emit, "      first block = ");
  nero_nfc_emit_dec_u32(emit, first_block);
  nero_nfc_emit_write(emit, ", block count = ");
  nero_nfc_emit_dec_u32(emit, block_count);
  nero_nfc_emit_write(emit, " (command carries count minus one)\r\n");
}

/* [T5T-ISO15693] section 10.3.2 — WriteSingleBlock (21h), addressed mode. */
static inline void nfc_tutorial_t5t_write_cmd(nero_nfc_emit_fn_t emit, const uint8_t *uid_lsb,
                                              uint8_t block, const uint8_t *data,
                                              uint8_t data_len) {
  if (emit == NERO_NFC_NULL) {
    return;
  }
  nfc_tutorial_byte_line(emit, NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED,
                         "request flags: Addressed + high data rate");
  nfc_tutorial_byte_line(emit, NFC_TAG_T5T_ISO15693_CMD_WRITE_SINGLE,
                         "21h WriteSingleBlock opcode ([T5T-ISO15693] section 10.3.2)");
  if (uid_lsb != NERO_NFC_NULL) {
    nfc_tutorial_hex_row(emit, "  UID (8 bytes, LSB first):", uid_lsb,
                         NFC_TAG_T5T_ISO15693_SYS_INFO_UID_FIELD_LEN);
  }
  nfc_tutorial_byte_line(emit, block, "block number to write");
  if (data != NERO_NFC_NULL) {
    nfc_tutorial_hex_row(emit, "  block data:", data, data_len);
  }
}

/* --- NFC Forum Type 4 (T4T) over ISO 7816-4 / ISO-DEP --- */

/* SELECT by name (NDEF Tag Application). ISO 7816-4: 00 A4 04 00 Lc AID [Le]. */
static inline void nfc_tutorial_t4t_select_app(nero_nfc_emit_fn_t emit, const uint8_t *aid,
                                               uint8_t aid_len) {
  if (emit == NERO_NFC_NULL) {
    return;
  }
  nero_nfc_emit_write(emit, "    [T4T SELECT application]\r\n");
  nfc_tutorial_byte_line(emit, NFC_ISO7816_CLA_ISO, "CLA = 00h");
  nfc_tutorial_byte_line(emit, NFC_ISO7816_INS_SELECT, "INS = A4h SELECT (ISO 7816-4)");
  nfc_tutorial_byte_line(emit, NFC_ISO7816_P1_SELECT_BY_DF_NAME,
                         "P1 = 04h select by name (DF/AID)");
  nfc_tutorial_byte_line(emit, NFC_ISO7816_P2_SELECT_FIRST, "P2 = 00h first/only occurrence");
  if (aid != NERO_NFC_NULL) {
    nfc_tutorial_byte_line(emit, aid_len, "Lc = AID length");
    nfc_tutorial_hex_row(emit, "  AID (NDEF Tag Application D2760000850101):", aid, aid_len);
  }
}

/* SELECT by file ID. [ISO7816-4] SELECT / [T4T-ISO14443-4] section 5.4.2. */
static inline void nfc_tutorial_t4t_select_file(nero_nfc_emit_fn_t emit, uint8_t fid_hi,
                                                uint8_t fid_lo) {
  const uint8_t fid[NFC_TUTORIAL_U16_FIELD_LEN] = {fid_hi, fid_lo};
  if (emit == NERO_NFC_NULL) {
    return;
  }
  nero_nfc_emit_write(emit, "    [T4T SELECT file]\r\n");
  nfc_tutorial_byte_line(emit, NFC_ISO7816_CLA_ISO, "CLA = 00h");
  nfc_tutorial_byte_line(emit, NFC_ISO7816_INS_SELECT, "INS = A4h SELECT");
  nfc_tutorial_byte_line(emit, NFC_ISO7816_P1_SELECT_BY_FILE_ID,
                         "P1 = 00h select by EF identifier");
  nfc_tutorial_byte_line(emit, NFC_ISO7816_P2_SELECT_NO_FCI, "P2 = 0Ch no response data");
  nfc_tutorial_byte_line(emit, NFC_ISO7816_LC_SELECT_FILE_ID, "Lc = 2 (file ID length)");
  nfc_tutorial_hex_row(emit, "  file ID (E103=CC, NDEF FID from CC):", fid,
                       NFC_TUTORIAL_U16_FIELD_LEN);
}

/* [T4T-ISO14443-4] section 7.5.1 — NFC_TAG_T4T_CC_MIN_LEN-byte Capability Container file. */
static inline void nfc_tutorial_t4t_cc(nero_nfc_emit_fn_t emit, const uint8_t *cc, uint8_t cc_len) {
  uint16_t cclen;
  uint16_t mle;
  uint16_t mlc;
  uint16_t maxf;
  if ((emit == NERO_NFC_NULL) || (cc == NERO_NFC_NULL) ||
      !nero_nfc_span_ok(0u, NFC_TAG_T4T_CC_MIN_LEN, cc_len)) {
    return;
  }
  cclen = (uint16_t)(((uint16_t)cc[0] << NFC_TUTORIAL_UINT8_SHIFT) | cc[1]);
  mle = (uint16_t)(((uint16_t)cc[NFC_TAG_T4T_CC_MLE_MSB_INDEX] << NFC_TUTORIAL_UINT8_SHIFT) |
                   cc[NFC_TAG_T4T_CC_MLE_LSB_INDEX]);
  mlc = (uint16_t)(((uint16_t)cc[NFC_TAG_T4T_CC_MLC_MSB_INDEX] << NFC_TUTORIAL_UINT8_SHIFT) |
                   cc[NFC_TAG_T4T_CC_MLC_LSB_INDEX]);
  maxf = (uint16_t)(((uint16_t)cc[NFC_TAG_T4T_CC_NDEF_SIZE_MSB_INDEX] << NFC_TUTORIAL_UINT8_SHIFT) |
                    cc[NFC_TAG_T4T_CC_NDEF_SIZE_LSB_INDEX]);
  nfc_tutorial_hex_row(emit, "[T4T CC file]", cc, NFC_TAG_T4T_CC_MIN_LEN);
  nfc_tutorial_hex_row(emit, "  bytes 0..1  CCLEN =", &cc[0], NFC_TUTORIAL_U16_FIELD_LEN);
  nero_nfc_emit_write(emit, "      (");
  nero_nfc_emit_dec_u32(emit, cclen);
  nero_nfc_emit_write(emit, " bytes of CC)\r\n");
  nfc_tutorial_byte_line(emit, cc[NFC_TAG_T4T_CC_MAPPING_VER_INDEX],
                         "byte 2  mapping version (hi.lo nibble)");
  nfc_tutorial_hex_row(emit, "  bytes 3..4  MLe =", &cc[NFC_TAG_T4T_CC_MLE_MSB_INDEX],
                       NFC_TUTORIAL_U16_FIELD_LEN);
  nero_nfc_emit_write(emit, "      (max bytes per READ BINARY response = ");
  nero_nfc_emit_dec_u32(emit, mle);
  nero_nfc_emit_write(emit, ")\r\n");
  nfc_tutorial_hex_row(emit, "  bytes 5..6  MLc =", &cc[NFC_TAG_T4T_CC_MLC_MSB_INDEX],
                       NFC_TUTORIAL_U16_FIELD_LEN);
  nero_nfc_emit_write(emit, "      (max bytes per UPDATE BINARY command = ");
  nero_nfc_emit_dec_u32(emit, mlc);
  nero_nfc_emit_write(emit, ")\r\n");
  nfc_tutorial_byte_line(emit, cc[NFC_TAG_T4T_CC_NDEF_TLV_TAG_INDEX],
                         "byte 7  NDEF File Control TLV T = 04h");
  nfc_tutorial_byte_line(emit, cc[NFC_TAG_T4T_CC_NDEF_TLV_LEN_INDEX],
                         "byte 8  TLV L = 06h (6 value bytes)");
  nfc_tutorial_hex_row(emit,
                       "  bytes 9..10 NDEF file ID =", &cc[NFC_TAG_T4T_CC_NDEF_FILE_ID_MSB_INDEX],
                       NFC_TUTORIAL_U16_FIELD_LEN);
  nfc_tutorial_hex_row(emit, "  bytes 11..12 max NDEF file size =",
                       &cc[NFC_TAG_T4T_CC_NDEF_SIZE_MSB_INDEX], NFC_TUTORIAL_U16_FIELD_LEN);
  nero_nfc_emit_write(emit, "      (");
  nero_nfc_emit_dec_u32(emit, maxf);
  nero_nfc_emit_write(emit, " bytes incl. 2-byte NLEN)\r\n");
  nfc_tutorial_byte_line(emit, cc[NFC_TAG_T4T_CC_READ_ACCESS_INDEX],
                         (cc[NFC_TAG_T4T_CC_READ_ACCESS_INDEX] == NFC_ISO7816_CLA_ISO)
                           ? "byte 13 read access = 00h (open)"
                           : "byte 13 read access (restricted/proprietary)");
  nfc_tutorial_byte_line(emit, cc[NFC_TAG_T4T_CC_WRITE_ACCESS_INDEX],
                         (cc[NFC_TAG_T4T_CC_WRITE_ACCESS_INDEX] == NFC_ISO7816_CLA_ISO)
                           ? "byte 14 write access = 00h (open)"
                           : "byte 14 write access (restricted/RO/proprietary)");
}

/* READ BINARY: [ISO7816-4] / [T4T-ISO14443-4] section 5.4.3. */
static inline void nfc_tutorial_t4t_read_binary(nero_nfc_emit_fn_t emit, uint16_t offset,
                                                uint8_t le) {
  if (emit == NERO_NFC_NULL) {
    return;
  }
  nero_nfc_emit_write(emit, "    [T4T READ BINARY]\r\n");
  nfc_tutorial_byte_line(emit, NFC_ISO7816_CLA_ISO, "CLA = 00h");
  nfc_tutorial_byte_line(emit, NFC_ISO7816_INS_READ_BINARY, "INS = B0h READ BINARY");
  nfc_tutorial_byte_line(emit, (uint8_t)(offset >> NFC_TUTORIAL_UINT8_SHIFT),
                         "P1 = offset high byte");
  nfc_tutorial_byte_line(emit, (uint8_t)(offset & NFC_BYTE_VALUE_MAX), "P2 = offset low byte");
  nfc_tutorial_byte_line(emit, le, "Le = bytes to read (response ends with 90 00)");
}

/* UPDATE BINARY: [ISO7816-4] / [T4T-ISO14443-4] section 5.4.5. */
static inline void nfc_tutorial_t4t_update_binary(nero_nfc_emit_fn_t emit, uint16_t offset,
                                                  const uint8_t *data, uint8_t data_len) {
  if (emit == NERO_NFC_NULL) {
    return;
  }
  nero_nfc_emit_write(emit, "    [T4T UPDATE BINARY]\r\n");
  nfc_tutorial_byte_line(emit, NFC_ISO7816_CLA_ISO, "CLA = 00h");
  nfc_tutorial_byte_line(emit, NFC_ISO7816_INS_UPDATE_BINARY, "INS = D6h UPDATE BINARY");
  nfc_tutorial_byte_line(emit, (uint8_t)(offset >> NFC_TUTORIAL_UINT8_SHIFT),
                         "P1 = offset high byte");
  nfc_tutorial_byte_line(emit, (uint8_t)(offset & NFC_BYTE_VALUE_MAX), "P2 = offset low byte");
  nfc_tutorial_byte_line(emit, data_len, "Lc = data length");
  if (data != NERO_NFC_NULL) {
    nfc_tutorial_hex_row(emit, "  data:", data, data_len);
  }
}

/* [T4T-ISO14443-4] section 7.5.2 — NDEF file NLEN prefix (2 bytes). */
static inline void nfc_tutorial_t4t_nlen(nero_nfc_emit_fn_t emit, uint16_t nlen) {
  const uint8_t bytes[NFC_TUTORIAL_U16_FIELD_LEN] = {(uint8_t)(nlen >> NFC_TUTORIAL_UINT8_SHIFT),
                                                     (uint8_t)(nlen & NFC_BYTE_VALUE_MAX)};
  if (emit == NERO_NFC_NULL) {
    return;
  }
  nfc_tutorial_hex_row(emit, "[T4T NLEN @ NDEF file offset 0]", bytes, NFC_TUTORIAL_U16_FIELD_LEN);
  nero_nfc_emit_write(emit, "      NLEN = ");
  nero_nfc_emit_dec_u32(emit, nlen);
  nero_nfc_emit_write(emit, " byte(s) of NDEF message follow at offset 2");
  if (nlen == 0u) {
    nero_nfc_emit_write(emit, " (0000h = file empty / invalid during write)");
  }
  nero_nfc_emit_write(emit, "\r\n");
}

static inline void nfc_tutorial_ndef_message(nero_nfc_emit_fn_t emit, const uint8_t *data,
                                             uint16_t len) {
  if ((emit == NERO_NFC_NULL) || ((data == NERO_NFC_NULL) && (len != 0u))) {
    return;
  }
  nero_nfc_emit_write(emit, "    [NDEF message]\r\n");
  nero_nfc_emit_write(emit, "      byte_len = ");
  nero_nfc_emit_dec_u32(emit, len);
  nero_nfc_emit_write(emit, "\r\n");
  if (len != 0u) {
    nfc_tutorial_hex_row(emit, "  bytes:", data, len);
  }
}

/* --- Shared NDEF Message TLV ([T2T-ISO14443-A] section 5.4 / [T5T-ISO15693] section 4.5) --- */

/*
 * Annotates an NDEF Message TLV: T=03h, L (1-byte, or FFh + 2-byte form), the
 * V (NDEF message bytes), and a trailing Terminator TLV (FEh) when present.
 */
static inline void nfc_tutorial_ndef_tlv(nero_nfc_emit_fn_t emit, const uint8_t *data,
                                         uint16_t len) {
  uint16_t value_len;
  uint16_t value_off;
  if ((emit == NERO_NFC_NULL) || (data == NERO_NFC_NULL) || (len < NFC_TUTORIAL_NDEF_TLV_MIN_LEN)) {
    return;
  }
  nero_nfc_emit_write(emit, "    [NDEF Message TLV]\r\n");
  nfc_tutorial_byte_line(emit, data[0],
                         (data[0] == NFC_NDEF_TLV_MESSAGE) ? "T = 03h NDEF Message TLV"
                                                           : "T (not an NDEF Message TLV)");
  if (data[0] != NFC_NDEF_TLV_MESSAGE) {
    return;
  }
  if (data[1] == NFC_NDEF_TLV_EXTENDED_LEN) {
    if (len < NFC_TUTORIAL_NDEF_TLV_EXT_MIN_LEN) {
      return;
    }
    if (!nero_nfc_span_ok(NFC_TUTORIAL_NDEF_TLV_EXT_LEN_LSB, 1u, len)) {
      return;
    }
    value_len =
      (uint16_t)(((uint16_t)data[NFC_TUTORIAL_NDEF_TLV_EXT_LEN_MSB] << NFC_TUTORIAL_UINT8_SHIFT) |
                 data[NFC_TUTORIAL_NDEF_TLV_EXT_LEN_LSB]);
    value_off = NFC_TUTORIAL_NDEF_TLV_VALUE_OFF_EXT;
    nfc_tutorial_byte_line(emit, data[1], "L = FFh -> 3-byte length form follows");
    nfc_tutorial_hex_row(emit, "  L (16-bit):", &data[NFC_TUTORIAL_NDEF_TLV_EXT_LEN_MSB],
                         NFC_TUTORIAL_NDEF_TLV_LEN_FIELD_LEN);
  } else {
    value_len = data[1];
    value_off = NFC_TUTORIAL_NDEF_TLV_VALUE_OFF_SHORT;
    nero_nfc_emit_write(emit, "      ");
    nero_nfc_emit_hex_u8(emit, data[1]);
    nero_nfc_emit_write(emit, "  L = ");
    nero_nfc_emit_dec_u32(emit, value_len);
    nero_nfc_emit_write(emit, " byte(s)\r\n");
  }
  if (nero_nfc_span_ok((size_t)value_off, (size_t)value_len, len)) {
    nfc_tutorial_hex_row(emit, "  V (NDEF message):", &data[value_off], value_len);
    if (nero_nfc_span_ok((size_t)value_off + (size_t)value_len, 1u, len)) {
      uint8_t terminator = data[value_off + value_len];
      if (terminator == NFC_NDEF_TLV_TERMINATOR) {
        nfc_tutorial_byte_line(emit, NFC_NDEF_TLV_TERMINATOR, "Terminator TLV (end of data area)");
      }
    }
  }
}
