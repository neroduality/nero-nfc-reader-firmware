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
 * st25r3916_iso15693.h
 *
 * Header-only ISO 15693 / NFC Forum Type 5 helpers for the ST25R3916B reader.
 * Provides:
 *   - configure_defaults: switch the ST25R3916 into ISO 15693 reader mode
 *   - inventory: single-slot anticollision returning an 8-byte UID
 *   - read_single_block / write_single_block (1-byte block address)
 *   - extended_read_single_block / extended_write_single_block (2-byte block
 * address)
 *
 * All addresses are 16-bit little-endian on the wire per ISO/IEC 15693 and the
 * ST25DV / ST25TV "extended" command extensions used for tags larger than 256
 * blocks. Block size is tag-specific (4 bytes on ST25DV64KC, 4 bytes on
 * ST25TV02KC) and is supplied by the caller.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "nero_nfc_attrs.h"
#include "nero_nfc_null.h"
#include "nero_nfc_mem_util.h"
#include "nfc_tag_geometry_limits.h"
#include "rfal_nfcv.h"
#include "st25_sketch_spi.h"
#include "st25r3916_runtime.h"

/* ISO 15693 / NFC-V wire values — NFC-RFAL rfal_nfcv.h */
#define ISO15693_CMD_INVENTORY RFAL_NFCV_CMD_INVENTORY
#define ISO15693_CMD_STAY_QUIET RFAL_NFCV_CMD_SLPV
#define ISO15693_CMD_READ_SINGLE_BLOCK RFAL_NFCV_CMD_READ_SINGLE_BLOCK
#define ISO15693_CMD_WRITE_SINGLE_BLOCK RFAL_NFCV_CMD_WRITE_SINGLE_BLOCK
#define ISO15693_CMD_LOCK_BLOCK RFAL_NFCV_CMD_LOCK_BLOCK
#define ISO15693_CMD_READ_MULTIPLE_BLOCK RFAL_NFCV_CMD_READ_MULTIPLE_BLOCKS
#define ISO15693_CMD_SELECT RFAL_NFCV_CMD_SELECT
#define ISO15693_CMD_RESET_TO_READY RFAL_NFCV_CMD_RESET_TO_READY
#define ISO15693_CMD_EXT_READ_SINGLE RFAL_NFCV_CMD_EXTENDED_READ_SINGLE_BLOCK
#define ISO15693_CMD_EXT_WRITE_SINGLE RFAL_NFCV_CMD_EXTENDED_WRITE_SINGLE_BLOCK
#define ISO15693_CMD_EXT_READ_MULTIPLE RFAL_NFCV_CMD_EXTENDED_READ_MULTIPLE_BLOCK

#define ISO15693_FLAG_SUBCARRIER RFAL_NFCV_REQ_FLAG_SUB_CARRIER
#define ISO15693_FLAG_DATA_RATE RFAL_NFCV_REQ_FLAG_DATA_RATE
#define ISO15693_FLAG_INVENTORY RFAL_NFCV_REQ_FLAG_INVENTORY
#define ISO15693_FLAG_SELECT RFAL_NFCV_REQ_FLAG_SELECT
#define ISO15693_FLAG_ADDRESS RFAL_NFCV_REQ_FLAG_ADDRESS
#define ISO15693_FLAG_OPTION RFAL_NFCV_REQ_FLAG_OPTION
#define ISO15693_FLAG_INVENTORY_1_SLOT RFAL_NFCV_REQ_FLAG_NB_SLOTS

#define ISO15693_FLAGS_INVENTORY                                                                   \
  ((uint8_t)(ISO15693_FLAG_DATA_RATE | ISO15693_FLAG_INVENTORY | ISO15693_FLAG_INVENTORY_1_SLOT))

#define ST25_ISO15693_UID_LEN RFAL_NFCV_UID_LEN
#define ST25_ISO15693_STREAM_SOF_1OF4 0x21u
#define ST25_ISO15693_STREAM_EOF_1OF4 0x04u
#define ST25_ISO15693_STREAM_00_1OF4 0x02u
#define ST25_ISO15693_STREAM_01_1OF4 0x08u
#define ST25_ISO15693_STREAM_10_1OF4 0x20u
#define ST25_ISO15693_STREAM_11_1OF4 0x80u
#define ST25_ISO15693_MAX_STREAM_FRAME 128u

static inline uint16_t st25_iso15693_crc16(const uint8_t *data, uint16_t len) {
  uint16_t crc = 0xFFFFu;

  if (data == NERO_NFC_NULL) {
    return 0u;
  }
  for (uint16_t i = 0u; i < len; i++) {
    crc ^= data[i];
    for (uint8_t bit = 0u; bit < 8u; bit++) {
      if ((crc & 0x0001u) != 0u) {
        crc = (uint16_t)((crc >> 1) ^ 0x8408u);
      } else {
        crc = (uint16_t)(crc >> 1);
      }
    }
  }
  return (uint16_t)~crc;
}

NERO_NFC_NODISCARD static inline bool
st25_iso15693_stream_put_1of4(uint8_t data, uint8_t *out, uint16_t out_max, uint16_t *pos) {
  if ((out == NERO_NFC_NULL) || (pos == NERO_NFC_NULL) || ((uint16_t)(*pos + 4u) > out_max)) {
    return false;
  }
  for (uint8_t i = 0u; i < 4u; i++) {
    switch (data & 0x03u) {
    case 0u:
      out[(*pos)++] = ST25_ISO15693_STREAM_00_1OF4;
      break;
    case 1u:
      out[(*pos)++] = ST25_ISO15693_STREAM_01_1OF4;
      break;
    case 2u:
      out[(*pos)++] = ST25_ISO15693_STREAM_10_1OF4;
      break;
    default:
      out[(*pos)++] = ST25_ISO15693_STREAM_11_1OF4;
      break;
    }
    data >>= 2;
  }
  return true;
}

/*
 * ST25R3916 subcarrier-stream mode is deliberately low-level: it shifts stream
 * symbols from FIFO and does not generate ISO 15693 SOF/EOF, 1-of-4 coding, or
 * CRC. Encode the VCD request exactly as RFAL does: SOF, 1-of-4 LSB-first data,
 * inverted ISO 15693 CRC, EOF.
 */
NERO_NFC_NODISCARD static inline bool st25_iso15693_stream_encode(const uint8_t *tx,
                                                                  uint16_t tx_len, uint8_t *out,
                                                                  uint16_t out_max,
                                                                  uint16_t *out_len) {
  uint16_t pos = 0u;
  uint16_t crc;

  if (out_len != NERO_NFC_NULL) {
    *out_len = 0u;
  }
  if ((tx == NERO_NFC_NULL) || (out == NERO_NFC_NULL) || (out_len == NERO_NFC_NULL) ||
      (tx_len == 0u) || (out_max < 2u)) {
    return false;
  }

  out[pos++] = ST25_ISO15693_STREAM_SOF_1OF4;
  for (uint16_t i = 0u; i < tx_len; i++) {
    if (!st25_iso15693_stream_put_1of4(tx[i], out, out_max, &pos)) {
      return false;
    }
  }
  crc = st25_iso15693_crc16(tx, tx_len);
  if (!st25_iso15693_stream_put_1of4((uint8_t)(crc & 0xFFu), out, out_max, &pos) ||
      !st25_iso15693_stream_put_1of4((uint8_t)(crc >> 8), out, out_max, &pos)) {
    return false;
  }
  if (pos >= out_max) {
    return false;
  }
  out[pos++] = ST25_ISO15693_STREAM_EOF_1OF4;
  *out_len = pos;
  return true;
}

static inline uint8_t st25_iso15693_stream_bit(const uint8_t *buf, uint16_t bit_pos) {
  return (uint8_t)((buf[bit_pos / 8u] >> (bit_pos % 8u)) & 0x01u);
}

/*
 * Decode the VICC Manchester stream returned by the ST25R3916 FIFO. On success,
 * the caller receives only the ISO 15693 response bytes; the trailing two CRC
 * bytes are checked and stripped.
 */
static inline int st25_iso15693_stream_decode(const uint8_t *in, uint16_t in_len, uint8_t *out,
                                              uint16_t out_max) {
  uint8_t tmp[ST25_ISO15693_MAX_STREAM_FRAME];
  uint16_t manchester_pos = 5u;
  uint16_t bit_pos = 0u;
  uint16_t byte_len;
  uint16_t crc;

  if ((in == NERO_NFC_NULL) || (out == NERO_NFC_NULL) || (in_len < 3u) ||
      (in_len > ST25_ISO15693_MAX_STREAM_FRAME) || ((in[0] & 0x1Fu) != 0x17u)) {
    return -1;
  }

  for (uint16_t i = 0u; i < sizeof(tmp); i++) {
    tmp[i] = 0u;
  }

  while ((uint16_t)(manchester_pos + 1u) < (uint16_t)(in_len * 8u)) {
    uint8_t man;

    if (((bit_pos % 8u) == 0u) && ((manchester_pos / 8u + 1u) < in_len) &&
        ((in[manchester_pos / 8u] & 0xE0u) == 0xA0u) && (in[(manchester_pos / 8u) + 1u] == 0x03u)) {
      break;
    }
    if (bit_pos >= (uint16_t)(sizeof(tmp) * 8u)) {
      return -1;
    }

    man = st25_iso15693_stream_bit(in, manchester_pos);
    man = (uint8_t)(man |
                    (uint8_t)(st25_iso15693_stream_bit(in, (uint16_t)(manchester_pos + 1u)) << 1));
    if (man == 0x02u) {
      tmp[bit_pos / 8u] |= (uint8_t)(1u << (bit_pos % 8u));
    } else if (man != 0x01u) {
      return -1;
    }
    bit_pos++;
    manchester_pos = (uint16_t)(manchester_pos + 2u);
  }

  if ((bit_pos == 0u) || ((bit_pos % 8u) != 0u)) {
    return -1;
  }
  byte_len = (uint16_t)(bit_pos / 8u);
  if ((byte_len <= 2u) || ((uint16_t)(byte_len - 2u) > out_max)) {
    return -1;
  }

  crc = st25_iso15693_crc16(tmp, (uint16_t)(byte_len - 2u));
  if ((tmp[byte_len - 2u] != (uint8_t)(crc & 0xFFu)) ||
      (tmp[byte_len - 1u] != (uint8_t)(crc >> 8))) {
    return -1;
  }
  for (uint16_t i = 0u; i < (uint16_t)(byte_len - 2u); i++) {
    out[i] = tmp[i];
  }
  return (int)(byte_len - 2u);
}

/*
 * Configures the ST25R3916B for ISO 15693 single-subcarrier high-data-rate
 * mode (26.48 kbps) and enables TX+RX.
 *
 * The previous version of this helper wrote MODE_OM_ISO15693 = 0x20 which is
 * actually NFC-Forum Type 1 (Topaz) initiator on the ST25R3916, NOT ISO
 * 15693. Tags such as ST25TV02KC silently ignore the request in that mode
 * and the writer would never detect them. The corrected value is OM=1110 →
 * 0x70, which the datasheet labels "subcarrier-stream initiator" and is
 * what the official ST RFAL library uses for NFC-V.
 *
 * Sequence (mirrors the ST RFAL `rfalNfcvAnalogConfig`/`InitMode15693` flow,
 * cross-checked against [ST25R3916] DS12484 section 4.5):
 *   1. Stop ongoing operations and clear FIFO so we don't fight a stale TX
 *      from a previous 14443-A WUPA.
 *   2. Set MODE = OM=ISO15693, TR_AM=0 (OOK, ISO 15693 is OOK from reader to
 *      tag and Manchester-coded subcarrier from tag to reader).
 *   3. Set BIT_RATE = BR_TX_26 | BR_RX_26 (TX and RX subcarrier-rate code 0x2 in
 *      each nibble → register value 0x22; see [ST25R3916] DS12484 section 4.5.5).
 *   4. Set STREAM_MODE = scf_sc424 | scp_8pulses | stx_106 (sub-carrier fc/32,
 *      8 pulses per bit period) — required when MODE.OM = subcarrier-stream so
 *      the reader's TX modulator generates
 *      ISO 15693-compatible 1-of-256 / 1-of-4 envelopes.
 *   5. Reset RX_CONF1..4 back to the chip defaults (the 14443-A configure
 *      helper changes them) so the demodulator chain is matched to ISO
 *      15693's 423 kHz Manchester subcarrier rather than 14443-A's
 *      Miller-coded 106 kHz envelope.
 *   6. Enable TX+RX in OP_CONTROL.
 */
static inline void st25_iso15693_configure_defaults(st25_write_reg_fn_t write_reg,
                                                    st25_write_reg_fn_t write_reg_b,
                                                    st25_reg_bits_fn_t set_reg_bits,
                                                    st25_reg_bits_fn_t clr_reg_bits,
                                                    st25_delay_ms_fn_t delay_ms) {
  if ((write_reg == NERO_NFC_NULL) || (write_reg_b == NERO_NFC_NULL) ||
      (set_reg_bits == NERO_NFC_NULL) || (clr_reg_bits == NERO_NFC_NULL) ||
      (delay_ms == NERO_NFC_NULL)) {
    return;
  }
  write_reg(ST25R3916_REG_MODE, ST25R3916_REG_MODE_om_subcarrier_stream);
  write_reg(ST25R3916_REG_BIT_RATE, BR_TX_26 | BR_RX_26);
  write_reg(ST25R3916_REG_STREAM_MODE, STREAM_MODE_ISO15693_26KBPS);
  /*
   * ST RFAL ST25R3916B NFC-V analog config:
   *   TX: OOK + pulse length 0x1C
   *   RX: RX_CONF1=0x13, RX_CONF2=0xED, CORR_CONF1=0x13, CORR_CONF2=0x01
   * These differ from the 14443-A/default receiver values and are needed for
   * the 423 kHz ISO 15693 subcarrier response from ST25TV/ST25DV tags.
   */
  write_reg(ST25R3916_REG_ISO14443A_NFC, 0x1Cu);
  write_reg(ST25R3916_REG_RX_CONF1, 0x13u);
  write_reg(ST25R3916_REG_RX_CONF2, 0xEDu);
  write_reg(ST25R3916_REG_RX_CONF3, 0x00u);
  write_reg(ST25R3916_REG_RX_CONF4, 0x00u);
  write_reg_b(REGB_CORR_CONF1, 0x13u);
  write_reg_b(REGB_CORR_CONF2, 0x01u);
  clr_reg_bits(ST25R3916_REG_AUX, ST25R3916_REG_AUX_dis_corr);
  set_reg_bits(ST25R3916_REG_OP_CONTROL,
               ST25R3916_REG_OP_CONTROL_tx_en | ST25R3916_REG_OP_CONTROL_rx_en);
  delay_ms(5u);
}

/*
 * Issues a generic ISO 15693 frame with CRC. Returns the FIFO byte count from
 * the response, or 0 on failure. The caller's transceive function is expected
 * to enable CRC append and 16-bit no-response-timer steps suitable for
 * ISO 15693 (≈10 ms typical).
 */
typedef int (*st25_iso15693_transceive_fn_t)(const uint8_t *tx, uint16_t tx_len, uint8_t *rx,
                                             uint16_t rx_max, uint16_t timeout_ms);

/*
 * Single-slot inventory. On success, copies the 8-byte UID (MSB first) into
 * uid_out and returns true. Single-slot mode means at most one tag may be in
 * the field; multi-slot inventory is not implemented because the only Type 5
 * tags supported here (ST25DV / ST25TV) are normally tested one-at-a-time.
 *
 * The wire UID is little-endian per ISO/IEC 15693. We reverse it here so
 * downstream code sees the conventional MSB-first form used in datasheets and
 * smartphone NFC stacks.
 */
NERO_NFC_NODISCARD static inline bool
st25_iso15693_inventory(st25_iso15693_transceive_fn_t transceive,
                        uint8_t uid_out[ST25_ISO15693_UID_LEN]) {
  uint8_t cmd[3];
  uint8_t rx[12];
  int rlen;

  if (uid_out != NERO_NFC_NULL) {
    for (uint8_t i = 0u; i < ST25_ISO15693_UID_LEN; i++) {
      uid_out[i] = 0u;
    }
  }
  if ((transceive == NERO_NFC_NULL) || (uid_out == NERO_NFC_NULL)) {
    return false;
  }

  cmd[0] = (uint8_t)(ISO15693_FLAGS_INVENTORY); /* 1-slot inventory */
  cmd[1] = ISO15693_CMD_INVENTORY;
  cmd[2] = 0x00u; /* mask length = 0 */

  rlen = transceive(cmd, sizeof(cmd), rx, sizeof(rx), 30u);
  if (rlen < 10) {
    return false;
  }
  if ((rx[0] & 0x01u) != 0u) {
    return false; /* response error flag */
  }
  /* rx[0]=flags, rx[1]=DSFID, rx[2..9]=UID (LSB first). Skip DSFID, then
   * reverse the 8-byte UID. */
  for (uint8_t i = 0u; i < ST25_ISO15693_UID_LEN; i++) {
    uid_out[i] = rx[2u + (ST25_ISO15693_UID_LEN - 1u - i)];
  }
  return true;
}

/*
 * Standard (1-byte block address) single block read. Required for tags that
 * do not implement the extended commands (e.g. ST25TV02KC, which only has
 * 80 user blocks and only supports the standard commands per its datasheet
 * DS13304). ST25DV* tags also support this form for blocks 0..0xFF.
 */
static inline int st25_iso15693_read_block(st25_iso15693_transceive_fn_t transceive,
                                           const uint8_t uid[ST25_ISO15693_UID_LEN],
                                           uint8_t block_addr, uint8_t *buf, uint8_t buf_len) {
  uint8_t cmd[12];
  uint8_t rx[36];
  int rlen;
  uint8_t copy_len;
  uint8_t n = 0u;

  if ((transceive == NERO_NFC_NULL) || (uid == NERO_NFC_NULL) || (buf == NERO_NFC_NULL)) {
    return -1;
  }

  cmd[n++] = NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED;
  cmd[n++] = ISO15693_CMD_READ_SINGLE_BLOCK;
  for (uint8_t i = 0u; i < ST25_ISO15693_UID_LEN; i++) {
    cmd[n++] = uid[ST25_ISO15693_UID_LEN - 1u - i];
  }
  cmd[n++] = block_addr;

  rlen = transceive(cmd, n, rx, sizeof(rx), 30u);
  if (rlen < 2) {
    return -1;
  }
  if ((rx[0] & 0x01u) != 0u) {
    return -1;
  }
  copy_len = (uint8_t)(rlen - 1);
  if (copy_len > buf_len) {
    copy_len = buf_len;
  }
  if (!nero_nfc_copy_bytes(buf, buf_len, 0u, &rx[1], copy_len)) {
    return -1;
  }
  return (int)copy_len;
}

/*
 * Standard (1-byte block address) single block write. ST25TV02KC postpones the
 * response when Option_flag=1 until the reader sends a later isolated EOF; this
 * lightweight transceive path does not implement that second EOF exchange, so
 * writes use Option_flag=0 and wait for the normal write-alike response.
 */
NERO_NFC_NODISCARD static inline bool
st25_iso15693_write_block(st25_iso15693_transceive_fn_t transceive,
                          const uint8_t uid[ST25_ISO15693_UID_LEN], uint8_t block_addr,
                          const uint8_t *data, uint8_t data_len) {
  uint8_t cmd[16];
  uint8_t rx[4];
  int rlen;
  uint8_t n = 0u;

  if ((transceive == NERO_NFC_NULL) || (uid == NERO_NFC_NULL) || (data == NERO_NFC_NULL) ||
      (data_len == 0u) || (data_len > 8u)) {
    return false;
  }

  cmd[n++] = NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED;
  cmd[n++] = ISO15693_CMD_WRITE_SINGLE_BLOCK;
  for (uint8_t i = 0u; i < ST25_ISO15693_UID_LEN; i++) {
    cmd[n++] = uid[ST25_ISO15693_UID_LEN - 1u - i];
  }
  cmd[n++] = block_addr;
  for (uint8_t i = 0u; i < data_len; i++) {
    cmd[n++] = data[i];
  }

  rlen = transceive(cmd, n, rx, sizeof(rx), 60u);
  if (rlen < 1) {
    return false;
  }
  return (rx[0] & 0x01u) == 0u;
}

/*
 * GetSystemInformation (0x2B). On success, returns true and reports the
 * tag's last-block address (NB_BLOCK) and block size (in bytes). The DSFID,
 * AFI and IC reference fields are ignored here. This lets the writer pick
 * 1-byte vs 2-byte block-addressed commands at runtime.
 *
 * Frame layout per [T5T-ISO15693] section 10.3.4:
 *   resp_flags | INFO_FLAGS | UID(8) | [DSFID] | [AFI] | [MEMSIZE_LSB
 * MEMSIZE_MSB] | [IC_REF] MEMSIZE_LSB = "Number of blocks" (NB_BLOCK),
 * MEMSIZE_MSB low 5 bits = block_size-1.
 */
NERO_NFC_NODISCARD static inline bool
st25_iso15693_get_system_info(st25_iso15693_transceive_fn_t transceive,
                              const uint8_t uid[ST25_ISO15693_UID_LEN], uint16_t *nb_blocks_out,
                              uint8_t *block_size_out) {
  uint8_t cmd[12];
  uint8_t rx[16];
  int rlen;
  uint8_t info_flags;
  uint8_t pos;
  uint8_t n = 0u;

  if (nb_blocks_out != NERO_NFC_NULL) {
    *nb_blocks_out = 0u;
  }
  if (block_size_out != NERO_NFC_NULL) {
    *block_size_out = 0u;
  }
  if (transceive == NERO_NFC_NULL) {
    return false;
  }

  cmd[n++] = NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED;
  cmd[n++] = NFC_TAG_T5T_ISO15693_CMD_GET_SYS_INFO;
  if (uid != NERO_NFC_NULL) {
    for (uint8_t i = 0u; i < ST25_ISO15693_UID_LEN; i++) {
      cmd[n++] = uid[ST25_ISO15693_UID_LEN - 1u - i];
    }
  } else {
    /*
     * Spec allows unaddressed GetSystemInfo (Address flag = 0). Re-encode
     * the request flags accordingly so the tag does not expect the UID.
     */
    cmd[0] = ISO15693_FLAG_DATA_RATE;
  }

  rlen = transceive(cmd, n, rx, sizeof(rx), 30u);
  if (rlen < 11) {
    return false;
  }
  if ((rx[0] & 0x01u) != 0u) {
    return false;
  }

  info_flags = rx[1];
  pos = (uint8_t)(2u + ST25_ISO15693_UID_LEN);
  if ((info_flags & 0x01u) != 0u) {
    pos++; /* skip DSFID */
  }
  if ((info_flags & 0x02u) != 0u) {
    pos++; /* skip AFI */
  }
  if ((info_flags & 0x04u) != 0u) {
    if ((uint16_t)(pos + 2u) > (uint16_t)rlen) {
      return false;
    }
    if (nb_blocks_out != NERO_NFC_NULL) {
      *nb_blocks_out = (uint16_t)((uint16_t)rx[pos] + 1u);
    }
    if (block_size_out != NERO_NFC_NULL) {
      *block_size_out = (uint8_t)((rx[pos + 1u] & 0x1Fu) + 1u);
    }
    return true;
  }
  return false;
}

/*
 * Extended (2-byte block address) single block read. Used by ST25DV* and
 * ST25TV* tags whose memory exceeds 256 blocks or whose system area lives
 * above 0x00FF.
 */
static inline int st25_iso15693_ext_read_block(st25_iso15693_transceive_fn_t transceive,
                                               const uint8_t uid[ST25_ISO15693_UID_LEN],
                                               uint16_t block_addr, uint8_t *buf, uint8_t buf_len) {
  uint8_t cmd[12];
  uint8_t rx[36];
  int rlen;
  uint8_t copy_len;
  uint8_t n = 0u;

  if ((transceive == NERO_NFC_NULL) || (uid == NERO_NFC_NULL) || (buf == NERO_NFC_NULL)) {
    return -1;
  }

  cmd[n++] =
    (uint8_t)(NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED | NFC_TAG_T5T_ISO15693_FLAG_PROTOCOL_EXTENSION);
  cmd[n++] = ISO15693_CMD_EXT_READ_SINGLE;
  for (uint8_t i = 0u; i < ST25_ISO15693_UID_LEN; i++) {
    cmd[n++] = uid[ST25_ISO15693_UID_LEN - 1u - i];
  }
  cmd[n++] = (uint8_t)(block_addr & 0xFFu);
  cmd[n++] = (uint8_t)(block_addr >> 8);

  rlen = transceive(cmd, n, rx, sizeof(rx), 30u);
  if (rlen < 2) {
    return -1;
  }
  if ((rx[0] & 0x01u) != 0u) {
    return -1; /* tag returned an error code */
  }
  copy_len = (uint8_t)(rlen - 1);
  if (copy_len > buf_len) {
    copy_len = buf_len;
  }
  if (!nero_nfc_copy_bytes(buf, buf_len, 0u, &rx[1], copy_len)) {
    return -1;
  }
  return (int)copy_len;
}

/*
 * Extended single block write. The no-option form keeps the write timing inside
 * a single request/response exchange; Option_flag=1 would require a subsequent
 * isolated EOF before the tag answers.
 */
NERO_NFC_NODISCARD static inline bool
st25_iso15693_ext_write_block(st25_iso15693_transceive_fn_t transceive,
                              const uint8_t uid[ST25_ISO15693_UID_LEN], uint16_t block_addr,
                              const uint8_t *data, uint8_t data_len) {
  uint8_t cmd[16];
  uint8_t rx[4];
  int rlen;
  uint8_t n = 0u;

  if ((transceive == NERO_NFC_NULL) || (uid == NERO_NFC_NULL) || (data == NERO_NFC_NULL) ||
      (data_len == 0u) || (data_len > 8u)) {
    return false;
  }

  cmd[n++] =
    (uint8_t)(NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED | NFC_TAG_T5T_ISO15693_FLAG_PROTOCOL_EXTENSION);
  cmd[n++] = ISO15693_CMD_EXT_WRITE_SINGLE;
  for (uint8_t i = 0u; i < ST25_ISO15693_UID_LEN; i++) {
    cmd[n++] = uid[ST25_ISO15693_UID_LEN - 1u - i];
  }
  cmd[n++] = (uint8_t)(block_addr & 0xFFu);
  cmd[n++] = (uint8_t)(block_addr >> 8);
  for (uint8_t i = 0u; i < data_len; i++) {
    cmd[n++] = data[i];
  }

  /*
   * Programming time: ST25DV / ST25TV datasheets specify ≤5 ms typical.
   * 60 ms is generous and forgiving of weak coupling.
   */
  rlen = transceive(cmd, n, rx, sizeof(rx), 60u);
  if (rlen < 1) {
    return false;
  }
  return (rx[0] & 0x01u) == 0u;
}
