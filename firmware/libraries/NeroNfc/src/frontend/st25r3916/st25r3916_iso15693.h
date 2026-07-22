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
#include "st25r3916_types.h"

/* ISO 15693 / NFC-V wire values (ISO/IEC 15693-3); literals keep this header C.
 */
#define ISO15693_CMD_STAY_QUIET 0x02u
#define ISO15693_CMD_LOCK_BLOCK 0x22u
#define ISO15693_CMD_READ_MULTIPLE_BLOCK 0x23u
#define ISO15693_CMD_SELECT 0x25u
#define ISO15693_CMD_RESET_TO_READY 0x26u
#define ISO15693_CMD_EXT_READ_MULTIPLE 0x33u

#define ISO15693_FLAG_SUBCARRIER 0x01u
#define ISO15693_FLAG_DATA_RATE 0x02u
#define ISO15693_FLAG_INVENTORY 0x04u
#define ISO15693_FLAG_SELECT 0x10u
#define ISO15693_FLAG_ADDRESS 0x20u
#define ISO15693_FLAG_OPTION 0x40u
#define ISO15693_FLAG_INVENTORY_1_SLOT 0x20u

#define ISO15693_FLAGS_INVENTORY                                 \
  ((uint8_t)(ISO15693_FLAG_DATA_RATE | ISO15693_FLAG_INVENTORY | \
             ISO15693_FLAG_INVENTORY_1_SLOT))

#define ST25_ISO15693_UID_LEN 8u

enum {
  K_ST25_V_DIBIT3 = 3u,
  K_ST25_V_INFO_FLAG_MEM_SIZE = 0x08u, /* may not be used */
  K_ST25_V_EXT_READ_CMD_CAP = 12u,
  K_ST25_V_EXT_WRITE_CMD_CAP = 16u,
  K_ST25_V_IDX0 = 0u,
  K_ST25_V_IDX1 = 1u,
};

uint16_t st25_iso15693_crc16(const uint8_t* data, uint16_t len);

NERO_NFC_NODISCARD bool st25_iso15693_stream_put1of4(uint8_t data, uint8_t* out,
                                                     uint16_t out_max,
                                                     uint16_t* pos);

/*
 * ST25R3916 subcarrier-stream mode is deliberately low-level: it shifts stream
 * symbols from FIFO and does not generate ISO 15693 SOF/EOF, 1-of-4 coding, or
 * CRC. Encode the VCD request exactly as RFAL does: SOF, 1-of-4 LSB-first data,
 * inverted ISO 15693 CRC, EOF.
 */
NERO_NFC_NODISCARD bool st25_iso15693_stream_encode(const uint8_t* tx,
                                                    uint16_t tx_len,
                                                    uint8_t* out,
                                                    uint16_t out_max,
                                                    uint16_t* out_len);

uint8_t st25_iso15693_stream_bit(const uint8_t* buf, uint16_t buf_len,
                                 uint16_t bit_pos);

/*
 * Decode the VICC Manchester stream returned by the ST25R3916 FIFO. On success,
 * the caller receives only the ISO 15693 response bytes; the trailing two CRC
 * bytes are checked and stripped.
 */
int st25_iso15693_stream_decode(const uint8_t* in, uint16_t in_len,
                                uint8_t* out, uint16_t out_max);

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
 *   3. Set BIT_RATE = BR_TX_26 | BR_RX_26 (TX and RX subcarrier-rate code 0x2
 * in each nibble → register value 0x22; see [ST25R3916] DS12484 section 4.5.5).
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
void st25_iso15693_configure_defaults(st25_write_reg_fn_t write_reg,
                                      st25_write_reg_fn_t write_reg_b,
                                      st25_reg_bits_fn_t set_reg_bits,
                                      st25_reg_bits_fn_t clr_reg_bits,
                                      st25_delay_ms_fn_t delay_ms);

/*
 * Issues a generic ISO 15693 frame with CRC. Returns the FIFO byte count from
 * the response, or 0 on failure. The caller's transceive function is expected
 * to enable CRC append and 16-bit no-response-timer steps suitable for
 * ISO 15693 (≈10 ms typical).
 */
typedef int (*st25_iso15693_transceive_fn_t)(void* context, const uint8_t* tx,
                                             uint16_t tx_len, uint8_t* rx,
                                             uint16_t rx_max,
                                             uint16_t timeout_ms);

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
NERO_NFC_NODISCARD bool st25_iso15693_inventory(
    st25_iso15693_transceive_fn_t transceive, void* context,
    uint8_t uid_out[ST25_ISO15693_UID_LEN]);

/*
 * Standard (1-byte block address) single block read. Required for tags that
 * do not implement the extended commands (e.g. ST25TV02KC, which only has
 * 80 user blocks and only supports the standard commands per its datasheet
 * DS13304). ST25DV* tags also support this form for blocks 0..0xFF.
 */
int st25_iso15693_read_block(st25_iso15693_transceive_fn_t transceive,
                             void* context,
                             const uint8_t uid[ST25_ISO15693_UID_LEN],
                             uint8_t block_addr, uint8_t* buf, uint8_t buf_len);

/*
 * Standard (1-byte block address) single block write. ST25TV02KC postpones the
 * response when Option_flag=1 until the reader sends a later isolated EOF; this
 * lightweight transceive path does not implement that second EOF exchange, so
 * writes use Option_flag=0 and wait for the normal write-alike response.
 */
NERO_NFC_NODISCARD bool st25_iso15693_write_block(
    st25_iso15693_transceive_fn_t transceive, void* context,
    const uint8_t uid[ST25_ISO15693_UID_LEN], uint8_t block_addr,
    const uint8_t* data, uint8_t data_len);

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
NERO_NFC_NODISCARD bool st25_iso15693_get_system_info(
    st25_iso15693_transceive_fn_t transceive, void* context,
    const uint8_t uid[ST25_ISO15693_UID_LEN], uint16_t* nb_blocks_out,
    uint8_t* block_size_out);

/*
 * Extended (2-byte block address) single block read. Used by ST25DV* and
 * ST25TV* tags whose memory exceeds 256 blocks or whose system area lives
 * above 0x00FF.
 */
int st25_iso15693_ext_read_block(st25_iso15693_transceive_fn_t transceive,
                                 void* context,
                                 const uint8_t uid[ST25_ISO15693_UID_LEN],
                                 uint16_t block_addr, uint8_t* buf,
                                 uint8_t buf_len);

/*
 * Extended single block write. The no-option form keeps the write timing inside
 * a single request/response exchange; Option_flag=1 would require a subsequent
 * isolated EOF before the tag answers.
 */
NERO_NFC_NODISCARD bool st25_iso15693_ext_write_block(
    st25_iso15693_transceive_fn_t transceive, void* context,
    const uint8_t uid[ST25_ISO15693_UID_LEN], uint16_t block_addr,
    const uint8_t* data, uint8_t data_len);
