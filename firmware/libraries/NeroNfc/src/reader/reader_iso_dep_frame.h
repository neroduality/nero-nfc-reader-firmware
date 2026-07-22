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
#include "nero_nfc_mem_util.h"
#include "nfc_pcsc_contactless.h"
#include "reader_iso_dep_timing.h"

#include <stdbool.h>
#include <stdint.h>

/* Manifest prefixes in this ISO-DEP frame parser:
 *   [ISO14443-3] CRC-A trailer length.
 *   [ISO14443-4] PCB/CID/NAD frame layout and block-control values. */
enum {
  ISO_DEP_CRC_A_INIT = 0x6363u,
  ISO_DEP_CRC_LEN = 2u,
  ISO_DEP_PCB_CLASS_MASK = 0xC0u,
  ISO_DEP_PCB_CLASS_I_BLOCK = 0x00u,
  ISO_DEP_PCB_CLASS_R_BLOCK = 0x80u,
  ISO_DEP_PCB_CLASS_S_BLOCK = 0xC0u,
  ISO_DEP_PCB_CID_BIT = 0x08u,
  ISO_DEP_PCB_NAD_BIT = 0x04u,
  ISO_DEP_PCB_CHAIN_BIT = 0x10u,
  ISO_DEP_PCB_I_BLOCK_BASE = 0x02u,
  ISO_DEP_PCB_R_BLOCK_BASE = 0xA2u,
  /* [DERIVED] R-block recognition mask; not a standalone ISO14443-4 SPEC entry.
   */
  ISO_DEP_PCB_R_BLOCK_EXPECT_MASK = 0xE6u,
  ISO_DEP_PCB_S_WTX = 0xF2u,
  ISO_DEP_WTXM_MASK = 0x3Fu,
  ISO_DEP_BLOCK_NUM_MASK = 0x01u,
  ISO_DEP_HDR_BASE_LEN = 1u,
  ISO_DEP_CID_HDR_OFFSET = 2u,
  ISO_DEP_INF_MIN_FRAME_LEN = 3u,
  ISO_DEP_BYTE_MASK_LOW = 0x00FFu,
  ISO_DEP_BYTE_SHIFT_8 = 8u,
  ISO_DEP_BYTE_SHIFT_4 = 4u,
  ISO_DEP_SW_CONFIDENCE_NONE = 0u,
  ISO_DEP_SW_CONFIDENCE_LOW = 1u,
  ISO_DEP_SW_CONFIDENCE_HIGH = 3u,
  ISO_DEP_SW_CONFIDENCE_MORE_DATA = 4u,
  ISO_DEP_MIN_TRIM_LEN = 4u,
  ISO_DEP_SELECT_RESP_PROBE_MAX_LEN = 100u,
  ISO_DEP_SELECT_RESP_LEN_MAX = 0x07u,
  ISO_DEP_NAD_IDX_BASE = 1u,
  ISO_DEP_NAD_IDX_WITH_CID = 2u,
  ISO_DEP_INF_STATUS_TAIL_OFFSET = 2u,
  ISO_DEP_INF_STATUS_BEFORE_OFFSET = 3u,
  ISO_DEP_INF_STATUS_BEFORE_TAIL_OFFSET = 4u,
  ISO_DEP_ACK_PCB_BASE_LEN = 1u,
  ISO_DEP_CRC_MUL_SHL = 3u,
  ISO_DEP_SELECT_RESP_TAG_D = 0x64u,
  ISO_DEP_SELECT_RESP_TAG_S = 0x53u,
  ISO_DEP_SELECT_RESP_SW1_MIN = 0x63u,
  ISO_DEP_SELECT_RESP_SW1_MAX = 0x6Eu,
  READER_ISO_DEP_SW16_CONFIDENCE_NONE = 0u,
};

static inline uint16_t reader_iso_dep_crc_a(const uint8_t* buf, uint16_t len) {
  uint16_t crc = ISO_DEP_CRC_A_INIT;

  if (buf == NERO_NFC_NULL) {
    return crc;
  }
  for (uint16_t i = 0u; i < len; i++) {
    uint8_t b = (uint8_t)(buf[i] ^ (uint8_t)(crc & ISO_DEP_BYTE_MASK_LOW));
    b = (uint8_t)(b ^ (uint8_t)(b << ISO_DEP_BYTE_SHIFT_4));
    crc = (uint16_t)((crc >> ISO_DEP_BYTE_SHIFT_8) ^
                     ((uint16_t)b << ISO_DEP_BYTE_SHIFT_8) ^
                     ((uint16_t)b << ISO_DEP_CRC_MUL_SHL) ^
                     ((uint16_t)b >> ISO_DEP_BYTE_SHIFT_4));
  }
  return crc;
}

NERO_NFC_NODISCARD static inline bool reader_iso_dep_has_crc_a_suffix(
    const uint8_t* frame, uint16_t len) {
  uint16_t crc;

  if ((frame == NERO_NFC_NULL) || (len < ISO_DEP_INF_MIN_FRAME_LEN)) {
    return false;
  }
  crc = reader_iso_dep_crc_a(frame, (uint16_t)(len - ISO_DEP_CRC_LEN));
  return (nero_nfc_u8_at(frame, (size_t)(len),
                         (size_t)(len - ISO_DEP_CRC_LEN)) ==
          (uint8_t)(crc & ISO_DEP_BYTE_MASK_LOW)) &&
         (nero_nfc_u8_at(frame, (size_t)(len),
                         (size_t)(len - ISO_DEP_HDR_BASE_LEN)) ==
          (uint8_t)(crc >> ISO_DEP_BYTE_SHIFT_8));
}

static inline uint8_t reader_iso_dep_chained_crc_tail_len(uint8_t pcb,
                                                          const uint8_t* frame,
                                                          uint16_t len) {
  if (frame == NERO_NFC_NULL) {
    return 0u;
  }
  if (((pcb & ISO_DEP_PCB_CHAIN_BIT) == 0u) ||
      !reader_iso_dep_has_crc_a_suffix(frame, len)) {
    return 0u;
  }
  return ISO_DEP_CRC_LEN;
}

static inline uint8_t reader_iso_dep_sw16_confidence(uint8_t s1, uint8_t s2) {
  if (s1 == (uint8_t)NFC_ISO7816_SW1_MORE_DATA) {
    return ISO_DEP_SW_CONFIDENCE_MORE_DATA;
  }
  if ((s1 == (uint8_t)NFC_ISO7816_SW1_SUCCESS) &&
      (s2 == (uint8_t)NFC_ISO7816_SW2_SUCCESS)) {
    return ISO_DEP_SW_CONFIDENCE_HIGH;
  }
  if ((s1 >= (uint8_t)NFC_ISO7816_SW1_WRONG_LENGTH_ALT) &&
      (s1 <= (uint8_t)NFC_ISO7816_SW1_GENERAL_ERROR)) {
    return ISO_DEP_SW_CONFIDENCE_HIGH;
  }
  if ((s1 >= (uint8_t)NFC_ISO7816_SW1_WARNING_MIN) &&
      (s1 <= (uint8_t)NFC_ISO7816_SW1_GENERAL_ERROR)) {
    return ISO_DEP_SW_CONFIDENCE_LOW;
  }
  return ISO_DEP_SW_CONFIDENCE_NONE;
}

static inline uint16_t reader_iso_dep_trim_crc_suffix(const uint8_t* buf,
                                                      uint16_t len) {
  uint8_t tail_confidence;
  uint8_t before_tail_confidence;

  if ((buf == NERO_NFC_NULL) || (len < ISO_DEP_MIN_TRIM_LEN)) {
    return len;
  }

  tail_confidence = reader_iso_dep_sw16_confidence(
      nero_nfc_u8_at(buf, (size_t)(len),
                     (size_t)(len - ISO_DEP_INF_STATUS_TAIL_OFFSET)),
      nero_nfc_u8_at(buf, (size_t)(len), (size_t)(len - ISO_DEP_HDR_BASE_LEN)));
  before_tail_confidence = reader_iso_dep_sw16_confidence(
      nero_nfc_u8_at(buf, (size_t)(len),
                     (size_t)(len - ISO_DEP_INF_STATUS_BEFORE_TAIL_OFFSET)),
      nero_nfc_u8_at(buf, (size_t)(len),
                     (size_t)(len - ISO_DEP_INF_STATUS_BEFORE_OFFSET)));
  /* CRC-A can resemble a 6xxx status. If a terminal success or continuation
   * status is immediately before it, keep that status unless the tail is the
   * host-visible 61xx continuation itself. */
  if (((nero_nfc_u8_at(buf, (size_t)(len),
                       (size_t)(len - ISO_DEP_INF_STATUS_BEFORE_TAIL_OFFSET)) ==
        (uint8_t)NFC_ISO7816_SW1_MORE_DATA) ||
       ((nero_nfc_u8_at(
             buf, (size_t)(len),
             (size_t)(len - ISO_DEP_INF_STATUS_BEFORE_TAIL_OFFSET)) ==
         (uint8_t)NFC_ISO7816_SW1_SUCCESS) &&
        (nero_nfc_u8_at(buf, (size_t)(len),
                        (size_t)(len - ISO_DEP_INF_STATUS_BEFORE_OFFSET)) ==
         (uint8_t)NFC_ISO7816_SW2_SUCCESS))) &&
      (nero_nfc_u8_at(buf, (size_t)(len),
                      (size_t)(len - ISO_DEP_INF_STATUS_TAIL_OFFSET)) !=
       (uint8_t)NFC_ISO7816_SW1_MORE_DATA)) {
    return (uint16_t)(len - ISO_DEP_CRC_LEN);
  }
  if ((before_tail_confidence != ISO_DEP_SW_CONFIDENCE_NONE) &&
      ((tail_confidence == ISO_DEP_SW_CONFIDENCE_NONE) ||
       (before_tail_confidence > tail_confidence))) {
    return (uint16_t)(len - ISO_DEP_CRC_LEN);
  }
  return len;
}

static inline uint8_t reader_iso_dep_rx_hdr_skip(uint8_t pcb) {
  uint8_t n = ISO_DEP_HDR_BASE_LEN;

  if ((pcb & ISO_DEP_PCB_CID_BIT) != 0u) {
    n++;
  }
  if ((pcb & ISO_DEP_PCB_NAD_BIT) != 0u) {
    n++;
  }
  return n;
}

NERO_NFC_NODISCARD static inline bool
reader_iso_dep_inf_first_plausible_select_resp(uint8_t b) {
  if ((b == (uint8_t)NFC_ISO7816_SW1_MORE_DATA) ||
      (b == (uint8_t)NFC_ISO7816_SW1_WARNING_MIN) ||
      (b == ISO_DEP_SELECT_RESP_TAG_D) ||
      (b == (uint8_t)NFC_ISO7816_SW1_WRONG_LENGTH_ALT) ||
      (b == (uint8_t)NFC_ISO7816_SW1_GENERAL_ERROR) ||
      (b == ISO_DEP_SELECT_RESP_TAG_S) ||
      (b == NFC_CBOR_HEADER_ONE_BYTE_TEXT) ||
      (b == (uint8_t)NFC_ISO7816_SW1_SUCCESS)) {
    return true;
  }
  if ((b >= ISO_DEP_SELECT_RESP_SW1_MIN) &&
      (b <= ISO_DEP_SELECT_RESP_SW1_MAX)) {
    return true;
  }
  return false;
}

static inline uint8_t reader_iso_dep_pick_inf_offset(const uint8_t* rx,
                                                     int rlen, bool pcb_has_cid,
                                                     uint8_t cid, bool have_tc,
                                                     uint8_t tc_byte) {
  uint8_t pcb;
  uint8_t nstd;

  if ((rlen < 1) || (rx == NERO_NFC_NULL)) {
    return 0u;
  }

  pcb = rx[0];
  nstd = reader_iso_dep_rx_hdr_skip(pcb);
  if (((pcb & ISO_DEP_PCB_CLASS_MASK) != ISO_DEP_PCB_CLASS_I_BLOCK) ||
      !pcb_has_cid) {
    return nstd;
  }

  if ((cid != 0u) && (rlen >= ISO_DEP_MIN_TRIM_LEN) &&
      ((pcb & ISO_DEP_PCB_CID_BIT) == 0u) &&
      (nero_nfc_u8_at(rx, (size_t)(rlen), (size_t)(ISO_DEP_HDR_BASE_LEN)) ==
       cid)) {
    return ISO_DEP_CID_HDR_OFFSET;
  }

  if (have_tc && ((tc_byte & ISO_DEP_BLOCK_NUM_MASK) != 0u) &&
      ((pcb & ISO_DEP_PCB_CID_BIT) != 0u) &&
      ((pcb & ISO_DEP_PCB_NAD_BIT) == 0u) &&
      ((pcb & ISO_DEP_PCB_CHAIN_BIT) == 0u) &&
      (nstd >= ISO_DEP_CID_HDR_OFFSET) &&
      (rlen >= (int)nstd + ISO_DEP_INF_MIN_FRAME_LEN) &&
      (rlen <= ISO_DEP_SELECT_RESP_PROBE_MAX_LEN)) {
    uint8_t fa = rx[nstd];
    uint8_t fb = rx[(uint8_t)(nstd + ISO_DEP_HDR_BASE_LEN)];

    if ((fa <= ISO_DEP_SELECT_RESP_LEN_MAX) &&
        reader_iso_dep_inf_first_plausible_select_resp(fb)) {
      return (uint8_t)(nstd + ISO_DEP_HDR_BASE_LEN);
    }
  }

  return nstd;
}

static inline uint8_t reader_iso_dep_rx_nad_byte(const uint8_t* rx, int rlen,
                                                 uint8_t pcb,
                                                 uint8_t default_nad) {
  uint8_t nad_idx = ISO_DEP_NAD_IDX_BASE;

  if ((pcb & ISO_DEP_PCB_CID_BIT) != 0u) {
    nad_idx = ISO_DEP_NAD_IDX_WITH_CID;
  }
  if (((pcb & ISO_DEP_PCB_NAD_BIT) != 0u) && (rx != NERO_NFC_NULL) &&
      (rlen > (int)nad_idx)) {
    return rx[nad_idx];
  }
  return default_nad;
}

NERO_NFC_NODISCARD static inline bool reader_iso_dep_rx_i_block_number_matches(
    const uint8_t* rx, int rlen, uint8_t expected_block) {
  uint8_t pcb;
  uint8_t need_hdr;

  if ((rx == NERO_NFC_NULL) || (rlen < 1)) {
    return false;
  }
  pcb = rx[0];
  if ((pcb & ISO_DEP_PCB_CLASS_MASK) != ISO_DEP_PCB_CLASS_I_BLOCK) {
    return false;
  }
  need_hdr = reader_iso_dep_rx_hdr_skip(pcb);
  if (rlen < (int)need_hdr) {
    return false;
  }
  /* [ISO14443-4] block-numbering rules A/B — the PCD accepts an I-block
   * only when its block number equals the PCD's current block number. */
  return (pcb & ISO_DEP_BLOCK_NUM_MASK) ==
         (expected_block & ISO_DEP_BLOCK_NUM_MASK);
}

static inline uint16_t reader_iso_dep_wtx_response_timeout_ms(
    uint32_t fwt_us, const uint8_t* rx, int rlen, uint8_t hdr_skip) {
  uint32_t base_ms =
      (fwt_us + ISO_DEP_US_TO_MS_ROUND_UP) / (ISO_DEP_US_TO_MS_ROUND_UP + 1u);
  uint32_t wait_ms;
  uint8_t wtxm = ISO_DEP_WTXM_MIN;

  if ((rx != NERO_NFC_NULL) && (rlen > (int)hdr_skip)) {
    wtxm = (uint8_t)(rx[hdr_skip] & ISO_DEP_WTXM_MASK);
    if ((wtxm < ISO_DEP_WTXM_MIN) || (wtxm > ISO_DEP_WTXM_MAX)) {
      wtxm = ISO_DEP_WTXM_MIN;
    }
  }
  wait_ms = (base_ms * (uint32_t)wtxm) + ISO_DEP_LINK_TIMEOUT_MARGIN_MS;
  if (wait_ms < ISO_DEP_LINK_TIMEOUT_MIN_MS) {
    wait_ms = ISO_DEP_LINK_TIMEOUT_MIN_MS;
  }
  if (wait_ms > ISO_DEP_WTX_TIMEOUT_MAX_MS) {
    wait_ms = ISO_DEP_WTX_TIMEOUT_MAX_MS;
  }
  return (uint16_t)wait_ms;
}

NERO_NFC_NODISCARD static inline bool reader_iso_dep_i_block_inf_len(
    const uint8_t* rx, int rlen, uint8_t inf_off, uint8_t pcb,
    uint16_t* inf_len_out, uint8_t* crc_tail_len_out) {
  uint16_t frame_inf_len;
  uint8_t crc_tail_len;

  if ((rx == NERO_NFC_NULL) || (inf_len_out == NERO_NFC_NULL) || (rlen < 0)) {
    return false;
  }
  *inf_len_out = 0u;
  if (crc_tail_len_out != NERO_NFC_NULL) {
    *crc_tail_len_out = 0u;
  }
  if (rlen < (int)inf_off + ISO_DEP_INF_STATUS_TAIL_OFFSET) {
    return false;
  }

  frame_inf_len = (uint16_t)((uint16_t)rlen - (uint16_t)inf_off);
  crc_tail_len = reader_iso_dep_chained_crc_tail_len(pcb, rx, (uint16_t)rlen);
  if (frame_inf_len < crc_tail_len) {
    return false;
  }

  *inf_len_out = (uint16_t)(frame_inf_len - crc_tail_len);
  if (crc_tail_len_out != NERO_NFC_NULL) {
    *crc_tail_len_out = crc_tail_len;
  }
  return true;
}

NERO_NFC_NODISCARD static inline bool reader_iso_dep_rx_rblock_block(
    const uint8_t* rx, int rlen, bool expect_nak, bool pcb_has_cid, uint8_t cid,
    uint8_t* block_out) {
  uint8_t pcb;
  uint8_t need_hdr;

  if ((rx == NERO_NFC_NULL) || (block_out == NERO_NFC_NULL) || (rlen < 1)) {
    return false;
  }
  pcb = rx[0];
  need_hdr = reader_iso_dep_rx_hdr_skip(pcb);
  if (rlen < (int)need_hdr) {
    return false;
  }
  if ((pcb & ISO_DEP_PCB_R_BLOCK_EXPECT_MASK) != ISO_DEP_PCB_R_BLOCK_BASE) {
    return false;
  }
  if (((pcb & ISO_DEP_PCB_CHAIN_BIT) != 0u) != expect_nak) {
    return false;
  }
  if (pcb_has_cid) {
    if ((pcb & ISO_DEP_PCB_CID_BIT) == 0u) {
      return false;
    }
    if (rx[ISO_DEP_HDR_BASE_LEN] != cid) {
      return false;
    }
  }
  *block_out = (uint8_t)(pcb & ISO_DEP_BLOCK_NUM_MASK);
  return true;
}

NERO_NFC_NODISCARD static inline bool reader_iso_dep_rx_is_chain_ack_for_block(
    const uint8_t* rx, int rlen, uint8_t blk_sent, bool pcb_has_cid,
    uint8_t cid, uint8_t* ack_block_out) {
  uint8_t block = 0u;

  if (!reader_iso_dep_rx_rblock_block(rx, rlen, false, pcb_has_cid, cid,
                                      &block)) {
    return false;
  }
  /* [ISO14443-4] §7.5.4 Rule 8 — during PCD chaining the PICC acknowledges a
   * chained I-block with an R(ACK) whose block number equals the received
   * I-block's block number (== blk_sent). Require exactly that; do not tolerate
   * the toggled value. */
  if (block != (blk_sent & ISO_DEP_BLOCK_NUM_MASK)) {
    return false;
  }
  if (ack_block_out != NERO_NFC_NULL) {
    *ack_block_out = block;
  }
  return true;
}

NERO_NFC_NODISCARD static inline bool reader_iso_dep_rx_is_chain_nak_for_block(
    const uint8_t* rx, int rlen, uint8_t blk_sent, bool pcb_has_cid,
    uint8_t cid) {
  uint8_t block = 0u;

  if (!reader_iso_dep_rx_rblock_block(rx, rlen, true, pcb_has_cid, cid,
                                      &block)) {
    return false;
  }
  return (block == (blk_sent & ISO_DEP_BLOCK_NUM_MASK)) ||
         (block ==
          ((blk_sent ^ ISO_DEP_BLOCK_NUM_MASK) & ISO_DEP_BLOCK_NUM_MASK));
}

NERO_NFC_NODISCARD static inline bool reader_iso_dep_build_chained_ack(
    uint8_t* ack_out, uint8_t ack_cap, uint8_t block_num, bool pcb_has_cid,
    uint8_t cid, uint8_t* ack_len_out) {
  uint8_t ack_pcb = (uint8_t)(ISO_DEP_PCB_R_BLOCK_BASE |
                              (block_num & ISO_DEP_BLOCK_NUM_MASK));
  uint8_t ack_pos = ISO_DEP_ACK_PCB_BASE_LEN;

  if ((ack_out == NERO_NFC_NULL) || (ack_len_out == NERO_NFC_NULL) ||
      (ack_cap < ISO_DEP_ACK_PCB_BASE_LEN)) {
    return false;
  }
  *ack_len_out = 0u;
  if (pcb_has_cid) {
    ack_pcb = (uint8_t)(ack_pcb | ISO_DEP_PCB_CID_BIT);
  }

  if (!nero_nfc_store_u8(ack_out, (size_t)(ack_cap), (size_t)(0), ack_pcb)) {
    return false;
  }
  if (pcb_has_cid) {
    if (ack_pos >= ack_cap) {
      return false;
    }
    if (!nero_nfc_store_u8(ack_out, (size_t)(ack_cap), (size_t)(ack_pos++),
                           cid)) {
      return false;
    }
  }
  *ack_len_out = ack_pos;
  return true;
}

NERO_NFC_NODISCARD static inline bool
reader_iso_dep_apdu_response_has_status_word(const uint8_t* rsp,
                                             uint16_t rsp_len) {
  if ((rsp == NERO_NFC_NULL) || (rsp_len < NFC_ISO7816_SW_STATUS_WORD_LEN)) {
    return false;
  }
  return (nero_nfc_u8_at(rsp, (size_t)(rsp_len),
                         (size_t)(rsp_len - ISO_DEP_INF_STATUS_TAIL_OFFSET)) ==
          NFC_ISO7816_SW1_SUCCESS) ||
         ((nero_nfc_u8_at(rsp, (size_t)(rsp_len),
                          (size_t)(rsp_len - ISO_DEP_INF_STATUS_TAIL_OFFSET)) ==
           NFC_ISO7816_SW1_MORE_DATA_VENDOR) &&
          (nero_nfc_u8_at(rsp, (size_t)(rsp_len),
                          (size_t)(rsp_len - ISO_DEP_HDR_BASE_LEN)) ==
           NFC_ISO7816_SW2_SUCCESS)) ||
         ((nero_nfc_u8_at(rsp, (size_t)(rsp_len),
                          (size_t)(rsp_len - ISO_DEP_INF_STATUS_TAIL_OFFSET)) >=
           NFC_ISO7816_SW1_MORE_DATA) &&
          (nero_nfc_u8_at(rsp, (size_t)(rsp_len),
                          (size_t)(rsp_len - ISO_DEP_INF_STATUS_TAIL_OFFSET)) <=
           NFC_ISO7816_SW1_GENERAL_ERROR));
}
