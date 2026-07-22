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
#include "nero_nfc_attrs.h"
#include "reader_context.h"
#include "reader_iso_dep_apdu_relay.h"
#include "reader_iso_dep_frame.h"
#include "reader_iso_dep_ats.h"

#include <stdbool.h>
#include <stdint.h>

NERO_NFC_NODISCARD static inline bool
reader_security_key_iso_dep_commit_rats_rx(int rlen, const uint8_t* rx,
                                           uint8_t rats_param) {
  uint8_t tl;

  if ((rlen < READER_ISO_DEP_ATS_MIN_LEN) || (rx == NERO_NFC_NULL)) {
    return false;
  }
  /* [ISO14443-4] §5.2.5 — ATS byte 0 (TL) is the authoritative ATS length
   * including itself. Bound storage by TL (not the raw RF receive length, which
   * may carry trailing CRC), and fail closed on a truncated or oversized ATS
   * rather than relaying a partial ATS as success. */
  tl = nero_nfc_u8_at(rx, (size_t)(rlen), 0u);
  if ((tl < READER_ISO_DEP_ATS_MIN_LEN) ||
      ((uint16_t)(tl) > (uint16_t)(rlen)) ||
      ((size_t)(tl) > sizeof(G_ATS_DATA))) {
    return false;
  }
  G_ATS_LEN = tl;
  if (!nero_nfc_copy_bytes(G_ATS_DATA, sizeof(G_ATS_DATA), 0u, rx, G_ATS_LEN)) {
    return false;
  }
  G_ISO_DEP_RATS_PARAM = rats_param;
  G_BLOCK_NUM = 0u;
  return true;
}

NERO_NFC_NODISCARD static inline bool
reader_security_key_iso_dep_probe_can_upgrade_cid(void) {
  return G_ISO_DEP_HAVE_TC &&
         ((G_ISO_DEP_TC_BYTE & READER_ISO_DEP_ATS_TC_CID_BIT) != 0u) &&
         !G_ISO_DEP_PCB_HAS_CID;
}

NERO_NFC_NODISCARD static inline bool
reader_security_key_iso_dep_tx_include_nad(void) {
  return G_ISO_DEP_HAVE_TC &&
         ((G_ISO_DEP_TC_BYTE & READER_ISO_DEP_ATS_TC_NAD_BIT) != 0u);
}

static inline uint8_t reader_security_key_iso_dep_tx_hdr_len(
    bool include_nad_byte) {
  return reader_iso_dep_i_block_tx_hdr_len(
      G_ISO_DEP_PCB_HAS_CID,
      include_nad_byte && reader_security_key_iso_dep_tx_include_nad());
}

static inline void reader_security_key_iso_dep_snap_raw_rx(const uint8_t* rx,
                                                           int rlen) {
  int n = rlen;

  if ((rlen <= 0) || (rx == NERO_NFC_NULL)) {
    G_ISO_DEP_RAW_RX_LEN = 0u;
    return;
  }
  n = NERO_NFC_MIN(n, (int)(ISO_DEP_RAW_RX_CAP));
  G_ISO_DEP_RAW_RX_LEN = (uint8_t)(n);
  (void)nero_nfc_copy_bytes(G_ISO_DEP_RAW_RX, ISO_DEP_RAW_RX_CAP, 0u, rx,
                            (size_t)(n));
}

static inline uint8_t reader_security_key_iso_dep_pick_inf_offset(
    const uint8_t* rx, int rlen) {
  return reader_iso_dep_pick_inf_offset(rx, rlen, G_ISO_DEP_PCB_HAS_CID,
                                        G_ISO_DEP_CID, G_ISO_DEP_HAVE_TC,
                                        G_ISO_DEP_TC_BYTE);
}

static inline uint16_t reader_security_key_iso_dep_apdu_chunk_budget(
    uint8_t tx_hdr_len) {
  return reader_iso_dep_apdu_chunk_budget(G_ISO_DEP_PIC_FRAME_MAX, tx_hdr_len);
}

NERO_NFC_NODISCARD static inline bool reader_security_key_iso_dep_tx_add_nad(
    uint16_t full_apdu_len, const uint8_t* apdu) {
  uint8_t hw;

  if (!reader_security_key_iso_dep_tx_include_nad()) {
    return false;
  }
  if (!G_ISO_DEP_PCB_HAS_CID) {
    return false;
  }
  if ((apdu != NERO_NFC_NULL) && (full_apdu_len >= 1u) &&
      (nero_nfc_u8_at(apdu, full_apdu_len, 0u) ==
       (uint8_t)(NFC_ISO7816_CLA_PROPRIETARY_SHORT))) {
    return false;
  }
  hw = reader_security_key_iso_dep_tx_hdr_len(true);
  return full_apdu_len <= reader_security_key_iso_dep_apdu_chunk_budget(hw);
}

static inline uint8_t reader_security_key_iso_dep_rx_nad_byte(const uint8_t* rx,
                                                              int rlen,
                                                              uint8_t pcb) {
  return reader_iso_dep_rx_nad_byte(rx, rlen, pcb, ISO_DEP_TX_NAD_VALUE);
}

static inline uint16_t reader_security_key_iso_dep_wtx_response_timeout_ms(
    const uint8_t* rx, int rlen, uint8_t hdr_skip) {
  return reader_iso_dep_wtx_response_timeout_ms(G_ISO_DEP_FWT_US, rx, rlen,
                                                hdr_skip);
}

NERO_NFC_NODISCARD static inline bool
reader_security_key_iso_dep_rx_is_chain_ack_for_block(const uint8_t* rx,
                                                      int rlen,
                                                      uint8_t blk_sent,
                                                      uint8_t* ack_block_out) {
  return reader_iso_dep_rx_is_chain_ack_for_block(
      rx, rlen, blk_sent, G_ISO_DEP_PCB_HAS_CID, G_ISO_DEP_CID, ack_block_out);
}

NERO_NFC_NODISCARD static inline bool
reader_security_key_iso_dep_rx_is_chain_nak_for_block(const uint8_t* rx,
                                                      int rlen,
                                                      uint8_t blk_sent) {
  return reader_iso_dep_rx_is_chain_nak_for_block(
      rx, rlen, blk_sent, G_ISO_DEP_PCB_HAS_CID, G_ISO_DEP_CID);
}

#ifdef __cplusplus
extern "C" {
#endif

NERO_NFC_NODISCARD bool reader_security_key_iso_dep_session_open(
    uint16_t rats_timeout_ms);

NERO_NFC_NODISCARD bool reader_security_key_iso_dep_session_open_quiet(
    uint16_t rats_timeout_ms);

NERO_NFC_NODISCARD bool reader_security_key_iso_dep_open_main_from_active(
    uint16_t rats_timeout_ms);

void reader_security_key_iso_dep_send_deselect(void);

NERO_NFC_NODISCARD bool reader_security_key_iso_dep_recover_session(void);

NERO_NFC_NODISCARD bool reader_security_key_iso_dep_activate_after_hlta(void);

void reader_security_key_iso_dep_post_recover_rf_settle(void);

void reader_security_key_iso_dep_wait_post_deselect_gap(void);

void reader_security_key_iso_dep_clear_last_deselect_ms(void);

void reader_security_key_iso_dep_protocol_settle(void);

void reader_security_key_iso_dep_pre_first_iblock_delay(void);

uint16_t reader_security_key_iso_dep_link_response_timeout_ms(void);

int reader_security_key_iso_dep_transceive(const uint8_t* tx, uint16_t tx_len,
                                           uint8_t* rx, uint16_t rx_max,
                                           bool with_crc, uint16_t timeout_ms);

void reader_security_key_iso_dep_ccid_heartbeat(void);

uint32_t reader_security_key_iso_dep_last_deselect_ms(void);

#if defined(NERO_CCID_USB_BUILD)

#include "reader_security_key.h"

void reader_security_key_iso_dep_set_last_error(uint8_t code);

uint8_t reader_security_key_iso_dep_last_error(void);

void reader_security_key_iso_dep_bind_ccid_time_extension(
    reader_security_key_ccid_time_extension_cb_t cb, void* ctx);

#else

static inline void reader_security_key_iso_dep_set_last_error(uint8_t code) {
  (void)code;
}

#endif

#ifdef __cplusplus
}
#endif
