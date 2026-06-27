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
reader_security_key_iso_dep_commit_rats_rx(int rlen, const uint8_t *rx, uint8_t rats_param) {
  uint8_t tl;

  if ((rlen < READER_ISO_DEP_ATS_MIN_LEN) || (rx == NERO_NFC_NULL)) {
    return false;
  }
  /* [ISO14443-4] §5.2.5 — ATS byte 0 (TL) is the authoritative ATS length including
   * itself. Bound storage by TL (not the raw RF receive length, which may carry
   * trailing CRC), and fail closed on a truncated or oversized ATS rather than
   * relaying a partial ATS as success. */
  tl = rx[0];
  if ((tl < READER_ISO_DEP_ATS_MIN_LEN) || ((uint16_t)tl > (uint16_t)rlen) ||
      ((size_t)tl > sizeof(g_ats_data))) {
    return false;
  }
  g_ats_len = tl;
  if (!nero_nfc_copy_bytes(g_ats_data, sizeof(g_ats_data), 0u, rx, g_ats_len)) {
    return false;
  }
  g_iso_dep_rats_param = rats_param;
  g_block_num = 0u;
  return true;
}

NERO_NFC_NODISCARD static inline bool reader_security_key_iso_dep_probe_can_upgrade_cid(void) {
  return g_iso_dep_have_tc && ((g_iso_dep_tc_byte & READER_ISO_DEP_ATS_TC_CID_BIT) != 0u) &&
         !g_iso_dep_pcb_has_cid;
}

NERO_NFC_NODISCARD static inline bool reader_security_key_iso_dep_tx_include_nad(void) {
  return g_iso_dep_have_tc && ((g_iso_dep_tc_byte & READER_ISO_DEP_ATS_TC_NAD_BIT) != 0u);
}

static inline uint8_t reader_security_key_iso_dep_tx_hdr_len(bool include_nad_byte) {
  return reader_iso_dep_i_block_tx_hdr_len(
    g_iso_dep_pcb_has_cid, include_nad_byte && reader_security_key_iso_dep_tx_include_nad());
}

static inline void reader_security_key_iso_dep_snap_raw_rx(const uint8_t *rx, int rlen) {
  int n = rlen;
  uint16_t i;

  if ((rlen <= 0) || (rx == NERO_NFC_NULL)) {
    g_iso_dep_raw_rx_len = 0u;
    return;
  }
  if (n > (int)ISO_DEP_RAW_RX_CAP) {
    n = (int)ISO_DEP_RAW_RX_CAP;
  }
  g_iso_dep_raw_rx_len = (uint8_t)n;
  for (i = 0u; i < (uint16_t)n; i++) {
    g_iso_dep_raw_rx[i] = rx[i];
  }
}

static inline uint8_t reader_security_key_iso_dep_pick_inf_offset(const uint8_t *rx, int rlen) {
  return reader_iso_dep_pick_inf_offset(rx, rlen, g_iso_dep_pcb_has_cid, g_iso_dep_cid,
                                        g_iso_dep_have_tc, g_iso_dep_tc_byte);
}

static inline uint16_t reader_security_key_iso_dep_apdu_chunk_budget(uint8_t tx_hdr_len) {
  return reader_iso_dep_apdu_chunk_budget(g_iso_dep_pic_frame_max, tx_hdr_len);
}

NERO_NFC_NODISCARD static inline bool reader_security_key_iso_dep_tx_add_nad(uint16_t full_apdu_len,
                                                                             const uint8_t *apdu) {
  uint8_t hw;

  if (!reader_security_key_iso_dep_tx_include_nad()) {
    return false;
  }
  if (!g_iso_dep_pcb_has_cid) {
    return false;
  }
  if ((apdu != NERO_NFC_NULL) && (full_apdu_len >= 1u) &&
      (apdu[0] == (uint8_t)NFC_ISO7816_CLA_PROPRIETARY_SHORT)) {
    return false;
  }
  hw = reader_security_key_iso_dep_tx_hdr_len(true);
  return full_apdu_len <= reader_security_key_iso_dep_apdu_chunk_budget(hw);
}

static inline uint8_t reader_security_key_iso_dep_rx_nad_byte(const uint8_t *rx, int rlen,
                                                              uint8_t pcb) {
  return reader_iso_dep_rx_nad_byte(rx, rlen, pcb, ISO_DEP_TX_NAD_VALUE);
}

static inline uint16_t
reader_security_key_iso_dep_wtx_response_timeout_ms(const uint8_t *rx, int rlen, uint8_t hdr_skip) {
  return reader_iso_dep_wtx_response_timeout_ms(g_iso_dep_fwt_us, rx, rlen, hdr_skip);
}

NERO_NFC_NODISCARD static inline bool
reader_security_key_iso_dep_rx_is_chain_ack_for_block(const uint8_t *rx, int rlen, uint8_t blk_sent,
                                                      uint8_t *ack_block_out) {
  return reader_iso_dep_rx_is_chain_ack_for_block(rx, rlen, blk_sent, g_iso_dep_pcb_has_cid,
                                                  g_iso_dep_cid, ack_block_out);
}

NERO_NFC_NODISCARD static inline bool
reader_security_key_iso_dep_rx_is_chain_nak_for_block(const uint8_t *rx, int rlen,
                                                      uint8_t blk_sent) {
  return reader_iso_dep_rx_is_chain_nak_for_block(rx, rlen, blk_sent, g_iso_dep_pcb_has_cid,
                                                  g_iso_dep_cid);
}

NERO_NFC_NODISCARD bool reader_security_key_iso_dep_session_open(uint16_t rats_timeout_ms);

NERO_NFC_NODISCARD bool reader_security_key_iso_dep_session_open_quiet(uint16_t rats_timeout_ms);

NERO_NFC_NODISCARD bool reader_security_key_iso_dep_open_main_from_active(uint16_t rats_timeout_ms);

void reader_security_key_iso_dep_send_deselect(void);

NERO_NFC_NODISCARD bool reader_security_key_iso_dep_recover_session(void);

NERO_NFC_NODISCARD bool reader_security_key_iso_dep_activate_after_hlta(void);

void reader_security_key_iso_dep_post_recover_rf_settle(void);

void reader_security_key_iso_dep_wait_post_deselect_gap(void);

void reader_security_key_iso_dep_clear_last_deselect_ms(void);

void reader_security_key_iso_dep_protocol_settle(void);

void reader_security_key_iso_dep_pre_first_iblock_delay(void);

uint16_t reader_security_key_iso_dep_link_response_timeout_ms(void);

int reader_security_key_iso_dep_transceive(const uint8_t *tx, uint16_t tx_len, uint8_t *rx,
                                           uint16_t rx_max, bool with_crc, uint16_t timeout_ms);

void reader_security_key_iso_dep_ccid_heartbeat(void);

uint32_t reader_security_key_iso_dep_last_deselect_ms(void);

#if defined(NERO_CCID_USB_BUILD)

#include "reader_security_key.h"

void reader_security_key_iso_dep_set_last_error(uint8_t code);

uint8_t reader_security_key_iso_dep_last_error(void);

void reader_security_key_iso_dep_bind_ccid_time_extension(
  reader_security_key_ccid_time_extension_cb_t cb, void *ctx);

#else

static inline void reader_security_key_iso_dep_set_last_error(uint8_t code) {
  (void)code;
}

#endif
