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
#include "reader_iso_dep_timing.h"
#include "reader_iso_dep_frame.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct reader_iso_dep_i_block_tx {
  uint8_t pcb;
  uint8_t hdr_len;
  uint16_t frag_len;
  uint16_t wire_len;
  bool chain_more;
} reader_iso_dep_i_block_tx_t;

static inline void reader_iso_dep_i_block_tx_reset(reader_iso_dep_i_block_tx_t *tx_info) {
  if (tx_info == NERO_NFC_NULL) {
    return;
  }
  tx_info->pcb = 0u;
  tx_info->hdr_len = 0u;
  tx_info->frag_len = 0u;
  tx_info->wire_len = 0u;
  tx_info->chain_more = false;
}

static inline uint8_t reader_iso_dep_i_block_tx_hdr_len(bool pcb_has_cid, bool include_nad) {
  uint8_t hdr_len = 1u;

  if (pcb_has_cid) {
    hdr_len++;
  }
  if (include_nad) {
    hdr_len++;
  }
  return hdr_len;
}

NERO_NFC_NODISCARD static inline bool
reader_iso_dep_build_i_block_tx(uint8_t *tx, uint16_t tx_cap, const uint8_t *apdu,
                                uint16_t apdu_len, uint16_t apdu_off, uint16_t frag_cap,
                                bool pcb_has_cid, uint8_t cid, bool include_nad, uint8_t nad,
                                uint8_t block_num, reader_iso_dep_i_block_tx_t *tx_info) {
  uint16_t remain;
  uint16_t frag_len;
  uint8_t hdr_len;
  uint16_t wire_len;
  uint8_t tx_pos;
  uint8_t pcb;

  if (tx_info != NERO_NFC_NULL) {
    reader_iso_dep_i_block_tx_reset(tx_info);
  }
  if ((tx == NERO_NFC_NULL) || (tx_info == NERO_NFC_NULL) || (apdu_off >= apdu_len) ||
      ((apdu == NERO_NFC_NULL) && (apdu_len != 0u)) || (frag_cap == 0u)) {
    return false;
  }

  remain = (uint16_t)(apdu_len - apdu_off);
  frag_len = (remain > frag_cap) ? frag_cap : remain;
  hdr_len = reader_iso_dep_i_block_tx_hdr_len(pcb_has_cid, include_nad);
  if (!nero_nfc_try_add_u16(frag_len, hdr_len, &wire_len) || (wire_len > tx_cap)) {
    return false;
  }

  pcb = (uint8_t)(ISO_DEP_PCB_I_BLOCK_BASE | (block_num & ISO_DEP_BLOCK_NUM_MASK));
  if (pcb_has_cid) {
    pcb = (uint8_t)(pcb | ISO_DEP_PCB_CID_BIT);
  }
  if (include_nad) {
    pcb = (uint8_t)(pcb | ISO_DEP_PCB_NAD_BIT);
  }
  if (remain > frag_cap) {
    pcb = (uint8_t)(pcb | ISO_DEP_PCB_CHAIN_BIT);
  }

  tx[0] = pcb;
  tx_pos = 1u;
  if (pcb_has_cid) {
    tx[tx_pos++] = cid;
  }
  if (include_nad) {
    tx[tx_pos++] = nad;
  }
  if (tx_pos != hdr_len) {
    return false;
  }
  if (!nero_nfc_copy_bytes(tx, tx_cap, hdr_len, &apdu[apdu_off], frag_len)) {
    return false;
  }

  tx_info->pcb = pcb;
  tx_info->hdr_len = hdr_len;
  tx_info->frag_len = frag_len;
  tx_info->wire_len = wire_len;
  tx_info->chain_more = (remain > frag_cap);
  return true;
}

NERO_NFC_NODISCARD static inline bool
reader_iso_dep_build_wtx_echo(uint8_t *wtx_out, uint8_t wtx_cap, const uint8_t *rx, int rlen,
                              uint8_t hdr_skip, uint8_t *wtx_len_out) {
  uint8_t wtx_len;
  uint8_t wtxm;

  if (wtx_len_out != NERO_NFC_NULL) {
    *wtx_len_out = 0u;
  }
  if ((wtx_out == NERO_NFC_NULL) || (rx == NERO_NFC_NULL) || (wtx_len_out == NERO_NFC_NULL) ||
      (rlen < 0) || (hdr_skip == UINT8_MAX)) {
    return false;
  }

  wtx_len = (uint8_t)(hdr_skip + 1u);
  if ((rlen < (int)wtx_len) || (wtx_len > wtx_cap)) {
    return false;
  }
  if (!nero_nfc_copy_bytes(wtx_out, wtx_cap, 0u, rx, wtx_len)) {
    return false;
  }
  wtxm = (uint8_t)(rx[hdr_skip] & ISO_DEP_WTXM_MASK);
  if ((wtxm < ISO_DEP_WTXM_MIN) || (wtxm > ISO_DEP_WTXM_MAX)) {
    return false;
  }
  wtx_out[hdr_skip] = wtxm;
  *wtx_len_out = wtx_len;
  return true;
}

NERO_NFC_NODISCARD static inline bool
reader_iso_dep_append_inf(uint8_t *resp, uint16_t resp_cap, uint16_t *total_io, const uint8_t *inf,
                          uint16_t inf_len, bool *appended_out) {
  uint16_t next_total;

  if (appended_out != NERO_NFC_NULL) {
    *appended_out = false;
  }
  if ((resp == NERO_NFC_NULL) || (total_io == NERO_NFC_NULL) ||
      ((inf == NERO_NFC_NULL) && (inf_len != 0u))) {
    return false;
  }
  if (!nero_nfc_try_add_u16(*total_io, inf_len, &next_total) || (next_total > resp_cap)) {
    return true;
  }
  if (!nero_nfc_copy_bytes(resp, resp_cap, *total_io, inf, inf_len)) {
    return false;
  }

  *total_io = next_total;
  if (appended_out != NERO_NFC_NULL) {
    *appended_out = true;
  }
  return true;
}
