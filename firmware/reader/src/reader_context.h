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

#include "nero_nfc_limits.h"
#include "nfc_frontend.h"
#include "nfc_ctap_codec.h"

#include <stdbool.h>
#include <stdint.h>

/* ISO-DEP transceive scratch for one I-block RX at FSDI=8 (512-byte FSD). */
#define READER_ISO_DEP_IBLOCK_RX_BUF_LEN 512u
#define READER_NDEF_URL_MAX 4u
#define READER_NDEF_URL_BYTES_MAX NERO_NFC_NDEF_DECODE_OUT_MAX
#define ISO_DEP_IBLOCK_TX_BUF_LEN NFC_ISO_DEP_IBLOCK_TX_BUF_LEN
/* When ATS mandates a NAD byte, 0x00 is invalid/reserved in ISO14443-4
 * addressing rules. */
#define ISO_DEP_TX_NAD_VALUE 0x01u
#define ISO_DEP_RAW_RX_CAP 24u

struct reader_rf_state_t {
  uint8_t uid14[10];
  uint8_t uid14_len;
  uint8_t atqa[2];
  bool atqa_valid;
  uint8_t sak;
  uint8_t uid15[NFC_FRONTEND_ISO15693_UID_LEN];
  uint8_t last_uid[10];
  uint8_t last_uid_len;
  uint8_t baseline_amp;
};

struct reader_ndef_state_t {
  char detected_url[NERO_NFC_NDEF_DECODE_OUT_MAX + 1u];
  char detected_urls[READER_NDEF_URL_MAX][READER_NDEF_URL_BYTES_MAX];
  uint8_t detected_url_count;
  bool url_detected;
};

struct reader_iso_dep_state_t {
  uint8_t block_num;
  uint8_t rats_param;
  uint8_t cid;
  bool pcb_has_cid;
  bool have_tc;
  uint8_t tc_byte;
  uint8_t fwi;
  uint32_t fwt_us;
  uint16_t pic_frame_max;
  uint8_t raw_rx[ISO_DEP_RAW_RX_CAP];
  uint8_t raw_rx_len;
  uint8_t last_inf_off;
  uint8_t iblock_tx[ISO_DEP_IBLOCK_TX_BUF_LEN];
  uint8_t ats_data[NFC_ISO14443_ATS_MAX];
  uint8_t ats_len;
};

struct reader_fido_state_t {
  uint8_t aaguid[16];
  bool aaguid_valid;
};

struct reader_iso_dep_debug_state_t {
  uint8_t iso_trace;
  nfc_frontend_transceive_diag_t last_xcvr_diag;
};

struct reader_context_t {
  reader_rf_state_t rf;
  reader_ndef_state_t ndef;
  reader_iso_dep_state_t iso_dep;
  reader_fido_state_t fido;
  reader_iso_dep_debug_state_t iso_dep_debug;
};

extern reader_context_t g_reader;

void reader_context_reset(reader_context_t *ctx);

#define g_uid14 (g_reader.rf.uid14)
#define g_uid14_len (g_reader.rf.uid14_len)
#define g_atqa (g_reader.rf.atqa)
#define g_atqa_valid (g_reader.rf.atqa_valid)
#define g_sak (g_reader.rf.sak)
#define g_uid15 (g_reader.rf.uid15)
#define g_last_uid (g_reader.rf.last_uid)
#define g_last_uid_len (g_reader.rf.last_uid_len)
#define g_baseline_amp (g_reader.rf.baseline_amp)

#define g_detected_url (g_reader.ndef.detected_url)
#define g_detected_urls (g_reader.ndef.detected_urls)
#define g_detected_url_count (g_reader.ndef.detected_url_count)
#define g_url_detected (g_reader.ndef.url_detected)

#define g_block_num (g_reader.iso_dep.block_num)
#define g_iso_dep_rats_param (g_reader.iso_dep.rats_param)
#define g_iso_dep_cid (g_reader.iso_dep.cid)
#define g_iso_dep_pcb_has_cid (g_reader.iso_dep.pcb_has_cid)
#define g_iso_dep_have_tc (g_reader.iso_dep.have_tc)
#define g_iso_dep_tc_byte (g_reader.iso_dep.tc_byte)
#define g_iso_dep_fwi (g_reader.iso_dep.fwi)
#define g_iso_dep_fwt_us (g_reader.iso_dep.fwt_us)
#define g_iso_dep_pic_frame_max (g_reader.iso_dep.pic_frame_max)
#define g_iso_dep_raw_rx (g_reader.iso_dep.raw_rx)
#define g_iso_dep_raw_rx_len (g_reader.iso_dep.raw_rx_len)
#define g_iso_dep_last_inf_off (g_reader.iso_dep.last_inf_off)
#define g_iso_dep_iblock_tx (g_reader.iso_dep.iblock_tx)
#define g_ats_data (g_reader.iso_dep.ats_data)
#define g_ats_len (g_reader.iso_dep.ats_len)

#define g_aaguid (g_reader.fido.aaguid)
#define g_aaguid_valid (g_reader.fido.aaguid_valid)

#define g_iso_dep_trace (g_reader.iso_dep_debug.iso_trace)
#define g_iso_dep_last_xcvr_diag (g_reader.iso_dep_debug.last_xcvr_diag)
