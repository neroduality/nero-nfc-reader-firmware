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
#include "nero_nfc_limits.h"
#include "nero_nfc_frontend.h"
#include "nfc_ctap_codec.h"
#include "nfc_tag_info.h"

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

typedef struct {
  uint8_t uid14[NFC_TAG_TYPEA_UID_MAX];
  uint8_t uid14_len;
  uint8_t atqa[NFC_TAG_TYPEA_ATQA_LEN];
  bool atqa_valid;
  uint8_t sak;
  uint8_t uid15[NFC_FRONTEND_ISO15693_UID_LEN];
  uint8_t last_uid[NFC_TAG_TYPEA_UID_MAX];
  uint8_t last_uid_len;
  uint8_t baseline_amp;
} reader_rf_state_t;

typedef struct {
  char detected_url[NERO_NFC_NDEF_DECODE_OUT_MAX + 1u];
  char detected_urls[READER_NDEF_URL_MAX][READER_NDEF_URL_BYTES_MAX];
  uint8_t detected_url_count;
  bool url_detected;
} reader_ndef_state_t;

typedef struct {
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
} reader_iso_dep_state_t;

typedef struct {
  uint8_t aaguid[NFC_CTAP_AAGUID_LEN];
  bool aaguid_valid;
} reader_fido_state_t;

typedef struct {
  uint8_t iso_trace;
  nfc_frontend_transceive_diag_t last_xcvr_diag;
} reader_iso_dep_debug_state_t;

typedef struct {
  uint32_t last_field_print_ms;
  uint32_t last_poll_ms;
  uint32_t poll_interval_ms;
  uint32_t last_ccid_poll_ms;
  uint32_t last_ccid_remove_probe_ms;
  bool nfc_frontend_ready;
  bool was_near;
  uint8_t ccid_remove_misses;
  uint8_t last_ccid_icc_status;
} reader_app_runtime_t;

typedef struct {
  uint8_t type2_fast_read_uid[NFC_TAG_TYPEA_UID_MAX];
  uint8_t type2_fast_read_uid_len;
  bool type2_fast_read_disabled;
  uint8_t type5_read_multiple_uid[NFC_FRONTEND_ISO15693_UID_LEN];
  bool type5_read_multiple_disabled;
} reader_tag_caps_cache_t;

typedef void (*reader_iso_dep_ccid_time_extension_fn_t)(const void* ctx);

#if defined(NERO_HOST_UNIT_TEST_HOOKS)
typedef int (*reader_iso_dep_utest_transceive_fn_t)(
    const uint8_t* tx, uint16_t tx_len, uint8_t* rx, uint16_t rx_max,
    bool with_crc, uint16_t timeout_ms);
#endif

typedef struct {
  uint32_t last_deselect_ms;
  uint8_t last_error;
  reader_iso_dep_ccid_time_extension_fn_t ccid_time_extension_cb;
  void* ccid_time_extension_ctx;
  uint32_t ccid_time_extension_last_ms;
#if defined(NERO_HOST_UNIT_TEST_HOOKS)
  reader_iso_dep_utest_transceive_fn_t utest_transceive;
#endif
} reader_iso_dep_session_runtime_t;

typedef struct reader_context {
  nfc_frontend_t* frontend;
  uint8_t ndef_buf[NERO_NFC_READER_NDEF_BUF_MAX];
  reader_rf_state_t rf;
  reader_ndef_state_t ndef;
  reader_iso_dep_state_t iso_dep;
  reader_fido_state_t fido;
  reader_iso_dep_debug_state_t iso_dep_debug;
  reader_app_runtime_t app;
  reader_tag_caps_cache_t tag_caps;
  reader_iso_dep_session_runtime_t iso_dep_session;
} reader_context_t;

#ifdef __cplusplus
extern "C" {
#endif

NERO_NFC_NODISCARD reader_context_t* reader_context_active(void);

void reader_context_reset(reader_context_t* ctx);

#ifdef __cplusplus
}
#endif

/* Transitional alias: mutable reader state lives in the active nero_nfc_app_t.
 */
#define G_READER (*reader_context_active())
#define READER_FRONTEND (G_READER.frontend)

#define G_UID14 (G_READER.rf.uid14)
#define G_UID14_LEN (G_READER.rf.uid14_len)
#define G_ATQA (G_READER.rf.atqa)
#define G_ATQA_VALID (G_READER.rf.atqa_valid)
#define G_SAK (G_READER.rf.sak)
#define G_UID15 (G_READER.rf.uid15)
#define G_LAST_UID (G_READER.rf.last_uid)
#define G_LAST_UID_LEN (G_READER.rf.last_uid_len)
#define G_BASELINE_AMP (G_READER.rf.baseline_amp)

#define G_DETECTED_URL (G_READER.ndef.detected_url)
#define G_DETECTED_URLS (G_READER.ndef.detected_urls)
#define G_DETECTED_URL_COUNT (G_READER.ndef.detected_url_count)
#define G_URL_DETECTED (G_READER.ndef.url_detected)

#define G_BLOCK_NUM (G_READER.iso_dep.block_num)
#define G_ISO_DEP_RATS_PARAM (G_READER.iso_dep.rats_param)
#define G_ISO_DEP_CID (G_READER.iso_dep.cid)
#define G_ISO_DEP_PCB_HAS_CID (G_READER.iso_dep.pcb_has_cid)
#define G_ISO_DEP_HAVE_TC (G_READER.iso_dep.have_tc)
#define G_ISO_DEP_TC_BYTE (G_READER.iso_dep.tc_byte)
#define G_ISO_DEP_FWI (G_READER.iso_dep.fwi)
#define G_ISO_DEP_FWT_US (G_READER.iso_dep.fwt_us)
#define G_ISO_DEP_PIC_FRAME_MAX (G_READER.iso_dep.pic_frame_max)
#define G_ISO_DEP_RAW_RX (G_READER.iso_dep.raw_rx)
#define G_ISO_DEP_RAW_RX_LEN (G_READER.iso_dep.raw_rx_len)
#define G_ISO_DEP_LAST_INF_OFF (G_READER.iso_dep.last_inf_off)
#define G_ISO_DEP_IBLOCK_TX (G_READER.iso_dep.iblock_tx)
#define G_ATS_DATA (G_READER.iso_dep.ats_data)
#define G_ATS_LEN (G_READER.iso_dep.ats_len)

#define G_AAGUID (G_READER.fido.aaguid)
#define G_AAGUID_VALID (G_READER.fido.aaguid_valid)

#define G_ISO_DEP_TRACE (G_READER.iso_dep_debug.iso_trace)
#define G_ISO_DEP_LAST_XCVR_DIAG (G_READER.iso_dep_debug.last_xcvr_diag)
