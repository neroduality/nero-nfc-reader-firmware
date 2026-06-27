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

#include "nfc_ctap_codec.h"
#include "nfc_pcsc_contactless.h"
#include "nero_nfc_mem_util.h"
#include "nero_nfc_attrs.h"
#include "reader_iso_dep_frame.h"

#include <stdbool.h>
#include <stdint.h>

enum {
  READER_SECURITY_KEY_ATR_TD1_OFFSET = 2u,
  READER_SECURITY_KEY_CTAP_MAKE_CREDENTIAL = NFC_CTAP_CMD_MAKE_CREDENTIAL,
  READER_SECURITY_KEY_CTAP_GET_ASSERTION = NFC_CTAP_CMD_GET_ASSERTION,
  READER_SECURITY_KEY_CTAP_CLIENT_PIN = NFC_CTAP_CMD_CLIENT_PIN,
};

static inline uint16_t reader_security_key_ctap_timeout_for_command(uint8_t ctap_cmd,
                                                                    uint16_t long_frame_ms,
                                                                    uint16_t short_frame_ms) {
  return ((ctap_cmd == READER_SECURITY_KEY_CTAP_MAKE_CREDENTIAL) ||
          (ctap_cmd == READER_SECURITY_KEY_CTAP_GET_ASSERTION) ||
          (ctap_cmd == READER_SECURITY_KEY_CTAP_CLIENT_PIN))
           ? long_frame_ms
           : short_frame_ms;
}

NERO_NFC_NODISCARD static inline bool
reader_security_key_copy_ats_as_pcsc_atr(const uint8_t *ats, uint16_t ats_len, uint8_t *dst,
                                         uint16_t dst_cap, uint16_t *alen_io) {
  uint16_t hist_len;
  uint16_t i;
  uint8_t tck;

  if ((ats == NERO_NFC_NULL) || (dst == NERO_NFC_NULL) || (alen_io == NERO_NFC_NULL) ||
      (ats_len == 0u)) {
    return false;
  }

  hist_len = ats_len;
  if (hist_len > NFC_ISO7816_HISTORICAL_BYTES_MAX) {
    hist_len = NFC_ISO7816_HISTORICAL_BYTES_MAX; /* [ISO7816-3] section 8.2 historical bytes cap */
  }
  if (dst_cap < (uint16_t)(hist_len + NFC_ISO7816_ATR_TS_TCK_OVERHEAD)) {
    return false;
  }

  dst[0] = NFC_ISO7816_ATR_TS; /* TS — direct convention (ISO 7816-3) */
  dst[1] = (uint8_t)(NFC_ISO7816_ATR_T0_HIST_LEN_MASK | hist_len); /* T0 — historical byte count */
  dst[READER_SECURITY_KEY_ATR_TD1_OFFSET] =
    NFC_ISO7816_ATR_TD1_T1; /* TD1 — T=1 interface bytes follow */
  if (!nero_nfc_copy_bytes(dst, dst_cap, NFC_ISO7816_ATR_FIXED_PREFIX_LEN, ats, hist_len)) {
    return false;
  }

  tck = 0u;
  for (i = 1u; i < (uint16_t)(NFC_ISO7816_ATR_FIXED_PREFIX_LEN + hist_len); ++i) {
    tck ^= dst[i];
  }
  dst[NFC_ISO7816_ATR_FIXED_PREFIX_LEN + hist_len] =
    tck; /* TCK — XOR from T0 through last historical byte */
  *alen_io = (uint16_t)(hist_len + NFC_ISO7816_ATR_TS_TCK_OVERHEAD);
  return true;
}

static inline uint16_t reader_security_key_relay_failure_response(uint8_t *rsp, uint16_t rsp_cap) {
  if ((rsp == NERO_NFC_NULL) || (rsp_cap < NFC_ISO7816_SW_STATUS_WORD_LEN)) {
    return 0u;
  }
  rsp[0] = NFC_ISO7816_SW1_GENERAL_ERROR;
  rsp[1] = NFC_ISO7816_SW2_SUCCESS;
  return NFC_ISO7816_SW_STATUS_WORD_LEN;
}

NERO_NFC_NODISCARD static inline bool
reader_security_key_apdu_is_select_fido_aid(const uint8_t *apdu, uint16_t apdu_len,
                                            bool *add_le_00_out) {
  return nfc_ctap_apdu_is_select_fido_aid(apdu, apdu_len, add_le_00_out);
}

NERO_NFC_NODISCARD static inline bool
reader_security_key_apdu_fido_ctap_command(const uint8_t *apdu, uint16_t apdu_len,
                                           uint8_t *cmd_out) {
  return nfc_ctap_apdu_command(apdu, apdu_len, cmd_out);
}

NERO_NFC_NODISCARD static inline bool
reader_security_key_apdu_response_has_status_word(const uint8_t *rsp, uint16_t rsp_len) {
  return reader_iso_dep_apdu_response_has_status_word(rsp, rsp_len);
}
