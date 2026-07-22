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

#include "nero_nfc_null.h"
#include "reader_security_key.h"

#include "nfc_ctap_codec.h"
#include "nfc_ccid_frame.h"
#include "nfc_pcsc_contactless.h"
#include "nero_nfc_mem_util.h"
#include "reader_context.h"
#include "reader_output.h"
#include "reader_protocol.h"
#include "reader_security_key_iso_dep_session.h"
#include "reader_security_key_iso_dep_transceive.h"
#include "reader_security_key_select.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "nero_nfc_format.h"

enum {
  READER_SECURITY_KEY_ABORT_SW1 = (uint8_t)(NFC_CCID_MSG_PC_TO_RDR_SECURE),
  READER_SECURITY_KEY_ABORT_SW2 = 0x17u,
  READER_SECURITY_KEY_DEBUG_APDU_PREVIEW_LEN =
      (uint16_t)(NFC_ISO7816_SELECT_AID_MAX),
  READER_SECURITY_KEY_SELECT_APDU_BUF_LEN = 24u,
  READER_SECURITY_KEY_SELECT_RESP_BUF_LEN = (uint16_t)(NFC_ISO14443_ATS_MAX),
};

bool reader_security_key_select_app_ex(const uint8_t* aid, uint8_t aid_len,
                                       const char* name, uint8_t p2,
                                       bool add_le_00, bool verbose,
                                       bool follow_get_response,
                                       uint8_t* rsp_out, uint16_t rsp_cap,
                                       uint16_t* rsp_len_out) {
  uint8_t apdu[READER_SECURITY_KEY_SELECT_APDU_BUF_LEN];
  uint8_t resp[READER_SECURITY_KEY_SELECT_RESP_BUF_LEN];
  int rlen;
  bool ok;
  uint16_t di;
  bool tried_cid_reopen = false;
  uint16_t apdu_len = 0u;

  if (!nfc_pcsc_build_select_aid_apdu(aid, aid_len, p2, add_le_00, apdu,
                                      (uint16_t)(sizeof(apdu)), &apdu_len)) {
    return false;
  }
  for (;;) {
    reader_security_key_iso_dep_ccid_heartbeat();
    if (reader_security_key_ccid_abort_pending()) {
      if ((rsp_out != NERO_NFC_NULL) && (rsp_len_out != NERO_NFC_NULL) &&
          (rsp_cap >= NFC_ISO7816_SW_STATUS_WORD_LEN)) {
        rsp_out[0] = READER_SECURITY_KEY_ABORT_SW1;
        rsp_out[1] = READER_SECURITY_KEY_ABORT_SW2;
        *rsp_len_out = NFC_ISO7816_SW_STATUS_WORD_LEN;
      }
      return false;
    }
    rlen = reader_security_key_send_apdu_timeout_ex(
        apdu, apdu_len, resp, (uint16_t)(sizeof(resp)),
        SECURITY_KEY_SHORT_FRAME_MS, follow_get_response);
    ok = nfc_iso7816_response_sw_ok(resp, rlen);
    if (ok || tried_cid_reopen ||
        !reader_security_key_iso_dep_probe_can_upgrade_cid() ||
        (rlen >= NFC_ISO7816_SW_STATUS_WORD_LEN)) {
      break;
    }
    if (verbose) {
      nero_nfc_log_write("    ");
      nero_nfc_log_write(name);
      nero_nfc_log_write(
          ": probe session gave no response; reopening ISO-DEP with CID "
          "fallback\r\n");
    }
    if (!reader_security_key_iso_dep_recover_session()) {
      break;
    }
    tried_cid_reopen = true;
    reader_security_key_iso_dep_ccid_heartbeat();
    reader_security_key_iso_dep_protocol_settle();
  }
  if (!verbose) {
    if ((rlen >= NFC_ISO7816_SW_STATUS_WORD_LEN) &&
        (rsp_out != NERO_NFC_NULL) && (rsp_len_out != NERO_NFC_NULL) &&
        ((uint16_t)(rlen) <= rsp_cap)) {
      (void)nero_nfc_copy_bytes(rsp_out, rsp_cap, 0u, resp, (uint16_t)(rlen));
      *rsp_len_out = (uint16_t)(rlen);
    }
    return ok;
  }
  nero_nfc_log_write("    ");
  nero_nfc_log_write(name);
  nero_nfc_log_write(": ");
  if (ok) {
    nero_nfc_log_line("YES");
  } else if (rlen >= NFC_ISO7816_SW_STATUS_WORD_LEN) {
    uint8_t sw1 = 0u;
    uint8_t sw2 = 0u;
    nero_nfc_log_write("no (SW=");
    if (nfc_iso7816_response_sw(resp, rlen, &sw1, &sw2)) {
      {
        char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
        (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(sw1));
        nero_nfc_log_write(nhx);
      }
      {
        char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
        (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(sw2));
        nero_nfc_log_write(nhx);
      }
    }
    nero_nfc_log_line(")");
    nero_nfc_log_write("      [ISO-DEP] dbg inf_off=");
    {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                              (unsigned)((uint32_t)(G_ISO_DEP_LAST_INF_OFF)));
      nero_nfc_log_write(ndc);
    }
    nero_nfc_log_write(" rf_rx=");
    for (di = 0u; di < (uint16_t)(G_ISO_DEP_RAW_RX_LEN); di++) {
      {
        char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
        (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X",
                                (unsigned)(G_ISO_DEP_RAW_RX[di]));
        nero_nfc_log_write(nhx);
      }
      nero_nfc_log_putc(' ');
    }
    nero_nfc_log_write("apdu_rx=");
    for (di = 0u; di < (uint16_t)(rlen) &&
                  di < READER_SECURITY_KEY_DEBUG_APDU_PREVIEW_LEN;
         di++) {
      nero_nfc_log_hex_u8(resp[di]);
      nero_nfc_log_putc(' ');
    }
    nero_nfc_log_write("\r\n");
  } else {
    nero_nfc_log_line("no response");
    nero_nfc_log_write("      [ISO-DEP] dbg rf_rx=");
    for (di = 0u; di < (uint16_t)(G_ISO_DEP_RAW_RX_LEN); di++) {
      {
        char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
        (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X",
                                (unsigned)(G_ISO_DEP_RAW_RX[di]));
        nero_nfc_log_write(nhx);
      }
      nero_nfc_log_putc(' ');
    }
    nero_nfc_log_write("\r\n");
  }
  if ((rlen >= NFC_ISO7816_SW_STATUS_WORD_LEN) && (rsp_out != NERO_NFC_NULL) &&
      (rsp_len_out != NERO_NFC_NULL) && ((uint16_t)(rlen) <= rsp_cap)) {
    (void)nero_nfc_copy_bytes(rsp_out, rsp_cap, 0u, resp, (uint16_t)(rlen));
    *rsp_len_out = (uint16_t)(rlen);
  }
  return ok;
}

bool reader_iso_dep_select_app(const uint8_t* aid, uint8_t aid_len,
                               const char* name) {
  return reader_security_key_select_app_ex(aid, aid_len, name, 0x00u, true,
                                           true, true, NERO_NFC_NULL, 0u,
                                           NERO_NFC_NULL);
}

bool reader_iso_dep_select_ndef_app(void) {
  for (uint8_t i = 0u; i < (uint8_t)(NFC_PCSC_NDEF_APP_SELECT_VARIANT_COUNT);
       ++i) {
    nfc_pcsc_ndef_app_select_variant_t variant;

    if (!nfc_pcsc_ndef_app_select_variant(i, &variant)) {
      break;
    }
    if (reader_security_key_select_app_ex(
            variant.aid, variant.aid_len, "NDEF", variant.p2, variant.add_le_00,
            true, true, NERO_NFC_NULL, 0u, NERO_NFC_NULL)) {
      return true;
    }
  }
  return false;
}

bool reader_security_key_select_fido_probe(bool verbose,
                                           bool follow_get_response,
                                           uint8_t* rsp_out, uint16_t rsp_cap,
                                           uint16_t* rsp_len_out) {
  for (uint8_t i = 0u; i < (uint8_t)(NFC_CTAP_FIDO_APP_SELECT_VARIANT_COUNT);
       ++i) {
    nfc_ctap_fido_app_select_variant_t variant;

    if (!nfc_ctap_fido_app_select_variant(i, &variant)) {
      break;
    }
    if (reader_security_key_select_app_ex(
            variant.aid, variant.aid_len, "FIDO/FIDO2", variant.p2,
            variant.add_le_00, verbose, follow_get_response, rsp_out, rsp_cap,
            rsp_len_out)) {
      return true;
    }
  }
  return false;
}
