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
#include "reader_security_key_ccid_relay.h"

#include "nfc_ctap_codec.h"
#include "nfc_pcsc_contactless.h"
#include "nfc_tag_geometry_limits.h"
#include "nfc_ccid_frame.h"
#include "reader_context.h"
#include "nero_nfc_frontend.h"
#include "reader_hal.h"
#include "reader_iso_dep_timing.h"
#include "reader_protocol.h"
#include "reader_security_key_ccid_codec.h"
#include "reader_security_key_iso_dep_session.h"
#include "reader_security_key_iso_dep_transceive.h"
#include "reader_security_key_select.h"
#include "reader_security_key_webauthn_select.h"

#include <stdbool.h>
#include <stdint.h>

enum {
  READER_SECURITY_KEY_RELAY_MIN_RESPONSE_LEN =
      NFC_ISO7816_MIN_RESPONSE_WITH_SW_LEN,
};

enum { READER_SECURITY_KEY_RELAY_EXCHANGE_TIMEOUT_MS = 45000u };
enum { READER_SECURITY_KEY_RELAY_POST_FIDO_SELECT_MS = 12u };

#if defined(NERO_CCID_USB_BUILD)

void reader_security_key_ccid_release_iso_session(void) {
  reader_security_key_iso_dep_send_deselect();
}

bool reader_security_key_ccid_open_iso_session(void) {
  bool reopen_after_deselect =
      (reader_security_key_iso_dep_last_deselect_ms() != 0u);
  bool active_type4_selection =
      (G_UID14_LEN != 0u) && ((G_SAK & NFC_TAG_T4T_SAK_ISO14443_4_BIT) != 0u);

  reader_security_key_iso_dep_wait_post_deselect_gap();
  reader_protocol_configure_iso14443a();
  nfc_frontend_ensure_tx_rx(READER_FRONTEND);
  if (reopen_after_deselect) {
    if (!reader_security_key_iso_dep_activate_after_hlta()) {
      return false;
    }
  } else if (!active_type4_selection) {
    if (!reader_protocol_activate_iso14443a()) {
      return false;
    }
  }
  if ((G_SAK & NFC_TAG_T4T_SAK_ISO14443_4_BIT) == 0u) {
    return false;
  }
  if (reopen_after_deselect) {
    reader_security_key_iso_dep_protocol_settle();
    if (!reader_security_key_iso_dep_open_main_from_active(
            SECURITY_KEY_RATS_TIMEOUT_MS)) {
      return false;
    }
    reader_security_key_iso_dep_post_recover_rf_settle();
  } else {
    if (!reader_security_key_iso_dep_session_open(
            SECURITY_KEY_RATS_TIMEOUT_MS)) {
      reader_protocol_configure_iso14443a();
      nfc_frontend_ensure_tx_rx(READER_FRONTEND);
      if (!reader_protocol_activate_iso14443a() ||
          !reader_security_key_iso_dep_session_open(
              SECURITY_KEY_RATS_TIMEOUT_MS)) {
        return false;
      }
    }
    /* Cold ICC_ON sessions on some contactless authenticators are noticeably
     * less stable than the immediate reopen that follows a failed first APDU.
     * Preemptively do one DESELECT→WUPA→RATS recovery here so the host gets the
     * stronger second-session behavior on its very first FIDO SELECT. */
    if (!reader_security_key_iso_dep_recover_session()) {
      return false;
    }
    reader_security_key_iso_dep_post_recover_rf_settle();
  }
  reader_security_key_iso_dep_clear_last_deselect_ms();
  reader_security_key_iso_dep_pre_first_iblock_delay();
  return true;
}

bool reader_security_key_pcsc_contactless_copy_atr(uint8_t* dst,
                                                   uint16_t dst_cap,
                                                   uint16_t* alen_io) {
  return reader_security_key_copy_ats_as_pcsc_atr(G_ATS_DATA, G_ATS_LEN, dst,
                                                  dst_cap, alen_io);
}

static uint16_t security_key_relay_failure_response(uint8_t* rsp,
                                                    uint16_t rsp_cap) {
  return reader_security_key_relay_failure_response(rsp, rsp_cap);
}

static bool relay_select_with_recovery(const uint8_t* apdu, uint16_t apdu_len,
                                       uint8_t* rsp, uint16_t rsp_cap,
                                       uint16_t* rsp_len_out) {
  int total;

  if ((rsp_len_out == NERO_NFC_NULL) || (rsp == NERO_NFC_NULL)) {
    return false;
  }
  *rsp_len_out = 0u;

  reader_security_key_iso_dep_pre_first_iblock_delay();
  /* [CTAP2.3] section 11.3.7.2 — host relays GETRESPONSE; do not merge SW61xx
   * here. */
  total = reader_security_key_send_apdu_timeout_ex(
      apdu, apdu_len, rsp, rsp_cap, SECURITY_KEY_SHORT_FRAME_MS, false);
  if (reader_security_key_apdu_response_has_status_word(
          rsp, (total >= 0) ? (uint16_t)(total) : 0u)) {
    *rsp_len_out = (uint16_t)(total);
    return true;
  }

  if (reader_security_key_iso_dep_recover_session()) {
    reader_security_key_iso_dep_post_recover_rf_settle();
    reader_security_key_iso_dep_pre_first_iblock_delay();
    total = reader_security_key_send_apdu_timeout_ex(
        apdu, apdu_len, rsp, rsp_cap, SECURITY_KEY_SHORT_FRAME_MS, false);
    if (reader_security_key_apdu_response_has_status_word(
            rsp, (total >= 0) ? (uint16_t)(total) : 0u)) {
      *rsp_len_out = (uint16_t)(total);
      return true;
    }
  }

  reader_security_key_iso_dep_protocol_settle();
  reader_security_key_iso_dep_pre_first_iblock_delay();
  for (uint8_t i = 0u; i < (uint8_t)(NFC_CTAP_FIDO_APP_SELECT_VARIANT_COUNT);
       ++i) {
    nfc_ctap_fido_app_select_variant_t variant;

    if (!nfc_ctap_fido_app_select_variant(i, &variant)) {
      break;
    }
    if (reader_security_key_select_app_ex(
            variant.aid, variant.aid_len, "FIDO/FIDO2", variant.p2,
            variant.add_le_00, false, false, rsp, rsp_cap, rsp_len_out)) {
      return true;
    }
  }
  return *rsp_len_out >= READER_SECURITY_KEY_RELAY_MIN_RESPONSE_LEN;
}

void reader_security_key_set_ccid_time_extension_callback(
    reader_security_key_ccid_time_extension_cb_t cb, void* ctx) {
  reader_security_key_iso_dep_bind_ccid_time_extension(cb, ctx);
}

bool reader_security_key_apdu_needs_ccid_time_extension(const uint8_t* apdu,
                                                        uint16_t apdu_len) {
  return nfc_ctap_apdu_needs_ccid_time_extension(apdu, apdu_len);
}

uint16_t reader_security_key_apdu_exchange(const uint8_t* apdu,
                                           uint16_t apdu_len, uint8_t* rsp,
                                           uint16_t rsp_cap) {
  int total;
  uint8_t ctap_cmd = 0u;
  bool is_ctap;
  uint16_t exchange_timeout_ms;
  if ((apdu == NERO_NFC_NULL) || (rsp == NERO_NFC_NULL) ||
      (rsp_cap < NFC_ISO7816_SW_STATUS_WORD_LEN)) {
    if ((rsp != NERO_NFC_NULL) && (rsp_cap >= NFC_ISO7816_SW_STATUS_WORD_LEN)) {
      return security_key_relay_failure_response(rsp, rsp_cap);
    }
    return 0u;
  }
  if (reader_security_key_apdu_is_select_fido_aid(apdu, apdu_len,
                                                  NERO_NFC_NULL)) {
    uint16_t select_len = 0u;
    if (relay_select_with_recovery(apdu, apdu_len, rsp, rsp_cap, &select_len)) {
      return select_len;
    }
    return security_key_relay_failure_response(rsp, rsp_cap);
  }
  is_ctap =
      reader_security_key_apdu_fido_ctap_command(apdu, apdu_len, &ctap_cmd);
  exchange_timeout_ms =
      is_ctap ? reader_security_key_ctap_timeout_for_command(
                    ctap_cmd, READER_SECURITY_KEY_RELAY_EXCHANGE_TIMEOUT_MS,
                    SECURITY_KEY_SHORT_FRAME_MS)
              : READER_SECURITY_KEY_RELAY_EXCHANGE_TIMEOUT_MS;
  reader_security_key_iso_dep_set_last_error(0u);
  /* Transparent APDU relay — host owns GET RESPONSE / NFCCTAP_GETRESPONSE
   * polling. */
  total = reader_security_key_send_apdu_timeout_ex(apdu, apdu_len, rsp, rsp_cap,
                                                   exchange_timeout_ms, false);
  if ((total < NFC_ISO7816_SW_STATUS_WORD_LEN) && is_ctap) {
    uint16_t select_len = 0u;

    if (reader_security_key_iso_dep_recover_session()) {
      reader_security_key_iso_dep_post_recover_rf_settle();
      if (reader_security_key_select_fido_for_host_webauthn(
              rsp, rsp_cap, &select_len, false)) {
        reader_hal_delay_ms(READER_SECURITY_KEY_RELAY_POST_FIDO_SELECT_MS);
        total = reader_security_key_send_apdu_timeout_ex(
            apdu, apdu_len, rsp, rsp_cap, exchange_timeout_ms, false);
      }
    }
  }
  /* [CTAP2.3] §11.3.5.2 — relay the token's response (including its ISO7816
   * status word) verbatim; never synthesize or rewrite a status word. Fail
   * closed with a clean ISO7816 error only when the token response is malformed
   * or carries a contradictory/error status word. 61xx/91xx are forwarded so
   * the host owns GET RESPONSE / NFCCTAP_GETRESPONSE. */
  if (is_ctap) {
    if (nfc_ctap_relay_response_disposition(
            rsp, (total >= 0) ? (uint16_t)(total) : 0u) ==
        NFC_CTAP_RELAY_FAIL_CLOSED) {
      return security_key_relay_failure_response(rsp, rsp_cap);
    }
    return (uint16_t)(total);
  }
  if (total < NFC_ISO7816_SW_STATUS_WORD_LEN) {
    return security_key_relay_failure_response(rsp, rsp_cap);
  }
  return (uint16_t)(total);
}

#endif /* defined(NERO_CCID_USB_BUILD) */
