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

#include "reader_security_key_webauthn_select.h"

#include "nero_nfc_null.h"
#include "nfc_ctap_codec.h"
#include "reader_hal.h"
#include "reader_output.h"
#include "reader_security_key_iso_dep_session.h"
#include "reader_security_key_select.h"

#include <stdbool.h>
#include <stdint.h>

bool reader_security_key_select_fido_for_host_webauthn(uint8_t *rsp_out, uint16_t rsp_cap,
                                                       uint16_t *rsp_len_out,
                                                       bool follow_get_response) {
  if (rsp_len_out != NERO_NFC_NULL) {
    *rsp_len_out = 0u;
  }
  reader_security_key_iso_dep_pre_first_iblock_delay();
  for (uint8_t step = 0u; step < (uint8_t)NFC_CTAP_FIDO_WEBAUTHN_SELECT_STEP_COUNT; ++step) {
    nfc_ctap_fido_webauthn_select_step_t step_info;
    nfc_ctap_fido_app_select_variant_t variant;

    if (!nfc_ctap_fido_webauthn_select_step(step, &step_info) ||
        !nfc_ctap_fido_app_select_variant(step_info.variant_index, &variant)) {
      break;
    }
    if (step > 0u) {
      if (step_info.log_before_prep == NFC_CTAP_FIDO_SELECT_LOG_REOPEN) {
        nero_nfc_log_line("[CCID-FIDO] FIDO SELECT(Le=00) failed; full reopen before retry");
      } else if (step_info.log_before_prep == NFC_CTAP_FIDO_SELECT_LOG_LAST_CHANCE) {
        nero_nfc_log_line(
          "[CCID-FIDO] FIDO SELECT(reopen + Le=00 + no-Le) failed; last-chance reopen");
      }
      if (step_info.prep == NFC_CTAP_FIDO_SELECT_PREP_RECOVER) {
        if (!reader_security_key_iso_dep_recover_session()) {
          return false;
        }
        reader_security_key_iso_dep_post_recover_rf_settle();
        reader_security_key_iso_dep_pre_first_iblock_delay();
      } else if (step_info.prep == NFC_CTAP_FIDO_SELECT_PREP_SETTLE) {
        reader_security_key_iso_dep_protocol_settle();
        reader_security_key_iso_dep_pre_first_iblock_delay();
      }
    }
    if (reader_security_key_select_app_ex(variant.aid, variant.aid_len, "FIDO/FIDO2", variant.p2,
                                          variant.add_le_00, true, follow_get_response, rsp_out,
                                          rsp_cap, rsp_len_out)) {
      return true;
    }
  }
  return false;
}
