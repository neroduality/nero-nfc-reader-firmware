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
#include "reader_ccid.h"

#include "nfc_ccid_frame.h"

#include "nfc_pcsc_contactless.h"
#include "nero_nfc_mem_util.h"
#include "nfc_session_owner.h"

#include "reader_ccid_protocol.h"
#include "reader_ccid_bulk_codec.h"
#include "reader_context.h"
#include "reader_hal.h"
#include "reader_security_key.h"

#if defined(NERO_HOST_UNIT_TEST_HOOKS)
#include "reader_ccid_utest.h"
#include "reader_hal_utest.h"
#endif

#include <stdint.h>
#include <string.h>

#ifndef NERO_CCID_USB_BUILD

void reader_ccid_poll(void) {}

void reader_ccid_on_tag_detected(nfc_tag_kind_t tag_kind) { (void)tag_kind; }

void reader_ccid_on_tag_removed_from_field(void) {}

uint8_t reader_ccid_icc_status(void) { return (uint8_t)NFC_CCID_ICC_NO_ICC; }

bool reader_ccid_fido_session_active(void) { return false; }

nfc_tag_kind_t reader_ccid_tag_kind(void) { return NFC_TAG_KIND_NONE; }

bool reader_ccid_removal_probe_due(uint32_t now_ms) {
  (void)now_ms;
  return true;
}

#else /* NERO_CCID_USB_BUILD */

#include "reader_ccid_internal.h"
#include "reader_ccid_cmd_codes.h"
#include "reader_ccid_xfr.h"

void reader_ccid_note_host_session_activity(void) {
  if (!G_SESS) {
    return;
  }
  G_REMOVE_DEFERRED = false;
  G_REMOVE_DEFER_UNTIL_MS = reader_hal_millis() + CCID_REMOVE_DEFER_MS;
}

bool reader_ccid_abort_requested(void) {
  uint8_t slot = 0u;
  uint8_t seq = 0u;
  return reader_hal_ccid_abort_request_pending(&slot, &seq) && slot == 0u;
}

void reader_ccid_poll(void) {
  const uint8_t* pkt = NERO_NFC_NULL;
  uint16_t rn = 0u;

  if (G_REMOVE_DEFERRED &&
      (!G_SESS || reader_ccid_deadline_elapsed(G_REMOVE_DEFER_UNTIL_MS))) {
    reader_ccid_complete_card_removal();
  }

  if (reader_hal_ccid_peek(&pkt, &rn)) {
    uint16_t copy_len = rn;
    copy_len = NERO_NFC_MIN(copy_len, (uint16_t)(sizeof(G_CCID_FRAME)));
    if (copy_len != 0u) {
      if (!nero_nfc_copy_bytes(G_CCID_FRAME, sizeof(G_CCID_FRAME), 0u, pkt,
                               copy_len)) {
        reader_hal_ccid_release();
        return;
      }
    }
    reader_hal_ccid_release();
    reader_ccid_handle_bulk(G_CCID_FRAME, copy_len);
  }
}
void reader_ccid_on_tag_detected(reader_tag_kind_t tag_kind) {
  if (G_REMOVE_DEFERRED) {
    reader_ccid_complete_card_removal();
  }
  reader_ccid_clear_xfr_response_chain();
  G_REMOVE_DEFERRED = false;
  G_TAG_KIND = tag_kind;
  G_TYPE4_SECURITY_KEY_APP = false;
  G_PROTOCOL_NUM = nfc_pcsc_protocol_for_tag(tag_kind);
  if (G_CARD_PRESENT) {
    return;
  }
  G_CARD_PRESENT = true;
  reader_hal_ccid_notify_slot_change(true);
}

void reader_ccid_on_tag_removed_from_field(void) {
  if (!G_CARD_PRESENT) {
    return;
  }
  if (G_SESS) {
    reader_ccid_complete_card_removal();
    return;
  }
  if (!reader_ccid_deadline_elapsed(G_REMOVE_DEFER_UNTIL_MS)) {
    G_REMOVE_DEFERRED = true;
    return;
  }
  reader_ccid_complete_card_removal();
}

uint8_t reader_ccid_icc_status(void) { return reader_ccid_current_icc_level(); }

bool reader_ccid_fido_session_active(void) {
  return G_SESS && G_ISO_SESSION_OPEN && G_TYPE4_SECURITY_KEY_APP;
}

reader_tag_kind_t reader_ccid_tag_kind(void) { return G_TAG_KIND; }

bool reader_ccid_removal_probe_due(uint32_t now_ms) {
  return (int32_t)(now_ms - G_REMOVE_DEFER_UNTIL_MS) >= 0;
}

#if defined(NERO_HOST_UNIT_TEST_HOOKS)

void reader_ccid_utest_reset(void) {
  G_SESS = false;
  G_CARD_PRESENT = false;
  G_ISO_SESSION_OPEN = false;
  G_TYPE4_SECURITY_KEY_APP = false;
  G_REMOVE_DEFERRED = false;
  G_REMOVE_DEFER_UNTIL_MS = 0u;
  G_TAG_KIND = READER_TAG_KIND_NONE;
  G_PROTOCOL_NUM = CCID_PROTOCOL_NUM_T1;
  G_CCID_TIME_EXTENSION_SEQ = 0u;
  reader_ccid_clear_xfr_response_chain();
  reader_ccid_clear_xfr_command_chain();
}

void reader_ccid_utest_handle_bulk(const uint8_t* frame, uint16_t nbytes) {
  reader_ccid_handle_bulk(frame, nbytes);
}

const uint8_t* reader_ccid_utest_last_send(void) {
  return reader_hal_utest_ccid_last_send();
}

uint16_t reader_ccid_utest_last_send_len(void) {
  return reader_hal_utest_ccid_last_send_len();
}

void reader_ccid_utest_set_millis(uint32_t ms) {
  reader_hal_utest_set_millis(ms);
}

void reader_ccid_utest_advance_millis(uint32_t delta) {
  reader_hal_utest_advance_millis(delta);
}

#endif /* NERO_HOST_UNIT_TEST_HOOKS */

#endif /* NERO_CCID_USB_BUILD */
