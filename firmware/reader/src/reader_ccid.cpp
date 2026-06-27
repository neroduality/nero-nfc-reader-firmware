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

#include <algorithm>
#include <cstdint>
#include <cstring>

#ifndef NERO_CCID_USB_BUILD

void reader_ccid_poll(void) {}

void reader_ccid_on_tag_detected(reader_tag_kind_t tag_kind) {
  (void)tag_kind;
}

void reader_ccid_on_tag_removed_from_field(void) {}

uint8_t reader_ccid_icc_status(void) {
  return (uint8_t)NFC_CCID_ICC_NO_ICC;
}

reader_tag_kind_t reader_ccid_tag_kind(void) {
  return READER_TAG_KIND_NONE;
}

#else /* NERO_CCID_USB_BUILD */

#include "reader_ccid_internal.h"
#include "reader_ccid_cmd_codes.h"
#include "reader_ccid_xfr.h"

bool g_sess;
bool g_card_present;
bool g_iso_session_open;
bool g_type4_security_key_app;
bool g_remove_deferred;
uint32_t g_remove_defer_until_ms;
reader_tag_kind_t g_tag_kind = READER_TAG_KIND_NONE;
uint8_t g_protocol_num = CCID_PROTOCOL_NUM_T1;
uint8_t g_ccid_apdu_rsp[CCID_APDU_RSP_BYTES];
uint8_t g_ccid_time_extension_seq;
uint8_t g_ccid_frame[NFC_CCID_WORK_BUF_SIZE];
uint8_t g_ccid_rsp[CCID_RSP_FRAME_BYTES];
uint8_t g_ccid_chain_buf[NFC_CCID_EXTENDED_RSP_BUF_SIZE];
uint16_t g_ccid_chain_len;
uint16_t g_ccid_chain_off;
bool g_ccid_chain_active;
uint8_t g_ccid_cmd_chain_buf[NFC_CCID_EXTENDED_RSP_BUF_SIZE];
uint16_t g_ccid_cmd_chain_len;
bool g_ccid_cmd_chain_active;

void reader_ccid_note_host_session_activity() {
  if (!g_sess) {
    return;
  }
  g_remove_deferred = false;
  g_remove_defer_until_ms = reader_hal_millis() + CCID_REMOVE_DEFER_MS;
}

void reader_ccid_poll() {
  const uint8_t *pkt = NERO_NFC_NULL;
  uint16_t rn = 0u;

  if (g_remove_deferred && (!g_sess || reader_ccid_deadline_elapsed(g_remove_defer_until_ms))) {
    reader_ccid_complete_card_removal();
  }

  if (reader_hal_ccid_peek(&pkt, &rn)) {
    uint16_t copy_len = rn;
    copy_len = std::min(copy_len, (uint16_t)sizeof(g_ccid_frame));
    if (copy_len != 0u) {
      if (!nero_nfc_copy_bytes(g_ccid_frame, sizeof(g_ccid_frame), 0u, pkt, copy_len)) {
        reader_hal_ccid_release();
        return;
      }
    }
    reader_hal_ccid_release();
    reader_ccid_handle_bulk(g_ccid_frame, copy_len);
  }
}
void reader_ccid_on_tag_detected(reader_tag_kind_t tag_kind) {
  if (g_remove_deferred) {
    reader_ccid_complete_card_removal();
  }
  reader_ccid_clear_xfr_response_chain();
  g_remove_deferred = false;
  g_tag_kind = tag_kind;
  g_type4_security_key_app = false;
  g_protocol_num = nfc_pcsc_protocol_for_tag(tag_kind);
  if (g_card_present) {
    return;
  }
  g_card_present = true;
  reader_hal_ccid_notify_slot_change(true);
}

void reader_ccid_on_tag_removed_from_field() {
  if (!g_card_present) {
    return;
  }
  if (g_sess) {
    reader_ccid_complete_card_removal();
    return;
  }
  if (!reader_ccid_deadline_elapsed(g_remove_defer_until_ms)) {
    g_remove_deferred = true;
    return;
  }
  reader_ccid_complete_card_removal();
}

uint8_t reader_ccid_icc_status() {
  return reader_ccid_current_icc_level();
}

reader_tag_kind_t reader_ccid_tag_kind() {
  return g_tag_kind;
}

#if defined(NERO_HOST_UNIT_TEST_HOOKS)

void reader_ccid_utest_reset(void) {
  g_sess = false;
  g_card_present = false;
  g_iso_session_open = false;
  g_type4_security_key_app = false;
  g_remove_deferred = false;
  g_remove_defer_until_ms = 0u;
  g_tag_kind = READER_TAG_KIND_NONE;
  g_protocol_num = CCID_PROTOCOL_NUM_T1;
  g_ccid_time_extension_seq = 0u;
  reader_ccid_clear_xfr_response_chain();
  reader_ccid_clear_xfr_command_chain();
}

void reader_ccid_utest_handle_bulk(const uint8_t *frame, uint16_t nbytes) {
  reader_ccid_handle_bulk(frame, nbytes);
}

const uint8_t *reader_ccid_utest_last_send(void) {
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
