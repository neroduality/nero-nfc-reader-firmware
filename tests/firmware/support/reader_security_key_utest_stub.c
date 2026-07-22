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
#include "reader_context.h"
#include "reader_hal_utest.h"
#include "reader_security_key.h"

#include "nero_nfc_mem_util.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

enum {
  TEST_LIT_0X6A = 0x6Au,
  TEST_LIT_0X82 = 0x82u,
  TEST_LIT_0X90 = 0x90u,
  TEST_LIT_2 = 2u,
  TEST_LIT_32 = 32,
  STUB_APDU_RESPONSE_CAP = 512u,
};

static bool g_open_session_ok = true;
static bool g_copy_atr_ok = true;
static uint8_t g_stub_atr[TEST_LIT_32];
static uint16_t g_stub_atr_len;
static uint8_t g_apdu_response[STUB_APDU_RESPONSE_CAP];
static uint16_t g_apdu_response_len;
static uint16_t g_last_apdu_rsp_cap;
static bool g_select_fido_probe_ok;
static uint16_t g_select_fido_probe_count;
static bool g_abort_during_exchange;
static uint16_t g_time_extension_binding_count;

void reader_security_key_utest_reset(void) {
  g_open_session_ok = true;
  g_copy_atr_ok = true;
  g_stub_atr_len = 0u;
  g_apdu_response_len = 0u;
  g_last_apdu_rsp_cap = 0u;
  g_select_fido_probe_ok = false;
  g_select_fido_probe_count = 0u;
  g_abort_during_exchange = false;
  g_time_extension_binding_count = 0u;
  static const uint8_t DEFAULT_ATR[] = {0x3Bu, 0x8Au, 0x80u, 0x01u,
                                        0x01u, 0x52u, 0x03u};
  g_stub_atr_len = (uint16_t)sizeof(DEFAULT_ATR);
  (void)nero_nfc_copy_bytes(&g_stub_atr[0], (uint16_t)sizeof(g_stub_atr), 0u,
                            &DEFAULT_ATR[0], g_stub_atr_len);
}

void reader_security_key_utest_set_open_session_ok(bool ok) {
  g_open_session_ok = ok;
}

void reader_security_key_utest_set_copy_atr_ok(bool ok) { g_copy_atr_ok = ok; }

void reader_security_key_utest_set_apdu_response(const uint8_t* rsp,
                                                 uint16_t len) {
  g_apdu_response_len = 0u;
  if ((rsp == NERO_NFC_NULL) || (len == 0u)) {
    return;
  }
  if (len > sizeof(g_apdu_response)) {
    len = (uint16_t)sizeof(g_apdu_response);
  }
  (void)nero_nfc_copy_bytes(&g_apdu_response[0],
                            (uint16_t)sizeof(g_apdu_response), 0u, rsp, len);
  g_apdu_response_len = len;
}

uint16_t reader_security_key_utest_last_apdu_rsp_cap(void) {
  return g_last_apdu_rsp_cap;
}

void reader_security_key_utest_set_select_fido_probe_ok(bool ok) {
  g_select_fido_probe_ok = ok;
}

uint16_t reader_security_key_utest_select_fido_probe_count(void) {
  return g_select_fido_probe_count;
}

void reader_security_key_utest_set_abort_during_exchange(bool enabled) {
  g_abort_during_exchange = enabled;
}

bool reader_security_key_select_fido_probe(bool verbose,
                                           bool follow_get_response,
                                           uint8_t* rsp_out, uint16_t rsp_cap,
                                           uint16_t* rsp_len_out) {
  (void)verbose;
  (void)follow_get_response;
  g_select_fido_probe_count++;
  if ((rsp_out != NERO_NFC_NULL) && (rsp_cap >= TEST_LIT_2) &&
      (rsp_len_out != NERO_NFC_NULL)) {
    const uint8_t sw[] = {
        g_select_fido_probe_ok ? (uint8_t)(TEST_LIT_0X90)
                               : (uint8_t)(TEST_LIT_0X6A),
        g_select_fido_probe_ok ? (uint8_t)(0x00u) : (uint8_t)(TEST_LIT_0X82),
    };
    (void)nero_nfc_copy_bytes(rsp_out, rsp_cap, 0u, &sw[0], sizeof(sw));
    *rsp_len_out = TEST_LIT_2;
  }
  return g_select_fido_probe_ok;
}

void reader_security_key_ccid_release_iso_session(void) {}

bool reader_security_key_ccid_open_iso_session(void) {
  return g_open_session_ok;
}

bool reader_security_key_pcsc_contactless_copy_atr(uint8_t* dst,
                                                   uint16_t dst_cap,
                                                   uint16_t* alen_io) {
  if (!g_copy_atr_ok || (dst == NERO_NFC_NULL) || (alen_io == NERO_NFC_NULL)) {
    return false;
  }
  if (!nero_nfc_copy_bytes(dst, dst_cap, 0u, &g_stub_atr[0], g_stub_atr_len)) {
    return false;
  }
  *alen_io = g_stub_atr_len;
  return true;
}

void reader_security_key_set_ccid_time_extension_callback(
    reader_security_key_ccid_time_extension_cb_t cb, void* ctx) {
  (void)cb;
  (void)ctx;
  g_time_extension_binding_count++;
}

uint16_t reader_security_key_utest_time_extension_binding_count(void) {
  return g_time_extension_binding_count;
}

bool reader_security_key_apdu_needs_ccid_time_extension(const uint8_t* apdu,
                                                        uint16_t apdu_len) {
  (void)apdu;
  (void)apdu_len;
  return false;
}

uint16_t reader_security_key_apdu_exchange(const uint8_t* apdu,
                                           uint16_t apdu_len, uint8_t* rsp,
                                           uint16_t rsp_cap) {
  (void)apdu;
  (void)apdu_len;
  g_last_apdu_rsp_cap = rsp_cap;
  if (g_abort_during_exchange) {
    reader_hal_utest_ccid_set_abort_pending(true, 0u, 0u);
  }
  if ((rsp == NERO_NFC_NULL) || (rsp_cap < TEST_LIT_2)) {
    return 0u;
  }
  if (g_apdu_response_len == 0u) {
    const uint8_t sw[] = {TEST_LIT_0X90, 0x00u};
    (void)nero_nfc_copy_bytes(rsp, rsp_cap, 0u, &sw[0], sizeof(sw));
    return TEST_LIT_2;
  }
  if (!nero_nfc_copy_bytes(rsp, rsp_cap, 0u, &g_apdu_response[0],
                           g_apdu_response_len)) {
    return 0u;
  }
  return g_apdu_response_len;
}
