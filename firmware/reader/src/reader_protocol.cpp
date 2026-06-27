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
#include "reader_protocol.h"

#include "nero_nfc_mem_util.h"
#include "reader_context.h"
#include "reader_frontend.h"
#include "reader_hal.h"
#include "reader_output.h"
#include "st25r3916_iso14443a_uid.h"

#include <stdbool.h>
#include <stdint.h>

void reader_protocol_configure_iso14443a(void) {
  reader_frontend_configure_iso14443a();
}

void reader_protocol_configure_iso15693(void) {
  reader_frontend_configure_iso15693();
}

bool reader_protocol_field_on(void) {
  bool used_direct = false;
  nfc_frontend_field_on_status_t s;

  nero_nfc_log_write("  RF field...");
  s = reader_frontend_field_on(&used_direct);
  if (used_direct) {
    nero_nfc_log_write("(direct) ");
  }
  if (s == NFC_FRONTEND_FIELD_ON_TXRX_VERIFY_FAIL) {
    nero_nfc_log_line(" ERROR: TX/RX not enabled!");
    return false;
  }
  if (s != NFC_FRONTEND_FIELD_ON_OK) {
    return false;
  }
  nero_nfc_log_line(" OK");
  return true;
}

/* ── ISO 14443-A transceive (Type 2 + ISO-DEP framing) ────────── */

int reader_protocol_transceive14(const uint8_t *tx_data, uint16_t tx_len, uint8_t *rx,
                                 uint16_t rx_max, bool with_crc, uint16_t timeout_ms, bool anticol,
                                 bool no_rx_par) {
  if (((tx_data == NERO_NFC_NULL) && (tx_len != 0u)) || (rx == NERO_NFC_NULL)) {
    return -1;
  }
  return reader_frontend_transceive(tx_data, tx_len, rx, rx_max, with_crc, timeout_ms, anticol,
                                    no_rx_par, false, false, true);
}

static int transceive14_i(const uint8_t *tx_data, uint16_t tx_len, uint8_t *rx, uint16_t rx_max,
                          int with_crc, uint16_t timeout_ms, int anticol, int no_rx_par) {
  return reader_protocol_transceive14(tx_data, tx_len, rx, rx_max, with_crc != 0, timeout_ms,
                                      anticol != 0, no_rx_par != 0);
}

bool reader_protocol_send_wupa(uint8_t *atqa) {
  const bool ok = reader_frontend_send_wupa(atqa);

  g_atqa_valid = false;
  if (ok && (atqa != NERO_NFC_NULL)) {
    g_atqa[0] = atqa[0];
    g_atqa[1] = atqa[1];
    g_atqa_valid = true;
  }
  return ok;
}
static bool send_reqa(uint8_t *atqa) {
  return reader_frontend_send_reqa(atqa);
}

static int anticollision_select(uint8_t sel_cmd, uint8_t *uid_out) {
  uint8_t uid_tmp[ST25_ISO14443A_UID_LEN_SINGLE];
  int sak_result = nfc_frontend_anticollision_select(sel_cmd, uid_tmp, transceive14_i);
  if (sak_result < 0) {
    return -1;
  }
  if (!nero_nfc_copy_bytes(uid_out, sizeof(uid_tmp), 0u, uid_tmp, sizeof(uid_tmp))) {
    return -1;
  }
  return sak_result;
}

bool reader_protocol_activate_iso14443a(void) {
  return nfc_frontend_activate_iso14443a(reader_protocol_send_wupa, send_reqa, reader_hal_delay_ms,
                                         true, anticollision_select, g_uid14,
                                         (uint8_t)sizeof(g_uid14), &g_uid14_len, &g_sak);
}

/* ── ISO 14443-4 (ISO-DEP) transport for security keys ────────── */

int reader_protocol_iso15693_transceive(const uint8_t *tx, uint16_t tx_len, uint8_t *rx,
                                        uint16_t rx_max, uint16_t timeout_ms) {
  if (((tx == NERO_NFC_NULL) && (tx_len != 0u)) || (rx == NERO_NFC_NULL)) {
    return -1;
  }
  return reader_frontend_iso15693_transceive(tx, tx_len, rx, rx_max, timeout_ms);
}
