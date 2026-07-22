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

#include "nero_nfc_frontend.h"

static uint8_t fake_measure(void* state) {
  (void)state;
  return 0u;
}

static nfc_frontend_init_status_t fake_init(void* state, uint8_t* chip_id,
                                            uint16_t* vdd_mv) {
  ((st25r3916_t*)state)->initialized = true;
  if (chip_id != 0) {
    *chip_id = 0u;
  }
  if (vdd_mv != 0) {
    *vdd_mv = 0u;
  }
  return NFC_FRONTEND_INIT_OK;
}

static void fake_void(void* state) { (void)state; }
static void fake_config(void* state) { (void)state; }
static void fake_quiesce(void* state) {
  ((st25r3916_t*)state)->quiesce_count++;
}

static nfc_frontend_field_on_status_t fake_field_on(void* state,
                                                    bool* used_direct) {
  (void)state;
  if (used_direct != 0) {
    *used_direct = false;
  }
  return NFC_FRONTEND_FIELD_ON_OK;
}

static int fake_transceive(void* state, const uint8_t* tx, uint16_t tx_len,
                           uint8_t* rx, uint16_t rx_max, bool with_crc,
                           uint16_t timeout_ms, bool anticol, bool no_rx_par,
                           bool extended_nrt, bool poll_rx, bool clear_nfc) {
  (void)state;
  (void)tx;
  (void)tx_len;
  if ((rx != 0) && (rx_max != 0u)) {
    rx[0] = 0u;
  }
  (void)with_crc;
  (void)timeout_ms;
  (void)anticol;
  (void)no_rx_par;
  (void)extended_nrt;
  (void)poll_rx;
  (void)clear_nfc;
  return 0;
}

static int fake_transceive_diag(void* state, const uint8_t* tx, uint16_t tx_len,
                                uint8_t* rx, uint16_t rx_max, bool with_crc,
                                uint16_t timeout_ms, bool anticol,
                                bool no_rx_par, bool extended_nrt, bool poll_rx,
                                bool clear_nfc,
                                nfc_frontend_transceive_diag_t* diag) {
  (void)diag;
  return fake_transceive(state, tx, tx_len, rx, rx_max, with_crc, timeout_ms,
                         anticol, no_rx_par, extended_nrt, poll_rx, clear_nfc);
}

static bool fake_short_frame(void* state, uint8_t* atqa) {
  (void)state;
  if (atqa != 0) {
    atqa[0] = 0u;
  }
  return false;
}

static const nfc_frontend_ops_t FAKE_OPS = {
    fake_measure,         fake_init,        fake_config,
    fake_config,          fake_field_on,    fake_transceive,
    fake_transceive_diag, fake_short_frame, fake_short_frame,
    fake_quiesce,         fake_void,        fake_void,
};

void nero_nfc_st25_frontend_bind(nfc_frontend_t* frontend, st25r3916_t* state,
                                 const nero_nfc_platform_ops_t* platform,
                                 const nero_nfc_board_config_t* board) {
  state->platform = platform;
  state->board = board;
  frontend->ops = &FAKE_OPS;
  frontend->state = state;
}
