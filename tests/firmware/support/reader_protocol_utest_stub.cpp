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

// Stubs RF/protocol entry points so ISO-DEP session sources link without ST25 SPI frontend.

#include "reader_protocol.h"

#include "nero_nfc_mem_util.h"

void reader_protocol_configure_iso14443a(void) {}

void reader_protocol_configure_iso15693(void) {}

bool reader_protocol_field_on(void) {
  return true;
}

bool reader_protocol_activate_iso14443a(void) {
  return true;
}

bool reader_protocol_send_wupa(uint8_t *atqa) {
  if (atqa != NERO_NFC_NULL) {
    atqa[0] = 0x04u;
    atqa[1] = 0x00u;
  }
  return true;
}

int reader_protocol_transceive14(const uint8_t *tx_data, uint16_t tx_len, uint8_t *rx,
                                 uint16_t rx_max, bool with_crc, uint16_t timeout_ms, bool anticol,
                                 bool no_rx_par) {
  (void)tx_data;
  (void)tx_len;
  (void)rx;
  (void)rx_max;
  (void)with_crc;
  (void)timeout_ms;
  (void)anticol;
  (void)no_rx_par;
  return -1;
}

int reader_protocol_iso15693_transceive(const uint8_t *tx, uint16_t tx_len, uint8_t *rx,
                                        uint16_t rx_max, uint16_t timeout_ms) {
  (void)tx;
  (void)tx_len;
  (void)rx;
  (void)rx_max;
  (void)timeout_ms;
  return -1;
}
