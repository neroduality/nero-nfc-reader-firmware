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

#include "nero_nfc_board.h"

#include "nero_nfc_mem_util.h"
#include "nero_nfc_null.h"
#include "nfc_board_defaults.h"

void nero_nfc_board_config_defaults(nero_nfc_board_config_t* out) {
  size_t name_len = 0u;

  if (out == NERO_NFC_NULL) {
    return;
  }
  nero_nfc_zero_bytes(out, sizeof(*out));
  out->cs_pin = (uint8_t)NFC_BOARD_CS_PIN;
  out->irq_pin = (uint8_t)NFC_BOARD_IRQ_PIN;
  out->led_pin = (uint8_t)NFC_BOARD_LED_PIN;
  out->serial_baud = (uint32_t)NFC_HOST_SERIAL_BAUD;
  out->spi_clock_hz = (uint32_t)NFC_BOARD_SPI_CLOCK_HZ;
  if (nero_nfc_bounded_strlen(NFC_HOST_BOARD_NAME, NERO_NFC_BOARD_NAME_CAP,
                              &name_len)) {
    (void)nero_nfc_copy_bytes(out->host_board_name, NERO_NFC_BOARD_NAME_CAP, 0u,
                              NFC_HOST_BOARD_NAME, name_len);
  }
  out->host_board_name[NERO_NFC_BOARD_NAME_CAP - 1u] = '\0';
}

bool nero_nfc_board_config_validate(const nero_nfc_board_config_t* board) {
  if (board == NERO_NFC_NULL) {
    return false;
  }
  if (board->serial_baud == 0u) {
    return false;
  }
  if (board->spi_clock_hz == 0u) {
    return false;
  }
  if (board->host_board_name[0] == '\0') {
    return false;
  }
  return true;
}

void nero_nfc_board_config_copy(nero_nfc_board_config_t* dst,
                                const nero_nfc_board_config_t* src) {
  if ((dst == NERO_NFC_NULL) || (src == NERO_NFC_NULL)) {
    return;
  }
  (void)nero_nfc_copy_bytes(dst, sizeof(*dst), 0u, src, sizeof(*src));
  dst->host_board_name[NERO_NFC_BOARD_NAME_CAP - 1u] = '\0';
}
