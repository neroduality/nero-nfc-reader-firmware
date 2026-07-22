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

#pragma once

#include "nero_nfc_attrs.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
  NERO_NFC_BOARD_NAME_CAP = 48u,
};

typedef struct nero_nfc_board_config {
  uint8_t cs_pin;
  uint8_t irq_pin;
  uint8_t led_pin;
  uint32_t serial_baud;
  uint32_t spi_clock_hz;
  char host_board_name[NERO_NFC_BOARD_NAME_CAP];
} nero_nfc_board_config_t;

void nero_nfc_board_config_defaults(nero_nfc_board_config_t* out);
NERO_NFC_NODISCARD bool nero_nfc_board_config_validate(
    const nero_nfc_board_config_t* board);
void nero_nfc_board_config_copy(nero_nfc_board_config_t* dst,
                                const nero_nfc_board_config_t* src);

#ifdef __cplusplus
}
#endif
