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

/*
 * Minimal USB console facade for firmware/nfc (combined image). Implemented in
 * the board HAL (runtime/nfc_hal_board.c) so nfc_app.c stays free of
 * Arduino UART headers.
 */
void nfc_combined_shell_serial_begin(unsigned long baud);
NERO_NFC_NODISCARD bool nfc_combined_shell_serial_ready(void);
void nfc_combined_shell_serial_write_byte(uint8_t value);
uint32_t nfc_combined_shell_millis(void);

#ifdef __cplusplus
}
#endif
