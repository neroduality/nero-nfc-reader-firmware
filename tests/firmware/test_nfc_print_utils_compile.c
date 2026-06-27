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

/*
 * Ensures nfc_print_utils.h is valid C (not only C++) and stays buildable if
 * helpers gain C-only constraints. Called once from the C++ test binary.
 */

#include <stdint.h>

#include "nfc_print_utils.h"

static void touch_putc(char c) { (void)c; }

void nero_nfc_print_utils_compile_touch_c(void) {
  nero_nfc_emit_write(touch_putc, "");
  nero_nfc_emit_write(touch_putc, "x");
  nero_nfc_emit_hex_u8(touch_putc, 0x00u);
  nero_nfc_emit_hex_u8(touch_putc, 0xFFu);
  nero_nfc_emit_dec_u32(touch_putc, 0u);
  nero_nfc_emit_dec_u32(touch_putc, 4294967295u);
  nero_nfc_emit_dec_i32(touch_putc, 0);
  nero_nfc_emit_dec_i32(touch_putc, INT32_MIN);
}
