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

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* HAL sink (one definition per firmware image). Valid as nero_nfc_emit_fn_t for tutorial emit. */
void nero_nfc_log_putc(char c);

/* Firmware CDC console print helpers (all nero_nfc_log_*). */
void nero_nfc_log_write(const char *s);
void nero_nfc_log_line(const char *s);
void nero_nfc_log_hex_u8(uint8_t value);
void nero_nfc_log_dec_u32(uint32_t value);
void nero_nfc_log_dec_i32(int32_t value);
void nero_nfc_log_hex_span(const uint8_t *buf, size_t cap, size_t off, size_t len);

#ifdef __cplusplus
}
#endif
