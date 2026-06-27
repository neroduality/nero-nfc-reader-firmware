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

#include "nero_nfc_mem_util.h"

#include <stdint.h>

#ifdef __cplusplus
using nero_nfc_emit_fn_t = void (*)(char c);
#else
typedef void (*nero_nfc_emit_fn_t)(char c);
#endif

enum {
  NERO_NFC_EMIT_HEX_NIBBLE_MASK = 0x0Fu,
  NERO_NFC_EMIT_HEX_HIGH_NIBBLE_SHIFT = 4u,
  NERO_NFC_EMIT_DEC_BUF_CAP = 11u,
  NERO_NFC_EMIT_DEC_RADIX = 10u,
};

/* Rename parameter to avoid collision with the picolibc putc(c,stream) macro. */
static inline void nero_nfc_emit_write(nero_nfc_emit_fn_t emit, const char *s) {
  if ((emit == NERO_NFC_NULL) || (s == NERO_NFC_NULL)) {
    return;
  }
  while (*s != '\0') {
    emit(*s++);
  }
}

static inline void nero_nfc_emit_hex_u8(nero_nfc_emit_fn_t emit, uint8_t value) {
  static const char kHex[] = "0123456789ABCDEF";
  if (emit == NERO_NFC_NULL) {
    return;
  }
  emit(kHex[value >> NERO_NFC_EMIT_HEX_HIGH_NIBBLE_SHIFT]);
  emit(kHex[value & NERO_NFC_EMIT_HEX_NIBBLE_MASK]);
}

static inline void nero_nfc_emit_dec_u32(nero_nfc_emit_fn_t emit, uint32_t value) {
  char buffer[NERO_NFC_EMIT_DEC_BUF_CAP];
  uint8_t pos = 0u;

  if (emit == NERO_NFC_NULL) {
    return;
  }
  if (value == 0u) {
    emit('0');
    return;
  }

  while (value > 0u) {
    buffer[pos++] = (char)('0' + (value % NERO_NFC_EMIT_DEC_RADIX));
    value /= NERO_NFC_EMIT_DEC_RADIX;
  }
  while (pos > 0u) {
    emit(buffer[--pos]);
  }
}

static inline void nero_nfc_emit_dec_i32(nero_nfc_emit_fn_t emit, int32_t value) {
  if (emit == NERO_NFC_NULL) {
    return;
  }
  if (value < 0) {
    emit('-');
    uint32_t mag;
    if (value == INT32_MIN) {
      mag = (uint32_t)INT32_MAX + 1u;
    } else {
      mag = (uint32_t)(-value);
    }
    nero_nfc_emit_dec_u32(emit, mag);
    return;
  }
  nero_nfc_emit_dec_u32(emit, (uint32_t)value);
}
