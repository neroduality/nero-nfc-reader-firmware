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

#include "nero_nfc_log.h"

#include "nero_nfc_app.h"
#include "nero_nfc_mem_util.h"
#include "nero_nfc_null.h"

#include <stdint.h>

enum {
  NERO_NFC_LOG_HEX_HIGH_NIBBLE_SHIFT = 4u,
  NERO_NFC_LOG_HEX_NIBBLE_MASK = 0x0Fu,
  NERO_NFC_LOG_DEC_BUF_CAP = 11u,
  NERO_NFC_LOG_DEC_RADIX = 10u,
};

void nero_nfc_log_set_sink(nero_nfc_log_sink_fn_t sink) {
  nero_nfc_app_set_log_sink(nero_nfc_app_active(), sink);
}

void nero_nfc_log_putc(char c) {
  nero_nfc_log_sink_fn_t sink = nero_nfc_app_log_sink(nero_nfc_app_active());
  if (sink != NERO_NFC_NULL) {
    sink(c);
  }
}

void nero_nfc_log_write(const char* s) {
  if (s == NERO_NFC_NULL) {
    return;
  }
  while (*s != '\0') {
    nero_nfc_log_putc(*s++);
  }
}

void nero_nfc_log_line(const char* s) {
  nero_nfc_log_write(s);
  nero_nfc_log_write("\r\n");
}

void nero_nfc_log_hex_u8(uint8_t value) {
  static const char K_HEX[] = "0123456789ABCDEF";

  nero_nfc_log_putc(K_HEX[value >> NERO_NFC_LOG_HEX_HIGH_NIBBLE_SHIFT]);
  nero_nfc_log_putc(K_HEX[value & NERO_NFC_LOG_HEX_NIBBLE_MASK]);
}

void nero_nfc_log_dec_u32(uint32_t value) {
  char buffer[NERO_NFC_LOG_DEC_BUF_CAP];
  uint8_t pos = 0u;

  if (value == 0u) {
    nero_nfc_log_putc('0');
    return;
  }

  while (value > 0u) {
    buffer[pos++] = (char)('0' + (value % NERO_NFC_LOG_DEC_RADIX));
    value /= NERO_NFC_LOG_DEC_RADIX;
  }
  while (pos > 0u) {
    nero_nfc_log_putc(buffer[--pos]);
  }
}

void nero_nfc_log_dec_i32(int32_t value) {
  if (value < 0) {
    nero_nfc_log_putc('-');
    uint32_t mag;
    if (value == INT32_MIN) {
      mag = (uint32_t)INT32_MAX + 1u;
    } else {
      mag = (uint32_t)(-value);
    }
    nero_nfc_log_dec_u32(mag);
    return;
  }
  nero_nfc_log_dec_u32((uint32_t)value);
}

void nero_nfc_log_hex_span(const uint8_t* buf, size_t cap, size_t off,
                           size_t len) {
  size_t i;

  if ((buf == NERO_NFC_NULL) || !nero_nfc_span_ok(off, len, cap)) {
    return;
  }
  for (i = 0u; i < len; i++) {
    if (!nero_nfc_span_ok(off + i, 1u, cap)) {
      return;
    }
    nero_nfc_log_hex_u8(buf[off + i]);
  }
}
