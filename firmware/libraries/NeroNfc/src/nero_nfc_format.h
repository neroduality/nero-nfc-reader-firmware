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

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
  NERO_NFC_FORMAT_SNPRINTF_DEC_CAP = 16u,
  NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP = 8u,
};

#if defined(__GNUC__)
#define NERO_NFC_PRINTF_LIKE(fmt_idx, arg_idx) \
  __attribute__((format(printf, fmt_idx, arg_idx)))
#else
#define NERO_NFC_PRINTF_LIKE(fmt_idx, arg_idx)
#endif

NERO_NFC_NODISCARD static inline bool nero_nfc_snprintf_ok(int n, size_t cap) {
  return n >= 0 && cap > 0u && (size_t)n < cap;
}

int nero_nfc_snprintf(char* buf, size_t cap, const char* fmt, ...)
    NERO_NFC_PRINTF_LIKE(3, 4);
int nero_nfc_vsnprintf(char* buf, size_t cap, const char* fmt, va_list args)
    NERO_NFC_PRINTF_LIKE(3, 0);

NERO_NFC_NODISCARD bool nero_nfc_try_snprintf(char* buf, size_t cap,
                                              const char* fmt, ...)
    NERO_NFC_PRINTF_LIKE(3, 4);
NERO_NFC_NODISCARD bool nero_nfc_try_vsnprintf(char* buf, size_t cap,
                                               const char* fmt, va_list args)
    NERO_NFC_PRINTF_LIKE(3, 0);

NERO_NFC_NODISCARD bool nero_nfc_appendf(char* buf, size_t cap, size_t* off,
                                         const char* fmt, ...)
    NERO_NFC_PRINTF_LIKE(4, 5);

#ifdef __cplusplus
}
#endif
