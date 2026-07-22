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

#include "nero_nfc_format.h"
#include "nero_nfc_null.h"

#include <stdarg.h>
#include <stdio.h>

int nero_nfc_vsnprintf(char* buf, size_t cap, const char* fmt, va_list args) {
  int n;
  va_list args_copy;

  if (buf == NERO_NFC_NULL || cap == 0u || fmt == NERO_NFC_NULL) {
    if (buf != NERO_NFC_NULL && cap > 0u) {
      buf[0] = '\0';
    }
    return -1;
  }
  va_copy(args_copy, args);
  /* Bounded printf wrapper: fmt is validated by the printf format attribute on
   * the public API; the libc call still requires a non-literal format. */
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
#endif
  n = vsnprintf(buf, cap, fmt, args_copy);
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
  va_end(args_copy);
  if (!nero_nfc_snprintf_ok(n, cap)) {
    buf[0] = '\0';
    return -1;
  }
  return n;
}

bool nero_nfc_try_vsnprintf(char* buf, size_t cap, const char* fmt,
                            va_list args) {
  const int n = nero_nfc_vsnprintf(buf, cap, fmt, args);
  if (nero_nfc_snprintf_ok(n, cap)) {
    return true;
  }
  /* Fail closed: do not leave truncated / indeterminate content. */
  if (buf != NERO_NFC_NULL && cap > 0u) {
    buf[0] = '\0';
  }
  return false;
}

bool nero_nfc_try_snprintf(char* buf, size_t cap, const char* fmt, ...) {
  va_list args;
  bool ok = false;

  if (fmt == NERO_NFC_NULL) {
    if (buf != NERO_NFC_NULL && cap > 0u) {
      buf[0] = '\0';
    }
    return false;
  }
  va_start(args, fmt);
  ok = nero_nfc_try_vsnprintf(buf, cap, fmt, args);
  va_end(args);
  return ok;
}

int nero_nfc_snprintf(char* buf, size_t cap, const char* fmt, ...) {
  va_list args;
  int n = -1;

  if (fmt == NERO_NFC_NULL) {
    if (buf != NERO_NFC_NULL && cap > 0u) {
      buf[0] = '\0';
    }
    return -1;
  }
  va_start(args, fmt);
  n = nero_nfc_vsnprintf(buf, cap, fmt, args);
  va_end(args);
  return n;
}

bool nero_nfc_appendf(char* buf, size_t cap, size_t* off, const char* fmt,
                      ...) {
  va_list args;

  if (fmt == NERO_NFC_NULL) {
    return false;
  }
  va_start(args, fmt);
  if (buf != NERO_NFC_NULL && off != NERO_NFC_NULL && *off <= cap) {
    const size_t remaining = cap - *off;
    const int n = nero_nfc_vsnprintf(buf + *off, remaining, fmt, args);
    if (nero_nfc_snprintf_ok(n, remaining)) {
      *off += (size_t)n;
      va_end(args);
      return true;
    }
    /* Undo any truncated write so the prior committed prefix stays intact. */
    if (remaining > 0u) {
      buf[*off] = '\0';
    }
  }
  va_end(args);
  return false;
}
