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
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if !defined(__cplusplus) && defined(__has_include)
#if __has_include(<stdckdint.h>)
#include <stdckdint.h>
#define NERO_NFC_HAVE_STDCKDINT 1
#endif
#endif

NERO_NFC_NODISCARD static inline bool nero_nfc_try_add_size(size_t a, size_t b, size_t *out) {
  if (out == NERO_NFC_NULL) {
    return false;
  }
#if defined(NERO_NFC_HAVE_STDCKDINT)
  return !ckd_add(out, a, b);
#else
  if (a > SIZE_MAX - b) {
    return false;
  }
  *out = a + b;
  return true;
#endif
}

NERO_NFC_NODISCARD static inline bool nero_nfc_try_sub_size(size_t a, size_t b, size_t *out) {
  if (out == NERO_NFC_NULL) {
    return false;
  }
#if defined(NERO_NFC_HAVE_STDCKDINT)
  return !ckd_sub(out, a, b);
#else
  if (b > a) {
    return false;
  }
  *out = a - b;
  return true;
#endif
}

NERO_NFC_NODISCARD static inline bool nero_nfc_try_add_u16(uint16_t a, uint16_t b, uint16_t *out) {
  if (out == NERO_NFC_NULL) {
    return false;
  }
#if defined(NERO_NFC_HAVE_STDCKDINT)
  return !ckd_add(out, a, b);
#else
  if ((unsigned)a > (unsigned)UINT16_MAX - (unsigned)b) {
    return false;
  }
  *out = (uint16_t)((unsigned)a + (unsigned)b);
  return true;
#endif
}

NERO_NFC_NODISCARD static inline bool nero_nfc_span_ok(size_t offset, size_t count, size_t cap) {
  size_t end = 0u;
  return nero_nfc_try_add_size(offset, count, &end) && end <= cap;
}

NERO_NFC_NODISCARD static inline bool nero_nfc_bounded_strlen(const char *s, size_t cap,
                                                              size_t *out_len) {
  size_t n = 0u;

  if (out_len != NERO_NFC_NULL) {
    *out_len = 0u;
  }
  if (s == NERO_NFC_NULL || out_len == NERO_NFC_NULL) {
    return false;
  }
  while (n < cap) {
    if (s[n] == '\0') {
      *out_len = n;
      return true;
    }
    n++;
  }
  return false;
}

NERO_NFC_NODISCARD static inline bool nero_nfc_copy_bytes(void *dst, size_t dst_cap, size_t dst_off,
                                                          const void *src, size_t src_len) {
  if (dst == NERO_NFC_NULL || (src == NERO_NFC_NULL && src_len != 0u)) {
    return false;
  }
  if (!nero_nfc_span_ok(dst_off, src_len, dst_cap)) {
    return false;
  }
  if (src_len == 0u) {
    return true;
  }
#if defined(__cplusplus)
  memcpy(static_cast<uint8_t *>(dst) + dst_off, src, src_len);
#else
  memcpy((uint8_t *)dst + dst_off, src, src_len);
#endif
  return true;
}

NERO_NFC_NODISCARD static inline bool nero_nfc_move_bytes(void *dst, size_t dst_cap, size_t dst_off,
                                                          const void *src, size_t src_len) {
  if (dst == NERO_NFC_NULL || (src == NERO_NFC_NULL && src_len != 0u)) {
    return false;
  }
  if (!nero_nfc_span_ok(dst_off, src_len, dst_cap)) {
    return false;
  }
  if (src_len == 0u) {
    return true;
  }
#if defined(__cplusplus)
  memmove(static_cast<uint8_t *>(dst) + dst_off, src, src_len);
#else
  memmove((uint8_t *)dst + dst_off, src, src_len);
#endif
  return true;
}

static inline void nero_nfc_zero_bytes(void *ptr, size_t len) {
  if (ptr == NERO_NFC_NULL || len == 0u) {
    return;
  }
#if defined(__cplusplus)
  memset(static_cast<void *>(ptr), 0, len);
#else
  memset(ptr, 0, len);
#endif
}

static inline void nero_nfc_secure_clear(void *ptr, size_t len) {
  if (ptr == NERO_NFC_NULL || len == 0u) {
    return;
  }
#ifdef NERO_NFC_HAVE_MEMSET_EXPLICIT
  memset_explicit(ptr, 0, len);
#else
#if defined(__cplusplus)
  auto *p = static_cast<volatile uint8_t *>(ptr);
#else
  volatile uint8_t *p = (volatile uint8_t *)ptr;
#endif
  while (len-- > 0u) {
    *p++ = 0u;
  }
#endif
}
