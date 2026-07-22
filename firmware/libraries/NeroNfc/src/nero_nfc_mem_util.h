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
#include "nero_nfc_null.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Bounded min/max for scalar arguments without side effects (firmware use). */
#define NERO_NFC_MIN(a, b) (((a) < (b)) ? (a) : (b))
#define NERO_NFC_MAX(a, b) (((a) > (b)) ? (a) : (b))

#if !defined(__cplusplus) && defined(__has_include)
#if __has_include(<stdckdint.h>)
#include <stdckdint.h>
#define NERO_NFC_HAVE_STDCKDINT 1
#endif
#endif

NERO_NFC_NODISCARD static inline bool nero_nfc_try_add_size(size_t a, size_t b,
                                                            size_t* out) {
  if (out == NERO_NFC_NULL) {
    return false;
  }
  *out = 0u;
#if defined(NERO_NFC_HAVE_STDCKDINT)
  {
    size_t value = 0u;
    if (ckd_add(&value, a, b)) {
      return false;
    }
    *out = value;
    return true;
  }
#else
  if (a > SIZE_MAX - b) {
    return false;
  }
  *out = a + b;
  return true;
#endif
}

NERO_NFC_NODISCARD static inline bool nero_nfc_try_sub_size(size_t a, size_t b,
                                                            size_t* out) {
  if (out == NERO_NFC_NULL) {
    return false;
  }
  *out = 0u;
#if defined(NERO_NFC_HAVE_STDCKDINT)
  {
    size_t value = 0u;
    if (ckd_sub(&value, a, b)) {
      return false;
    }
    *out = value;
    return true;
  }
#else
  if (b > a) {
    return false;
  }
  *out = a - b;
  return true;
#endif
}

NERO_NFC_NODISCARD static inline bool nero_nfc_try_add_u16(uint16_t a,
                                                           uint16_t b,
                                                           uint16_t* out) {
  if (out == NERO_NFC_NULL) {
    return false;
  }
  *out = 0u;
#if defined(NERO_NFC_HAVE_STDCKDINT)
  {
    uint16_t value = 0u;
    if (ckd_add(&value, a, b)) {
      return false;
    }
    *out = value;
    return true;
  }
#else
  if ((unsigned)(a) > (unsigned)UINT16_MAX - (unsigned)(b)) {
    return false;
  }
  *out = (uint16_t)((unsigned)(a) + (unsigned)(b));
  return true;
#endif
}

#if !defined(__cplusplus)
#define NERO_NFC_TRY_ADD(a, b, out)   \
  _Generic((out),                     \
      size_t*: nero_nfc_try_add_size, \
      uint16_t*: nero_nfc_try_add_u16)((a), (b), (out))
#endif

NERO_NFC_NODISCARD static inline bool nero_nfc_span_ok(size_t offset,
                                                       size_t count,
                                                       size_t cap) {
  size_t end = 0u;
  return nero_nfc_try_add_size(offset, count, &end) && end <= cap;
}

NERO_NFC_NODISCARD static inline bool nero_nfc_bounded_strlen(const char* s,
                                                              size_t cap,
                                                              size_t* out_len) {
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

NERO_NFC_NODISCARD static inline bool nero_nfc_copy_bytes(void* dst,
                                                          size_t dst_cap,
                                                          size_t dst_off,
                                                          const void* src,
                                                          size_t src_len) {
  if (dst == NERO_NFC_NULL || (src == NERO_NFC_NULL && src_len != 0u)) {
    return false;
  }
  if (!nero_nfc_span_ok(dst_off, src_len, dst_cap)) {
    return false;
  }
  if (src_len == 0u) {
    return true;
  }
  /* memmove preserves the bounded-copy contract even when ranges overlap. */
#if defined(__cplusplus)
  memmove((uint8_t*)(dst) + dst_off, src, src_len);
#else
  memmove((uint8_t*)dst + dst_off, src, src_len);
#endif
  return true;
}

/* Bounded byte load/store — keep pointer math in this .h so host cxx tidy
 * (HeaderFilterRegex: *.hpp only) does not flag call sites in .hpp / .cpp. */
NERO_NFC_NODISCARD static inline bool nero_nfc_copy_from(
    void* dst, size_t dst_cap, size_t dst_off, const uint8_t* src,
    size_t src_cap, size_t src_off, size_t len) {
  if (dst == NERO_NFC_NULL || ((src == NERO_NFC_NULL) && (len != 0u))) {
    return false;
  }
  if (!nero_nfc_span_ok(src_off, len, src_cap)) {
    return false;
  }
  if (len == 0u) {
    return true;
  }
  return nero_nfc_copy_bytes(dst, dst_cap, dst_off, src + src_off, len);
}

NERO_NFC_NODISCARD static inline bool nero_nfc_load_u8(const uint8_t* base,
                                                       size_t cap, size_t off,
                                                       uint8_t* out) {
  if (out == NERO_NFC_NULL) {
    return false;
  }
  *out = 0u;
  return nero_nfc_copy_from(out, 1u, 0u, base, cap, off, 1u);
}

NERO_NFC_NODISCARD static inline bool nero_nfc_store_u8(uint8_t* base,
                                                        size_t cap, size_t off,
                                                        uint8_t value) {
  return nero_nfc_copy_bytes(base, cap, off, &value, 1u);
}

/* Convenience load after a proven in-range offset. Out-of-range returns 0 so
 * compares against non-zero protocol constants fail closed; prefer
 * nero_nfc_load_u8 when the value may legitimately be zero. */
NERO_NFC_NODISCARD static inline uint8_t nero_nfc_u8_at(const uint8_t* base,
                                                        size_t cap,
                                                        size_t off) {
  uint8_t value = 0u;
  if (!nero_nfc_load_u8(base, cap, off, &value)) {
    return 0u;
  }
  return value;
}

NERO_NFC_NODISCARD static inline bool nero_nfc_move_bytes(
    void* dst, size_t dst_cap, size_t dst_off, const void* src, size_t src_len);

NERO_NFC_NODISCARD static inline bool nero_nfc_copy_cstr(char* dst,
                                                         size_t dst_cap,
                                                         const char* src) {
  size_t len = 0u;
  if (dst == NERO_NFC_NULL || dst_cap == 0u) {
    return false;
  }
  if (src == NERO_NFC_NULL) {
    dst[0] = '\0';
    return true;
  }
  if (!nero_nfc_bounded_strlen(src, dst_cap, &len) ||
      !nero_nfc_try_add_size(len, 1u, &len) || len > dst_cap) {
    dst[0] = '\0';
    return false;
  }
  if (len <= 1u) {
    dst[0] = '\0';
    return true;
  }
  if (!nero_nfc_move_bytes(dst, dst_cap, 0u, src, len - 1u)) {
    dst[0] = '\0';
    return false;
  }
  if (!nero_nfc_span_ok(len - 1u, 1u, dst_cap)) {
    dst[0] = '\0';
    return false;
  }
  dst[len - 1u] = '\0';
  return true;
}

NERO_NFC_NODISCARD static inline bool nero_nfc_move_bytes(void* dst,
                                                          size_t dst_cap,
                                                          size_t dst_off,
                                                          const void* src,
                                                          size_t src_len) {
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
  memmove((uint8_t*)(dst) + dst_off, src, src_len);
#else
  memmove((uint8_t*)dst + dst_off, src, src_len);
#endif
  return true;
}

static inline void nero_nfc_zero_bytes(void* ptr, size_t len) {
  if (ptr == NERO_NFC_NULL || len == 0u) {
    return;
  }
#if defined(__cplusplus)
  memset(ptr, 0, len);
#else
  memset(ptr, 0, len);
#endif
}

static inline void nero_nfc_secure_clear(void* ptr, size_t len) {
  if (ptr == NERO_NFC_NULL || len == 0u) {
    return;
  }
#ifdef NERO_NFC_HAVE_MEMSET_EXPLICIT
  memset_explicit(ptr, 0, len);
#else
  volatile uint8_t* p = (volatile uint8_t*)ptr;
  while (len-- > 0u) {
    *p++ = 0u;
  }
#endif
}
