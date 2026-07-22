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

#include "nero_nfc_null.h"
#include "reader_cbor.h"

#include "nero_nfc_limits.h"
#include "nero_nfc_mem_util.h"
#include "nfc_tag_geometry_limits.h"

#include <stdint.h>

enum {
  READER_CBOR_AI_MASK = 0x1Fu,
  READER_CBOR_MAJOR_TYPE_SHIFT = 5u,
  READER_CBOR_UINT32_SHIFT_BYTE3 = 24u,
  READER_CBOR_UINT32_SHIFT_BYTE2 = 16u,
  READER_CBOR_AI_UINT8 = 24u,
  READER_CBOR_AI_UINT16 = 25u,
  READER_CBOR_AI_UINT32 = 26u,
  READER_CBOR_AI_UINT8_LEN = 1u,
  READER_CBOR_AI_UINT16_LEN = 2u,
  READER_CBOR_AI_UINT32_LEN = 4u,
  READER_CBOR_BREAK_BYTE = 0xFFu,
  READER_CBOR_HEADER_INDEF_BYTES = 0x5Fu,
  READER_CBOR_LEGACY_ALIAS_KEY = 3u,
  READER_CBOR_MAJOR_TAG = 6u,
};

bool cbor_has_remaining(const cbor_reader_t* c, uint32_t count) {
  if (c == NERO_NFC_NULL) {
    return false;
  }
  return (c->pos <= c->len) && (((uint32_t)(c->len) - c->pos) >= count);
}
bool cbor_at_end(const cbor_reader_t* c) {
  if (c == NERO_NFC_NULL) {
    return true;
  }
  return c->pos >= c->len;
}
uint8_t cbor_next(cbor_reader_t* c) {
  if ((c == NERO_NFC_NULL) || (c->data == NERO_NFC_NULL)) {
    return 0u;
  }
  return (c->pos < c->len) ? c->data[c->pos++] : 0u;
}
bool cbor_read_head(cbor_reader_t* c, uint8_t* major, uint32_t* value) {
  uint16_t start;
  uint8_t ib;
  uint8_t ai;

  if ((c == NERO_NFC_NULL) || (major == NERO_NFC_NULL) ||
      (value == NERO_NFC_NULL) || (c->data == NERO_NFC_NULL)) {
    return false;
  }
  if (c->pos >= c->len) {
    return false;
  }
  start = c->pos;
  ib = cbor_next(c);
  *major = (uint8_t)(ib >> READER_CBOR_MAJOR_TYPE_SHIFT);
  ai = (uint8_t)(ib & READER_CBOR_AI_MASK);
  if (ai < READER_CBOR_AI_UINT8) {
    *value = ai;
    return true;
  }
  if (ai == READER_CBOR_AI_UINT8) {
    if (!cbor_has_remaining(c, READER_CBOR_AI_UINT8_LEN)) {
      c->pos = start;
      return false;
    }
    *value = cbor_next(c);
    return true;
  }
  if (ai == READER_CBOR_AI_UINT16) {
    if (!cbor_has_remaining(c, READER_CBOR_AI_UINT16_LEN)) {
      c->pos = start;
      return false;
    }
    *value = ((uint32_t)(cbor_next(c)) << NFC_BYTE_SHIFT_8) | cbor_next(c);
    return true;
  }
  if (ai == READER_CBOR_AI_UINT32) {
    if (!cbor_has_remaining(c, READER_CBOR_AI_UINT32_LEN)) {
      c->pos = start;
      return false;
    }
    *value = ((uint32_t)(cbor_next(c)) << READER_CBOR_UINT32_SHIFT_BYTE3) |
             ((uint32_t)(cbor_next(c)) << READER_CBOR_UINT32_SHIFT_BYTE2) |
             ((uint32_t)(cbor_next(c)) << NFC_BYTE_SHIFT_8) | cbor_next(c);
    return true;
  }

  /* Indefinite lengths (ai==31) and other additional information values are
   * handled elsewhere. */
  c->pos = start;
  return false;
}
bool cbor_read_uint(cbor_reader_t* c, uint32_t* value) {
  uint16_t start;
  uint8_t major;

  if ((c == NERO_NFC_NULL) || (value == NERO_NFC_NULL)) {
    return false;
  }
  start = c->pos;
  if (!cbor_read_head(c, &major, value)) {
    return false;
  }
  if (major != 0u) {
    c->pos = start;
    return false;
  }
  return true;
}
bool cbor_read_text(cbor_reader_t* c, char* buffer, uint16_t buffer_len) {
  uint16_t start;
  uint8_t major;
  uint32_t str_len;

  if (c == NERO_NFC_NULL) {
    return false;
  }
  start = c->pos;
  if (!cbor_read_head(c, &major, &str_len)) {
    return false;
  }
  if (major != NFC_CBOR_MAJOR_TEXT) {
    c->pos = start;
    return false;
  }
  if ((buffer == NERO_NFC_NULL) || (buffer_len == 0u) ||
      !cbor_has_remaining(c, str_len) || (str_len >= (uint32_t)(buffer_len))) {
    c->pos = start;
    return false;
  }
  for (uint32_t i = 0u; i < str_len; i++) {
    if (!nero_nfc_store_u8((uint8_t*)(buffer), (size_t)(buffer_len),
                           (size_t)(i), cbor_next(c))) {
      c->pos = start;
      return false;
    }
  }
  if (!nero_nfc_store_u8((uint8_t*)(buffer), (size_t)(buffer_len),
                         (size_t)(str_len), 0u)) {
    c->pos = start;
    return false;
  }
  return true;
}
bool cbor_read_bytes(cbor_reader_t* c, uint8_t* buffer, uint16_t buffer_len,
                     uint16_t* out_len) {
  uint16_t start;
  uint8_t major;
  uint32_t byte_len;

  if (c == NERO_NFC_NULL) {
    return false;
  }
  start = c->pos;
  if (!cbor_read_head(c, &major, &byte_len)) {
    return false;
  }
  if (major != NFC_CBOR_MAJOR_BYTES) {
    c->pos = start;
    return false;
  }
  if ((out_len == NERO_NFC_NULL) || !cbor_has_remaining(c, byte_len) ||
      ((buffer == NERO_NFC_NULL) && (buffer_len > 0u)) ||
      ((buffer == NERO_NFC_NULL) && (byte_len > 0u)) ||
      (byte_len > (uint32_t)(UINT16_MAX)) ||
      ((buffer != NERO_NFC_NULL) && (byte_len > (uint32_t)(buffer_len)))) {
    c->pos = start;
    return false;
  }
  *out_len = (uint16_t)(byte_len);
  for (uint32_t i = 0u; i < byte_len; i++) {
    if (!nero_nfc_store_u8(buffer, (size_t)(buffer_len), (size_t)(i),
                           cbor_next(c))) {
      c->pos = start;
      return false;
    }
  }
  return true;
}

bool cbor_read_bytes_indefinite(cbor_reader_t* c, uint8_t* buffer,
                                uint16_t buffer_len, uint16_t* out_len) {
  uint32_t total = 0u;

  if ((c == NERO_NFC_NULL) || (c->data == NERO_NFC_NULL) ||
      (out_len == NERO_NFC_NULL) ||
      ((buffer == NERO_NFC_NULL) && (buffer_len > 0u)) ||
      !cbor_has_remaining(c, 1u) ||
      (c->data[c->pos] != READER_CBOR_HEADER_INDEF_BYTES)) {
    return false;
  }
  c->pos = (uint16_t)(c->pos + 1u);
  while (c->pos < c->len) {
    uint8_t chunk_major;
    uint32_t chunk_len;
    if (c->data[c->pos] == READER_CBOR_BREAK_BYTE) {
      c->pos = (uint16_t)(c->pos + 1u);
      if ((buffer != NERO_NFC_NULL) && (total > (uint32_t)(buffer_len))) {
        return false;
      }
      *out_len = (uint16_t)(total);
      return true;
    }
    if (!cbor_read_head(c, &chunk_major, &chunk_len) ||
        (chunk_major != NFC_CBOR_MAJOR_BYTES) ||
        !cbor_has_remaining(c, chunk_len) ||
        ((uint32_t)(UINT16_MAX)-total < chunk_len)) {
      return false;
    }
    if ((buffer != NERO_NFC_NULL) &&
        ((total + chunk_len) > (uint32_t)(buffer_len))) {
      return false;
    }
    for (uint32_t i = 0u; i < chunk_len; i++) {
      uint8_t ch = cbor_next(c);
      if (buffer != NERO_NFC_NULL) {
        buffer[total + i] = ch;
      }
    }
    total += chunk_len;
  }
  return false;
}

bool cbor_read_bytes_flexible(cbor_reader_t* c, uint8_t* buffer,
                              uint16_t buffer_len, uint16_t* out_len) {
  if ((c == NERO_NFC_NULL) || (out_len == NERO_NFC_NULL)) {
    return false;
  }
  if (cbor_read_bytes(c, buffer, buffer_len, out_len)) {
    return true;
  }
  return cbor_read_bytes_indefinite(c, buffer, buffer_len, out_len);
}

bool cbor_read_bytes_maybe_tagged(cbor_reader_t* c, uint8_t* buffer,
                                  uint16_t buffer_len, uint16_t* out_len) {
  cbor_reader_t probe;
  uint8_t major;
  uint32_t value;

  if ((c == NERO_NFC_NULL) || (out_len == NERO_NFC_NULL)) {
    return false;
  }
  if (cbor_read_bytes_flexible(c, buffer, buffer_len, out_len)) {
    return true;
  }
  probe = *c;
  if (!cbor_read_head(&probe, &major, &value) ||
      (major != READER_CBOR_MAJOR_TAG)) {
    return false;
  }
  /* `probe` and `c` started aligned: one successful tag head advances `probe`
   * past the tag. */
  *c = probe;
  return cbor_read_bytes_flexible(c, buffer, buffer_len, out_len);
}

bool cbor_read_legacy_signature_tail(cbor_reader_t* c, uint8_t* buffer,
                                     uint16_t buffer_len, uint16_t* out_len) {
  cbor_reader_t probe;
  uint32_t alias_key;

  if ((c == NERO_NFC_NULL) || (out_len == NERO_NFC_NULL)) {
    return false;
  }
  probe = *c;
  if (!cbor_read_uint(&probe, &alias_key) ||
      (alias_key != READER_CBOR_LEGACY_ALIAS_KEY)) {
    return false;
  }
  if (!cbor_read_bytes_maybe_tagged(&probe, buffer, buffer_len, out_len)) {
    return false;
  }
  *c = probe;
  return true;
}
static bool cbor_skip_depth(cbor_reader_t* c, unsigned depth);

bool cbor_skip(cbor_reader_t* c) {
  if (c == NERO_NFC_NULL) {
    return false;
  }
  return cbor_skip_depth(c, 0u);
}

static bool cbor_skip_depth(cbor_reader_t* c, unsigned depth) {
  uint8_t ib;
  uint8_t major;
  uint32_t value;
  /* NERO_NFC_BOUNDED_RECURSION max depth: NERO_NFC_CBOR_MAX_NEST_DEPTH. */
  if ((c == NERO_NFC_NULL) || (c->data == NERO_NFC_NULL)) {
    return false;
  }
  if (depth > NERO_NFC_CBOR_MAX_NEST_DEPTH) {
    return false;
  }
  if (c->pos >= c->len) {
    return false;
  }
  ib = c->data[c->pos];
  if ((ib & READER_CBOR_AI_MASK) == READER_CBOR_AI_MASK) {
    c->pos = (uint16_t)(c->pos + 1u);
    switch (ib >> READER_CBOR_MAJOR_TYPE_SHIFT) {
      case NFC_CBOR_MAJOR_BYTES:
      case NFC_CBOR_MAJOR_TEXT: {
        uint8_t chunk_major = (uint8_t)(ib >> READER_CBOR_MAJOR_TYPE_SHIFT);
        while (c->pos < c->len) {
          uint32_t chunk_len;
          if (c->data[c->pos] == READER_CBOR_BREAK_BYTE) {
            c->pos = (uint16_t)(c->pos + 1u);
            return true;
          }
          if (!cbor_read_head(c, &major, &chunk_len) ||
              (major != chunk_major) || !cbor_has_remaining(c, chunk_len)) {
            return false;
          }
          c->pos = (uint16_t)(c->pos + chunk_len);
        }
        return false;
      }
      case NFC_CBOR_MAJOR_ARRAY:
        while (c->pos < c->len) {
          if (c->data[c->pos] == READER_CBOR_BREAK_BYTE) {
            c->pos = (uint16_t)(c->pos + 1u);
            return true;
          }
          if (!cbor_skip_depth(c, depth + 1u)) {
            return false;
          }
        }
        return false;
      case NFC_CBOR_MAJOR_MAP:
        while (c->pos < c->len) {
          if (c->data[c->pos] == READER_CBOR_BREAK_BYTE) {
            c->pos = (uint16_t)(c->pos + 1u);
            return true;
          }
          if (!cbor_skip_depth(c, depth + 1u) ||
              !cbor_skip_depth(c, depth + 1u)) {
            return false;
          }
        }
        return false;
      default:
        return false;
    }
  }
  if (!cbor_read_head(c, &major, &value)) {
    return false;
  }
  switch (major) {
    case NFC_CBOR_MAJOR_UNSIGNED:
    case NFC_CBOR_MAJOR_NEGATIVE:
    case NFC_CBOR_MAJOR_FLOAT_SIMPLE:
      return true;
    case NFC_CBOR_MAJOR_BYTES:
    case NFC_CBOR_MAJOR_TEXT: {
      const uint32_t len32 = (uint32_t)(c->len);
      const uint32_t pos32 = (uint32_t)(c->pos);
      const uint32_t remaining = (len32 >= pos32) ? (len32 - pos32) : 0u;
      if (value > remaining) {
        return false;
      }
      c->pos = (uint16_t)(c->pos + value);
      return c->pos <= c->len;
    }
    case NFC_CBOR_MAJOR_ARRAY:
      for (uint32_t i = 0u; i < value; i++) {
        if (!cbor_skip_depth(c, depth + 1u)) {
          return false;
        }
      }
      return true;
    case NFC_CBOR_MAJOR_MAP:
      for (uint32_t i = 0u; i < value; i++) {
        if (!cbor_skip_depth(c, depth + 1u) ||
            !cbor_skip_depth(c, depth + 1u)) {
          return false;
        }
      }
      return true;
    case READER_CBOR_MAJOR_TAG:
      return cbor_skip_depth(c, depth + 1u);
    default:
      return false;
  }
}
