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
#include "nero_nfc_attrs.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
  NFC_NDEF_TLV_NULL = 0x00u,
  NFC_NDEF_TLV_MESSAGE = 0x03u,
  NFC_NDEF_TLV_TERMINATOR = 0xFEu,
  NFC_NDEF_TLV_EXTENDED_LEN = 0xFFu,
  NFC_NDEF_TLV_SHORT_ENVELOPE_OVERHEAD = 3u,
  NFC_NDEF_TLV_EXTENDED_ENVELOPE_OVERHEAD = 5u,
  NFC_NDEF_TLV_ONE_BYTE_LEN_MAX = 255u,
  NFC_NDEF_TLV_EXTENDED_LEN_FIELD_BYTES = 3u,
  NFC_NDEF_TLV_EXTENDED_LEN_MSB_OFFSET = 1u,
  NFC_NDEF_TLV_EXTENDED_LEN_LSB_OFFSET = 2u,
  NFC_NDEF_TLV_LEN_SHIFT = 8u,
  NFC_NDEF_TLV_BYTE_MASK = 0xFFu,
  NFC_NDEF_TLV_NEED_LEN_CLAMP_MAX = 0xFFFFu,
};

#ifdef __cplusplus
enum nfc_ndef_tlv_status_t {
#else
typedef enum {
#endif
  NFC_NDEF_TLV_OK = 0,
  NFC_NDEF_TLV_NOT_FOUND = 1,
  NFC_NDEF_TLV_TRUNCATED = 2,
  NFC_NDEF_TLV_INVALID_ARG = 3,
  NFC_NDEF_TLV_TOO_LARGE = 4,
#ifdef __cplusplus
};
#else
} nfc_ndef_tlv_status_t;
#endif

#ifdef __cplusplus
struct nfc_ndef_tlv_t {
#else
typedef struct {
#endif
  uint8_t type;
  uint16_t header_offset;
  uint16_t value_offset;
  uint16_t value_len;
#ifdef __cplusplus
};
#else
} nfc_ndef_tlv_t;
#endif

static inline uint32_t nfc_ndef_tlv_envelope_len(uint16_t ndef_len) {
  return (uint32_t)ndef_len + ((ndef_len < NFC_NDEF_TLV_EXTENDED_LEN)
                                 ? NFC_NDEF_TLV_SHORT_ENVELOPE_OVERHEAD
                                 : NFC_NDEF_TLV_EXTENDED_ENVELOPE_OVERHEAD);
}

static inline uint16_t nfc_ndef_tlv_max_payload_for_data_area(uint16_t data_area_size) {
  if (data_area_size <= NFC_NDEF_TLV_SHORT_ENVELOPE_OVERHEAD) {
    return 0u;
  }
  if (data_area_size <= NFC_NDEF_TLV_ONE_BYTE_LEN_MAX) {
    return (uint16_t)(data_area_size - NFC_NDEF_TLV_SHORT_ENVELOPE_OVERHEAD);
  }
  return (uint16_t)(data_area_size - NFC_NDEF_TLV_EXTENDED_ENVELOPE_OVERHEAD);
}

static inline nfc_ndef_tlv_status_t nfc_ndef_tlv_next(const uint8_t *data, uint16_t data_len,
                                                      uint16_t start_offset,
                                                      nfc_ndef_tlv_t *tlv_out,
                                                      uint16_t *next_offset_out) {
  uint16_t pos = start_offset;
  size_t value_end = 0u;

  if (tlv_out != NERO_NFC_NULL) {
    nero_nfc_zero_bytes(tlv_out, sizeof(*tlv_out));
  }
  if (next_offset_out != NERO_NFC_NULL) {
    *next_offset_out = 0u;
  }
  if ((data == NERO_NFC_NULL) || (tlv_out == NERO_NFC_NULL) || (next_offset_out == NERO_NFC_NULL) ||
      (start_offset > data_len)) {
    return NFC_NDEF_TLV_INVALID_ARG;
  }
  while (pos < data_len) {
    uint16_t tlv_start = pos;
    uint8_t type = data[pos++];
    uint16_t len;

    if (type == NFC_NDEF_TLV_NULL) {
      continue;
    }
    if (type == NFC_NDEF_TLV_TERMINATOR) {
      *next_offset_out = pos;
      return NFC_NDEF_TLV_NOT_FOUND;
    }
    if (pos >= data_len) {
      return NFC_NDEF_TLV_TRUNCATED;
    }
    if (data[pos] == NFC_NDEF_TLV_EXTENDED_LEN) {
      if (!nero_nfc_span_ok((size_t)pos, NFC_NDEF_TLV_EXTENDED_LEN_FIELD_BYTES, data_len)) {
        return NFC_NDEF_TLV_TRUNCATED;
      }
      len = (uint16_t)(((uint16_t)data[pos + NFC_NDEF_TLV_EXTENDED_LEN_MSB_OFFSET]
                        << NFC_NDEF_TLV_LEN_SHIFT) |
                       data[pos + NFC_NDEF_TLV_EXTENDED_LEN_LSB_OFFSET]);
      pos = (uint16_t)(pos + NFC_NDEF_TLV_EXTENDED_LEN_FIELD_BYTES);
    } else {
      len = data[pos++];
    }
    if (!nero_nfc_try_add_size((size_t)pos, (size_t)len, &value_end) ||
        (value_end > (size_t)data_len)) {
      return NFC_NDEF_TLV_TRUNCATED;
    }

    tlv_out->type = type;
    tlv_out->header_offset = tlv_start;
    tlv_out->value_offset = pos;
    tlv_out->value_len = len;
    *next_offset_out = (uint16_t)value_end;
    return NFC_NDEF_TLV_OK;
  }
  *next_offset_out = pos;
  return NFC_NDEF_TLV_NOT_FOUND;
}

static inline nfc_ndef_tlv_status_t nfc_ndef_find_message_tlv(const uint8_t *data,
                                                              uint16_t data_len,
                                                              uint16_t start_offset,
                                                              nfc_ndef_tlv_t *tlv_out) {
  uint16_t pos = start_offset;

  if (tlv_out != NERO_NFC_NULL) {
    nero_nfc_zero_bytes(tlv_out, sizeof(*tlv_out));
  }
  if ((data == NERO_NFC_NULL) || (tlv_out == NERO_NFC_NULL) || (start_offset > data_len)) {
    return NFC_NDEF_TLV_INVALID_ARG;
  }
  while (pos < data_len) {
    uint16_t next = pos;
    nfc_ndef_tlv_status_t status = nfc_ndef_tlv_next(data, data_len, pos, tlv_out, &next);
    if (status != NFC_NDEF_TLV_OK) {
      return status;
    }
    if (tlv_out->type == NFC_NDEF_TLV_MESSAGE) {
      return NFC_NDEF_TLV_OK;
    }
    pos = next;
  }
  return NFC_NDEF_TLV_NOT_FOUND;
}

NERO_NFC_NODISCARD static inline bool nfc_ndef_build_message_tlv(const uint8_t *ndef,
                                                                 uint16_t ndef_len, uint8_t *out,
                                                                 uint16_t out_cap,
                                                                 uint16_t *out_len) {
  uint32_t need = nfc_ndef_tlv_envelope_len(ndef_len);
  uint16_t pos = 0u;

  if (out_len != NERO_NFC_NULL) {
    *out_len = 0u;
  }
  if ((out == NERO_NFC_NULL) || (out_len == NERO_NFC_NULL) ||
      ((ndef_len != 0u) && (ndef == NERO_NFC_NULL))) {
    return false;
  }
  if (need > out_cap) {
    *out_len = (need > (uint32_t)NFC_NDEF_TLV_NEED_LEN_CLAMP_MAX)
                 ? (uint16_t)NFC_NDEF_TLV_NEED_LEN_CLAMP_MAX
                 : (uint16_t)need;
    return false;
  }

  out[pos++] = NFC_NDEF_TLV_MESSAGE;
  if (ndef_len < NFC_NDEF_TLV_EXTENDED_LEN) {
    out[pos++] = (uint8_t)ndef_len;
  } else {
    out[pos++] = NFC_NDEF_TLV_EXTENDED_LEN;
    out[pos++] = (uint8_t)(ndef_len >> NFC_NDEF_TLV_LEN_SHIFT);
    out[pos++] = (uint8_t)(ndef_len & NFC_NDEF_TLV_BYTE_MASK);
  }
  if ((ndef_len != 0u) && !nero_nfc_copy_bytes(out, out_cap, pos, ndef, ndef_len)) {
    return false;
  }
  pos = (uint16_t)(pos + ndef_len);
  out[pos++] = NFC_NDEF_TLV_TERMINATOR;
  *out_len = pos;
  return true;
}

#ifdef __cplusplus
}
#endif
