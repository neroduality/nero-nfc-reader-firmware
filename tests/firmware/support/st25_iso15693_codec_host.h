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

// Host-test mirror of pure ISO15693 codec helpers from st25r3916_iso15693.h
// (no RFAL / ST25 register dependencies).

#pragma once

#include "nero_nfc_mem_util.h"
#include "nero_nfc_attrs.h"

#include <stdbool.h>
#include <stdint.h>

enum {
  ST25_ISO15693_STREAM_SOF_1OF4 = 0x21u,
  ST25_ISO15693_STREAM_EOF_1OF4 = 0x04u,
  ST25_ISO15693_STREAM_00_1OF4 = 0x02u,
  ST25_ISO15693_STREAM_01_1OF4 = 0x08u,
  ST25_ISO15693_STREAM_10_1OF4 = 0x20u,
  ST25_ISO15693_STREAM_11_1OF4 = 0x80u,
};

static inline uint16_t st25_iso15693_crc16(const uint8_t *data, uint16_t len) {
  uint16_t crc = 0xFFFFu;

  if (data == NERO_NFC_NULL) {
    return 0u;
  }
  for (uint16_t i = 0u; i < len; i++) {
    crc ^= data[i];
    for (uint8_t bit = 0u; bit < 8u; bit++) {
      if ((crc & 0x0001u) != 0u) {
        crc = (uint16_t)((crc >> 1) ^ 0x8408u);
      } else {
        crc = (uint16_t)(crc >> 1);
      }
    }
  }
  return (uint16_t)~crc;
}

NERO_NFC_NODISCARD static inline bool st25_iso15693_stream_put_1of4(uint8_t data, uint8_t *out,
                                                                    uint16_t out_max,
                                                                    uint16_t *pos) {
  if ((out == NERO_NFC_NULL) || (pos == NERO_NFC_NULL) || ((uint16_t)(*pos + 4u) > out_max)) {
    return false;
  }
  for (uint8_t i = 0u; i < 4u; i++) {
    switch (data & 0x03u) {
    case 0u:
      out[(*pos)++] = ST25_ISO15693_STREAM_00_1OF4;
      break;
    case 1u:
      out[(*pos)++] = ST25_ISO15693_STREAM_01_1OF4;
      break;
    case 2u:
      out[(*pos)++] = ST25_ISO15693_STREAM_10_1OF4;
      break;
    default:
      out[(*pos)++] = ST25_ISO15693_STREAM_11_1OF4;
      break;
    }
    data >>= 2;
  }
  return true;
}

NERO_NFC_NODISCARD static inline bool st25_iso15693_stream_encode(const uint8_t *tx,
                                                                  uint16_t tx_len, uint8_t *out,
                                                                  uint16_t out_max,
                                                                  uint16_t *out_len) {
  uint16_t pos = 0u;
  uint16_t crc;

  if (out_len != NERO_NFC_NULL) {
    *out_len = 0u;
  }
  if ((tx == NERO_NFC_NULL) || (out == NERO_NFC_NULL) || (out_len == NERO_NFC_NULL) ||
      (tx_len == 0u) || (out_max < 2u)) {
    return false;
  }

  out[pos++] = ST25_ISO15693_STREAM_SOF_1OF4;
  for (uint16_t i = 0u; i < tx_len; i++) {
    if (!st25_iso15693_stream_put_1of4(tx[i], out, out_max, &pos)) {
      return false;
    }
  }
  crc = st25_iso15693_crc16(tx, tx_len);
  if (!st25_iso15693_stream_put_1of4((uint8_t)(crc & 0xFFu), out, out_max, &pos) ||
      !st25_iso15693_stream_put_1of4((uint8_t)(crc >> 8), out, out_max, &pos)) {
    return false;
  }
  if (pos >= out_max) {
    return false;
  }
  out[pos++] = ST25_ISO15693_STREAM_EOF_1OF4;
  *out_len = pos;
  return true;
}

static inline uint32_t st25_runtime_tx_wait_budget_us(uint16_t tx_len) {
  uint32_t tx_bits = ((uint32_t)tx_len * 10u) + 64u;
  uint32_t tx_us = (tx_bits * 1000000u + 105999u) / 106000u;
  uint32_t budget = tx_us + 4000u;

  return (budget < 5000u) ? 5000u : budget;
}
