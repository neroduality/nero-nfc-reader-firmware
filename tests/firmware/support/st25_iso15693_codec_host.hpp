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

#include "nero_nfc_attrs.h"
#include "nero_nfc_mem_util.h"

#include <cstdint>

enum {
  kSt25Iso15693StreamSof1of4 = 0x21u,
  kSt25Iso15693StreamEof1of4 = 0x04u,
  kSt25Iso15693Stream001of4 = 0x02u,
  kSt25Iso15693Stream011of4 = 0x08u,
  kSt25Iso15693Stream101of4 = 0x20u,
  kSt25Iso15693Stream111of4 = 0x80u,
  kSt25Iso15693Crc16Init = 0xFFFFu,
  kSt25Iso15693Crc16Poly = 0x8408u,
  kSt25Iso15693Crc16BitsPerByte = 8u,
  kSt25Iso15693StreamSymbolsPerByte = 4u,
  kSt25Iso15693StreamDibitMask = 0x03u,
  kSt25Iso15693StreamDibitShift = 2u,
  kSt25Iso15693StreamDibitVal10 = 2u,
  kSt25Iso15693StreamMinOut = 2u,
  kSt25Iso15693ByteMask = 0xFFu,
  kSt25Iso15693BitsPerByte = 8u,
  kSt25RuntimeTxBitsPerByte = 10u,
  kSt25RuntimeTxOverheadBits = 64u,
  kSt25RuntimeUsPerSec = 1000000u,
  kSt25RuntimeIso15693BitRateHz = 106000u,
  kSt25RuntimeIso15693BitRateRound = 105999u,
  kSt25RuntimeTxWaitSlackUs = 4000u,
  kSt25RuntimeTxWaitMinUs = 5000u,
};

static inline uint16_t St25Iso15693Crc16(const uint8_t* data, uint16_t len) {
  uint16_t crc = kSt25Iso15693Crc16Init;

  if (data == NERO_NFC_NULL) {
    return 0u;
  }
  for (uint16_t i = 0u; i < len; i++) {
    crc ^= nero_nfc_u8_at(data, len, i);
    for (unsigned bit = 0u; bit < kSt25Iso15693Crc16BitsPerByte; bit++) {
      if ((crc & 0x0001u) != 0u) {
        crc = static_cast<uint16_t>((crc >> 1) ^ kSt25Iso15693Crc16Poly);
      } else {
        crc = static_cast<uint16_t>(crc >> 1);
      }
    }
  }
  return static_cast<uint16_t>(~crc);
}

NERO_NFC_NODISCARD static inline bool St25Iso15693StreamPut1of4(
    uint8_t data, uint8_t* out, uint16_t out_max, uint16_t* pos) {
  if ((out == NERO_NFC_NULL) || (pos == NERO_NFC_NULL) ||
      (static_cast<uint16_t>(*pos + kSt25Iso15693StreamSymbolsPerByte) >
       out_max)) {
    return false;
  }
  for (unsigned i = 0u; i < kSt25Iso15693StreamSymbolsPerByte; i++) {
    uint8_t symbol = 0u;
    switch (data & kSt25Iso15693StreamDibitMask) {
      case 0u:
        symbol = kSt25Iso15693Stream001of4;
        break;
      case 1u:
        symbol = kSt25Iso15693Stream011of4;
        break;
      case kSt25Iso15693StreamDibitVal10:
        symbol = kSt25Iso15693Stream101of4;
        break;
      default:
        symbol = kSt25Iso15693Stream111of4;
        break;
    }
    if (!nero_nfc_store_u8(out, out_max, *pos, symbol)) {
      return false;
    }
    (*pos)++;
    data >>= kSt25Iso15693StreamDibitShift;
  }
  return true;
}

NERO_NFC_NODISCARD static inline bool St25Iso15693StreamEncode(
    const uint8_t* tx, uint16_t tx_len, uint8_t* out, uint16_t out_max,
    uint16_t* out_len) {
  uint16_t pos = 0u;
  uint16_t crc;

  if (out_len != NERO_NFC_NULL) {
    *out_len = 0u;
  }
  if ((tx == NERO_NFC_NULL) || (out == NERO_NFC_NULL) ||
      (out_len == NERO_NFC_NULL) || (tx_len == 0u) ||
      (out_max < kSt25Iso15693StreamMinOut)) {
    return false;
  }

  if (!nero_nfc_store_u8(out, out_max, pos, kSt25Iso15693StreamSof1of4)) {
    return false;
  }
  pos++;
  for (uint16_t i = 0u; i < tx_len; i++) {
    if (!St25Iso15693StreamPut1of4(nero_nfc_u8_at(tx, tx_len, i), out, out_max,
                                   &pos)) {
      return false;
    }
  }
  crc = St25Iso15693Crc16(tx, tx_len);
  if (!St25Iso15693StreamPut1of4(
          static_cast<uint8_t>(crc & kSt25Iso15693ByteMask), out, out_max,
          &pos) ||
      !St25Iso15693StreamPut1of4(
          static_cast<uint8_t>(crc >> kSt25Iso15693BitsPerByte), out, out_max,
          &pos)) {
    return false;
  }
  if (pos >= out_max) {
    return false;
  }
  if (!nero_nfc_store_u8(out, out_max, pos, kSt25Iso15693StreamEof1of4)) {
    return false;
  }
  pos++;
  *out_len = pos;
  return true;
}

static inline uint32_t St25RuntimeTxWaitBudgetUs(uint16_t tx_len) {
  const uint32_t kTxBits =
      (static_cast<uint32_t>(tx_len) * kSt25RuntimeTxBitsPerByte) +
      kSt25RuntimeTxOverheadBits;
  const uint32_t kTxUs =
      (kTxBits * kSt25RuntimeUsPerSec + kSt25RuntimeIso15693BitRateRound) /
      kSt25RuntimeIso15693BitRateHz;
  const uint32_t kBudget = kTxUs + kSt25RuntimeTxWaitSlackUs;

  const auto kMinUs = static_cast<uint32_t>(kSt25RuntimeTxWaitMinUs);
  return (kBudget < kMinUs) ? kMinUs : kBudget;
}
