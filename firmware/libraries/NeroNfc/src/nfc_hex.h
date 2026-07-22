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

#include <stdint.h>

enum { NFC_HEX_ALPHA_NIBBLE_BASE = 10 };

/*
 * Canonical ASCII hex-nibble decoder for firmware hex parsers (writer serial
 * CLI, writer payload BT MAC). Centralizing the digit
 * interpretation here prevents the three call sites from drifting apart.
 *
 * Returns the 0..15 value of a single hex digit, or -1 for any non-hex byte.
 * Accepts both lower- and upper-case A..F.
 */
NERO_NFC_NODISCARD static inline int nfc_hex_nibble(uint8_t c) {
  if ((c >= (uint8_t)'0') && (c <= (uint8_t)'9')) {
    return (int)(c - (uint8_t)'0');
  }
  if ((c >= (uint8_t)'a') && (c <= (uint8_t)'f')) {
    return (NFC_HEX_ALPHA_NIBBLE_BASE + (c - (uint8_t)'a'));
  }
  if ((c >= (uint8_t)'A') && (c <= (uint8_t)'F')) {
    return (NFC_HEX_ALPHA_NIBBLE_BASE + (c - (uint8_t)'A'));
  }
  return -1;
}
