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

#include <stdbool.h>
#include <stdint.h>

#define NFC_MODE_SCAN_CAP 32u

enum {
  NFC_MODE_SCAN_PUSHBACK_BUF_EXTRA = 4u,
  NFC_MODE_SCAN_PREFIX_LEN = 5u,
  NFC_MODE_SCAN_CMD_LEN = 11u,
};

typedef struct {
  uint8_t buf[NFC_MODE_SCAN_CAP];
  uint16_t len;
} nfc_mode_scan_state_t;

typedef enum {
  NFC_MODE_SCAN_INGESTED = 0,
  NFC_MODE_SCAN_GOT_READER,
  NFC_MODE_SCAN_GOT_WRITER,
  NFC_MODE_SCAN_PUSHBACK_STOP,
} nfc_mode_scan_result_t;

void nfc_mode_scan_reset(nfc_mode_scan_state_t *st);

/*
 * Stateful parser for newline-terminated lines matching exactly "mode reader"
 * or "mode writer". Ignores '\\r'. On non-command lines or prefix mismatch,
 * returns PUSHBACK_STOP with bytes to push back (including a trailing '\\n'
 * when applicable). Caller must supply pushback_cap >= NFC_MODE_SCAN_CAP (worst
 * case pushback length).
 */
nfc_mode_scan_result_t nfc_mode_scan_feed(nfc_mode_scan_state_t *st, uint8_t ch, uint8_t *pushback,
                                          uint16_t *push_len, uint16_t pushback_cap);
