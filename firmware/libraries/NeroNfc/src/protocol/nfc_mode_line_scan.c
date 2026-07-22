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

#include "nfc_mode_line_scan.h"
#include "nero_nfc_null.h"

#include "nero_nfc_mem_util.h"

#include <string.h>

void nfc_mode_scan_reset(nfc_mode_scan_state_t* st) {
  if (st != NERO_NFC_NULL) {
    st->len = 0u;
  }
}

nfc_mode_scan_result_t nfc_mode_scan_feed(nfc_mode_scan_state_t* st, uint8_t ch,
                                          uint8_t* pushback, uint16_t* push_len,
                                          uint16_t pushback_cap) {
  static const char K_MODE_PREFIX[] = "mode ";

  if ((st == NERO_NFC_NULL) || (pushback == NERO_NFC_NULL) ||
      (push_len == NERO_NFC_NULL)) {
    return NFC_MODE_SCAN_PUSHBACK_STOP;
  }
  *push_len = 0u;

  if (ch == '\r') {
    return NFC_MODE_SCAN_INGESTED;
  }

  if (ch == '\n') {
    const bool is_reader =
        (st->len == NFC_MODE_SCAN_CMD_LEN) &&
        (memcmp(st->buf, "mode reader", NFC_MODE_SCAN_CMD_LEN) == 0);
    const bool is_writer =
        (st->len == NFC_MODE_SCAN_CMD_LEN) &&
        (memcmp(st->buf, "mode writer", NFC_MODE_SCAN_CMD_LEN) == 0);

    if (is_reader || is_writer) {
      st->len = 0u;
      return is_writer ? NFC_MODE_SCAN_GOT_WRITER : NFC_MODE_SCAN_GOT_READER;
    }

    st->buf[st->len] = '\n';
    st->len++;
    if (st->len > pushback_cap) {
      st->len = 0u;
      return NFC_MODE_SCAN_PUSHBACK_STOP;
    }
    if (!nero_nfc_copy_bytes(pushback, pushback_cap, 0u, st->buf, st->len)) {
      st->len = 0u;
      return NFC_MODE_SCAN_PUSHBACK_STOP;
    }
    *push_len = st->len;
    st->len = 0u;
    return NFC_MODE_SCAN_PUSHBACK_STOP;
  }

  st->buf[st->len] = ch;

  if (st->len < NFC_MODE_SCAN_PREFIX_LEN) {
    if (ch != (uint8_t)K_MODE_PREFIX[st->len]) {
      st->len++;
      if (st->len > pushback_cap) {
        st->len = 0u;
        return NFC_MODE_SCAN_PUSHBACK_STOP;
      }
      if (!nero_nfc_copy_bytes(pushback, pushback_cap, 0u, st->buf, st->len)) {
        st->len = 0u;
        return NFC_MODE_SCAN_PUSHBACK_STOP;
      }
      *push_len = st->len;
      st->len = 0u;
      return NFC_MODE_SCAN_PUSHBACK_STOP;
    }
  }

  st->len++;

  if (st->len >= (NFC_MODE_SCAN_CAP - 1u)) {
    if (st->len > pushback_cap) {
      st->len = 0u;
      return NFC_MODE_SCAN_PUSHBACK_STOP;
    }
    if (!nero_nfc_copy_bytes(pushback, pushback_cap, 0u, st->buf, st->len)) {
      st->len = 0u;
      return NFC_MODE_SCAN_PUSHBACK_STOP;
    }
    *push_len = st->len;
    st->len = 0u;
    return NFC_MODE_SCAN_PUSHBACK_STOP;
  }

  return NFC_MODE_SCAN_INGESTED;
}
