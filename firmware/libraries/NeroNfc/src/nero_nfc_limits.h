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

#include "nfc_tag_geometry_limits.h"
#include "nero_nfc_attrs.h"

#include <stdint.h>

/* CBOR nest depth cap — RFC 8949; prevents stack exhaustion on hostile CTAP
 * CBOR. */
enum {
  NERO_NFC_CBOR_MAX_NEST_DEPTH = 32u,
};

/* Bounded decimal parse / error-text caps (atoi/strtol replacements). */
enum {
  NERO_NFC_PARSE_TEXT_MAX = 256u,
  NERO_NFC_PARSE_DEC_BASE = 10u,
};

/* Shared RTD URI/text decode output cap (firmware reader + userspace PC/SC). */
enum { NERO_NFC_NDEF_DECODE_OUT_MAX = 256u };

/* Host NDEF parse caps (userspace tag decode). */
enum {
  NERO_NFC_NDEF_MAX_RECORDS = 64u,
  NERO_NFC_NDEF_MAX_TOTAL_BYTES = 65536u,
  /* Short-form NDEF URI record: 1-byte prefix code + suffix ≤ 255 payload
     bytes. */
  NERO_NFC_NDEF_SHORT_URI_SUFFIX_MAX = 254u,
  /* NFC Forum RTD Text — short-record payload (status + lang + text). */
  NERO_NFC_NDEF_SR_PAYLOAD_MAX = 255u,
  NERO_NFC_NDEF_TEXT_LANG_MAX = 63u,
};

/* Reader serial NDEF assembly (UNO R4 WiFi SRAM budget). */
enum { NERO_NFC_READER_NDEF_BUF_MAX = 1024u };

/*
 * Host PC/SC Type 2 storage NDEF TLV scan cap. This is a conservative host scan
 * window; parsed CC MLEN and derived page caps still bound real tag access.
 */
enum { NERO_NFC_TYPE2_STORAGE_NDEF_SCAN_MAX = NFC_TAG_T2T_HOST_NDEF_SCAN_MAX };

/*
 * NTAG21x last user page reachable via host READ BINARY (matches firmware).
 * NTAG216 (NTAG21x datasheet, memory organization) exposes pages 0..225.
 */
enum { NERO_NFC_TYPE2_STORAGE_MAX_PAGE = NFC_TAG_NTAG216_LAST_PAGE };

/* Host PC/SC Type 5 storage read cap from block 0; TLV spans are
 * uint16-bounded. */
enum { NERO_NFC_TYPE5_STORAGE_READ_MAX = 65535u };

/* [PCSC-P1] SCardStatus ATR buffer (typical contactless ATR ≤ 33 bytes; PC/SC
 * allows larger). */
enum { NERO_NFC_PCSC_ATR_HOST_MAX = 64u };

/* [PCSC-P1] SCardTransmit response buffer. */
enum { NERO_NFC_PCSC_APDU_RX_MAX = 65536u };

/* [PCSC-P1] API string scratch (SCardStatus reader name, formatted error
 * notes). */
enum {
  NERO_NFC_PCSC_ERROR_MSG_MAX = 160u,
  NERO_NFC_PCSC_READER_NAME_MAX = 256u,
};

/* Userspace serial line pump — matches default firmware SERIAL_LINE_MAX. */
enum { NERO_NFC_HOST_SERIAL_LINE_MAX = 8192u };

/* NFC Forum RTD URI 1.0 — identifier codes 0x00..0x23 (36 prefix table
 * entries). */
enum { NERO_NFC_URI_PREFIX_CODE_COUNT = 36u };

/* Arduino UNO R4 WiFi SRAM ceiling (32 KiB). Lint/CI link gates use this
 * budget. */
enum {
  NERO_NFC_UNO_R4_SRAM_BYTES = 32768u,
  NERO_NFC_UNO_R4_GLOBAL_RAM_MAX = 22000u,
  NERO_NFC_CONSTRAINED_SERIAL_LINE_MAX = 256u,
};

/* CCID extended APDU response scratch for Type 4 relay responses on constrained
 * SRAM. */
enum { NERO_NFC_CCID_APDU_RSP_BUF_MAX = 2048u };

NERO_NFC_STATIC_ASSERT(NERO_NFC_CBOR_MAX_NEST_DEPTH >= 8u,
                       "CBOR depth cap must allow normal FIDO maps");
