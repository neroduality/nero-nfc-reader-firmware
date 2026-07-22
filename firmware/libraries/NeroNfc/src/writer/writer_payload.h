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

/*
 * Modular NDEF payload kinds.
 * Serial CLI maps user-friendly commands into this structure.
 * `writer_payload_build_tlv` produces the TLV-wrapped form for Type 2 / Type 5
 * user memory. `writer_payload_build_ndef` produces a raw NDEF message for Type
 * 4 ISO-DEP APDU writes.
 */
typedef enum {
  WRITER_PAYLOAD_NONE = 0,
  WRITER_PAYLOAD_URL_HTTPS,
  WRITER_PAYLOAD_PLAIN_TEXT,
  WRITER_PAYLOAD_SMS_URI,
  WRITER_PAYLOAD_MAILTO_URI,
  WRITER_PAYLOAD_GEO_URI,
  WRITER_PAYLOAD_VCARD_MIME,
  WRITER_PAYLOAD_WIFI_WSC,
  WRITER_PAYLOAD_URI_RAW,
  WRITER_PAYLOAD_BT_OOB,
  WRITER_PAYLOAD_RAW_NDEF,
} writer_payload_kind_t;

/*
 * Buffer for NDEF message + Type-2 TLV wrapper.
 * 880 bytes covers NTAG216 (868-byte NDEF) with a small margin.
 */
#define WRITER_NDEF_MAX_BYTES 880u

/* Max serial line: "ndef-hex " + 2 hex digits per NDEF byte + margin.
 * Makefile NFC_CDC_SERIAL_LINE_CAP must stay in sync (see root Makefile). */
#define WRITER_CLI_LINE_CAP ((WRITER_NDEF_MAX_BYTES * 2u) + 16u)

NERO_NFC_STATIC_ASSERT(WRITER_CLI_LINE_CAP ==
                           ((WRITER_NDEF_MAX_BYTES * 2u) + 16u),
                       "writer CLI line cap must track NDEF hex capacity");

#define WRITER_STR1_MAX 860u
#define WRITER_STR2_MAX 120u

/* NFC Forum RTD field caps (URI/text/mime payloads in writer_payload.c).
 * Wi-Fi PSK bounds live in nfc_wsc.h (NFC_WSC_PSK_*). */
enum {
  WRITER_RTD_URI_PAYLOAD_MAX = 220u,
  WRITER_RTD_TEXT_PAYLOAD_MAX = 200u,
  WRITER_RTD_MIME_TYPE_MAX = 60u,
  WRITER_RTD_VCARD_BODY_MAX = 380u,
  WRITER_VCARD_ST_R2_FIELDS = 2u,
};

/* vCard MIME text assembly (FN + TEL + EMAIL + fixed lines). */
#define WRITER_VCARD_TEMPLATE_OVERHEAD 66u
#define WRITER_VCARD_TEXT_MAX                                        \
  (WRITER_STR1_MAX + (WRITER_STR2_MAX * WRITER_VCARD_ST_R2_FIELDS) + \
   WRITER_VCARD_TEMPLATE_OVERHEAD)

/* Wi-Fi WSC credential blob scratch (see build_wifi_wsc in writer_payload.c).
 */
enum {
  WRITER_WIFI_WSC_INNER_MAX = 140u,
  WRITER_WIFI_WSC_CRED_MAX = 144u,
  WRITER_WIFI_WSC_BLOB_MAX = 200u,
};

NERO_NFC_STATIC_ASSERT(WRITER_VCARD_TEXT_MAX > WRITER_RTD_VCARD_BODY_MAX,
                       "vcard snprintf buffer must cover RTD MIME body cap");

typedef struct {
  writer_payload_kind_t kind;
  /* str1/str2 interpretation depends on `kind` (see writer_serial_cli.c). */
  char str1[WRITER_STR1_MAX];
  char str2[WRITER_STR2_MAX];
  uint8_t* raw_ndef;
  uint16_t raw_ndef_len;
  /* NFC Forum RTD URI identifier (0 = no abbreviation) for URI_RAW. */
  uint8_t uri_id;
} writer_payload_config_t;

#ifdef __cplusplus
extern "C" {
#endif

void writer_payload_default(writer_payload_config_t* cfg);
NERO_NFC_NODISCARD bool writer_payload_configured(
    const writer_payload_config_t* cfg);

/* NDEF message length only (inside TLV value), for CC / T5 MLEN sizing. */
uint16_t writer_payload_ndef_len(const writer_payload_config_t* cfg);

/*
 * Full Type 2 / Type 5 memory image: TLV 0x03 + NDEF + terminator 0xFE.
 * Returns 0 on overflow / encoding error.
 */
uint16_t writer_payload_build_tlv(const writer_payload_config_t* cfg,
                                  uint8_t* out, uint16_t out_max);

/*
 * Raw NDEF message bytes without any TLV wrapper.
 * Use for Type 4 tags where the NDEF container is managed via ISO-DEP APDU
 * sequences; Type 2 / Type 5 tags use the TLV-wrapped form from
 * writer_payload_build_tlv(). Returns 0 on overflow / encoding error.
 */
uint16_t writer_payload_build_ndef(const writer_payload_config_t* cfg,
                                   uint8_t* out, uint16_t out_max);

const char* writer_payload_kind_name(writer_payload_kind_t k);

#ifdef __cplusplus
}
#endif
