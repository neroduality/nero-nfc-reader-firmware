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
#include <stdint.h>

/* NFC Forum NDEF MIME (TNF 0x02) media-type record type strings shared by the
 * firmware and host writers so both emit identical "type" fields. */
#define NFC_NDEF_MIME_VCARD "text/vcard"
#define NFC_NDEF_MIME_BT_OOB "application/vnd.bluetooth.ep.oob"

/* NDEF record header flag bits, TNF values, and NFC Forum RTD type bytes.
 * [NDEF] section 3.2 (record header) and RTD 1.0. Shared by the firmware
 * decode path and the firmware/host encode paths so the wire layout never
 * drifts. */
enum {
  NFC_NDEF_HDR_MB = 0x80u,       /* Message Begin */
  NFC_NDEF_HDR_ME = 0x40u,       /* Message End */
  NFC_NDEF_HDR_SR = 0x10u,       /* Short Record */
  NFC_NDEF_HDR_TNF_MASK = 0x07u, /* Type Name Format mask */

  NFC_NDEF_TNF_WELL_KNOWN = 0x01u, /* NFC Forum well-known type (RTD) */
  NFC_NDEF_TNF_MIME = 0x02u,       /* Media type (RFC 2046) */

  NFC_NDEF_RTD_TYPE_TEXT = 0x54u, /* RTD 'T' text record */
  NFC_NDEF_RTD_TYPE_URI = 0x55u,  /* RTD 'U' URI record */

  /* RTD URI 1.0 prefix table index 0x04 — "https://". */
  NFC_NDEF_URI_PREFIX_HTTPS = 0x04u,
};

#ifdef __cplusplus
extern "C" {
#endif

/*
 * NFC Forum RTD URI 1.0 abbreviation table (identifier code -> prefix string),
 * indexed 0x00..0x23. Single definition in nfc_ndef_record_decode.c, shared by
 * the firmware decode path and the host encode path (which links that .c).
 */
extern const char* const NFC_NDEF_URI_PREFIXES[];

NERO_NFC_NODISCARD bool nfc_ndef_decode_uri_payload(const uint8_t* payload,
                                                    uint32_t len, char* out,
                                                    uint16_t out_cap);

NERO_NFC_NODISCARD bool nfc_ndef_decode_text_payload(const uint8_t* payload,
                                                     uint32_t len, char* out,
                                                     uint16_t out_cap);

#ifdef __cplusplus
enum nfc_ndef_record_status_t {
#else
typedef enum {
#endif
  NFC_NDEF_RECORD_OK = 0,
  NFC_NDEF_RECORD_EMPTY = 1,
  NFC_NDEF_RECORD_TRUNCATED = 2,
  NFC_NDEF_RECORD_INVALID_ARG = 3,
  NFC_NDEF_RECORD_UNSUPPORTED =
      4, /* [NDEF] intentional scope limit: CF/chunked; no reassembly */
#ifdef __cplusplus
};
#else
} nfc_ndef_record_status_t;
#endif

#ifdef __cplusplus
struct nfc_ndef_record_t {
#else
typedef struct {
#endif
  uint8_t header;
  uint8_t tnf;
  uint8_t type_len;
  uint32_t payload_len;
  uint16_t type_offset;
  uint16_t payload_offset;
  uint16_t record_len;
  bool message_end;
#ifdef __cplusplus
};
#else
} nfc_ndef_record_t;
#endif

NERO_NFC_NODISCARD nfc_ndef_record_status_t
nfc_ndef_record_next(const uint8_t* msg, uint16_t msg_len, uint16_t pos,
                     nfc_ndef_record_t* rec_out, uint16_t* next_pos_out);

#ifdef __cplusplus
}
#endif
