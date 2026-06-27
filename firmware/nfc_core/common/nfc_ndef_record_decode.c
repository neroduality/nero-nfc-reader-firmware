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

#include "nfc_ndef_record_decode.h"

#include "nero_nfc_mem_util.h"
#include "nfc_tag_geometry_limits.h"
#include "nero_nfc_limits.h"

#include <string.h>

enum {
  NFC_NDEF_HDR_IL = 0x08u, /* ID Length present — decode-only; not needed by encode callers */
  NFC_NDEF_HDR_CF = 0x20u, /* Chunk Flag — decode-only; chunked records are rejected here */
  NFC_NDEF_TEXT_STATUS_LANG_LEN_MASK = 0x3Fu,
  NFC_NDEF_TEXT_STATUS_UTF16 = 0x80u,
  NFC_NDEF_RECORD_MIN_HDR_LEN = 3u,
  NFC_NDEF_RECORD_LONG_MIN_HDR_LEN = 6u,
  NFC_NDEF_RECORD_TYPE_LEN_OFFSET = 1u,
  NFC_NDEF_RECORD_SR_PAYLOAD_LEN_OFFSET = 2u,
  NFC_NDEF_RECORD_SR_TYPE_OFFSET = 3u,
  NFC_NDEF_RECORD_SR_TYPE_OFFSET_IL = 4u,
  NFC_NDEF_RECORD_LONG_PAYLOAD_LEN_OFFSET = 2u,
  NFC_NDEF_RECORD_LONG_PAYLOAD_LEN_FIELD = 4u,
  NFC_NDEF_RECORD_LONG_PAYLOAD_LEN_BYTE1_REL = 1u,
  NFC_NDEF_RECORD_LONG_PAYLOAD_LEN_BYTE2_REL = 2u,
  NFC_NDEF_RECORD_LONG_PAYLOAD_LEN_BYTE3_REL = 3u,
  NFC_NDEF_RECORD_LONG_PAYLOAD_LEN_SHIFT_MSB = 24u,
  NFC_NDEF_RECORD_LONG_PAYLOAD_LEN_SHIFT_MID = 16u,
  NFC_NDEF_RECORD_LONG_TYPE_OFFSET = 6u,
  NFC_NDEF_RECORD_LONG_TYPE_OFFSET_IL = 7u,
  NFC_NDEF_URI_MIN_OUT_CAP = 2u,
  NFC_NDEF_URI_PCT_HI_OFFSET = 1u, /* [RFC3986] first hex digit after '%' */
  NFC_NDEF_URI_PCT_LO_OFFSET = 2u, /* [RFC3986] second hex digit after '%' */
};

static bool nfc_ndef_is_hex_digit(uint8_t ch) {
  return ((ch >= (uint8_t)'0') && (ch <= (uint8_t)'9')) ||
         ((ch >= (uint8_t)'a') && (ch <= (uint8_t)'f')) ||
         ((ch >= (uint8_t)'A') && (ch <= (uint8_t)'F'));
}

static bool nfc_ndef_url_safe_char(uint8_t ch) {
  if (((ch >= (uint8_t)'a') && (ch <= (uint8_t)'z')) ||
      ((ch >= (uint8_t)'A') && (ch <= (uint8_t)'Z')) ||
      ((ch >= (uint8_t)'0') && (ch <= (uint8_t)'9'))) {
    return true;
  }
  return strchr("-._~:/?#[]@!$&'()*+,;=%", (int)ch) != NERO_NFC_NULL;
}

const char *const NFC_NDEF_URI_PREFIXES[] = {
  "",
  "http://www.",
  "https://www.",
  "http://",
  "https://",
  "tel:",
  "mailto:",
  "ftp://anonymous:anonymous@",
  "ftp://ftp.",
  "ftps://",
  "sftp://",
  "smb://",
  "nfs://",
  "ftp://",
  "dav://",
  "news:",
  "telnet://",
  "imap:",
  "rtsp://",
  "urn:",
  "pop:",
  "sip:",
  "sips:",
  "tftp:",
  "btspp://",
  "btl2cap://",
  "btgoep://",
  "tcpobex://",
  "irdaobex://",
  "file://",
  "urn:epc:id:",
  "urn:epc:tag:",
  "urn:epc:pat:",
  "urn:epc:raw:",
  "urn:epc:",
  "urn:nfc:",
};

NERO_NFC_STATIC_ASSERT((sizeof(NFC_NDEF_URI_PREFIXES) / sizeof(NFC_NDEF_URI_PREFIXES[0])) ==
                         NERO_NFC_URI_PREFIX_CODE_COUNT,
                       "URI prefix table must match NFC Forum RTD URI 1.0 code count");

bool nfc_ndef_decode_uri_payload(const uint8_t *payload, uint32_t len, char *out,
                                 uint16_t out_cap) {
  uint16_t pos = 0u;

  if ((payload == NERO_NFC_NULL) || (out == NERO_NFC_NULL) ||
      (out_cap < NFC_NDEF_URI_MIN_OUT_CAP) || (len < 1u)) {
    return false;
  }
  out[0] = '\0';
  if (payload[0] >= NERO_NFC_URI_PREFIX_CODE_COUNT) {
    return false;
  }
  {
    const char *prefix = NFC_NDEF_URI_PREFIXES[payload[0]];
    size_t prefix_len = 0u;
    if (!nero_nfc_bounded_strlen(prefix, NERO_NFC_NDEF_DECODE_OUT_MAX, &prefix_len)) {
      return false;
    }
    if (prefix_len >= (size_t)out_cap) {
      return false;
    }
    if (!nero_nfc_copy_bytes(out, out_cap, 0u, prefix, (uint16_t)prefix_len)) {
      return false;
    }
    pos = (uint16_t)prefix_len;
  }
  for (uint32_t i = 1u; i < len; ++i) {
    if ((payload[i] == 0u) || !nfc_ndef_url_safe_char(payload[i]) || (pos + 1u) >= out_cap) {
      out[0] = '\0';
      return false;
    }
    /* [RFC3986] §2.1 — a percent sign must introduce a "%" HEXDIG HEXDIG triplet. */
    if (payload[i] == (uint8_t)'%') {
      if ((((uint32_t)i + NFC_NDEF_URI_PCT_LO_OFFSET) >= len) ||
          !nfc_ndef_is_hex_digit(payload[i + NFC_NDEF_URI_PCT_HI_OFFSET]) ||
          !nfc_ndef_is_hex_digit(payload[i + NFC_NDEF_URI_PCT_LO_OFFSET])) {
        out[0] = '\0';
        return false;
      }
    }
    out[pos++] = (char)payload[i];
  }
  out[pos] = '\0';
  return pos != 0u;
}

bool nfc_ndef_decode_text_payload(const uint8_t *payload, uint32_t len, char *out,
                                  uint16_t out_cap) {
  static const char kUtf16TextRecord[] = "UTF-16 text record";
  uint8_t lang_len;
  uint16_t pos = 0u;
  size_t text_start = 0u;

  if ((payload == NERO_NFC_NULL) || (out == NERO_NFC_NULL) || (out_cap == 0u) || (len < 1u)) {
    return false;
  }
  out[0] = '\0';
  lang_len = (uint8_t)(payload[0] & NFC_NDEF_TEXT_STATUS_LANG_LEN_MASK);
  if ((payload[0] & NFC_NDEF_TEXT_STATUS_UTF16) != 0u) {
    return nero_nfc_copy_bytes(out, out_cap, 0u, kUtf16TextRecord,
                               (uint16_t)sizeof(kUtf16TextRecord));
  }
  if (!nero_nfc_try_add_size(1u, (size_t)lang_len, &text_start) || (text_start > len)) {
    return false;
  }
  for (uint32_t i = (uint32_t)text_start; i < len; ++i) {
    if ((payload[i] == 0u) || (pos + 1u) >= out_cap) {
      out[0] = '\0';
      return false;
    }
    out[pos++] = (char)payload[i];
  }
  out[pos] = '\0';
  return true;
}

nfc_ndef_record_status_t nfc_ndef_record_next(const uint8_t *msg, uint16_t msg_len, uint16_t pos,
                                              nfc_ndef_record_t *rec_out, uint16_t *next_pos_out) {
  uint8_t hdr;
  bool sr;
  bool il;
  uint8_t type_len;
  uint32_t payload_len;
  uint16_t off;
  uint16_t type_offset;
  size_t rec_end = 0u;

  if (rec_out != NERO_NFC_NULL) {
    nero_nfc_zero_bytes(rec_out, sizeof(*rec_out));
  }
  if (next_pos_out != NERO_NFC_NULL) {
    *next_pos_out = 0u;
  }
  if ((msg == NERO_NFC_NULL) || (rec_out == NERO_NFC_NULL) || (next_pos_out == NERO_NFC_NULL) ||
      (pos > msg_len)) {
    return NFC_NDEF_RECORD_INVALID_ARG;
  }
  if (pos >= msg_len) {
    return NFC_NDEF_RECORD_TRUNCATED;
  }
  hdr = msg[pos];
  if (hdr == 0x00u) {
    *next_pos_out = (uint16_t)(pos + 1u);
    return NFC_NDEF_RECORD_EMPTY;
  }
  /* [NDEF] Chunked records (CF set) require multi-record payload reassembly,
   * which this walker does not implement; fail closed rather than decode a
   * partial chunk as a complete record. */
  if ((hdr & NFC_NDEF_HDR_CF) != 0u) {
    return NFC_NDEF_RECORD_UNSUPPORTED;
  }
  if ((uint16_t)(msg_len - pos) < NFC_NDEF_RECORD_MIN_HDR_LEN) {
    return NFC_NDEF_RECORD_TRUNCATED;
  }
  sr = (hdr & NFC_NDEF_HDR_SR) != 0u;
  il = (hdr & NFC_NDEF_HDR_IL) != 0u;
  type_len = msg[pos + NFC_NDEF_RECORD_TYPE_LEN_OFFSET];
  if (sr) {
    payload_len = msg[pos + NFC_NDEF_RECORD_SR_PAYLOAD_LEN_OFFSET];
    type_offset = il ? NFC_NDEF_RECORD_SR_TYPE_OFFSET_IL : NFC_NDEF_RECORD_SR_TYPE_OFFSET;
  } else {
    if ((uint16_t)(msg_len - pos) < NFC_NDEF_RECORD_LONG_MIN_HDR_LEN) {
      return NFC_NDEF_RECORD_TRUNCATED;
    }
    if (!nero_nfc_span_ok((size_t)pos + NFC_NDEF_RECORD_LONG_PAYLOAD_LEN_OFFSET,
                          NFC_NDEF_RECORD_LONG_PAYLOAD_LEN_FIELD, msg_len)) {
      return NFC_NDEF_RECORD_TRUNCATED;
    }
    payload_len = ((uint32_t)msg[pos + NFC_NDEF_RECORD_LONG_PAYLOAD_LEN_OFFSET]
                   << NFC_NDEF_RECORD_LONG_PAYLOAD_LEN_SHIFT_MSB) |
                  ((uint32_t)msg[pos + NFC_NDEF_RECORD_LONG_PAYLOAD_LEN_OFFSET +
                                 NFC_NDEF_RECORD_LONG_PAYLOAD_LEN_BYTE1_REL]
                   << NFC_NDEF_RECORD_LONG_PAYLOAD_LEN_SHIFT_MID) |
                  ((uint32_t)msg[pos + NFC_NDEF_RECORD_LONG_PAYLOAD_LEN_OFFSET +
                                 NFC_NDEF_RECORD_LONG_PAYLOAD_LEN_BYTE2_REL]
                   << NFC_BYTE_SHIFT_8) |
                  msg[pos + NFC_NDEF_RECORD_LONG_PAYLOAD_LEN_OFFSET +
                      NFC_NDEF_RECORD_LONG_PAYLOAD_LEN_BYTE3_REL];
    type_offset = il ? NFC_NDEF_RECORD_LONG_TYPE_OFFSET_IL : NFC_NDEF_RECORD_LONG_TYPE_OFFSET;
  }
  off = (uint16_t)(type_offset + type_len);
  if (il) {
    uint8_t id_len;
    size_t id_len_pos = 0u;
    size_t next_off = 0u;

    if (!nero_nfc_try_add_size((size_t)pos, (size_t)(type_offset - 1u), &id_len_pos) ||
        !nero_nfc_span_ok(id_len_pos, 1u, msg_len)) {
      return NFC_NDEF_RECORD_TRUNCATED;
    }
    id_len = msg[id_len_pos];
    if (!nero_nfc_try_add_size((size_t)off, (size_t)id_len, &next_off) || (next_off > UINT16_MAX)) {
      return NFC_NDEF_RECORD_TRUNCATED;
    }
    off = (uint16_t)next_off;
  }
  if (!nero_nfc_try_add_size((size_t)off, (size_t)payload_len, &rec_end) ||
      (rec_end > (size_t)(msg_len - pos))) {
    return NFC_NDEF_RECORD_TRUNCATED;
  }
  rec_out->header = hdr;
  rec_out->tnf = (uint8_t)(hdr & NFC_NDEF_HDR_TNF_MASK);
  rec_out->type_len = type_len;
  rec_out->payload_len = payload_len;
  rec_out->type_offset = type_offset;
  rec_out->payload_offset = off;
  rec_out->record_len = (uint16_t)rec_end;
  rec_out->message_end = (hdr & NFC_NDEF_HDR_ME) != 0u;
  *next_pos_out = (uint16_t)(pos + rec_end);
  return NFC_NDEF_RECORD_OK;
}
