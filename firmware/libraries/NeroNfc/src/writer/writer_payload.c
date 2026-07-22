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

#include "nero_nfc_null.h"
#include "writer_payload.h"

#include "nero_nfc_limits.h"
#include "nfc_hex.h"
#include "nfc_ndef_record_decode.h"
#include "nfc_ndef_tlv.h"
#include "nfc_pcsc_contactless.h"
#include "nero_nfc_mem_util.h"
#include "nero_nfc_format.h"
#include "nfc_tag_geometry_limits.h"
#include "nfc_wsc.h"

#include <ctype.h>
#include <string.h>

#include <stdio.h>

enum {
  WRITER_WSC_SSID_MAX_LEN = 32u,
  WRITER_WPS_ATTR_HDR_LEN = 4u,
  WRITER_WPS_U16_FIELD_LEN = 2u,
  WRITER_NDEF_SR_RECORD_HDR_LEN = 3u,
  WRITER_NDEF_WELL_KNOWN_TYPE_LEN = 1u,
  WRITER_NDEF_URI_ID_LEN = 1u,
  WRITER_NDEF_TEXT_STATUS_UTF8_LANG2 = 0x02u,
  WRITER_NDEF_URI_PREFIX_NONE = 0x00u,
  WRITER_BT_MAC_OCTET_COUNT = 6u,
  WRITER_BT_MAC_LAST_OCTET_INDEX = 5u,
  WRITER_BT_MAC_STR_LEN = 17u,
  WRITER_BT_OOB_PAYLOAD_LEN = 8u,
  WRITER_HEX_NIBBLE_SHIFT = 4u,
  WRITER_MAILTO_URI_OVERHEAD = 32u,
  WRITER_GEO_URI_OVERHEAD = 8u,
  /* str2 may appear twice in a mailto URI (subject and body) when split. */
  WRITER_MAILTO_STR2_COPIES = 2u,
  /* [WSC] big-endian 2-byte attribute ID/length serialization. */
  WRITER_WSC_BYTE_SHIFT8 = 8u,
  WRITER_WSC_BYTE_MASK = 0xFFu,
  /* [WSC] AP MAC Address attribute placeholder — the writer does not know the
   * AP BSSID, so it emits the all-zero MAC the enrollee fills in from the link.
   */
  WRITER_WSC_AP_MAC_PLACEHOLDER = 0x00u,
  WRITER_SMS_URI_OVERHEAD = 24u,
  WRITER_NDEF_SR_PAYLOAD_LEN_OFFSET = 2u,
  WRITER_NDEF_SR_TYPE_OFFSET = 3u,
  WRITER_NDEF_SR_URI_ID_OFFSET = 4u,
  WRITER_BT_OOB_MAC_DEST_START = 2u,
  WRITER_BT_OOB_MAC_DEST_OFFSET1 = 1u,
  WRITER_BT_OOB_MAC_DEST_OFFSET2 = 2u,
  WRITER_BT_OOB_MAC_DEST_OFFSET3 = 3u,
  WRITER_BT_OOB_MAC_DEST_OFFSET4 = 4u,
  WRITER_BT_OOB_MAC_DEST_OFFSET5 = 5u,
  WRITER_BT_MAC_OCTET_INDEX0 = 0u,
  WRITER_BT_MAC_OCTET_INDEX1 = 1u,
  WRITER_BT_MAC_OCTET_INDEX2 = 2u,
  WRITER_BT_MAC_OCTET_INDEX3 = 3u,
  WRITER_BT_MAC_OCTET_INDEX4 = 4u,
};

static uint16_t tlv_pack(const uint8_t* ndef, uint16_t nlen, uint8_t* out,
                         uint16_t cap) {
  uint16_t out_len = 0u;
  return nfc_ndef_build_message_tlv(ndef, nlen, out, cap, &out_len) ? out_len
                                                                    : 0u;
}

static uint16_t ndef_emit_uri(uint8_t* out, uint16_t cap, uint8_t uri_id,
                              const char* uri) {
  size_t ul = 0u;
  /* [NDEF-RTD] URI Record Type 1.0 — identifier codes 0x00..0x23 only; reject
   * RFU codes so the writer never emits a record its own decoder would reject.
   */
  if (uri_id >= (uint8_t)(NERO_NFC_URI_PREFIX_CODE_COUNT)) {
    return 0u;
  }
  if ((out == NERO_NFC_NULL) || (uri == NERO_NFC_NULL) ||
      !nero_nfc_bounded_strlen(uri, (size_t)(WRITER_RTD_URI_PAYLOAD_MAX) + 1u,
                               &ul) ||
      (ul > WRITER_RTD_URI_PAYLOAD_MAX) || (ul == 0u)) {
    return 0u;
  }
  uint16_t plen = (uint16_t)(WRITER_NDEF_URI_ID_LEN + ul);
  uint16_t need = (uint16_t)(WRITER_NDEF_SR_RECORD_HDR_LEN +
                             WRITER_NDEF_WELL_KNOWN_TYPE_LEN + plen);
  if (need > cap) {
    return 0u;
  }
  if (!nero_nfc_store_u8(
          out, (size_t)(cap), (size_t)(0),
          (uint8_t)(NFC_NDEF_HDR_MB | NFC_NDEF_HDR_ME | NFC_NDEF_HDR_SR |
                    NFC_NDEF_TNF_WELL_KNOWN))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(out, (size_t)(cap), (size_t)(1),
                         (uint8_t)(WRITER_NDEF_WELL_KNOWN_TYPE_LEN))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(out, (size_t)(cap),
                         (size_t)(WRITER_NDEF_SR_PAYLOAD_LEN_OFFSET),
                         (uint8_t)(plen))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(out, (size_t)(cap),
                         (size_t)(WRITER_NDEF_SR_TYPE_OFFSET),
                         (uint8_t)(NFC_NDEF_RTD_TYPE_URI))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(out, (size_t)(cap),
                         (size_t)(WRITER_NDEF_SR_URI_ID_OFFSET), uri_id)) {
    return 0u;
  }
  return nero_nfc_copy_bytes(out, cap,
                             (uint16_t)(WRITER_NDEF_SR_RECORD_HDR_LEN +
                                        WRITER_NDEF_WELL_KNOWN_TYPE_LEN +
                                        WRITER_NDEF_URI_ID_LEN),
                             uri, ul)
             ? need
             : 0u;
}

static uint16_t ndef_emit_text(uint8_t* out, uint16_t cap, const char* text) {
  static const char EN_LANG[] = "en";
  size_t tl = 0u;
  if ((out == NERO_NFC_NULL) || (text == NERO_NFC_NULL) ||
      !nero_nfc_bounded_strlen(text, (size_t)(WRITER_RTD_TEXT_PAYLOAD_MAX) + 1u,
                               &tl) ||
      (tl > WRITER_RTD_TEXT_PAYLOAD_MAX)) {
    return 0u;
  }
  uint16_t plen =
      (uint16_t)(WRITER_NDEF_URI_ID_LEN + sizeof(EN_LANG) - 1u + tl);
  uint16_t need = (uint16_t)(WRITER_NDEF_SR_RECORD_HDR_LEN +
                             WRITER_NDEF_WELL_KNOWN_TYPE_LEN + plen);
  if (need > cap) {
    return 0u;
  }
  if (!nero_nfc_store_u8(
          out, (size_t)(cap), (size_t)(0),
          (uint8_t)(NFC_NDEF_HDR_MB | NFC_NDEF_HDR_ME | NFC_NDEF_HDR_SR |
                    NFC_NDEF_TNF_WELL_KNOWN))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(out, (size_t)(cap), (size_t)(1),
                         (uint8_t)(WRITER_NDEF_WELL_KNOWN_TYPE_LEN))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(out, (size_t)(cap),
                         (size_t)(WRITER_NDEF_SR_PAYLOAD_LEN_OFFSET),
                         (uint8_t)(plen))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(out, (size_t)(cap),
                         (size_t)(WRITER_NDEF_SR_TYPE_OFFSET),
                         (uint8_t)(NFC_NDEF_RTD_TYPE_TEXT))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(out, (size_t)(cap),
                         (size_t)(WRITER_NDEF_SR_URI_ID_OFFSET),
                         (uint8_t)(WRITER_NDEF_TEXT_STATUS_UTF8_LANG2))) {
    return 0u;
  }
  if (!nero_nfc_copy_bytes(
          out, cap,
          (uint16_t)(WRITER_NDEF_SR_RECORD_HDR_LEN +
                     WRITER_NDEF_WELL_KNOWN_TYPE_LEN + WRITER_NDEF_URI_ID_LEN),
          EN_LANG, sizeof(EN_LANG) - 1u) ||
      !nero_nfc_copy_bytes(
          out, cap,
          (uint16_t)(WRITER_NDEF_SR_RECORD_HDR_LEN +
                     WRITER_NDEF_WELL_KNOWN_TYPE_LEN + WRITER_NDEF_URI_ID_LEN +
                     sizeof(EN_LANG) - 1u),
          text, tl)) {
    return 0u;
  }
  return need;
}

static uint16_t ndef_emit_mime_sr(uint8_t* out, uint16_t cap, const char* mime,
                                  const uint8_t* payload,
                                  uint16_t payload_len) {
  size_t ml = 0u;
  if ((out == NERO_NFC_NULL) || (mime == NERO_NFC_NULL) ||
      ((payload == NERO_NFC_NULL) && (payload_len != 0u)) ||
      !nero_nfc_bounded_strlen(mime, (size_t)(WRITER_RTD_MIME_TYPE_MAX) + 1u,
                               &ml) ||
      (ml > WRITER_RTD_MIME_TYPE_MAX) || (ml == 0u) ||
      (payload_len > WRITER_RTD_VCARD_BODY_MAX)) {
    return 0u;
  }
  uint16_t need =
      (uint16_t)(WRITER_NDEF_SR_RECORD_HDR_LEN + (uint16_t)(ml) + payload_len);
  if ((payload_len >= NERO_NFC_NDEF_SR_PAYLOAD_MAX) || (need > cap)) {
    return 0u;
  }
  /* SR MIME */
  if (!nero_nfc_store_u8(out, (size_t)(cap), (size_t)(0),
                         (uint8_t)(NFC_NDEF_HDR_MB | NFC_NDEF_HDR_ME |
                                   NFC_NDEF_HDR_SR | NFC_NDEF_TNF_MIME)) ||
      !nero_nfc_store_u8(out, (size_t)(cap), (size_t)(1), (uint8_t)(ml)) ||
      !nero_nfc_store_u8(out, (size_t)(cap),
                         (size_t)(WRITER_NDEF_SR_PAYLOAD_LEN_OFFSET),
                         (uint8_t)(payload_len))) {
    return 0u;
  }
  if (!nero_nfc_copy_bytes(out, cap, WRITER_NDEF_SR_RECORD_HDR_LEN, mime, ml) ||
      !nero_nfc_copy_bytes(out, cap,
                           (uint16_t)(WRITER_NDEF_SR_RECORD_HDR_LEN + ml),
                           payload, payload_len)) {
    return 0u;
  }
  return need;
}

static bool wps_put_attr(uint8_t* buf, uint16_t buf_cap, uint16_t* pos_io,
                         uint16_t attr, const uint8_t* data, uint16_t dlen) {
  uint16_t pos;
  size_t needed = 0u;

  if ((buf == NERO_NFC_NULL) || (pos_io == NERO_NFC_NULL) ||
      ((data == NERO_NFC_NULL) && (dlen != 0u))) {
    return false;
  }
  pos = *pos_io;
  if (!nero_nfc_try_add_size((size_t)(pos), WRITER_WPS_ATTR_HDR_LEN, &needed) ||
      !nero_nfc_try_add_size(needed, (size_t)(dlen), &needed) ||
      (needed > (size_t)(buf_cap))) {
    return false;
  }
  if (!nero_nfc_store_u8(buf, (size_t)(buf_cap), (size_t)(pos++),
                         (uint8_t)(attr >> WRITER_WSC_BYTE_SHIFT8))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(buf, (size_t)(buf_cap), (size_t)(pos++),
                         (uint8_t)(attr & WRITER_WSC_BYTE_MASK))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(buf, (size_t)(buf_cap), (size_t)(pos++),
                         (uint8_t)(dlen >> WRITER_WSC_BYTE_SHIFT8))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(buf, (size_t)(buf_cap), (size_t)(pos++),
                         (uint8_t)(dlen & WRITER_WSC_BYTE_MASK))) {
    return 0u;
  }
  if ((dlen != 0u) && !nero_nfc_copy_bytes(buf, buf_cap, pos, data, dlen)) {
    return false;
  }
  *pos_io = (uint16_t)(pos + dlen);
  return true;
}

static bool build_wifi_wsc(uint8_t* blob, uint16_t blob_cap, uint16_t* out_len,
                           const char* ssid, const char* psk) {
  size_t sl = 0u;
  size_t kl = 0u;
  if (!nero_nfc_bounded_strlen(ssid, (size_t)(WRITER_WSC_SSID_MAX_LEN) + 1u,
                               &sl) ||
      !nero_nfc_bounded_strlen(psk, (size_t)(NFC_WSC_PSK_MAX_LEN) + 1u, &kl) ||
      (sl == 0u) || (sl > WRITER_WSC_SSID_MAX_LEN) ||
      (kl < NFC_WSC_PSK_MIN_LEN) || (kl > NFC_WSC_PSK_MAX_LEN)) {
    return false;
  }
  uint8_t inner[WRITER_WIFI_WSC_INNER_MAX]; /* max fill: 5+36+6+6+67+10 = 130
                                               bytes (SSID≤32, PSK≤63) */
  uint16_t q = 0u;
  const uint8_t idx = 0x01u;
  if (!wps_put_attr(inner, (uint16_t)(sizeof(inner)), &q,
                    NFC_WSC_ATTR_NETWORK_INDEX, &idx, 1u) ||
      !wps_put_attr(inner, (uint16_t)(sizeof(inner)), &q, NFC_WSC_ATTR_SSID,
                    (const uint8_t*)(ssid), (uint16_t)(sl))) {
    return false;
  }
  const uint8_t auth[WRITER_WPS_U16_FIELD_LEN] = NFC_WSC_AUTH_WPA2_PSK_INIT;
  if (!wps_put_attr(inner, (uint16_t)(sizeof(inner)), &q,
                    NFC_WSC_ATTR_AUTH_TYPE, auth, WRITER_WPS_U16_FIELD_LEN)) {
    return false;
  }
  const uint8_t enc[WRITER_WPS_U16_FIELD_LEN] = NFC_WSC_ENCR_AES_INIT;
  if (!wps_put_attr(inner, (uint16_t)(sizeof(inner)), &q,
                    NFC_WSC_ATTR_ENCR_TYPE, enc, WRITER_WPS_U16_FIELD_LEN) ||
      !wps_put_attr(inner, (uint16_t)(sizeof(inner)), &q,
                    NFC_WSC_ATTR_NETWORK_KEY, (const uint8_t*)(psk),
                    (uint16_t)(kl))) {
    return false;
  }
  const uint8_t mac[WRITER_BT_MAC_OCTET_COUNT] = {
      (uint8_t)(WRITER_WSC_AP_MAC_PLACEHOLDER),
      (uint8_t)(WRITER_WSC_AP_MAC_PLACEHOLDER),
      (uint8_t)(WRITER_WSC_AP_MAC_PLACEHOLDER),
      (uint8_t)(WRITER_WSC_AP_MAC_PLACEHOLDER),
      (uint8_t)(WRITER_WSC_AP_MAC_PLACEHOLDER),
      (uint8_t)(WRITER_WSC_AP_MAC_PLACEHOLDER)};
  if (!wps_put_attr(inner, (uint16_t)(sizeof(inner)), &q,
                    NFC_WSC_ATTR_MAC_ADDRESS, mac, sizeof(mac))) {
    return false;
  }
  uint16_t inner_len = q;
  uint8_t cred[WRITER_WIFI_WSC_CRED_MAX]; /* max fill: 4 (TLV header) + inner
                                             (≤130) = 134 bytes */
  uint16_t cred_len = 0u;
  if (!wps_put_attr(cred, (uint16_t)(sizeof(cred)), &cred_len,
                    NFC_WSC_ATTR_CREDENTIAL, inner, inner_len)) {
    return false;
  }
  static const uint8_t WSC_VERSION[] = NFC_WSC_VERSION_HEADER_INIT;
  NERO_NFC_STATIC_ASSERT(
      sizeof(WSC_VERSION) + sizeof(cred) <= WRITER_WIFI_WSC_BLOB_MAX,
      "WSC credential blob fits WRITER_WIFI_WSC_BLOB_MAX stack buffer");
  size_t blob_need = 0u;
  if (!nero_nfc_try_add_size((size_t)(cred_len), sizeof(WSC_VERSION),
                             &blob_need) ||
      (blob_need > (size_t)(blob_cap))) {
    return false;
  }
  if (!nero_nfc_copy_bytes(blob, blob_cap, 0u, WSC_VERSION,
                           sizeof(WSC_VERSION)) ||
      !nero_nfc_copy_bytes(blob, blob_cap, sizeof(WSC_VERSION), cred,
                           cred_len)) {
    return false;
  }
  *out_len = (uint16_t)(sizeof(WSC_VERSION) + cred_len);
  nero_nfc_secure_clear(inner, sizeof(inner));
  nero_nfc_secure_clear(cred, sizeof(cred));
  return true;
}

static bool parse_bt_mac(const char* s,
                         uint8_t mac[WRITER_BT_MAC_OCTET_COUNT]) {
  for (unsigned i = 0u; i < (unsigned)WRITER_BT_MAC_OCTET_COUNT; i++) {
    int hi = nfc_hex_nibble((uint8_t)(*s++));
    int lo = nfc_hex_nibble((uint8_t)(*s++));
    if ((hi < 0) || (lo < 0)) {
      return false;
    }
    mac[i] = (uint8_t)((hi << WRITER_HEX_NIBBLE_SHIFT) | lo);
    if ((i < WRITER_BT_MAC_LAST_OCTET_INDEX) && (*s++ != ':')) {
      return false;
    }
  }
  return *s == '\0';
}

static bool writer_copy_cstr_from_span(char* dst, size_t dst_cap,
                                       const char* src, size_t src_cap) {
  if (src == NERO_NFC_NULL) {
    if ((dst != NERO_NFC_NULL) && (dst_cap > 0u)) {
      if (!nero_nfc_store_u8((uint8_t*)(dst), dst_cap, (size_t)(0),
                             (uint8_t)('\0'))) {
        return false;
      }
    }
    return false;
  }
  size_t len = 0u;
  if (!nero_nfc_bounded_strlen(src, src_cap, &len)) {
    if ((dst != NERO_NFC_NULL) && (dst_cap > 0u)) {
      if (!nero_nfc_store_u8((uint8_t*)(dst), dst_cap, (size_t)(0),
                             (uint8_t)('\0'))) {
        return false;
      }
    }
    return false;
  }
  if (len >= dst_cap) {
    return false;
  }
  if (!nero_nfc_copy_bytes(dst, dst_cap, 0u, src, len)) {
    return false;
  }
  if (!nero_nfc_store_u8((uint8_t*)(dst), dst_cap, len, (uint8_t)('\0'))) {
    return false;
  }
  return true;
}

static bool writer_copy_cstr(char* dst, size_t dst_cap, const char* src) {
  return writer_copy_cstr_from_span(dst, dst_cap, src, dst_cap);
}

static bool nero_nfc_snprintf_fits(int n, size_t cap) {
  if (n < 0) {
    return false;
  }
  const size_t written = (size_t)(n);
  return written < cap;
}

/* [RFC6350] vCard property values must not contain raw control characters
 * (notably CR/LF), which would inject additional properties. */
static bool writer_cstr_has_control_char(const char* s) {
  size_t len = 0u;

  if (s == NERO_NFC_NULL) {
    return false;
  }
  if (!nero_nfc_bounded_strlen(s, WRITER_STR1_MAX, &len)) {
    return true; /* unterminated within the sanity bound; treat as unsafe */
  }
  for (size_t i = 0u; i < len; ++i) {
    if ((uint8_t)(s[i]) < NFC_RFC6350_ASCII_FIRST_PRINTABLE) {
      return true;
    }
  }
  return false;
}

void writer_payload_default(writer_payload_config_t* cfg) {
  if (cfg == NERO_NFC_NULL) {
    return;
  }
  nero_nfc_zero_bytes(cfg, sizeof(*cfg));
  cfg->kind = WRITER_PAYLOAD_NONE;
}

bool writer_payload_configured(const writer_payload_config_t* cfg) {
  return (cfg != NERO_NFC_NULL) && (writer_payload_ndef_len(cfg) != 0u);
}

const char* writer_payload_kind_name(writer_payload_kind_t k) {
  const int ind_bits = (int)(k);
  switch (ind_bits) {
    case WRITER_PAYLOAD_NONE:
      return "none";
    case WRITER_PAYLOAD_URL_HTTPS:
      return "url";
    case WRITER_PAYLOAD_PLAIN_TEXT:
      return "text";
    case WRITER_PAYLOAD_SMS_URI:
      return "sms";
    case WRITER_PAYLOAD_MAILTO_URI:
      return "mailto";
    case WRITER_PAYLOAD_GEO_URI:
      return "geo";
    case WRITER_PAYLOAD_VCARD_MIME:
      return "vcard";
    case WRITER_PAYLOAD_WIFI_WSC:
      return "wifi";
    case WRITER_PAYLOAD_URI_RAW:
      return "uri";
    case WRITER_PAYLOAD_BT_OOB:
      return "bt";
    case WRITER_PAYLOAD_RAW_NDEF:
      return "raw-ndef";
    default:
      return "?";
  }
}

static uint16_t build_ndef_message(const writer_payload_config_t* cfg,
                                   uint8_t* out, uint16_t cap) {
  uint8_t scratch[WRITER_NDEF_MAX_BYTES];
  uint8_t* dst = (out != NERO_NFC_NULL) ? out : scratch;
  uint16_t cap_use = (out != NERO_NFC_NULL) ? cap : (uint16_t)(sizeof(scratch));
  size_t cfg_str1_len = 0u;
  size_t cfg_str2_len = 0u;

  if (cfg == NERO_NFC_NULL) {
    return 0u;
  }
  const int ind_bits = (int)(cfg->kind);
  if (!nero_nfc_bounded_strlen(cfg->str1, sizeof(cfg->str1), &cfg_str1_len) ||
      !nero_nfc_bounded_strlen(cfg->str2, sizeof(cfg->str2), &cfg_str2_len)) {
    return 0u;
  }
  switch (ind_bits) {
    case WRITER_PAYLOAD_NONE:
      return 0u;
    case WRITER_PAYLOAD_URL_HTTPS:
      return ndef_emit_uri(dst, cap_use, (uint8_t)(NFC_NDEF_URI_PREFIX_HTTPS),
                           cfg->str1);

    case WRITER_PAYLOAD_PLAIN_TEXT:
      return ndef_emit_text(dst, cap_use, cfg->str1);

    case WRITER_PAYLOAD_URI_RAW:
      return ndef_emit_uri(dst, cap_use, cfg->uri_id, cfg->str1);

    case WRITER_PAYLOAD_RAW_NDEF:
      if (cfg->raw_ndef == NERO_NFC_NULL || cfg->raw_ndef_len == 0u ||
          cfg->raw_ndef_len > cap_use) {
        return 0u;
      }
      if (!nero_nfc_copy_bytes(dst, cap_use, 0u, cfg->raw_ndef,
                               cfg->raw_ndef_len)) {
        return 0u;
      }
      return cfg->raw_ndef_len;

    case WRITER_PAYLOAD_SMS_URI: {
      /* str1 = phone (digits/+), str2 = optional body */
      char uri[WRITER_STR1_MAX + WRITER_STR2_MAX + WRITER_SMS_URI_OVERHEAD];
      int n = 0;
      if (cfg->str2[0] != '\0') {
        n = nero_nfc_snprintf(uri, sizeof(uri), "sms:%s?body=%s", cfg->str1,
                              cfg->str2);
      } else {
        n = nero_nfc_snprintf(uri, sizeof(uri), "sms:%s", cfg->str1);
      }
      if (!nero_nfc_snprintf_fits(n, sizeof(uri))) {
        return 0u;
      }
      return ndef_emit_uri(dst, cap_use, (uint8_t)(WRITER_NDEF_URI_PREFIX_NONE),
                           uri);
    }

    case WRITER_PAYLOAD_MAILTO_URI: {
      /* str1 = addr, str2 = subject|body (first '|' splits) */
      char subj[WRITER_STR2_MAX];
      char body[WRITER_STR2_MAX];
      subj[0] = '\0';
      body[0] = '\0';
      const char* sep = (const char*)(memchr(cfg->str2, '|', cfg_str2_len));
      if (sep != NERO_NFC_NULL) {
        /* `cfg->str2` is `WRITER_STR2_MAX` bytes; `|` cannot land at index >=
         * sizeof(subj)-1. */
        size_t sl = (size_t)(sep - cfg->str2);
        if ((sl >= sizeof(subj)) ||
            !nero_nfc_copy_bytes(subj, sizeof(subj), 0u, cfg->str2, sl)) {
          return 0u;
        }
        subj[sl] = '\0';
        if (!writer_copy_cstr_from_span(body, sizeof(body), sep + 1u,
                                        cfg_str2_len - sl)) {
          return 0u;
        }
      } else if (!writer_copy_cstr(subj, sizeof(subj), cfg->str2)) {
        return 0u;
      }
      char uri[WRITER_STR1_MAX + (WRITER_STR2_MAX * WRITER_MAILTO_STR2_COPIES) +
               WRITER_MAILTO_URI_OVERHEAD];
      int n = 0;
      if (body[0] != '\0') {
        n = nero_nfc_snprintf(uri, sizeof(uri), "mailto:%s?subject=%s&body=%s",
                              cfg->str1, subj, body);
      } else if (subj[0] != '\0') {
        n = nero_nfc_snprintf(uri, sizeof(uri), "mailto:%s?subject=%s",
                              cfg->str1, subj);
      } else {
        n = nero_nfc_snprintf(uri, sizeof(uri), "mailto:%s", cfg->str1);
      }
      if (!nero_nfc_snprintf_fits(n, sizeof(uri))) {
        return 0u;
      }
      return ndef_emit_uri(dst, cap_use, (uint8_t)(WRITER_NDEF_URI_PREFIX_NONE),
                           uri);
    }

    case WRITER_PAYLOAD_GEO_URI: {
      char uri[WRITER_STR1_MAX + WRITER_GEO_URI_OVERHEAD];
      const int n = nero_nfc_snprintf(uri, sizeof(uri), "geo:%s", cfg->str1);
      if (!nero_nfc_snprintf_fits(n, sizeof(uri))) {
        return 0u;
      }
      return ndef_emit_uri(dst, cap_use, (uint8_t)(WRITER_NDEF_URI_PREFIX_NONE),
                           uri);
    }

    case WRITER_PAYLOAD_VCARD_MIME: {
      /* str1 = display name, str2 = tel|email */
      char tel[WRITER_STR2_MAX];
      char email[WRITER_STR2_MAX];
      tel[0] = '\0';
      email[0] = '\0';
      const char* sep = (const char*)(memchr(cfg->str2, '|', cfg_str2_len));
      if (sep != NERO_NFC_NULL) {
        size_t tl = (size_t)(sep - cfg->str2);
        if ((tl >= sizeof(tel)) ||
            !nero_nfc_copy_bytes(tel, sizeof(tel), 0u, cfg->str2, tl)) {
          return 0u;
        }
        tel[tl] = '\0';
        if (!writer_copy_cstr_from_span(email, sizeof(email), sep + 1u,
                                        cfg_str2_len - tl)) {
          return 0u;
        }
      } else if (!writer_copy_cstr(tel, sizeof(tel), cfg->str2)) {
        return 0u;
      }
      if (writer_cstr_has_control_char(cfg->str1) ||
          writer_cstr_has_control_char(tel) ||
          writer_cstr_has_control_char(email)) {
        return 0u;
      }
      char vcard[WRITER_VCARD_TEXT_MAX];
      const int n = nero_nfc_snprintf(vcard, sizeof(vcard),
                                      "BEGIN:VCARD\r\n"
                                      "VERSION:%u.0\r\n"
                                      "FN:%s\r\n"
                                      "TEL:%s\r\n"
                                      "EMAIL:%s\r\n"
                                      "END:VCARD\r\n",
                                      NFC_RFC6350_VCARD_VERSION_MAJOR,
                                      cfg->str1, tel, email);
      if (!nero_nfc_snprintf_fits(n, sizeof(vcard))) {
        return 0u;
      }
      static const char VCARD_MIME[] = NFC_NDEF_MIME_VCARD;
      return ndef_emit_mime_sr(dst, cap_use, VCARD_MIME,
                               (const uint8_t*)(vcard), (uint16_t)(n));
    }

    case WRITER_PAYLOAD_WIFI_WSC: {
      uint8_t wsc[WRITER_WIFI_WSC_BLOB_MAX];
      uint16_t wlen = 0u;
      if (!build_wifi_wsc(wsc, (uint16_t)(sizeof(wsc)), &wlen, cfg->str1,
                          cfg->str2)) {
        return 0u;
      }
      static const char WSC_MIME[] = NFC_NDEF_MIME_WSC;
      return ndef_emit_mime_sr(dst, cap_use, WSC_MIME, wsc, wlen);
    }

    case WRITER_PAYLOAD_BT_OOB: {
      uint8_t mac[WRITER_BT_MAC_OCTET_COUNT];
      if ((cfg_str1_len != WRITER_BT_MAC_STR_LEN) ||
          !parse_bt_mac(cfg->str1, mac)) {
        return 0u;
      }
      uint8_t payload[WRITER_BT_OOB_PAYLOAD_LEN];
      /* [BT-OOB] Bluetooth SSP-over-NFC OOB block: 2-byte OOB Data Length (LSB
       * first, total length including itself) followed by the 6-byte BD_ADDR in
       * little-endian (LSB first) order. */
      payload[0] = (uint8_t)(WRITER_BT_OOB_PAYLOAD_LEN);
      payload[1] = 0u;
      payload[WRITER_BT_OOB_MAC_DEST_START] =
          mac[WRITER_BT_MAC_LAST_OCTET_INDEX];
      payload[WRITER_BT_OOB_MAC_DEST_START + WRITER_BT_OOB_MAC_DEST_OFFSET1] =
          mac[WRITER_BT_MAC_OCTET_INDEX4];
      payload[WRITER_BT_OOB_MAC_DEST_START + WRITER_BT_OOB_MAC_DEST_OFFSET2] =
          mac[WRITER_BT_MAC_OCTET_INDEX3];
      payload[WRITER_BT_OOB_MAC_DEST_START + WRITER_BT_OOB_MAC_DEST_OFFSET3] =
          mac[WRITER_BT_MAC_OCTET_INDEX2];
      payload[WRITER_BT_OOB_MAC_DEST_START + WRITER_BT_OOB_MAC_DEST_OFFSET4] =
          mac[WRITER_BT_MAC_OCTET_INDEX1];
      payload[WRITER_BT_OOB_MAC_DEST_START + WRITER_BT_OOB_MAC_DEST_OFFSET5] =
          mac[WRITER_BT_MAC_OCTET_INDEX0];
      static const char BT_OOB_MIME[] = NFC_NDEF_MIME_BT_OOB;
      return ndef_emit_mime_sr(dst, cap_use, BT_OOB_MIME, payload,
                               sizeof(payload));
    }

    default:
      return 0u;
  }
}

uint16_t writer_payload_ndef_len(const writer_payload_config_t* cfg) {
  if (cfg == NERO_NFC_NULL) {
    return 0u;
  }
  return build_ndef_message(cfg, NERO_NFC_NULL, 0u);
}

uint16_t writer_payload_build_tlv(const writer_payload_config_t* cfg,
                                  uint8_t* out, uint16_t out_max) {
  if ((cfg == NERO_NFC_NULL) || (out == NERO_NFC_NULL) ||
      (out_max < NFC_TAG_T2T_MIN_NDEF_DUMP_BYTES)) {
    return 0u;
  }
  uint8_t ndef[WRITER_NDEF_MAX_BYTES];
  uint16_t nl = build_ndef_message(cfg, ndef, (uint16_t)(sizeof(ndef)));
  if (nl == 0u) {
    return 0u;
  }
  return tlv_pack(ndef, nl, out, out_max);
}

uint16_t writer_payload_build_ndef(const writer_payload_config_t* cfg,
                                   uint8_t* out, uint16_t out_max) {
  if ((cfg == NERO_NFC_NULL) || (out == NERO_NFC_NULL) || (out_max == 0u)) {
    return 0u;
  }
  return build_ndef_message(cfg, out, out_max);
}

#if defined(NERO_HOST_UNIT_TEST_HOOKS)
/*
 * Host unit tests link `nero_under_test` with NERO_HOST_UNIT_TEST_HOOKS;
 * firmware images must not define this macro so the symbol stays out of device
 * builds.
 */
bool writer_payload_utest_wifi_wsc_encode(uint8_t* blob, uint16_t blob_cap,
                                          uint16_t* out_len, const char* ssid,
                                          const char* psk) {
  return build_wifi_wsc(blob, blob_cap, out_len, ssid, psk);
}
#endif

/* Device CCID is reader-only: omit writer TU bodies so UNO RAM fits.
 * CDC keeps identical library commands; host tests keep writer bodies. */
#if !defined(NERO_CCID_USB_BUILD) || defined(NERO_HOST_UNIT_TEST_HOOKS)

#endif /* !CCID device || host tests */
