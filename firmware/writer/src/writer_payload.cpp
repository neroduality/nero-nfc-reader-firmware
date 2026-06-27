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

#include <cctype>
#include <cstring>

#include <cstdio>
#include <type_traits>

#include <utility>

enum {
  kWriterWscSsidMaxLen = 32u,
  kWriterWpsAttrHdrLen = 4u,
  kWriterWpsU16FieldLen = 2u,
  kWriterNdefSrRecordHdrLen = 3u,
  kWriterNdefWellKnownTypeLen = 1u,
  kWriterNdefUriIdLen = 1u,
  kWriterNdefTextStatusUtf8Lang2 = 0x02u,
  kWriterNdefUriPrefixNone = 0x00u,
  kWriterBtMacOctetCount = 6u,
  kWriterBtMacLastOctetIndex = 5u,
  kWriterBtMacStrLen = 17u,
  kWriterBtOobPayloadLen = 8u,
  kWriterHexNibbleShift = 4u,
  kWriterMailtoUriOverhead = 32u,
  kWriterGeoUriOverhead = 8u,
  /* str2 may appear twice in a mailto URI (subject and body) when split. */
  kWriterMailtoStr2Copies = 2u,
  /* [WSC] big-endian 2-byte attribute ID/length serialization. */
  kWriterWscByteShift_8 = 8u,
  kWriterWscByteMask = 0xFFu,
  /* [WSC] AP MAC Address attribute placeholder — the writer does not know the
   * AP BSSID, so it emits the all-zero MAC the enrollee fills in from the link. */
  kWriterWscApMacPlaceholder = 0x00u,
  kWriterSmsUriOverhead = 24u,
  kWriterNdefSrPayloadLenOffset = 2u,
  kWriterNdefSrTypeOffset = 3u,
  kWriterNdefSrUriIdOffset = 4u,
  kWriterBtOobMacDestStart = 2u,
  kWriterBtOobMacDestOffset1 = 1u,
  kWriterBtOobMacDestOffset2 = 2u,
  kWriterBtOobMacDestOffset3 = 3u,
  kWriterBtOobMacDestOffset4 = 4u,
  kWriterBtOobMacDestOffset5 = 5u,
  kWriterBtMacOctetIndex0 = 0u,
  kWriterBtMacOctetIndex1 = 1u,
  kWriterBtMacOctetIndex2 = 2u,
  kWriterBtMacOctetIndex3 = 3u,
  kWriterBtMacOctetIndex4 = 4u,
};

static uint16_t tlv_pack(const uint8_t *ndef, uint16_t nlen, uint8_t *out, uint16_t cap) {
  uint16_t out_len = 0u;
  return nfc_ndef_build_message_tlv(ndef, nlen, out, cap, &out_len) ? out_len : 0u;
}

static uint16_t ndef_emit_uri(uint8_t *out, uint16_t cap, uint8_t uri_id, const char *uri) {
  size_t ul = 0u;
  /* [NDEF-RTD] URI Record Type 1.0 — identifier codes 0x00..0x23 only; reject RFU
   * codes so the writer never emits a record its own decoder would reject. */
  if (uri_id >= (uint8_t)NERO_NFC_URI_PREFIX_CODE_COUNT) {
    return 0u;
  }
  if ((out == NERO_NFC_NULL) || (uri == NERO_NFC_NULL) ||
      !nero_nfc_bounded_strlen(uri, (size_t)WRITER_RTD_URI_PAYLOAD_MAX + 1u, &ul) ||
      (ul > WRITER_RTD_URI_PAYLOAD_MAX) || (ul == 0u)) {
    return 0u;
  }
  auto plen = (uint16_t)(kWriterNdefUriIdLen + ul);
  auto need = (uint16_t)(kWriterNdefSrRecordHdrLen + kWriterNdefWellKnownTypeLen + plen);
  if (need > cap) {
    return 0u;
  }
  out[0] = (uint8_t)(NFC_NDEF_HDR_MB | NFC_NDEF_HDR_ME | NFC_NDEF_HDR_SR | NFC_NDEF_TNF_WELL_KNOWN);
  out[1] = kWriterNdefWellKnownTypeLen;
  out[kWriterNdefSrPayloadLenOffset] = (uint8_t)plen;
  out[kWriterNdefSrTypeOffset] = NFC_NDEF_RTD_TYPE_URI;
  out[kWriterNdefSrUriIdOffset] = uri_id;
  return nero_nfc_copy_bytes(out, cap,
                             (uint16_t)(kWriterNdefSrRecordHdrLen + kWriterNdefWellKnownTypeLen +
                                        kWriterNdefUriIdLen),
                             uri, ul)
           ? need
           : 0u;
}

static uint16_t ndef_emit_text(uint8_t *out, uint16_t cap, const char *text) {
  static const char kEnLang[] = "en";
  size_t tl = 0u;
  if ((out == NERO_NFC_NULL) || (text == NERO_NFC_NULL) ||
      !nero_nfc_bounded_strlen(text, (size_t)WRITER_RTD_TEXT_PAYLOAD_MAX + 1u, &tl) ||
      (tl > WRITER_RTD_TEXT_PAYLOAD_MAX)) {
    return 0u;
  }
  auto plen = (uint16_t)(kWriterNdefUriIdLen + sizeof(kEnLang) - 1u + tl);
  auto need = (uint16_t)(kWriterNdefSrRecordHdrLen + kWriterNdefWellKnownTypeLen + plen);
  if (need > cap) {
    return 0u;
  }
  out[0] = (uint8_t)(NFC_NDEF_HDR_MB | NFC_NDEF_HDR_ME | NFC_NDEF_HDR_SR | NFC_NDEF_TNF_WELL_KNOWN);
  out[1] = kWriterNdefWellKnownTypeLen;
  out[kWriterNdefSrPayloadLenOffset] = (uint8_t)plen;
  out[kWriterNdefSrTypeOffset] = NFC_NDEF_RTD_TYPE_TEXT;
  out[kWriterNdefSrUriIdOffset] = kWriterNdefTextStatusUtf8Lang2;
  if (!nero_nfc_copy_bytes(
        out, cap,
        (uint16_t)(kWriterNdefSrRecordHdrLen + kWriterNdefWellKnownTypeLen + kWriterNdefUriIdLen),
        kEnLang, sizeof(kEnLang) - 1u) ||
      !nero_nfc_copy_bytes(out, cap,
                           (uint16_t)(kWriterNdefSrRecordHdrLen + kWriterNdefWellKnownTypeLen +
                                      kWriterNdefUriIdLen + sizeof(kEnLang) - 1u),
                           text, tl)) {
    return 0u;
  }
  return need;
}

static uint16_t ndef_emit_mime_sr(uint8_t *out, uint16_t cap, const char *mime,
                                  const uint8_t *payload, uint16_t payload_len) {
  size_t ml = 0u;
  if ((out == NERO_NFC_NULL) || (mime == NERO_NFC_NULL) ||
      ((payload == NERO_NFC_NULL) && (payload_len != 0u)) ||
      !nero_nfc_bounded_strlen(mime, (size_t)WRITER_RTD_MIME_TYPE_MAX + 1u, &ml) ||
      (ml > WRITER_RTD_MIME_TYPE_MAX) || (ml == 0u) || (payload_len > WRITER_RTD_VCARD_BODY_MAX)) {
    return 0u;
  }
  auto need = (uint16_t)(kWriterNdefSrRecordHdrLen + (uint16_t)ml + payload_len);
  if ((payload_len >= NERO_NFC_NDEF_SR_PAYLOAD_MAX) || (need > cap)) {
    return 0u;
  }
  out[0] = (uint8_t)(NFC_NDEF_HDR_MB | NFC_NDEF_HDR_ME | NFC_NDEF_HDR_SR |
                     NFC_NDEF_TNF_MIME); /* SR MIME */
  out[1] = (uint8_t)ml;
  out[kWriterNdefSrPayloadLenOffset] = (uint8_t)payload_len;
  if (!nero_nfc_copy_bytes(out, cap, kWriterNdefSrRecordHdrLen, mime, ml) ||
      !nero_nfc_copy_bytes(out, cap, (uint16_t)(kWriterNdefSrRecordHdrLen + ml), payload,
                           payload_len)) {
    return 0u;
  }
  return need;
}

static bool wps_put_attr(uint8_t *buf, uint16_t buf_cap, uint16_t *pos_io, uint16_t attr,
                         const uint8_t *data, uint16_t dlen) {
  uint16_t pos;
  size_t needed = 0u;

  if ((buf == NERO_NFC_NULL) || (pos_io == NERO_NFC_NULL) ||
      ((data == NERO_NFC_NULL) && (dlen != 0u))) {
    return false;
  }
  pos = *pos_io;
  if (!nero_nfc_try_add_size((size_t)pos, kWriterWpsAttrHdrLen, &needed) ||
      !nero_nfc_try_add_size(needed, (size_t)dlen, &needed) || (needed > (size_t)buf_cap)) {
    return false;
  }
  buf[pos++] = (uint8_t)(attr >> kWriterWscByteShift_8);
  buf[pos++] = (uint8_t)(attr & kWriterWscByteMask);
  buf[pos++] = (uint8_t)(dlen >> kWriterWscByteShift_8);
  buf[pos++] = (uint8_t)(dlen & kWriterWscByteMask);
  if ((dlen != 0u) && !nero_nfc_copy_bytes(buf, buf_cap, pos, data, dlen)) {
    return false;
  }
  *pos_io = (uint16_t)(pos + dlen);
  return true;
}

static bool build_wifi_wsc(uint8_t *blob, uint16_t blob_cap, uint16_t *out_len, const char *ssid,
                           const char *psk) {
  size_t sl = 0u;
  size_t kl = 0u;
  if (!nero_nfc_bounded_strlen(ssid, (size_t)kWriterWscSsidMaxLen + 1u, &sl) ||
      !nero_nfc_bounded_strlen(psk, (size_t)NFC_WSC_PSK_MAX_LEN + 1u, &kl) || (sl == 0u) ||
      (sl > kWriterWscSsidMaxLen) || (kl < NFC_WSC_PSK_MIN_LEN) || (kl > NFC_WSC_PSK_MAX_LEN)) {
    return false;
  }
  uint8_t
    inner[WRITER_WIFI_WSC_INNER_MAX]; /* max fill: 5+36+6+6+67+10 = 130 bytes (SSID≤32, PSK≤63) */
  uint16_t q = 0u;
  const uint8_t idx = 0x01u;
  if (!wps_put_attr(inner, (uint16_t)sizeof(inner), &q, NFC_WSC_ATTR_NETWORK_INDEX, &idx, 1u) ||
      !wps_put_attr(inner, (uint16_t)sizeof(inner), &q, NFC_WSC_ATTR_SSID,
                    reinterpret_cast<const uint8_t *>(ssid), (uint16_t)sl)) {
    return false;
  }
  const uint8_t auth[kWriterWpsU16FieldLen] = NFC_WSC_AUTH_WPA2_PSK_INIT;
  if (!wps_put_attr(inner, (uint16_t)sizeof(inner), &q, NFC_WSC_ATTR_AUTH_TYPE, auth,
                    kWriterWpsU16FieldLen)) {
    return false;
  }
  const uint8_t enc[kWriterWpsU16FieldLen] = NFC_WSC_ENCR_AES_INIT;
  if (!wps_put_attr(inner, (uint16_t)sizeof(inner), &q, NFC_WSC_ATTR_ENCR_TYPE, enc,
                    kWriterWpsU16FieldLen) ||
      !wps_put_attr(inner, (uint16_t)sizeof(inner), &q, NFC_WSC_ATTR_NETWORK_KEY,
                    reinterpret_cast<const uint8_t *>(psk), (uint16_t)kl)) {
    return false;
  }
  const uint8_t mac[kWriterBtMacOctetCount] = {
    (uint8_t)kWriterWscApMacPlaceholder, (uint8_t)kWriterWscApMacPlaceholder,
    (uint8_t)kWriterWscApMacPlaceholder, (uint8_t)kWriterWscApMacPlaceholder,
    (uint8_t)kWriterWscApMacPlaceholder, (uint8_t)kWriterWscApMacPlaceholder};
  if (!wps_put_attr(inner, (uint16_t)sizeof(inner), &q, NFC_WSC_ATTR_MAC_ADDRESS, mac,
                    sizeof(mac))) {
    return false;
  }
  auto inner_len = q;
  uint8_t cred[WRITER_WIFI_WSC_CRED_MAX]; /* max fill: 4 (TLV header) + inner (≤130) = 134 bytes */
  uint16_t cred_len = 0u;
  if (!wps_put_attr(cred, (uint16_t)sizeof(cred), &cred_len, NFC_WSC_ATTR_CREDENTIAL, inner,
                    inner_len)) {
    return false;
  }
  static const uint8_t kWscVersion[] = NFC_WSC_VERSION_HEADER_INIT;
  static_assert(sizeof(kWscVersion) + sizeof(cred) <= WRITER_WIFI_WSC_BLOB_MAX,
                "WSC credential blob fits WRITER_WIFI_WSC_BLOB_MAX stack buffer");
  size_t blob_need = 0u;
  if (!nero_nfc_try_add_size((size_t)cred_len, sizeof(kWscVersion), &blob_need) ||
      (blob_need > (size_t)blob_cap)) {
    return false;
  }
  if (!nero_nfc_copy_bytes(blob, blob_cap, 0u, kWscVersion, sizeof(kWscVersion)) ||
      !nero_nfc_copy_bytes(blob, blob_cap, sizeof(kWscVersion), cred, cred_len)) {
    return false;
  }
  *out_len = (uint16_t)(sizeof(kWscVersion) + cred_len);
  nero_nfc_secure_clear(inner, sizeof(inner));
  nero_nfc_secure_clear(cred, sizeof(cred));
  return true;
}

static bool parse_bt_mac(const char *s, uint8_t mac[kWriterBtMacOctetCount]) {
  for (uint8_t i = 0u; i < kWriterBtMacOctetCount; i++) {
    int hi = nfc_hex_nibble((uint8_t)*s++);
    int lo = nfc_hex_nibble((uint8_t)*s++);
    if ((hi < 0) || (lo < 0)) {
      return false;
    }
    mac[i] = (uint8_t)((hi << kWriterHexNibbleShift) | lo);
    if ((i < kWriterBtMacLastOctetIndex) && (*s++ != ':')) {
      return false;
    }
  }
  return *s == '\0';
}

template <size_t N>
static bool writer_copy_cstr_from_span(char (&dst)[N], const char *src, size_t src_cap) {
  if (src == NERO_NFC_NULL) {
    dst[0] = '\0';
    return false;
  }
  size_t len = 0u;
  if (!nero_nfc_bounded_strlen(src, src_cap, &len)) {
    dst[0] = '\0';
    return false;
  }
  if (len >= N) {
    return false;
  }
  if (!nero_nfc_copy_bytes(dst, N, 0u, src, len)) {
    return false;
  }
  dst[len] = '\0';
  return true;
}

template <size_t N> static bool writer_copy_cstr(char (&dst)[N], const char *src) {
  return writer_copy_cstr_from_span(dst, src, N);
}

static bool nero_nfc_snprintf_fits(int n, size_t cap) {
  if (n < 0) {
    return false;
  }
  const auto written = static_cast<size_t>(n);
  return written < cap;
}

/* [RFC6350] vCard property values must not contain raw control characters
 * (notably CR/LF), which would inject additional properties. */
static bool writer_cstr_has_control_char(const char *s) {
  size_t i = 0u;
  if (s == NERO_NFC_NULL) {
    return false;
  }
  for (i = 0u; s[i] != '\0'; ++i) {
    if ((uint8_t)s[i] < NFC_RFC6350_ASCII_FIRST_PRINTABLE) {
      return true;
    }
  }
  return false;
}

void writer_payload_default(writer_payload_config_t *cfg) {
  if (cfg == NERO_NFC_NULL) {
    return;
  }
  nero_nfc_zero_bytes(cfg, sizeof(*cfg));
  cfg->kind = WRITER_PAYLOAD_NONE;
}

bool writer_payload_configured(const writer_payload_config_t *cfg) {
  return (cfg != NERO_NFC_NULL) && (writer_payload_ndef_len(cfg) != 0u);
}

const char *writer_payload_kind_name(writer_payload_kind_t k) {
  const auto kind_bits = static_cast<std::underlying_type_t<writer_payload_kind_t>>(k);
  switch (kind_bits) {
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

static uint16_t build_ndef_message(const writer_payload_config_t *cfg, uint8_t *out, uint16_t cap) {
  uint8_t scratch[WRITER_NDEF_MAX_BYTES];
  uint8_t *dst = (out != NERO_NFC_NULL) ? out : scratch;
  uint16_t cap_use = (out != NERO_NFC_NULL) ? cap : (uint16_t)sizeof(scratch);
  size_t cfg_str1_len = 0u;
  size_t cfg_str2_len = 0u;

  if (cfg == NERO_NFC_NULL) {
    return 0u;
  }
  const auto kind_bits = static_cast<std::underlying_type_t<writer_payload_kind_t>>(cfg->kind);
  if (!nero_nfc_bounded_strlen(cfg->str1, sizeof(cfg->str1), &cfg_str1_len) ||
      !nero_nfc_bounded_strlen(cfg->str2, sizeof(cfg->str2), &cfg_str2_len)) {
    return 0u;
  }
  switch (kind_bits) {
  case WRITER_PAYLOAD_NONE:
    return 0u;
  case WRITER_PAYLOAD_URL_HTTPS:
    return ndef_emit_uri(dst, cap_use, (uint8_t)NFC_NDEF_URI_PREFIX_HTTPS, cfg->str1);

  case WRITER_PAYLOAD_PLAIN_TEXT:
    return ndef_emit_text(dst, cap_use, cfg->str1);

  case WRITER_PAYLOAD_URI_RAW:
    return ndef_emit_uri(dst, cap_use, cfg->uri_id, cfg->str1);

  case WRITER_PAYLOAD_RAW_NDEF:
    if (cfg->raw_ndef == NERO_NFC_NULL || cfg->raw_ndef_len == 0u || cfg->raw_ndef_len > cap_use) {
      return 0u;
    }
    if (!nero_nfc_copy_bytes(dst, cap_use, 0u, cfg->raw_ndef, cfg->raw_ndef_len)) {
      return 0u;
    }
    return cfg->raw_ndef_len;

  case WRITER_PAYLOAD_SMS_URI: {
    /* str1 = phone (digits/+), str2 = optional body */
    char uri[WRITER_STR1_MAX + WRITER_STR2_MAX + kWriterSmsUriOverhead];
    int n = 0;
    if (cfg->str2[0] != '\0') {
      n = nero_nfc_snprintf(uri, sizeof(uri), "sms:%s?body=%s", cfg->str1, cfg->str2);
    } else {
      n = nero_nfc_snprintf(uri, sizeof(uri), "sms:%s", cfg->str1);
    }
    if (!nero_nfc_snprintf_fits(n, sizeof(uri))) {
      return 0u;
    }
    return ndef_emit_uri(dst, cap_use, (uint8_t)kWriterNdefUriPrefixNone, uri);
  }

  case WRITER_PAYLOAD_MAILTO_URI: {
    /* str1 = addr, str2 = subject|body (first '|' splits) */
    char subj[WRITER_STR2_MAX];
    char body[WRITER_STR2_MAX];
    subj[0] = '\0';
    body[0] = '\0';
    const char *sep = static_cast<const char *>(memchr(cfg->str2, '|', cfg_str2_len));
    if (sep != NERO_NFC_NULL) {
      /* `cfg->str2` is `WRITER_STR2_MAX` bytes; `|` cannot land at index >=
       * sizeof(subj)-1. */
      auto sl = (size_t)(sep - cfg->str2);
      if ((sl >= sizeof(subj)) || !nero_nfc_copy_bytes(subj, sizeof(subj), 0u, cfg->str2, sl)) {
        return 0u;
      }
      subj[sl] = '\0';
      if (!writer_copy_cstr_from_span(body, sep + 1u, cfg_str2_len - sl)) {
        return 0u;
      }
    } else if (!writer_copy_cstr(subj, cfg->str2)) {
      return 0u;
    }
    char
      uri[WRITER_STR1_MAX + (WRITER_STR2_MAX * kWriterMailtoStr2Copies) + kWriterMailtoUriOverhead];
    int n = 0;
    if (body[0] != '\0') {
      n =
        nero_nfc_snprintf(uri, sizeof(uri), "mailto:%s?subject=%s&body=%s", cfg->str1, subj, body);
    } else if (subj[0] != '\0') {
      n = nero_nfc_snprintf(uri, sizeof(uri), "mailto:%s?subject=%s", cfg->str1, subj);
    } else {
      n = nero_nfc_snprintf(uri, sizeof(uri), "mailto:%s", cfg->str1);
    }
    if (!nero_nfc_snprintf_fits(n, sizeof(uri))) {
      return 0u;
    }
    return ndef_emit_uri(dst, cap_use, (uint8_t)kWriterNdefUriPrefixNone, uri);
  }

  case WRITER_PAYLOAD_GEO_URI: {
    char uri[WRITER_STR1_MAX + kWriterGeoUriOverhead];
    const int n = nero_nfc_snprintf(uri, sizeof(uri), "geo:%s", cfg->str1);
    if (!nero_nfc_snprintf_fits(n, sizeof(uri))) {
      return 0u;
    }
    return ndef_emit_uri(dst, cap_use, (uint8_t)kWriterNdefUriPrefixNone, uri);
  }

  case WRITER_PAYLOAD_VCARD_MIME: {
    /* str1 = display name, str2 = tel|email */
    char tel[WRITER_STR2_MAX];
    char email[WRITER_STR2_MAX];
    tel[0] = '\0';
    email[0] = '\0';
    const char *sep = static_cast<const char *>(memchr(cfg->str2, '|', cfg_str2_len));
    if (sep != NERO_NFC_NULL) {
      auto tl = (size_t)(sep - cfg->str2);
      if ((tl >= sizeof(tel)) || !nero_nfc_copy_bytes(tel, sizeof(tel), 0u, cfg->str2, tl)) {
        return 0u;
      }
      tel[tl] = '\0';
      if (!writer_copy_cstr_from_span(email, sep + 1u, cfg_str2_len - tl)) {
        return 0u;
      }
    } else if (!writer_copy_cstr(tel, cfg->str2)) {
      return 0u;
    }
    if (writer_cstr_has_control_char(cfg->str1) || writer_cstr_has_control_char(tel) ||
        writer_cstr_has_control_char(email)) {
      return 0u;
    }
    char vcard[WRITER_VCARD_TEXT_MAX];
    const int n =
      nero_nfc_snprintf(vcard, sizeof(vcard),
                        "BEGIN:VCARD\r\n"
                        "VERSION:%u.0\r\n"
                        "FN:%s\r\n"
                        "TEL:%s\r\n"
                        "EMAIL:%s\r\n"
                        "END:VCARD\r\n",
                        (unsigned)NFC_RFC6350_VCARD_VERSION_MAJOR, cfg->str1, tel, email);
    if (!nero_nfc_snprintf_fits(n, sizeof(vcard))) {
      return 0u;
    }
    static const char kVcardMime[] = NFC_NDEF_MIME_VCARD;
    return ndef_emit_mime_sr(dst, cap_use, kVcardMime, reinterpret_cast<const uint8_t *>(vcard),
                             (uint16_t)n);
  }

  case WRITER_PAYLOAD_WIFI_WSC: {
    uint8_t wsc[WRITER_WIFI_WSC_BLOB_MAX];
    uint16_t wlen = 0u;
    if (!build_wifi_wsc(wsc, (uint16_t)sizeof(wsc), &wlen, cfg->str1, cfg->str2)) {
      return 0u;
    }
    static const char kWscMime[] = NFC_NDEF_MIME_WSC;
    return ndef_emit_mime_sr(dst, cap_use, kWscMime, wsc, wlen);
  }

  case WRITER_PAYLOAD_BT_OOB: {
    uint8_t mac[kWriterBtMacOctetCount];
    if ((cfg_str1_len != kWriterBtMacStrLen) || !parse_bt_mac(cfg->str1, mac)) {
      return 0u;
    }
    uint8_t payload[kWriterBtOobPayloadLen];
    /* [BT-OOB] Bluetooth SSP-over-NFC OOB block: 2-byte OOB Data Length (LSB
     * first, total length including itself) followed by the 6-byte BD_ADDR in
     * little-endian (LSB first) order. */
    payload[0] = (uint8_t)kWriterBtOobPayloadLen;
    payload[1] = 0u;
    payload[kWriterBtOobMacDestStart] = mac[kWriterBtMacLastOctetIndex];
    payload[kWriterBtOobMacDestStart + kWriterBtOobMacDestOffset1] = mac[kWriterBtMacOctetIndex4];
    payload[kWriterBtOobMacDestStart + kWriterBtOobMacDestOffset2] = mac[kWriterBtMacOctetIndex3];
    payload[kWriterBtOobMacDestStart + kWriterBtOobMacDestOffset3] = mac[kWriterBtMacOctetIndex2];
    payload[kWriterBtOobMacDestStart + kWriterBtOobMacDestOffset4] = mac[kWriterBtMacOctetIndex1];
    payload[kWriterBtOobMacDestStart + kWriterBtOobMacDestOffset5] = mac[kWriterBtMacOctetIndex0];
    static const char kBtOobMime[] = NFC_NDEF_MIME_BT_OOB;
    return ndef_emit_mime_sr(dst, cap_use, kBtOobMime, payload, sizeof(payload));
  }

  default:
    return 0u;
  }
}

uint16_t writer_payload_ndef_len(const writer_payload_config_t *cfg) {
  if (cfg == NERO_NFC_NULL) {
    return 0u;
  }
  return build_ndef_message(cfg, NERO_NFC_NULL, 0u);
}

uint16_t writer_payload_build_tlv(const writer_payload_config_t *cfg, uint8_t *out,
                                  uint16_t out_max) {
  if ((cfg == NERO_NFC_NULL) || (out == NERO_NFC_NULL) ||
      (out_max < NFC_TAG_T2T_MIN_NDEF_DUMP_BYTES)) {
    return 0u;
  }
  uint8_t ndef[WRITER_NDEF_MAX_BYTES];
  uint16_t nl = build_ndef_message(cfg, ndef, (uint16_t)sizeof(ndef));
  if (nl == 0u) {
    return 0u;
  }
  return tlv_pack(ndef, nl, out, out_max);
}

uint16_t writer_payload_build_ndef(const writer_payload_config_t *cfg, uint8_t *out,
                                   uint16_t out_max) {
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
bool writer_payload_utest_wifi_wsc_encode(uint8_t *blob, uint16_t blob_cap, uint16_t *out_len,
                                          const char *ssid, const char *psk) {
  return build_wifi_wsc(blob, blob_cap, out_len, ssid, psk);
}
#endif
