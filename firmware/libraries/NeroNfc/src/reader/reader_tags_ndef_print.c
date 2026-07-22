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
/*
 * reader_tags_ndef_print.c — NDEF record decode/print helpers for tag reads.
 */

#include "reader_tags.h"
#include "reader_tags_internal.h"

#include "nfc_ndef_tlv.h"
#include "nfc_pcsc_contactless.h"
#include "nfc_wsc.h"
#include "nero_nfc_mem_util.h"
#include "reader_context.h"
#include "reader_output.h"

#include "reader_tags_ndef_decode.h"

#include "nfc_ndef_record_decode.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "nero_nfc_format.h"

enum {
  READER_NDEF_PRINTABLE_MIN = 0x20u,
  READER_NDEF_PRINTABLE_MAX = 0x7Eu,
  READER_NDEF_WSC_ATTR_HEADER_BYTES = 4u,
  READER_NDEF_WSC_ATTR_LEN_OFFSET = 2u,
  READER_NDEF_WSC_U16_VALUE_LEN = 2u,
  READER_NDEF_BT_OOB_MIN_PAYLOAD_LEN = 8u,
  READER_NDEF_BT_OOB_LENGTH_MSB_INDEX = 1u,
  READER_NDEF_BT_OOB_ADDR_LEN = 6u,
  READER_NDEF_BT_OOB_ADDR_OFFSET = 2u,
  READER_NDEF_WSC_WPA2_PSK_LSB = 0x20u,
  READER_NDEF_WSC_AES_LSB = 0x08u,
  READER_NDEF_HEX_TEXT_CAP = 3u,
  READER_NDEF_HEX_HIGH_NIBBLE_SHIFT = 4u,
  READER_NDEF_HEX_NIBBLE_MASK = 0x0Fu,
  READER_NDEF_HEX_NUL_INDEX = 2u,
};

void reader_tags_reset_detected_urls(void) {
  G_URL_DETECTED = false;
  G_DETECTED_URL[0] = '\0';
  G_DETECTED_URL_COUNT = 0u;
}

static void remember_detected_url(const char* url) {
  size_t len = 0u;
  size_t copy_len = 0u;

  if (url == NERO_NFC_NULL) {
    return;
  }
  if (!nero_nfc_bounded_strlen(url, READER_NDEF_URL_BYTES_MAX, &len) ||
      !nero_nfc_try_add_size(len, 1u, &copy_len)) {
    return;
  }
  if (len == 0u) {
    return;
  }
  if (nero_nfc_copy_bytes(G_DETECTED_URL, sizeof(G_DETECTED_URL), 0u, url,
                          copy_len)) {
    G_URL_DETECTED = true;
  }
  if (G_DETECTED_URL_COUNT < READER_NDEF_URL_MAX &&
      nero_nfc_copy_bytes(G_DETECTED_URLS[G_DETECTED_URL_COUNT],
                          READER_NDEF_URL_BYTES_MAX, 0u, url, copy_len)) {
    G_DETECTED_URL_COUNT++;
  }
}

static bool decode_uri_payload(const uint8_t* payload, uint32_t len, char* out,
                               uint16_t out_cap) {
  if (!reader_tags_decode_uri_payload(payload, len, out, out_cap)) {
    return false;
  }
  remember_detected_url(out);
  return true;
}

static bool decode_text_payload(const uint8_t* payload, uint32_t len, char* out,
                                uint16_t out_cap) {
  return reader_tags_decode_text_payload(payload, len, out, out_cap);
}

static bool type_equals(const uint8_t* type, uint8_t type_len,
                        const char* expected) {
  size_t expected_len = 0u;

  if (((type == NERO_NFC_NULL) && (type_len != 0u)) ||
      (expected == NERO_NFC_NULL) ||
      !nero_nfc_bounded_strlen(expected, UINT8_MAX, &expected_len)) {
    return false;
  }
  return (expected_len == type_len) && (memcmp(type, expected, type_len) == 0);
}

static bool payload_is_display_text(const uint8_t* payload, uint32_t len) {
  if ((payload == NERO_NFC_NULL) && (len != 0u)) {
    return false;
  }
  for (uint32_t i = 0u; i < len; i++) {
    const uint8_t ch = payload[i];
    if ((ch != (uint8_t)('\r')) && (ch != (uint8_t)('\n')) &&
        (ch != (uint8_t)('\t')) &&
        ((ch < READER_NDEF_PRINTABLE_MIN) ||
         (ch > READER_NDEF_PRINTABLE_MAX))) {
      return false;
    }
  }
  return true;
}

static bool append_text(char* out, uint16_t out_cap, size_t* pos,
                        const char* text) {
  size_t len = 0u;

  if ((out == NERO_NFC_NULL) || (pos == NERO_NFC_NULL) ||
      (text == NERO_NFC_NULL) ||
      !nero_nfc_bounded_strlen(text, out_cap, &len) ||
      !nero_nfc_span_ok(*pos, len + 1u, out_cap)) {
    return false;
  }
  if (!nero_nfc_copy_bytes(out, out_cap, *pos, text, len)) {
    return false;
  }
  *pos += len;
  if (!nero_nfc_store_u8((uint8_t*)(out), (size_t)(out_cap), *pos,
                         (uint8_t)('\0'))) {
    return false;
  }
  return true;
}

static bool append_span(char* out, uint16_t out_cap, size_t* pos,
                        const uint8_t* src, uint16_t len) {
  if ((out == NERO_NFC_NULL) || (pos == NERO_NFC_NULL) ||
      ((src == NERO_NFC_NULL) && (len != 0u)) ||
      !nero_nfc_span_ok(*pos, len + 1u, out_cap)) {
    return false;
  }
  if (!nero_nfc_copy_bytes(out, out_cap, *pos, src, len)) {
    return false;
  }
  *pos += len;
  if (!nero_nfc_store_u8((uint8_t*)(out), (size_t)(out_cap), *pos,
                         (uint8_t)('\0'))) {
    return false;
  }
  return true;
}

static bool byte_at(const uint8_t* payload, uint32_t len, uint32_t offset,
                    uint8_t* value) {
  if ((payload == NERO_NFC_NULL) || (value == NERO_NFC_NULL) ||
      !nero_nfc_span_ok(offset, 1u, len)) {
    return false;
  }
  *value = *(payload + offset);
  return true;
}

static bool vcard_property(const uint8_t* payload, uint32_t len,
                           const char* name, const uint8_t** value,
                           uint16_t* value_len) {
  size_t name_len = 0u;
  uint32_t line_start = 0u;

  if ((payload == NERO_NFC_NULL) || (name == NERO_NFC_NULL) ||
      (value == NERO_NFC_NULL) || (value_len == NERO_NFC_NULL) ||
      !nero_nfc_bounded_strlen(name, UINT8_MAX, &name_len)) {
    return false;
  }
  *value = NERO_NFC_NULL;
  *value_len = 0u;
  while (line_start < len) {
    uint32_t line_end = line_start;
    while ((line_end < len) && (payload[line_end] != (uint8_t)('\r')) &&
           (payload[line_end] != (uint8_t)('\n'))) {
      line_end++;
    }
    uint8_t name_suffix = 0u;
    if ((line_end > line_start) && (line_end - line_start > name_len) &&
        byte_at(payload, len, (uint32_t)(line_start + name_len),
                &name_suffix) &&
        (memcmp(payload + line_start, name, name_len) == 0) &&
        ((name_suffix == (uint8_t)(':')) || (name_suffix == (uint8_t)(';')))) {
      uint32_t value_start = (uint32_t)(line_start + name_len + 1u);
      uint8_t value_prev = 0u;
      while ((value_start < line_end) &&
             byte_at(payload, len, value_start - 1u, &value_prev) &&
             (value_prev != (uint8_t)(':'))) {
        value_start++;
      }
      if ((value_start > line_end) || ((line_end - value_start) > UINT16_MAX)) {
        return false;
      }
      *value_len = (uint16_t)(line_end - value_start);
      if ((*value_len != 0u) &&
          !nero_nfc_span_ok(value_start, *value_len, len)) {
        return false;
      }
      *value = (*value_len == 0u) ? NERO_NFC_NULL : payload + value_start;
      return true;
    }
    line_start = line_end + 1u;
    uint8_t line_end_ch = 0u;
    uint8_t line_start_ch = 0u;
    if ((line_start < len) && byte_at(payload, len, line_end, &line_end_ch) &&
        byte_at(payload, len, line_start, &line_start_ch) &&
        (line_end_ch == (uint8_t)('\r')) &&
        (line_start_ch == (uint8_t)('\n'))) {
      line_start++;
    }
  }
  return false;
}

static bool decode_vcard_payload(const uint8_t* payload, uint32_t len,
                                 char* out, uint16_t out_cap) {
  const uint8_t* name = NERO_NFC_NULL;
  const uint8_t* tel = NERO_NFC_NULL;
  const uint8_t* email = NERO_NFC_NULL;
  uint16_t name_len = 0u;
  uint16_t tel_len = 0u;
  uint16_t email_len = 0u;
  size_t pos = 0u;

  if (!payload_is_display_text(payload, len) ||
      !vcard_property(payload, len, "FN", &name, &name_len)) {
    return false;
  }
  (void)vcard_property(payload, len, "TEL", &tel, &tel_len);
  (void)vcard_property(payload, len, "EMAIL", &email, &email_len);
  return append_text(out, out_cap, &pos, "Contact: name=") &&
         append_span(out, out_cap, &pos, name, name_len) &&
         ((tel_len == 0u) || (append_text(out, out_cap, &pos, " tel=") &&
                              append_span(out, out_cap, &pos, tel, tel_len))) &&
         ((email_len == 0u) ||
          (append_text(out, out_cap, &pos, " email=") &&
           append_span(out, out_cap, &pos, email, email_len)));
}

static bool be16_at(const uint8_t* payload, uint32_t len, uint32_t offset,
                    uint16_t* value) {
  if ((payload == NERO_NFC_NULL) || (value == NERO_NFC_NULL) ||
      !nero_nfc_span_ok(offset, READER_NDEF_WSC_U16_VALUE_LEN, len)) {
    return false;
  }
  *value =
      (uint16_t)(((uint16_t)nero_nfc_u8_at(payload, (size_t)(len),
                                           (size_t)(offset))
                  << NFC_BYTE_SHIFT_8) |
                 nero_nfc_u8_at(payload, (size_t)(len), (size_t)(offset + 1u)));
  return true;
}

static bool wsc_attr_payload(const uint8_t* payload, uint32_t len,
                             uint16_t attr_id, const uint8_t** value,
                             uint16_t* value_len) {
  uint32_t pos = 0u;

  if ((payload == NERO_NFC_NULL) || (value == NERO_NFC_NULL) ||
      (value_len == NERO_NFC_NULL)) {
    return false;
  }
  *value = NERO_NFC_NULL;
  *value_len = 0u;
  while (pos + READER_NDEF_WSC_ATTR_HEADER_BYTES <= len) {
    uint16_t id = 0u;
    uint16_t attr_len = 0u;
    if (!be16_at(payload, len, pos, &id) ||
        !be16_at(payload, len, pos + READER_NDEF_WSC_ATTR_LEN_OFFSET,
                 &attr_len)) {
      return false;
    }
    pos += READER_NDEF_WSC_ATTR_HEADER_BYTES;
    if (pos + attr_len > len) {
      return false;
    }
    if (id == attr_id) {
      *value_len = attr_len;
      *value = (attr_len == 0u) ? NERO_NFC_NULL : payload + pos;
      return true;
    }
    pos += attr_len;
  }
  return false;
}

static const char* wsc_u16_name(const uint8_t* value, uint16_t value_len,
                                uint8_t lsb, const char* known) {
  if ((value != NERO_NFC_NULL) &&
      (value_len == READER_NDEF_WSC_U16_VALUE_LEN) &&
      (nero_nfc_u8_at(value, (size_t)(value_len), (size_t)(0)) == 0x00u) &&
      (nero_nfc_u8_at(value, (size_t)(value_len), (size_t)(1)) == lsb)) {
    return known;
  }
  return "unknown";
}

static bool decode_wifi_wsc_payload(const uint8_t* payload, uint32_t len,
                                    char* out, uint16_t out_cap) {
  const uint8_t* credential = NERO_NFC_NULL;
  const uint8_t* ssid = NERO_NFC_NULL;
  const uint8_t* key = NERO_NFC_NULL;
  const uint8_t* auth = NERO_NFC_NULL;
  const uint8_t* encr = NERO_NFC_NULL;
  uint16_t credential_len = 0u;
  uint16_t ssid_len = 0u;
  uint16_t key_len = 0u;
  uint16_t auth_len = 0u;
  uint16_t encr_len = 0u;
  size_t pos = 0u;

  if (!wsc_attr_payload(payload, len, NFC_WSC_ATTR_CREDENTIAL, &credential,
                        &credential_len) ||
      !wsc_attr_payload(credential, credential_len, NFC_WSC_ATTR_SSID, &ssid,
                        &ssid_len) ||
      !payload_is_display_text(ssid, ssid_len)) {
    return false;
  }
  (void)wsc_attr_payload(credential, credential_len, NFC_WSC_ATTR_NETWORK_KEY,
                         &key, &key_len);
  (void)wsc_attr_payload(credential, credential_len, NFC_WSC_ATTR_AUTH_TYPE,
                         &auth, &auth_len);
  (void)wsc_attr_payload(credential, credential_len, NFC_WSC_ATTR_ENCR_TYPE,
                         &encr, &encr_len);
  if ((key_len != 0u) && !payload_is_display_text(key, key_len)) {
    return false;
  }
  return append_text(out, out_cap, &pos, "Wi-Fi: ssid=") &&
         append_span(out, out_cap, &pos, ssid, ssid_len) &&
         append_text(out, out_cap, &pos, " auth=") &&
         append_text(out, out_cap, &pos,
                     wsc_u16_name(auth, auth_len, READER_NDEF_WSC_WPA2_PSK_LSB,
                                  "WPA2-Personal")) &&
         append_text(out, out_cap, &pos, " encryption=") &&
         append_text(
             out, out_cap, &pos,
             wsc_u16_name(encr, encr_len, READER_NDEF_WSC_AES_LSB, "AES")) &&
         ((key_len == 0u) || (append_text(out, out_cap, &pos, " key=") &&
                              append_span(out, out_cap, &pos, key, key_len)));
}

static bool append_hex_u8(char* out, uint16_t out_cap, size_t* pos,
                          uint8_t value) {
  static const char HEX[] = "0123456789ABCDEF";
  char text[READER_NDEF_HEX_TEXT_CAP];

  text[0] = HEX[value >> READER_NDEF_HEX_HIGH_NIBBLE_SHIFT];
  text[1] = HEX[value & READER_NDEF_HEX_NIBBLE_MASK];
  text[READER_NDEF_HEX_NUL_INDEX] = '\0';
  return append_text(out, out_cap, pos, text);
}

static bool decode_bluetooth_oob_payload(const uint8_t* payload, uint32_t len,
                                         char* out, uint16_t out_cap) {
  size_t pos = 0u;

  if ((payload == NERO_NFC_NULL) ||
      (len < READER_NDEF_BT_OOB_MIN_PAYLOAD_LEN) ||
      (nero_nfc_u8_at(payload, (size_t)(len), (size_t)(0)) <
       READER_NDEF_BT_OOB_MIN_PAYLOAD_LEN) ||
      (nero_nfc_u8_at(payload, (size_t)(len),
                      (size_t)(READER_NDEF_BT_OOB_LENGTH_MSB_INDEX)) != 0u)) {
    return false;
  }
  if (!append_text(out, out_cap, &pos, "Bluetooth OOB: address=")) {
    return false;
  }
  for (unsigned i = 0u; i < (unsigned)READER_NDEF_BT_OOB_ADDR_LEN; i++) {
    const uint32_t payload_index =
        (uint32_t)(READER_NDEF_BT_OOB_ADDR_OFFSET +
                   READER_NDEF_BT_OOB_ADDR_LEN - 1u - i);
    if (!nero_nfc_span_ok(payload_index, 1u, len) ||
        ((i != 0u) && !append_text(out, out_cap, &pos, ":")) ||
        !append_hex_u8(
            out, out_cap, &pos,
            nero_nfc_u8_at(payload, (size_t)len, (size_t)payload_index))) {
      return false;
    }
  }
  return true;
}

static bool decode_mime_payload(const uint8_t* type, uint8_t type_len,
                                const uint8_t* payload, uint32_t payload_len,
                                char* out, uint16_t out_cap) {
  if (type_equals(type, type_len, NFC_NDEF_MIME_VCARD)) {
    return decode_vcard_payload(payload, payload_len, out, out_cap);
  }
  if (type_equals(type, type_len, NFC_NDEF_MIME_WSC)) {
    return decode_wifi_wsc_payload(payload, payload_len, out, out_cap);
  }
  if (type_equals(type, type_len, NFC_NDEF_MIME_BT_OOB)) {
    return decode_bluetooth_oob_payload(payload, payload_len, out, out_cap);
  }
  return false;
}

static void print_type_field(const uint8_t* type, uint8_t type_len) {
  if ((type == NERO_NFC_NULL) && (type_len != 0u)) {
    return;
  }
  for (uint8_t i = 0u; i < type_len; ++i) {
    const uint8_t ch = type[i];
    char out_ch = '.';
    if ((ch >= READER_NDEF_PRINTABLE_MIN) &&
        (ch <= READER_NDEF_PRINTABLE_MAX)) {
      out_ch = (char)ch;
    }
    nero_nfc_log_putc(out_ch);
  }
}

static void print_ndef_record_summary(const uint8_t* rec,
                                      const nfc_ndef_record_t* parsed,
                                      uint8_t record_num) {
  char decoded[READER_NDEF_URL_BYTES_MAX];
  uint32_t payload_len;

  if ((rec == NERO_NFC_NULL) || (parsed == NERO_NFC_NULL)) {
    return;
  }
  payload_len = parsed->payload_len;
  if (!nero_nfc_span_ok((size_t)(parsed->type_offset),
                        (size_t)(parsed->type_len),
                        (size_t)(parsed->record_len)) ||
      ((parsed->payload_offset > parsed->record_len))) {
    return;
  }
  if (!nero_nfc_span_ok((size_t)(parsed->payload_offset), (size_t)(payload_len),
                        (size_t)(parsed->record_len))) {
    payload_len =
        (uint32_t)(parsed->record_len - (uint32_t)(parsed->payload_offset));
  }
  nero_nfc_log_write("  Record #");
  {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                            (unsigned)((uint32_t)(record_num)));
    nero_nfc_log_write(ndc);
  }
  nero_nfc_log_write(": TNF=");
  {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                            (unsigned)((uint32_t)(parsed->tnf)));
    nero_nfc_log_write(ndc);
  }
  nero_nfc_log_write(" Type=");
  print_type_field(&rec[parsed->type_offset], parsed->type_len);
  nero_nfc_log_write(" Payload=");
  {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(payload_len));
    nero_nfc_log_write(ndc);
  }
  nero_nfc_log_write("B");
  if (((parsed->tnf == NFC_NDEF_TNF_WELL_KNOWN) && (parsed->type_len == 1u) &&
       (rec[parsed->type_offset] == NFC_NDEF_RTD_TYPE_URI) &&
       decode_uri_payload(&rec[parsed->payload_offset], payload_len, decoded,
                          (uint16_t)(sizeof(decoded)))) ||
      ((parsed->tnf == NFC_NDEF_TNF_WELL_KNOWN) && (parsed->type_len == 1u) &&
       (rec[parsed->type_offset] == NFC_NDEF_RTD_TYPE_TEXT) &&
       decode_text_payload(&rec[parsed->payload_offset], payload_len, decoded,
                           (uint16_t)(sizeof(decoded)))) ||
      ((parsed->tnf == NFC_NDEF_TNF_MIME) &&
       decode_mime_payload(&rec[parsed->type_offset], parsed->type_len,
                           &rec[parsed->payload_offset], payload_len, decoded,
                           (uint16_t)(sizeof(decoded))))) {
    nero_nfc_log_write(" Decoded=\"");
    nero_nfc_log_write(decoded);
    nero_nfc_log_putc('"');
  }
  nero_nfc_log_write("\r\n");
}

void reader_tags_print_ndef_records(const uint8_t* data, uint16_t len) {
  uint16_t pos = 0u;
  uint8_t record_num = 0u;

  if (data == NERO_NFC_NULL) {
    return;
  }

  while (pos < len) {
    nfc_ndef_record_t rec;
    uint16_t next = pos;
    const nfc_ndef_record_status_t status =
        nfc_ndef_record_next(data, len, pos, &rec, &next);

    if (status == NFC_NDEF_RECORD_EMPTY) {
      pos = next;
      continue;
    }
    if (status == NFC_NDEF_RECORD_UNSUPPORTED) {
      nero_nfc_log_line("  (chunked NDEF record — unsupported)");
      return;
    }
    if (status != NFC_NDEF_RECORD_OK) {
      return;
    }
    record_num++;
    print_ndef_record_summary(&data[pos], &rec, record_num);
    pos = next;
    if (rec.message_end) {
      return;
    }
  }
}

void reader_tags_parse_ndef_tlv_area(const uint8_t* data, uint16_t len,
                                     uint16_t start_offset) {
  if ((data == NERO_NFC_NULL) || (start_offset > len)) {
    return;
  }
  uint16_t pos = start_offset;
  bool printed_message = false;

  while (pos < len) {
    nfc_ndef_tlv_t tlv;
    uint16_t next = pos;
    nfc_ndef_tlv_status_t status =
        nfc_ndef_tlv_next(data, len, pos, &tlv, &next);

    if (status == NFC_NDEF_TLV_NOT_FOUND) {
      break;
    }
    if (status == NFC_NDEF_TLV_TRUNCATED) {
      nero_nfc_log_line("  NDEF TLV truncated");
      return;
    }
    if (status != NFC_NDEF_TLV_OK) {
      break;
    }
    if (tlv.type == NFC_NDEF_TLV_MESSAGE) {
      printed_message = true;
      nero_nfc_log_write("  NDEF message: ");
      {
        char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
        (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                                (unsigned)((uint32_t)(tlv.value_len)));
        nero_nfc_log_write(ndc);
      }
      nero_nfc_log_line(" bytes");
      if (!nero_nfc_span_ok((size_t)(tlv.value_offset), (size_t)(tlv.value_len),
                            len)) {
        return;
      }
      reader_tags_print_ndef_records(&data[tlv.value_offset], tlv.value_len);
    }
    pos = next;
  }
  if (!printed_message) {
    nero_nfc_log_line("  NDEF message: 0 bytes");
  }
}
