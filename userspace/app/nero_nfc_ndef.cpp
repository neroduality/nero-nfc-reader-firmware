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

#include "nero_nfc_ndef.h"

#include "nero_nfc_attrs.h"
#include "nero_nfc_format.h"
#include "nero_nfc_limits.h"
#include "nero_nfc_mem_util.h"

#include "nfc_ndef_record_decode.h"
#include "nfc_tag_geometry_limits.h"
#include "nfc_wsc.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <sstream>

namespace nero_nfc {
namespace {

enum : unsigned {
  kAsciiDelete = 0x7Fu,
  kWscAttrHeaderBytes = 4u,
  kWscAttrLenOffset = 2u,
  kWscU16ValueLen = 2u,
  kWscWpa2PskLsb = 0x20u,
  kWscAesLsb = 0x08u,
  kBtOobMinPayloadLen = 8u,
  kBtOobLengthMsbIndex = 1u,
  kBtOobAddrLen = 6u,
  kBtOobAddrOffset = 2u,
  kHexByteTextCap = 4u,
};

// URI abbreviation prefixes come from the shared NFC_NDEF_URI_PREFIXES table
// (firmware/nfc_core/common/nfc_ndef_record_decode.c), linked into this binary.

bool append_short_record(std::vector<std::uint8_t> &out, std::uint8_t tnf, std::string_view type,
                         const std::vector<std::uint8_t> &payload) {
  if (type.size() > NERO_NFC_NDEF_SR_PAYLOAD_MAX || payload.size() > NERO_NFC_NDEF_SR_PAYLOAD_MAX) {
    return false;
  }
  out.push_back(static_cast<std::uint8_t>(NFC_NDEF_HDR_MB | NFC_NDEF_HDR_ME | NFC_NDEF_HDR_SR |
                                          (tnf & NFC_NDEF_HDR_TNF_MASK)));
  out.push_back(static_cast<std::uint8_t>(type.size()));
  out.push_back(static_cast<std::uint8_t>(payload.size()));
  out.insert(out.end(), type.begin(), type.end());
  out.insert(out.end(), payload.begin(), payload.end());
  return true;
}

bool bytes_are_display_text(const std::vector<std::uint8_t> &payload) {
  return std::ranges::all_of(payload, [](std::uint8_t ch) {
    return ch == '\r' || ch == '\n' || ch == '\t' ||
           (ch >= static_cast<std::uint8_t>(NFC_RFC6350_ASCII_FIRST_PRINTABLE) &&
            ch < static_cast<std::uint8_t>(kAsciiDelete));
  });
}

std::optional<std::string> text_payload(const std::vector<std::uint8_t> &payload) {
  if (!bytes_are_display_text(payload)) {
    return std::nullopt;
  }
  return std::string(payload.begin(), payload.end());
}

std::vector<std::string> text_lines(std::string_view text) {
  std::vector<std::string> lines;
  std::size_t start = 0u;
  while (start <= text.size()) {
    const std::size_t pos = text.find_first_of("\r\n", start);
    if (pos == std::string_view::npos) {
      if (start < text.size()) {
        lines.emplace_back(text.substr(start));
      }
      break;
    }
    if (pos > start) {
      lines.emplace_back(text.substr(start, pos - start));
    }
    start = pos + 1u;
    if (start < text.size() && text[pos] == '\r' && text[start] == '\n') {
      ++start;
    }
  }
  return lines;
}

std::optional<std::string> vcard_property(std::string_view body, std::string_view name) {
  for (const auto &line : text_lines(body)) {
    const auto colon = line.find(':');
    if (colon == std::string::npos) {
      continue;
    }
    const std::string_view key(line.data(), colon);
    if (key == name || key.starts_with(std::string(name) + ";")) {
      return line.substr(colon + 1u);
    }
  }
  return std::nullopt;
}

std::optional<std::string> decode_vcard_payload(const std::vector<std::uint8_t> &payload) {
  const auto body = text_payload(payload);
  if (!body.has_value() || body->find("BEGIN:VCARD") == std::string::npos) {
    return std::nullopt;
  }
  const auto name = vcard_property(*body, "FN");
  const auto tel = vcard_property(*body, "TEL");
  const auto email = vcard_property(*body, "EMAIL");
  if (!name.has_value() && !tel.has_value() && !email.has_value()) {
    return std::nullopt;
  }
  std::ostringstream out;
  out << "Contact:";
  if (name.has_value()) {
    out << " name=" << *name;
  }
  if (tel.has_value()) {
    out << " tel=" << *tel;
  }
  if (email.has_value()) {
    out << " email=" << *email;
  }
  return out.str();
}

bool be16_at(const std::vector<std::uint8_t> &payload, std::size_t offset,
             std::uint16_t &value_out) {
  value_out = 0u;
  if (!nero_nfc_span_ok(offset, kWscU16ValueLen, payload.size())) {
    return false;
  }
  value_out =
    static_cast<std::uint16_t>((static_cast<std::uint16_t>(payload[offset]) << NFC_BYTE_SHIFT_8) |
                               static_cast<std::uint16_t>(payload[offset + 1u]));
  return true;
}

std::optional<std::vector<std::uint8_t>> wsc_attr_payload(const std::vector<std::uint8_t> &payload,
                                                          std::uint16_t attr_id) {
  std::size_t pos = 0u;
  while (pos + kWscAttrHeaderBytes <= payload.size()) {
    std::uint16_t id = 0u;
    std::uint16_t len = 0u;
    if (!be16_at(payload, pos, id) || !be16_at(payload, pos + kWscAttrLenOffset, len)) {
      return std::nullopt;
    }
    pos += kWscAttrHeaderBytes;
    if (pos + len > payload.size()) {
      return std::nullopt;
    }
    if (id == attr_id) {
      return std::vector<std::uint8_t>(payload.begin() + static_cast<std::ptrdiff_t>(pos),
                                       payload.begin() + static_cast<std::ptrdiff_t>(pos + len));
    }
    pos += len;
  }
  return std::nullopt;
}

std::optional<std::string> ascii_attr(const std::vector<std::uint8_t> &payload,
                                      std::uint16_t attr_id) {
  const auto attr = wsc_attr_payload(payload, attr_id);
  if (!attr.has_value() || !bytes_are_display_text(*attr)) {
    return std::nullopt;
  }
  return std::string(attr->begin(), attr->end());
}

std::string wsc_auth_name(const std::optional<std::vector<std::uint8_t>> &attr) {
  if (attr.has_value() && attr->size() == kWscU16ValueLen && (*attr)[0] == 0x00u &&
      (*attr)[1] == static_cast<std::uint8_t>(kWscWpa2PskLsb)) {
    return "WPA2-Personal";
  }
  return "unknown";
}

std::string wsc_encr_name(const std::optional<std::vector<std::uint8_t>> &attr) {
  if (attr.has_value() && attr->size() == kWscU16ValueLen && (*attr)[0] == 0x00u &&
      (*attr)[1] == static_cast<std::uint8_t>(kWscAesLsb)) {
    return "AES";
  }
  return "unknown";
}

std::optional<std::string> decode_wifi_wsc_payload(const std::vector<std::uint8_t> &payload) {
  const auto credential = wsc_attr_payload(payload, NFC_WSC_ATTR_CREDENTIAL);
  if (!credential.has_value()) {
    return std::nullopt;
  }
  const auto ssid = ascii_attr(*credential, NFC_WSC_ATTR_SSID);
  const auto key = ascii_attr(*credential, NFC_WSC_ATTR_NETWORK_KEY);
  if (!ssid.has_value()) {
    return std::nullopt;
  }
  std::ostringstream out;
  out << "Wi-Fi: ssid=" << *ssid
      << " auth=" << wsc_auth_name(wsc_attr_payload(*credential, NFC_WSC_ATTR_AUTH_TYPE))
      << " encryption=" << wsc_encr_name(wsc_attr_payload(*credential, NFC_WSC_ATTR_ENCR_TYPE));
  if (key.has_value()) {
    out << " key=" << *key;
  }
  return out.str();
}

std::optional<std::string> decode_bluetooth_oob_payload(const std::vector<std::uint8_t> &payload) {
  if (payload.size() < kBtOobMinPayloadLen || payload[0] < kBtOobMinPayloadLen ||
      payload[kBtOobLengthMsbIndex] != 0u) {
    return std::nullopt;
  }
  std::string out = "Bluetooth OOB: address=";
  for (std::size_t i = 0u; i < kBtOobAddrLen; ++i) {
    char byte_text[kHexByteTextCap]{};
    if (i != 0u) {
      out.push_back(':');
    }
    const auto payload_index = static_cast<std::size_t>(kBtOobAddrOffset + kBtOobAddrLen - 1u - i);
    if (!nero_nfc_span_ok(payload_index, 1u, payload.size())) {
      return std::nullopt;
    }
    const int written = nero_nfc_snprintf(byte_text, sizeof(byte_text), "%02X",
                                          static_cast<unsigned>(payload[payload_index]));
    if (written <= 0 || static_cast<std::size_t>(written) >= sizeof(byte_text)) {
      return std::nullopt;
    }
    out += byte_text;
  }
  return out;
}

std::optional<std::string> decode_record_payload(std::uint8_t tnf, std::string_view type,
                                                 const std::vector<std::uint8_t> &payload) {
  if (payload.size() > UINT32_MAX) {
    return std::nullopt;
  }
  const auto payload_len = static_cast<std::uint32_t>(payload.size());
  char decoded[NERO_NFC_NDEF_DECODE_OUT_MAX];

  if (tnf == NFC_NDEF_TNF_WELL_KNOWN && type == "T") {
    if (!nfc_ndef_decode_text_payload(payload.data(), payload_len, decoded,
                                      NERO_NFC_NDEF_DECODE_OUT_MAX)) {
      return std::nullopt;
    }
    return std::string(decoded);
  }
  if (tnf == NFC_NDEF_TNF_WELL_KNOWN && type == "U") {
    if (!nfc_ndef_decode_uri_payload(payload.data(), payload_len, decoded,
                                     NERO_NFC_NDEF_DECODE_OUT_MAX)) {
      return std::nullopt;
    }
    return std::string(decoded);
  }
  if (tnf == NFC_NDEF_TNF_MIME && type == NFC_NDEF_MIME_VCARD) {
    return decode_vcard_payload(payload);
  }
  if (tnf == NFC_NDEF_TNF_MIME && type == NFC_NDEF_MIME_WSC) {
    return decode_wifi_wsc_payload(payload);
  }
  if (tnf == NFC_NDEF_TNF_MIME && type == NFC_NDEF_MIME_BT_OOB) {
    return decode_bluetooth_oob_payload(payload);
  }
  return std::nullopt;
}

} // namespace

std::vector<std::uint8_t> build_ndef_text_record(std::string_view text, std::string_view lang) {
  if (lang.size() > NERO_NFC_NDEF_TEXT_LANG_MAX) {
    return {};
  }
  if ((1u + lang.size() + text.size()) > NERO_NFC_NDEF_SR_PAYLOAD_MAX) {
    return {};
  }
  // Single fixed-size allocation (size is bounded above): fill by iterator so
  // there is no reserve()+push_back() realloc path. That pattern trips a GCC
  // -Wfree-nonheap-object false positive under _FORTIFY_SOURCE/_GLIBCXX_ASSERTIONS.
  std::vector<std::uint8_t> payload(1u + lang.size() + text.size());
  payload[0] = static_cast<std::uint8_t>(lang.size());
  std::copy(lang.begin(), lang.end(), payload.begin() + 1);
  std::copy(text.begin(), text.end(),
            payload.begin() + 1 + static_cast<std::ptrdiff_t>(lang.size()));
  {
    char probe[NERO_NFC_NDEF_DECODE_OUT_MAX];
    if (!nfc_ndef_decode_text_payload(payload.data(), static_cast<std::uint32_t>(payload.size()),
                                      probe, NERO_NFC_NDEF_DECODE_OUT_MAX)) {
      return {};
    }
  }
  std::vector<std::uint8_t> out;
  if (!append_short_record(out, NFC_NDEF_TNF_WELL_KNOWN, "T", payload)) {
    return {};
  }
  return out;
}

std::vector<std::uint8_t> build_ndef_uri_record(std::string_view uri) {
  std::uint8_t prefix_code = 0;
  std::string_view suffix = uri;
  for (std::size_t i = 1; i < NERO_NFC_URI_PREFIX_CODE_COUNT; ++i) {
    const std::string_view prefix{NFC_NDEF_URI_PREFIXES[i]};
    const std::string_view best{NFC_NDEF_URI_PREFIXES[prefix_code]};
    if (!prefix.empty() && uri.starts_with(prefix) && prefix.size() > best.size()) {
      prefix_code = static_cast<std::uint8_t>(i);
      suffix = uri.substr(prefix.size());
    }
  }
  if (suffix.size() > NERO_NFC_NDEF_SHORT_URI_SUFFIX_MAX) {
    return {};
  }
  // Single fixed-size allocation; fill by iterator (see build_ndef_text_record).
  std::vector<std::uint8_t> payload(1u + suffix.size());
  payload[0] = prefix_code;
  std::copy(suffix.begin(), suffix.end(), payload.begin() + 1);
  {
    char probe[NERO_NFC_NDEF_DECODE_OUT_MAX];
    if (!nfc_ndef_decode_uri_payload(payload.data(), static_cast<std::uint32_t>(payload.size()),
                                     probe, NERO_NFC_NDEF_DECODE_OUT_MAX)) {
      return {};
    }
  }
  std::vector<std::uint8_t> out;
  if (!append_short_record(out, NFC_NDEF_TNF_WELL_KNOWN, "U", payload)) {
    return {};
  }
  return out;
}

std::vector<std::uint8_t> build_ndef_mime_record(std::string_view mime,
                                                 const std::vector<std::uint8_t> &payload) {
  if (mime.empty() || mime.size() > NERO_NFC_NDEF_SR_PAYLOAD_MAX ||
      payload.size() > NERO_NFC_NDEF_SR_PAYLOAD_MAX) {
    return {};
  }
  std::vector<std::uint8_t> out;
  if (!append_short_record(out, NFC_NDEF_TNF_MIME, mime, payload)) {
    return {};
  }
  return out;
}

std::vector<std::uint8_t>
build_ndef_message(const std::vector<std::vector<std::uint8_t>> &records) {
  std::vector<std::uint8_t> out;
  if (records.empty()) {
    return out;
  }
  for (std::size_t i = 0; i < records.size(); ++i) {
    if (records[i].empty()) {
      return {};
    }
    std::vector<std::uint8_t> record = records[i];
    record.front() =
      static_cast<std::uint8_t>(record.front() & ~(NFC_NDEF_HDR_MB | NFC_NDEF_HDR_ME));
    if (i == 0u) {
      record.front() = static_cast<std::uint8_t>(record.front() | NFC_NDEF_HDR_MB);
    }
    if (i + 1u == records.size()) {
      record.front() = static_cast<std::uint8_t>(record.front() | NFC_NDEF_HDR_ME);
    }
    out.insert(out.end(), record.begin(), record.end());
  }
  return out;
}

std::vector<NdefRecordSummary> parse_ndef_records(const std::vector<std::uint8_t> &ndef) {
  std::vector<NdefRecordSummary> records;
  if (ndef.size() > NERO_NFC_NDEF_MAX_TOTAL_BYTES || ndef.size() > UINT16_MAX) {
    return records;
  }
  const uint16_t ndef_len = static_cast<uint16_t>(ndef.size());
  std::size_t total_payload = 0u;
  uint16_t pos = 0u;
  while (pos < ndef_len) {
    nfc_ndef_record_t rec{};
    uint16_t next = pos;
    const nfc_ndef_record_status_t status =
      nfc_ndef_record_next(ndef.data(), ndef_len, pos, &rec, &next);

    if (status == NFC_NDEF_RECORD_EMPTY) {
      pos = next;
      continue;
    }
    if (status != NFC_NDEF_RECORD_OK) {
      break;
    }
    if (records.size() >= NERO_NFC_NDEF_MAX_RECORDS) {
      break;
    }
    if (!nero_nfc_try_add_size(total_payload, rec.payload_len, &total_payload) ||
        total_payload > NERO_NFC_NDEF_MAX_TOTAL_BYTES) {
      break;
    }
    const uint8_t *record = ndef.data() + pos;
    std::string type(reinterpret_cast<const char *>(record + rec.type_offset), rec.type_len);
    std::vector<std::uint8_t> payload(record + rec.payload_offset,
                                      record + rec.payload_offset + rec.payload_len);
    records.push_back({rec.tnf, type, payload, decode_record_payload(rec.tnf, type, payload)});
    pos = next;
    if (rec.message_end) {
      break;
    }
  }
  return records;
}

} // namespace nero_nfc
