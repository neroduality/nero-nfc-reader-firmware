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

#include "nero_nfc_writer_payload.hpp"
#include <span>
#include "nero_nfc_bounds.hpp"

#include "nero_nfc_hex.hpp"
#include "nero_nfc_ndef.hpp"
#include "nfc_ndef_record_decode.h"
#include "nfc_ndef_tlv.h"
#include "nfc_pcsc_contactless.h"
#include "nfc_tag_geometry_limits.h"
#include "nfc_wsc.h"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace nero_nfc {
namespace {

enum : unsigned {
  kUrlNibbleShift = 4u,
  kUrlNibbleMask = 0x0Fu,
  kBtOobDataLength = 8u, /* [BT-OOB] OOB Data Length field value (2-byte len +
                            6-byte BD_ADDR). */
  kSpecThirdFieldIndex =
      2u, /* pipe-split spec: index of the optional third field. */
  kWifiMinSpecParts = 2u, /* WiFi spec requires at least SSID|password. */
  kWscApMacPlaceholder =
      0x00u, /* [WSC] all-zero AP MAC placeholder (enrollee fills in). */
  kWriterBtMacOctetCount = 6u,
  kWriterBtMacLastOctetIndex = 5u,
  kWriterBtMacOctetIndex0 = 0u,
  kWriterBtMacOctetIndex1 = 1u,
  kWriterBtMacOctetIndex2 = 2u,
  kWriterBtMacOctetIndex3 = 3u,
  kWriterBtMacOctetIndex4 = 4u,
  kWriterBtMacOctetIndex5 = 5u,
};

std::vector<std::string> SplitPipe(std::string_view value) {
  std::vector<std::string> parts;
  std::size_t start = 0;
  while (start <= value.size()) {
    std::size_t pos = value.find('|', start);
    if (pos == std::string_view::npos) {
      parts.emplace_back(value.substr(start));
      break;
    }
    parts.emplace_back(value.substr(start, pos - start));
    start = pos + 1u;
  }
  return parts;
}

std::vector<std::uint8_t> BytesOf(std::string_view text) {
  return {text.begin(), text.end()};
}

bool ParseBtMac(std::string_view value,
                std::span<std::uint8_t, kWriterBtMacOctetCount> mac) {
  std::string compact;
  for (char c : value) {
    if (std::isxdigit(static_cast<unsigned char>(c)) != 0) {
      compact.push_back(c);
    } else if (c != ':' && c != '-' &&
               std::isspace(static_cast<unsigned char>(c)) == 0) {
      return false;
    }
  }
  if (compact.size() !=
      static_cast<std::size_t>(NFC_ISO_DEP_IBLOCK_TX_OVERHEAD)) {
    return false;
  }
  std::vector<std::uint8_t> parsed;
  if (!ParseHexBytes(compact, parsed) ||
      parsed.size() != static_cast<std::size_t>(NFC_PCSC_T4_NDEF_FC_TLV_LEN)) {
    return false;
  }
  for (std::size_t i = 0; i < parsed.size(); ++i) {
    mac[i] = parsed[i];  // span subscript — not C-array pro-bounds
  }
  return true;
}

void WpsPutAttr(std::vector<std::uint8_t>& out, std::uint16_t attr,
                const std::vector<std::uint8_t>& data) {
  out.push_back(
      static_cast<std::uint8_t>(attr >> NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES));
  out.push_back(static_cast<std::uint8_t>(attr & NFC_BYTE_VALUE_MAX));
  out.push_back(static_cast<std::uint8_t>(data.size() >>
                                          NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES));
  out.push_back(static_cast<std::uint8_t>(data.size() & NFC_BYTE_VALUE_MAX));
  out.insert(out.end(), data.begin(), data.end());
}

}  // namespace

std::string WriterUrlComponentEncode(std::string_view text) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string out;
  for (char raw : text) {
    auto c = static_cast<unsigned char>(raw);
    /* [RFC3986] §2.3 unreserved set is emitted verbatim; everything else
     * (including space) is percent-encoded. Space is %20, not '+' ('+' is only
     * for application/x-www-form-urlencoded form bodies, not URIs/mailto). */
    if (std::isalnum(c) != 0 || c == '-' || c == '_' || c == '.' || c == '~') {
      out.push_back(static_cast<char>(c));
    } else {
      out.push_back('%');
      out.push_back(At(kHex, static_cast<std::size_t>(c >> kUrlNibbleShift)));
      out.push_back(At(kHex, static_cast<std::size_t>(c & kUrlNibbleMask)));
    }
  }
  return out;
}

std::vector<std::uint8_t> BuildWriterVcardRecord(std::string_view spec) {
  auto parts = SplitPipe(spec);
  if (parts.empty() || parts[0].empty()) {
    return {};
  }
  /* [RFC6350] vCard property values are line-folded text; reject embedded
   * control characters (notably CR/LF) so a field value cannot inject extra
   * properties. */
  const auto kHasControlChar = [](std::string_view value) {
    return std::ranges::any_of(value, [](char raw) {
      return static_cast<unsigned>(static_cast<unsigned char>(raw)) <
             NFC_RFC6350_ASCII_FIRST_PRINTABLE;
    });
  };
  if (std::ranges::any_of(parts, kHasControlChar)) {
    return {};
  }
  std::ostringstream vcard;
  vcard << "BEGIN:VCARD\r\nVERSION:" << NFC_RFC6350_VCARD_VERSION_MAJOR
        << ".0\r\nFN:" << parts[0] << "\r\n";
  if (parts.size() > 1u && !parts[1].empty()) {
    vcard << "TEL:" << parts[1] << "\r\n";
  }
  if (parts.size() > static_cast<std::size_t>(kSpecThirdFieldIndex) &&
      !parts[kSpecThirdFieldIndex].empty()) {
    vcard << "EMAIL:" << parts[kSpecThirdFieldIndex] << "\r\n";
  }
  vcard << "END:VCARD\r\n";
  return BuildNdefMimeRecord(NFC_NDEF_MIME_VCARD, BytesOf(vcard.str()));
}

void NormalizeWriterNdefHexPayload(std::vector<std::uint8_t>& bytes) {
  nfc_ndef_tlv_t tlv{};

  if (bytes.empty() || bytes[0] != NFC_NDEF_TLV_MESSAGE ||
      bytes.size() > static_cast<std::size_t>(UINT16_MAX) ||
      nfc_ndef_find_message_tlv(bytes.data(),
                                static_cast<std::uint16_t>(bytes.size()), 0u,
                                &tlv) != NFC_NDEF_TLV_OK) {
    return;
  }
  const auto kValueEnd = static_cast<std::size_t>(tlv.value_offset) +
                         static_cast<std::size_t>(tlv.value_len);
  if (kValueEnd >= bytes.size() ||
      bytes[kValueEnd] != NFC_NDEF_TLV_TERMINATOR ||
      (kValueEnd + 1u) != bytes.size()) {
    return;
  }
  bytes.assign(bytes.begin() + static_cast<std::ptrdiff_t>(tlv.value_offset),
               bytes.begin() + static_cast<std::ptrdiff_t>(kValueEnd));
}

std::vector<std::uint8_t> BuildWriterMailRecord(std::string_view spec) {
  auto parts = SplitPipe(spec);
  if (parts.empty() || parts[0].empty()) {
    return {};
  }
  std::string uri = "mailto:" + parts[0];
  bool first_query = true;
  if (parts.size() > 1u && !parts[1].empty()) {
    uri += first_query ? '?' : '&';
    first_query = false;
    uri += "subject=" + WriterUrlComponentEncode(parts[1]);
  }
  if (parts.size() > static_cast<std::size_t>(kSpecThirdFieldIndex) &&
      !parts[kSpecThirdFieldIndex].empty()) {
    uri += first_query ? '?' : '&';
    uri += "body=" + WriterUrlComponentEncode(parts[kSpecThirdFieldIndex]);
  }
  return BuildNdefUriRecord(uri);
}

std::vector<std::uint8_t> BuildWriterSmsRecord(std::string_view spec) {
  auto parts = SplitPipe(spec);
  if (parts.empty() || parts[0].empty()) {
    return {};
  }
  std::string uri = "sms:" + parts[0];
  if (parts.size() > 1u && !parts[1].empty()) {
    uri += "?body=" + WriterUrlComponentEncode(parts[1]);
  }
  return BuildNdefUriRecord(uri);
}

std::vector<std::uint8_t> BuildWriterBluetoothRecord(std::string_view value) {
  std::uint8_t mac[kWriterBtMacOctetCount]{};
  if (!ParseBtMac(value, AsSpan(mac))) {
    return {};
  }
  /* [BT-OOB] Bluetooth SSP-over-NFC OOB block: 2-byte OOB Data Length (LSB
   * first, total length including itself) then 6-byte BD_ADDR LSB first. */
  std::vector<std::uint8_t> payload = {
      static_cast<std::uint8_t>(kBtOobDataLength),
      0x00u,
      mac[kWriterBtMacOctetIndex5],
      mac[kWriterBtMacOctetIndex4],
      mac[kWriterBtMacOctetIndex3],
      mac[kWriterBtMacOctetIndex2],
      mac[kWriterBtMacOctetIndex1],
      mac[kWriterBtMacOctetIndex0],
  };
  return BuildNdefMimeRecord(NFC_NDEF_MIME_BT_OOB, payload);
}

std::vector<std::uint8_t> BuildWriterWifiRecord(std::string_view spec) {
  auto parts = SplitPipe(spec);
  if (parts.size() < static_cast<std::size_t>(kWifiMinSpecParts) ||
      parts[0].empty() || parts[1].size() < NFC_WSC_PSK_MIN_LEN ||
      parts[1].size() > NFC_WSC_PSK_MAX_LEN) {
    return {};
  }
  std::vector<std::uint8_t> inner;
  WpsPutAttr(inner, NFC_WSC_ATTR_NETWORK_INDEX, {0x01u});
  WpsPutAttr(inner, NFC_WSC_ATTR_SSID, BytesOf(parts[0]));
  WpsPutAttr(inner, NFC_WSC_ATTR_AUTH_TYPE, NFC_WSC_AUTH_WPA2_PSK_INIT);
  WpsPutAttr(inner, NFC_WSC_ATTR_ENCR_TYPE, NFC_WSC_ENCR_AES_INIT);
  WpsPutAttr(inner, NFC_WSC_ATTR_NETWORK_KEY, BytesOf(parts[1]));
  WpsPutAttr(inner, NFC_WSC_ATTR_MAC_ADDRESS,
             {static_cast<std::uint8_t>(kWscApMacPlaceholder),
              static_cast<std::uint8_t>(kWscApMacPlaceholder),
              static_cast<std::uint8_t>(kWscApMacPlaceholder),
              static_cast<std::uint8_t>(kWscApMacPlaceholder),
              static_cast<std::uint8_t>(kWscApMacPlaceholder),
              static_cast<std::uint8_t>(kWscApMacPlaceholder)});

  std::vector<std::uint8_t> credential;
  WpsPutAttr(credential, NFC_WSC_ATTR_CREDENTIAL, inner);
  std::vector<std::uint8_t> payload = NFC_WSC_VERSION_HEADER_INIT;
  payload.insert(payload.end(), credential.begin(), credential.end());
  return BuildNdefMimeRecord(NFC_NDEF_MIME_WSC, payload);
}

}  // namespace nero_nfc
