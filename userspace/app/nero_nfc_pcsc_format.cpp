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

#include "nero_nfc_pcsc.h"

#include <sstream>

namespace nero_nfc {

std::string format_pcsc_tag_snapshot_header(const PcscTagSnapshot &tag) {
  std::ostringstream out;
  out << "PC/SC reader: " << tag.reader_name << '\n';
  if (!tag.tag_type.empty()) {
    out << "Tag type: " << tag.tag_type << '\n';
  }
  return out.str();
}

std::string format_pcsc_tag_snapshot_body(const PcscTagSnapshot &tag) {
  std::ostringstream out;
  if (!tag.tech_list.empty()) {
    out << "Tech list: " << tag.tech_list << '\n';
  }
  if (!tag.uid_hex.empty()) {
    out << "Serial number / UID: " << tag.uid_hex << '\n';
  }
  if (!tag.atqa_hex.empty()) {
    out << "ATQA: " << tag.atqa_hex << '\n';
  }
  if (!tag.sak_hex.empty()) {
    out << "SAK: 0x" << tag.sak_hex << '\n';
  }
  if (!tag.ats_hex.empty()) {
    out << "ATS: " << tag.ats_hex << '\n';
  }
  if (!tag.manufacturer.empty()) {
    out << "Manufacturer: " << tag.manufacturer << '\n';
  }
  if (!tag.product_name.empty()) {
    out << "Product: " << tag.product_name << '\n';
  }
  if (!tag.family_name.empty()) {
    out << "Family: " << tag.family_name << '\n';
  }
  if (!tag.atr_hex.empty()) {
    out << "ATR: " << tag.atr_hex << '\n';
  }
  if (!tag.type2_version_hex.empty()) {
    out << "GET_VERSION: " << tag.type2_version_hex << '\n';
  }
  if (!tag.type2_signature_hex.empty()) {
    out << "Signature: " << tag.type2_signature_hex << '\n';
  }
  if (!tag.type5_system_info_hex.empty()) {
    out << "System Info: " << tag.type5_system_info_hex << '\n';
  }
  for (const auto &line : tag.detail_lines) {
    out << line << '\n';
  }
  if (tag.max_ndef_size != 0u) {
    out << "NDEF max size: " << tag.max_ndef_size << " bytes\n";
    out << "Read access: " << (tag.read_access_open ? "open" : "restricted")
        << "  Write access: " << (tag.write_access_open ? "open" : "restricted") << '\n';
  }
  if (!tag.ndef_message.empty()) {
    out << "NDEF message: " << tag.ndef_message.size() << " bytes\n";
    for (std::size_t i = 0; i < tag.records.size(); ++i) {
      const auto &rec = tag.records[i];
      out << "  Record #" << (i + 1u) << ": TNF=" << static_cast<unsigned>(rec.tnf)
          << " Type=" << rec.type << " Payload=" << rec.payload.size() << "B";
      if (rec.decoded) {
        out << " Decoded=\"" << *rec.decoded << '"';
      }
      out << '\n';
    }
  }
  return out.str();
}

std::string format_pcsc_tag_snapshot(const PcscTagSnapshot &tag) {
  return format_pcsc_tag_snapshot_header(tag) + format_pcsc_tag_snapshot_body(tag);
}

} // namespace nero_nfc
