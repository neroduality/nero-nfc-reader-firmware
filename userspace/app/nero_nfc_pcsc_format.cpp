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

#include "nero_nfc_pcsc.hpp"

#include <sstream>

namespace nero_nfc {

std::string FormatPcscTagSnapshotHeader(const PcscTagSnapshot& tag) {
  std::ostringstream out;
  out << "PC/SC reader: " << tag.reader_name_ << '\n';
  if (!tag.tag_type_.empty()) {
    out << "Tag type: " << tag.tag_type_ << '\n';
  }
  return out.str();
}

std::string FormatPcscTagSnapshotBody(const PcscTagSnapshot& tag) {
  std::ostringstream out;
  if (!tag.tech_list_.empty()) {
    out << "Tech list: " << tag.tech_list_ << '\n';
  }
  if (!tag.uid_hex_.empty()) {
    out << "Serial number / UID: " << tag.uid_hex_ << '\n';
  }
  if (!tag.atqa_hex_.empty()) {
    out << "ATQA: " << tag.atqa_hex_ << '\n';
  }
  if (!tag.sak_hex_.empty()) {
    out << "SAK: 0x" << tag.sak_hex_ << '\n';
  }
  if (!tag.ats_hex_.empty()) {
    out << "ATS: " << tag.ats_hex_ << '\n';
  }
  if (!tag.manufacturer_.empty()) {
    out << "Manufacturer: " << tag.manufacturer_ << '\n';
  }
  if (!tag.product_name_.empty()) {
    out << "Product: " << tag.product_name_ << '\n';
  }
  if (!tag.family_name_.empty()) {
    out << "Family: " << tag.family_name_ << '\n';
  }
  if (!tag.atr_hex_.empty()) {
    out << "ATR: " << tag.atr_hex_ << '\n';
  }
  if (!tag.type2_version_hex_.empty()) {
    out << "GET_VERSION: " << tag.type2_version_hex_ << '\n';
  }
  if (!tag.type2_signature_hex_.empty()) {
    out << "Signature: " << tag.type2_signature_hex_ << '\n';
  }
  if (!tag.type5_system_info_hex_.empty()) {
    out << "System Info: " << tag.type5_system_info_hex_ << '\n';
  }
  for (const auto& line : tag.detail_lines_) {
    out << line << '\n';
  }
  if (tag.max_ndef_size_ != 0u) {
    out << "NDEF max size: " << tag.max_ndef_size_ << " bytes\n";
    out << "Read access: " << (tag.read_access_open_ ? "open" : "restricted")
        << "  Write access: "
        << (tag.write_access_open_ ? "open" : "restricted") << '\n';
  }
  if (!tag.ndef_message_.empty()) {
    out << "NDEF message: " << tag.ndef_message_.size() << " bytes\n";
    for (std::size_t i = 0; i < tag.records_.size(); ++i) {
      const auto& rec = tag.records_[i];
      out << "  Record #" << (i + 1u)
          << ": TNF=" << static_cast<unsigned>(rec.tnf_)
          << " Type=" << rec.type_ << " Payload=" << rec.payload_.size() << "B";
      if (rec.decoded_) {
        out << " Decoded=\"" << *rec.decoded_ << '"';
      }
      out << '\n';
    }
  }
  return out.str();
}

std::string FormatPcscTagSnapshot(const PcscTagSnapshot& tag) {
  return FormatPcscTagSnapshotHeader(tag) + FormatPcscTagSnapshotBody(tag);
}

}  // namespace nero_nfc
