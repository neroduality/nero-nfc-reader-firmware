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

#include "nero_nfc_hex.hpp"
#include "nero_nfc_attrs.h"

#include "nero_nfc_ndef.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace nero_nfc {

enum class PcscShareMode : std::uint8_t {
  kShared,
  kExclusive,
};

struct PcscTagSnapshot {
  std::string reader_name_;
  std::string atr_hex_;
  std::string uid_hex_;
  std::string ats_hex_;
  std::string sak_hex_;
  std::string atqa_hex_;
  std::string tech_list_;
  std::string manufacturer_;
  std::string product_name_;
  std::string family_name_;
  std::string type2_version_hex_;
  std::string type2_signature_hex_;
  std::string type5_system_info_hex_;
  std::string tag_type_;
  std::uint16_t max_ndef_size_{};
  bool read_access_open_{};
  bool write_access_open_{};
  std::vector<std::string> detail_lines_;
  std::vector<std::uint8_t> ndef_message_;
  std::vector<NdefRecordSummary> records_;
};

struct PcscWriteRequest {
  std::vector<std::uint8_t> ndef_message_;
  PcscShareMode share_mode_{PcscShareMode::kShared};
};

struct PcscReadOptions {
  PcscShareMode share_mode_{PcscShareMode::kShared};
};

std::string FormatPcscTagSnapshot(const PcscTagSnapshot& tag);
std::string FormatPcscTagSnapshotHeader(const PcscTagSnapshot& tag);
std::string FormatPcscTagSnapshotBody(const PcscTagSnapshot& tag);

std::optional<PcscShareMode> ParsePcscShareMode(std::string_view text);
std::string_view PcscShareModeName(PcscShareMode mode);
std::string PcscReaderSubstringFromEnv();
NERO_NFC_NODISCARD bool ListPcscReaders(std::vector<std::string>& readers,
                                        std::string& err);
NERO_NFC_NODISCARD bool ChoosePcscReaderFromList(
    const std::vector<std::string>& readers, std::string_view reader_substring,
    std::string& reader, std::string& err);
NERO_NFC_NODISCARD bool ResolvePcscReader(std::string_view reader_substring,
                                          std::string& reader,
                                          std::string& err);

NERO_NFC_NODISCARD bool PcscReadTag(std::string_view reader_substring,
                                    const PcscReadOptions& options,
                                    PcscTagSnapshot& out, std::string& err);
NERO_NFC_NODISCARD bool PcscReadTag(std::string_view reader_substring,
                                    PcscTagSnapshot& out, std::string& err);
NERO_NFC_NODISCARD bool PcscWriteTag(std::string_view reader_substring,
                                     const PcscWriteRequest& request,
                                     PcscTagSnapshot* after_write,
                                     std::string& err);

int RunPcscReader(std::string_view reader_substring,
                  const PcscReadOptions& options);
int RunPcscReader(std::string_view reader_substring);
int RunPcscWriter(std::string_view reader_substring,
                  const PcscWriteRequest& request);

#ifdef NERO_HOST_UNIT_TEST_HOOKS
void NeroNfcUtestSetListPcscReadersOverride(
    const std::vector<std::string>* readers);
void NeroNfcUtestClearListPcscReadersOverride();
NERO_NFC_NODISCARD bool NeroNfcUtestExtractStorageNdef(
    const std::vector<std::uint8_t>& tlv_area, std::uint16_t start_offset,
    PcscTagSnapshot& tag, std::string& err);
NERO_NFC_NODISCARD bool NeroNfcUtestBuildStorageNdefTlv(
    const std::vector<std::uint8_t>& ndef, std::uint16_t data_area_size,
    std::vector<std::uint8_t>& tlv_area, std::string& err);
std::uint16_t NeroNfcUtestStorageTlvPayloadCap(std::uint16_t data_area_size);
NERO_NFC_NODISCARD bool NeroNfcUtestBuildSelectApdu(
    std::uint8_t p1, std::uint8_t p2, const std::vector<std::uint8_t>& data,
    std::vector<std::uint8_t>& capdu, std::string& err);
NERO_NFC_NODISCARD bool NeroNfcUtestType4NdefLenFitsShortBinary(
    std::size_t ndef_len);
std::uint16_t NeroNfcUtestStorageType2ReadUnitLimit(
    std::uint16_t first_unit, std::uint8_t unit_size,
    std::uint16_t tlv_start_offset, std::uint16_t data_area_size);
std::uint8_t NeroNfcUtestType2StorageBulkReadLen(std::uint16_t data_area_size);
std::uint16_t NeroNfcUtestStorageType5ReadBlockLimit(
    std::uint16_t tlv_start_offset, std::uint16_t data_area_size);
std::vector<std::uint8_t> NeroNfcUtestType5TransparentBlockCommand(
    bool write, const std::vector<std::uint8_t>& uid_lsb, std::uint16_t block);
std::vector<std::uint8_t> NeroNfcUtestType5TransparentReadMultipleCommand(
    const std::vector<std::uint8_t>& uid_lsb, std::uint16_t first_block,
    std::uint16_t block_count);
std::vector<std::uint8_t> NeroNfcUtestType5TransparentSystemInfoExtCommand(
    const std::vector<std::uint8_t>& uid_lsb);
#endif

}  // namespace nero_nfc
