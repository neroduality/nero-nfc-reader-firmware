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

#include "nero_nfc_hex.h"
#include "nero_nfc_attrs.h"

#include "nero_nfc_ndef.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace nero_nfc {

enum class PcscShareMode : std::uint8_t {
  Shared,
  Exclusive,
};

struct PcscTagSnapshot {
  std::string reader_name;
  std::string atr_hex;
  std::string uid_hex;
  std::string ats_hex;
  std::string sak_hex;
  std::string atqa_hex;
  std::string tech_list;
  std::string manufacturer;
  std::string product_name;
  std::string family_name;
  std::string type2_version_hex;
  std::string type2_signature_hex;
  std::string type5_system_info_hex;
  std::string tag_type;
  std::uint16_t max_ndef_size{};
  bool read_access_open{};
  bool write_access_open{};
  std::vector<std::string> detail_lines;
  std::vector<std::uint8_t> ndef_message;
  std::vector<NdefRecordSummary> records;
};

struct PcscWriteRequest {
  std::vector<std::uint8_t> ndef_message;
  PcscShareMode share_mode{PcscShareMode::Shared};
};

struct PcscReadOptions {
  PcscShareMode share_mode{PcscShareMode::Shared};
};

std::string format_pcsc_tag_snapshot(const PcscTagSnapshot &tag);
std::string format_pcsc_tag_snapshot_header(const PcscTagSnapshot &tag);
std::string format_pcsc_tag_snapshot_body(const PcscTagSnapshot &tag);

std::optional<PcscShareMode> parse_pcsc_share_mode(std::string_view text);
std::string_view pcsc_share_mode_name(PcscShareMode mode);
std::string pcsc_reader_substring_from_env();
NERO_NFC_NODISCARD bool list_pcsc_readers(std::vector<std::string> &readers, std::string &err);
NERO_NFC_NODISCARD bool choose_pcsc_reader_from_list(const std::vector<std::string> &readers,
                                                     std::string_view reader_substring,
                                                     std::string &reader, std::string &err);
NERO_NFC_NODISCARD bool resolve_pcsc_reader(std::string_view reader_substring, std::string &reader,
                                            std::string &err);

NERO_NFC_NODISCARD bool pcsc_read_tag(std::string_view reader_substring,
                                      const PcscReadOptions &options, PcscTagSnapshot &out,
                                      std::string &err);
NERO_NFC_NODISCARD bool pcsc_read_tag(std::string_view reader_substring, PcscTagSnapshot &out,
                                      std::string &err);
NERO_NFC_NODISCARD bool pcsc_write_tag(std::string_view reader_substring,
                                       const PcscWriteRequest &request,
                                       PcscTagSnapshot *after_write, std::string &err);

int run_pcsc_reader(std::string_view reader_substring, const PcscReadOptions &options);
int run_pcsc_reader(std::string_view reader_substring);
int run_pcsc_writer(std::string_view reader_substring, const PcscWriteRequest &request);

#ifdef NERO_HOST_UNIT_TEST_HOOKS
void nero_nfc_utest_set_list_pcsc_readers_override(const std::vector<std::string> *readers);
void nero_nfc_utest_clear_list_pcsc_readers_override();
NERO_NFC_NODISCARD bool
nero_nfc_utest_extract_storage_ndef(const std::vector<std::uint8_t> &tlv_area,
                                    std::uint16_t start_offset, PcscTagSnapshot &tag,
                                    std::string &err);
NERO_NFC_NODISCARD bool nero_nfc_utest_build_storage_ndef_tlv(const std::vector<std::uint8_t> &ndef,
                                                              std::uint16_t data_area_size,
                                                              std::vector<std::uint8_t> &tlv_area,
                                                              std::string &err);
std::uint16_t nero_nfc_utest_storage_tlv_payload_cap(std::uint16_t data_area_size);
NERO_NFC_NODISCARD bool nero_nfc_utest_build_select_apdu(std::uint8_t p1, std::uint8_t p2,
                                                         const std::vector<std::uint8_t> &data,
                                                         std::vector<std::uint8_t> &capdu,
                                                         std::string &err);
NERO_NFC_NODISCARD bool nero_nfc_utest_type4_ndef_len_fits_short_binary(std::size_t ndef_len);
std::uint16_t nero_nfc_utest_storage_type2_read_unit_limit(std::uint16_t first_unit,
                                                           std::uint8_t unit_size,
                                                           std::uint16_t tlv_start_offset,
                                                           std::uint16_t data_area_size);
std::uint8_t nero_nfc_utest_type2_storage_bulk_read_len(std::uint16_t data_area_size);
std::uint16_t nero_nfc_utest_storage_type5_read_block_limit(std::uint16_t tlv_start_offset,
                                                            std::uint16_t data_area_size);
std::vector<std::uint8_t>
nero_nfc_utest_type5_transparent_block_command(bool write, const std::vector<std::uint8_t> &uid_lsb,
                                               std::uint16_t block);
std::vector<std::uint8_t> nero_nfc_utest_type5_transparent_read_multiple_command(
  const std::vector<std::uint8_t> &uid_lsb, std::uint16_t first_block, std::uint16_t block_count);
std::vector<std::uint8_t>
nero_nfc_utest_type5_transparent_system_info_ext_command(const std::vector<std::uint8_t> &uid_lsb);
#endif

} // namespace nero_nfc
