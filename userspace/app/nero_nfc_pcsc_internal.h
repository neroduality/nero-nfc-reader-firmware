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

#include "nero_nfc_attrs.h"
#include "nero_nfc_pcsc.h"

#include "nfc_ndef_tlv.h"

#include <chrono>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#ifdef NERO_USERSPACE_HAVE_PCSC
#include <PCSC/winscard.h>
#endif

namespace nero_nfc::pcsc_internal {

#ifdef NERO_HOST_UNIT_TEST_HOOKS
extern const std::vector<std::string> *g_list_pcsc_readers_override;
#endif

std::string lower_copy(std::string_view in);
std::string join_reader_names(const std::vector<std::string> &readers);
NERO_NFC_NODISCARD bool is_preferred_nero_reader(std::string_view reader_name);
NERO_NFC_NODISCARD bool is_sam_reader(std::string_view reader_name);
std::vector<std::string> selectable_pcsc_readers(const std::vector<std::string> &readers);

const char *tlv_status_name(nfc_ndef_tlv_status_t status);
NERO_NFC_NODISCARD bool extract_ndef_from_tlv_area(const std::vector<std::uint8_t> &tlv_area,
                                                   std::uint16_t start_offset, PcscTagSnapshot &tag,
                                                   std::string &err);
NERO_NFC_NODISCARD bool build_storage_ndef_tlv(const std::vector<std::uint8_t> &ndef,
                                               std::uint16_t data_area_size,
                                               std::vector<std::uint8_t> &tlv_area,
                                               std::string &err);
std::uint16_t storage_tlv_payload_cap(std::uint16_t data_area_size);
NERO_NFC_NODISCARD bool tlv_area_has_terminator(const std::vector<std::uint8_t> &raw,
                                                std::uint16_t start_offset);
std::vector<std::uint8_t> normalize_type5_uid(std::vector<std::uint8_t> uid);
NERO_NFC_NODISCARD bool build_select_apdu(std::uint8_t p1, std::uint8_t p2,
                                          const std::vector<std::uint8_t> &data,
                                          std::vector<std::uint8_t> &capdu, std::string &err);
std::vector<std::uint8_t> type5_addressed_block_command(std::uint8_t short_command,
                                                        std::uint8_t extended_command,
                                                        const std::vector<std::uint8_t> &uid_lsb,
                                                        std::uint16_t block);
std::vector<std::uint8_t>
type5_addressed_read_multiple_command(const std::vector<std::uint8_t> &uid_lsb,
                                      std::uint16_t first_block, std::uint16_t block_count);
std::vector<std::uint8_t>
type5_addressed_system_info_ext_command(const std::vector<std::uint8_t> &uid_lsb);
NERO_NFC_NODISCARD bool type4_ndef_len_fits_short_binary(std::size_t ndef_len);
std::uint16_t storage_cap_data_area_scan(std::uint16_t data_area_size, std::uint16_t scan_max);
std::uint16_t storage_type2_read_unit_limit(std::uint16_t first_unit, std::uint8_t unit_size,
                                            std::uint16_t tlv_start_offset,
                                            std::uint16_t data_area_size);
std::uint8_t type2_storage_bulk_read_len(std::uint16_t data_area_size);
std::uint16_t storage_type5_read_block_limit(std::uint16_t tlv_start_offset,
                                             std::uint16_t data_area_size);

#ifdef NERO_USERSPACE_HAVE_PCSC

DWORD pcsc_share_mode_to_scard(PcscShareMode mode);

inline constexpr auto kPcscPollSleep = std::chrono::milliseconds(20);
inline constexpr auto kPcscFastRetrySleep = std::chrono::milliseconds(5);
inline constexpr auto kPcscFastRetryWindow = std::chrono::milliseconds(250);
inline constexpr auto kPcscRemovalPollWindow = std::chrono::seconds(5);
inline constexpr auto kPcscRemovalSettleWindow = std::chrono::milliseconds(50);

NERO_NFC_NODISCARD bool is_type4_compatible(const PcscTagSnapshot &tag);
NERO_NFC_NODISCARD bool status_ok(const std::vector<std::uint8_t> &rapdu);
std::vector<std::uint8_t> without_status(const std::vector<std::uint8_t> &rapdu);

void pcsc_note(LONG rv, std::string &err, std::string_view stage);
std::string reader_state_summary(DWORD state);
NERO_NFC_NODISCARD bool
wait_for_card_state(SCARDCONTEXT ctx, const std::string &reader, bool want_present,
                    std::optional<std::chrono::steady_clock::time_point> deadline,
                    std::string &err);
NERO_NFC_NODISCARD bool
wait_for_card_present(SCARDCONTEXT ctx, const std::string &reader,
                      std::optional<std::chrono::steady_clock::time_point> deadline,
                      std::string &err);
NERO_NFC_NODISCARD bool
wait_for_card_absent(SCARDCONTEXT ctx, const std::string &reader,
                     std::optional<std::chrono::steady_clock::time_point> deadline,
                     std::string &err);
NERO_NFC_NODISCARD bool wait_for_card_absent_stable(SCARDCONTEXT ctx, const std::string &reader,
                                                    std::string &err);
NERO_NFC_NODISCARD bool wait_for_present_reader(SCARDCONTEXT ctx,
                                                const std::vector<std::string> &readers,
                                                std::string &reader, std::string &err,
                                                bool announce_selection = true,
                                                std::size_t *present_count_out = NERO_NFC_NULL);
void announce_pcsc_reader_selection(std::size_t present_count, const std::string &reader);
std::string tag_fingerprint(const PcscTagSnapshot &tag);
NERO_NFC_NODISCARD bool is_retryable_connect_error(LONG rv);
void prime_reader_state(SCARDCONTEXT ctx, const std::string &reader);
NERO_NFC_NODISCARD bool list_readers_impl(std::vector<std::string> &readers, std::string &err);

class PcscCard {
public:
  ~PcscCard();
  PcscCard(const PcscCard &) = delete;
  PcscCard &operator=(const PcscCard &) = delete;
  PcscCard(PcscCard &&) = delete;
  PcscCard &operator=(PcscCard &&) = delete;
  PcscCard();

  [[nodiscard]] const std::string &readerName() const;
  [[nodiscard]] SCARDCONTEXT context() const;
  NERO_NFC_NODISCARD bool ensureContext(std::string &err);
  void disconnect(DWORD disposition = SCARD_UNPOWER_CARD);
  NERO_NFC_NODISCARD bool connect(const std::string &reader, PcscShareMode share_mode,
                                  std::string &err);
  NERO_NFC_NODISCARD bool beginTransaction(std::string &err);
  NERO_NFC_NODISCARD bool endTransaction(std::string &err);
  NERO_NFC_NODISCARD bool status(std::vector<std::uint8_t> &atr, std::string &err);
  NERO_NFC_NODISCARD bool transmit(const std::vector<std::uint8_t> &capdu,
                                   std::vector<std::uint8_t> &rapdu, std::string &err);

private:
  std::string reader_name_;
  SCARDCONTEXT ctx_{};
  SCARDHANDLE card_{};
  DWORD protocol_{};
  const SCARD_IO_REQUEST *pci_{SCARD_PCI_T1};
  bool transaction_active_{};
};

NERO_NFC_NODISCARD bool transmit_ok(PcscCard &card, const std::vector<std::uint8_t> &capdu,
                                    std::vector<std::uint8_t> &data, std::string &err);
std::vector<std::uint8_t> try_get_data_bytes(PcscCard &card, std::uint8_t p1, std::uint8_t p2);
NERO_NFC_NODISCARD bool select_bytes(PcscCard &card, std::uint8_t p1, std::uint8_t p2,
                                     const std::vector<std::uint8_t> &data, std::string &err);
NERO_NFC_NODISCARD bool select_file(PcscCard &card, std::uint8_t hi, std::uint8_t lo,
                                    std::string &err);
NERO_NFC_NODISCARD bool read_binary(PcscCard &card, std::uint16_t offset, std::uint8_t len,
                                    std::vector<std::uint8_t> &data, std::string &err);
NERO_NFC_NODISCARD bool update_binary(PcscCard &card, std::uint16_t offset,
                                      const std::vector<std::uint8_t> &bytes, std::string &err);

NERO_NFC_NODISCARD bool storage_read_binary_apdu(PcscCard &card, std::uint8_t p1, std::uint8_t p2,
                                                 std::uint8_t len, std::vector<std::uint8_t> &data,
                                                 std::string &err);
NERO_NFC_NODISCARD bool storage_read_binary(PcscCard &card, std::uint16_t unit, std::uint8_t len,
                                            std::vector<std::uint8_t> &data, std::string &err);
NERO_NFC_NODISCARD bool type5_storage_read_binary(PcscCard &card, std::uint16_t block,
                                                  std::uint8_t len, std::vector<std::uint8_t> &data,
                                                  std::string &err);
NERO_NFC_NODISCARD bool type5_storage_read_binary(PcscCard &card, std::uint16_t block,
                                                  std::vector<std::uint8_t> &data,
                                                  std::string &err);
NERO_NFC_NODISCARD bool storage_update_binary_apdu(PcscCard &card, std::uint8_t p1, std::uint8_t p2,
                                                   const std::vector<std::uint8_t> &bytes,
                                                   std::string &err);
NERO_NFC_NODISCARD bool storage_update_binary(PcscCard &card, std::uint16_t unit,
                                              const std::vector<std::uint8_t> &bytes,
                                              std::string &err);
NERO_NFC_NODISCARD bool type5_storage_update_binary(PcscCard &card, std::uint16_t block,
                                                    const std::vector<std::uint8_t> &bytes,
                                                    std::string &err);
using StorageWriteUnitFn = bool (*)(PcscCard &card, const std::vector<std::uint8_t> &uid,
                                    std::uint16_t unit, const std::vector<std::uint8_t> &bytes,
                                    std::string &err);
NERO_NFC_NODISCARD bool storage_write_units(PcscCard &card, std::uint16_t first_unit,
                                            std::uint8_t unit_size,
                                            const std::vector<std::uint8_t> &bytes,
                                            std::string &err);
NERO_NFC_NODISCARD bool
storage_write_units_with_io(PcscCard &card, const std::vector<std::uint8_t> &uid,
                            std::uint16_t first_unit, std::uint8_t unit_size,
                            const std::vector<std::uint8_t> &bytes, StorageWriteUnitFn write_unit,
                            std::string &err);
NERO_NFC_NODISCARD bool
type2_storage_write_unit(PcscCard &card, const std::vector<std::uint8_t> &uid, std::uint16_t unit,
                         const std::vector<std::uint8_t> &bytes, std::string &err);
NERO_NFC_NODISCARD bool type5_storage_write_unit(PcscCard &card,
                                                 const std::vector<std::uint8_t> &uid_lsb,
                                                 std::uint16_t unit,
                                                 const std::vector<std::uint8_t> &bytes,
                                                 std::string &err);
NERO_NFC_NODISCARD bool read_type2_storage_ndef(PcscCard &card, PcscTagSnapshot &tag,
                                                std::vector<std::uint8_t> &type2_cc,
                                                std::string &err);
NERO_NFC_NODISCARD bool
read_type5_storage_ndef(PcscCard &card, const std::vector<std::uint8_t> &uid, PcscTagSnapshot &tag,
                        std::vector<std::uint8_t> &type5_cc,
                        std::vector<std::uint8_t> &type5_system_info, std::string &err);
NERO_NFC_NODISCARD bool
write_type2_storage_ndef(PcscCard &card, const std::vector<std::uint8_t> &ndef, std::string &err);
NERO_NFC_NODISCARD bool write_type5_storage_ndef(PcscCard &card,
                                                 const std::vector<std::uint8_t> &uid,
                                                 const std::vector<std::uint8_t> &ndef,
                                                 std::string &err);
NERO_NFC_NODISCARD bool type5_transparent_get_system_info(PcscCard &card,
                                                          const std::vector<std::uint8_t> &uid,
                                                          std::vector<std::uint8_t> &system_info,
                                                          std::string &err);

NERO_NFC_NODISCARD bool select_ndef_app(PcscCard &card, std::string &err);
NERO_NFC_NODISCARD bool read_ndef_file(PcscCard &card, PcscTagSnapshot &tag,
                                       std::vector<std::uint8_t> *cc_out, std::string &err);
NERO_NFC_NODISCARD bool should_attempt_type4_ndef_io(const PcscTagSnapshot &tag,
                                                     const std::vector<std::uint8_t> &type4_cc);
void note_passive_type4_probe(PcscTagSnapshot &tag);
NERO_NFC_NODISCARD bool write_ndef_file(PcscCard &card, const std::vector<std::uint8_t> &ndef,
                                        std::string &err);

NERO_NFC_NODISCARD bool pcsc_read_connected_tag(PcscCard &card, const std::string &reader,
                                                PcscTagSnapshot &out, std::string &err);
NERO_NFC_NODISCARD bool pcsc_read_tag_with_card(PcscCard &card, const std::string &reader,
                                                const PcscReadOptions &options,
                                                PcscTagSnapshot &out, std::string &err);
NERO_NFC_NODISCARD bool pcsc_write_tag_with_card(PcscCard &card, const std::string &reader,
                                                 const PcscWriteRequest &request, std::string &err);
NERO_NFC_NODISCARD bool resolve_pcsc_reader_for_operation(
  const PcscCard &card, std::string_view requested, std::string &reader, std::string &err,
  bool announce_selection = true, std::size_t *present_count_out = NERO_NFC_NULL);

#endif // NERO_USERSPACE_HAVE_PCSC

} // namespace nero_nfc::pcsc_internal
