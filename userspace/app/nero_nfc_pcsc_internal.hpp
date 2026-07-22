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
#include "nero_nfc_pcsc.hpp"

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
extern const std::vector<std::string>* g_list_pcsc_readers_override;
#endif

std::string LowerCopy(std::string_view in);
std::string JoinReaderNames(const std::vector<std::string>& readers);
NERO_NFC_NODISCARD bool IsPreferredNeroReader(std::string_view reader_name);
NERO_NFC_NODISCARD bool IsSamReader(std::string_view reader_name);
std::vector<std::string> SelectablePcscReaders(
    const std::vector<std::string>& readers);

const char* TlvStatusName(nfc_ndef_tlv_status_t status);
NERO_NFC_NODISCARD bool ExtractNdefFromTlvArea(
    const std::vector<std::uint8_t>& tlv_area, std::uint16_t start_offset,
    PcscTagSnapshot& tag, std::string& err);
NERO_NFC_NODISCARD bool BuildStorageNdefTlv(
    const std::vector<std::uint8_t>& ndef, std::uint16_t data_area_size,
    std::vector<std::uint8_t>& tlv_area, std::string& err);
std::uint16_t StorageTlvPayloadCap(std::uint16_t data_area_size);
NERO_NFC_NODISCARD bool TlvAreaHasTerminator(
    const std::vector<std::uint8_t>& raw, std::uint16_t start_offset);
std::vector<std::uint8_t> NormalizeType5Uid(std::vector<std::uint8_t> uid);
NERO_NFC_NODISCARD bool BuildSelectApdu(std::uint8_t p1, std::uint8_t p2,
                                        const std::vector<std::uint8_t>& data,
                                        std::vector<std::uint8_t>& capdu,
                                        std::string& err);
std::vector<std::uint8_t> Type5AddressedBlockCommand(
    std::uint8_t short_command, std::uint8_t extended_command,
    const std::vector<std::uint8_t>& uid_lsb, std::uint16_t block);
std::vector<std::uint8_t> Type5AddressedReadMultipleCommand(
    const std::vector<std::uint8_t>& uid_lsb, std::uint16_t first_block,
    std::uint16_t block_count);
std::vector<std::uint8_t> Type5AddressedSystemInfoExtCommand(
    const std::vector<std::uint8_t>& uid_lsb);
NERO_NFC_NODISCARD bool Type4NdefLenFitsShortBinary(std::size_t ndef_len);
std::uint16_t StorageCapDataAreaScan(std::uint16_t data_area_size,
                                     std::uint16_t scan_max);
std::uint16_t StorageType2ReadUnitLimit(std::uint16_t first_unit,
                                        std::uint8_t unit_size,
                                        std::uint16_t tlv_start_offset,
                                        std::uint16_t data_area_size);
std::uint8_t Type2StorageBulkReadLen(std::uint16_t data_area_size);
std::uint16_t StorageType5ReadBlockLimit(std::uint16_t tlv_start_offset,
                                         std::uint16_t data_area_size);

#ifdef NERO_USERSPACE_HAVE_PCSC

DWORD PcscShareModeToScard(PcscShareMode mode);

inline constexpr auto kPcscPollSleep = std::chrono::milliseconds(20);
inline constexpr auto kPcscFastRetrySleep = std::chrono::milliseconds(5);
inline constexpr auto kPcscFastRetryWindow = std::chrono::milliseconds(250);
inline constexpr auto kPcscConnectRetryWindow = std::chrono::seconds(5);
inline constexpr auto kPcscRemovalPollWindow = std::chrono::seconds(5);
inline constexpr auto kPcscRemovalSettleWindow = std::chrono::milliseconds(50);

NERO_NFC_NODISCARD bool IsType4Compatible(const PcscTagSnapshot& tag);
NERO_NFC_NODISCARD bool StatusOk(const std::vector<std::uint8_t>& rapdu);
std::vector<std::uint8_t> WithoutStatus(const std::vector<std::uint8_t>& rapdu);

void PcscNote(LONG rv, std::string& err, std::string_view stage);
std::string ReaderStateSummary(DWORD state);
NERO_NFC_NODISCARD bool WaitForCardState(
    SCARDCONTEXT ctx, const std::string& reader, bool want_present,
    std::optional<std::chrono::steady_clock::time_point> deadline,
    std::string& err);
NERO_NFC_NODISCARD bool WaitForCardPresent(
    SCARDCONTEXT ctx, const std::string& reader,
    std::optional<std::chrono::steady_clock::time_point> deadline,
    std::string& err);
NERO_NFC_NODISCARD bool WaitForCardAbsent(
    SCARDCONTEXT ctx, const std::string& reader,
    std::optional<std::chrono::steady_clock::time_point> deadline,
    std::string& err);
NERO_NFC_NODISCARD bool WaitForCardAbsentStable(SCARDCONTEXT ctx,
                                                const std::string& reader,
                                                std::string& err);
NERO_NFC_NODISCARD bool WaitForPresentReader(
    SCARDCONTEXT ctx, const std::vector<std::string>& readers,
    std::string& reader, std::string& err, bool announce_selection = true,
    std::size_t* present_count_out = NERO_NFC_NULL);
void AnnouncePcscReaderSelection(std::size_t present_count,
                                 const std::string& reader);
std::string TagFingerprint(const PcscTagSnapshot& tag);
NERO_NFC_NODISCARD bool IsRetryableConnectError(LONG rv);
void PrimeReaderState(SCARDCONTEXT ctx, const std::string& reader);
NERO_NFC_NODISCARD bool ListReadersImpl(std::vector<std::string>& readers,
                                        std::string& err);

class PcscCard {
 public:
  ~PcscCard();
  PcscCard(const PcscCard&) = delete;
  PcscCard& operator=(const PcscCard&) = delete;
  PcscCard(PcscCard&&) = delete;
  PcscCard& operator=(PcscCard&&) = delete;
  PcscCard();

  [[nodiscard]] const std::string& ReaderName() const;
  [[nodiscard]] SCARDCONTEXT Context() const;
  NERO_NFC_NODISCARD bool EnsureContext(std::string& err);
  void Disconnect(DWORD disposition = SCARD_UNPOWER_CARD);
  NERO_NFC_NODISCARD bool Connect(const std::string& reader,
                                  PcscShareMode share_mode, std::string& err);
  NERO_NFC_NODISCARD bool BeginTransaction(std::string& err);
  NERO_NFC_NODISCARD bool EndTransaction(std::string& err);
  NERO_NFC_NODISCARD bool Status(std::vector<std::uint8_t>& atr,
                                 std::string& err);
  NERO_NFC_NODISCARD bool Transmit(const std::vector<std::uint8_t>& capdu,
                                   std::vector<std::uint8_t>& rapdu,
                                   std::string& err);

 private:
  std::string reader_name_;
  SCARDCONTEXT ctx_{};
  SCARDHANDLE card_{};
  DWORD protocol_{};
  const SCARD_IO_REQUEST* pci_{SCARD_PCI_T1};
  bool transaction_active_{};
};

NERO_NFC_NODISCARD bool TransmitOk(PcscCard& card,
                                   const std::vector<std::uint8_t>& capdu,
                                   std::vector<std::uint8_t>& data,
                                   std::string& err);
std::vector<std::uint8_t> TryGetDataBytes(PcscCard& card, std::uint8_t p1,
                                          std::uint8_t p2);
NERO_NFC_NODISCARD bool SelectBytes(PcscCard& card, std::uint8_t p1,
                                    std::uint8_t p2,
                                    const std::vector<std::uint8_t>& data,
                                    std::string& err);
NERO_NFC_NODISCARD bool SelectFile(PcscCard& card, std::uint8_t hi,
                                   std::uint8_t lo, std::string& err);
NERO_NFC_NODISCARD bool ReadBinary(PcscCard& card, std::uint16_t offset,
                                   std::uint8_t len,
                                   std::vector<std::uint8_t>& data,
                                   std::string& err);
NERO_NFC_NODISCARD bool UpdateBinary(PcscCard& card, std::uint16_t offset,
                                     const std::vector<std::uint8_t>& bytes,
                                     std::string& err);

NERO_NFC_NODISCARD bool StorageReadBinaryApdu(PcscCard& card, std::uint8_t p1,
                                              std::uint8_t p2, std::uint8_t len,
                                              std::vector<std::uint8_t>& data,
                                              std::string& err);
NERO_NFC_NODISCARD bool StorageReadBinary(PcscCard& card, std::uint16_t unit,
                                          std::uint8_t len,
                                          std::vector<std::uint8_t>& data,
                                          std::string& err);
NERO_NFC_NODISCARD bool Type5StorageReadBinary(PcscCard& card,
                                               std::uint16_t block,
                                               std::uint8_t len,
                                               std::vector<std::uint8_t>& data,
                                               std::string& err);
NERO_NFC_NODISCARD bool Type5StorageReadBinary(PcscCard& card,
                                               std::uint16_t block,
                                               std::vector<std::uint8_t>& data,
                                               std::string& err);
NERO_NFC_NODISCARD bool StorageUpdateBinaryApdu(
    PcscCard& card, std::uint8_t p1, std::uint8_t p2,
    const std::vector<std::uint8_t>& bytes, std::string& err);
NERO_NFC_NODISCARD bool StorageUpdateBinary(
    PcscCard& card, std::uint16_t unit, const std::vector<std::uint8_t>& bytes,
    std::string& err);
NERO_NFC_NODISCARD bool Type5StorageUpdateBinary(
    PcscCard& card, std::uint16_t block, const std::vector<std::uint8_t>& bytes,
    std::string& err);
using StorageWriteUnitFn = bool (*)(PcscCard& card,
                                    const std::vector<std::uint8_t>& uid,
                                    std::uint16_t unit,
                                    const std::vector<std::uint8_t>& bytes,
                                    std::string& err);
NERO_NFC_NODISCARD bool StorageWriteUnits(
    PcscCard& card, std::uint16_t first_unit, std::uint8_t unit_size,
    const std::vector<std::uint8_t>& bytes, std::string& err);
NERO_NFC_NODISCARD bool StorageWriteUnitsWithIo(
    PcscCard& card, const std::vector<std::uint8_t>& uid,
    std::uint16_t first_unit, std::uint8_t unit_size,
    const std::vector<std::uint8_t>& bytes, StorageWriteUnitFn write_unit,
    std::string& err);
NERO_NFC_NODISCARD bool Type2StorageWriteUnit(
    PcscCard& card, const std::vector<std::uint8_t>& uid, std::uint16_t unit,
    const std::vector<std::uint8_t>& bytes, std::string& err);
NERO_NFC_NODISCARD bool Type5StorageWriteUnit(
    PcscCard& card, const std::vector<std::uint8_t>& uid_lsb,
    std::uint16_t unit, const std::vector<std::uint8_t>& bytes,
    std::string& err);
NERO_NFC_NODISCARD bool ReadType2StorageNdef(
    PcscCard& card, PcscTagSnapshot& tag, std::vector<std::uint8_t>& type2_cc,
    std::string& err);
NERO_NFC_NODISCARD bool ReadType5StorageNdef(
    PcscCard& card, const std::vector<std::uint8_t>& uid, PcscTagSnapshot& tag,
    std::vector<std::uint8_t>& type5_cc,
    std::vector<std::uint8_t>& type5_system_info, std::string& err);
NERO_NFC_NODISCARD bool WriteType2StorageNdef(
    PcscCard& card, const std::vector<std::uint8_t>& ndef, std::string& err);
NERO_NFC_NODISCARD bool WriteType5StorageNdef(
    PcscCard& card, const std::vector<std::uint8_t>& uid,
    const std::vector<std::uint8_t>& ndef, std::string& err);
NERO_NFC_NODISCARD bool Type5TransparentGetSystemInfo(
    PcscCard& card, const std::vector<std::uint8_t>& uid,
    std::vector<std::uint8_t>& system_info, std::string& err);

NERO_NFC_NODISCARD bool SelectNdefApp(PcscCard& card, std::string& err);
NERO_NFC_NODISCARD bool ReadNdefFile(PcscCard& card, PcscTagSnapshot& tag,
                                     std::vector<std::uint8_t>* cc_out,
                                     std::string& err);
NERO_NFC_NODISCARD bool ShouldAttemptType4NdefIo(
    const PcscTagSnapshot& tag, const std::vector<std::uint8_t>& type4_cc);
void NotePassiveType4Probe(PcscTagSnapshot& tag);
NERO_NFC_NODISCARD bool WriteNdefFile(PcscCard& card,
                                      const std::vector<std::uint8_t>& ndef,
                                      std::string& err);

NERO_NFC_NODISCARD bool PcscReadConnectedTag(PcscCard& card,
                                             const std::string& reader,
                                             PcscTagSnapshot& out,
                                             std::string& err);
NERO_NFC_NODISCARD bool PcscReadTagWithCard(PcscCard& card,
                                            const std::string& reader,
                                            const PcscReadOptions& options,
                                            PcscTagSnapshot& out,
                                            std::string& err);
NERO_NFC_NODISCARD bool PcscWriteTagWithCard(PcscCard& card,
                                             const std::string& reader,
                                             const PcscWriteRequest& request,
                                             std::string& err);
NERO_NFC_NODISCARD bool ResolvePcscReaderForOperation(
    const PcscCard& card, std::string_view requested, std::string& reader,
    std::string& err, bool announce_selection = true,
    std::size_t* present_count_out = NERO_NFC_NULL);

#endif  // NERO_USERSPACE_HAVE_PCSC

}  // namespace nero_nfc::pcsc_internal
