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
#include "nero_nfc_bounds.hpp"
#include <span>
#include "nero_nfc_hex.hpp"
#include "nero_nfc_io.hpp"
#include "nero_nfc_null.h"
#include "nero_nfc_pcsc_internal.hpp"
#include "nero_nfc_pcsc_tag_details.hpp"
#include "nfc_pcsc_contactless.h"
#include "nfc_tag_geometry_limits.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <optional>
#include <ranges>
#include <string_view>
#include <thread>
#include <utility>

#ifdef NERO_USERSPACE_HAVE_PCSC
#include <PCSC/winscard.h>
#endif

#ifdef NERO_USERSPACE_HAVE_PCSC
namespace nero_nfc::pcsc_internal {

namespace {

// Probe the contactless identity fields (UID/ATS/SAK/ATQA via GET DATA) and
// record their hex + the Type 4 contactless hint on the snapshot.
void ProbeAndApplyContactlessFields(PcscCard& card, PcscTagSnapshot& out,
                                    std::vector<std::uint8_t>& uid,
                                    bool storage_type5) {
  if (uid.empty()) {
    uid = TryGetDataBytes(card, NFC_PCSC_GET_DATA_UID,
                          NFC_ISO7816_GET_DATA_P2_DEFAULT);
  }
  if (storage_type5) {
    uid = NormalizeType5Uid(std::move(uid));
  }
  const std::vector<std::uint8_t> kAts = TryGetDataBytes(
      card, NFC_PCSC_GET_DATA_ATS, NFC_ISO7816_GET_DATA_P2_DEFAULT);
  const std::vector<std::uint8_t> kSak = TryGetDataBytes(
      card, NFC_PCSC_GET_DATA_SAK, NFC_ISO7816_GET_DATA_P2_DEFAULT);
  const std::vector<std::uint8_t> kAtqa = TryGetDataBytes(
      card, NFC_PCSC_GET_DATA_ATQA, NFC_ISO7816_GET_DATA_P2_DEFAULT);

  out.uid_hex_ = HexBytes(uid);
  out.ats_hex_ = HexBytes(kAts);
  out.sak_hex_ = HexBytes(kSak, '\0');
  out.atqa_hex_ = HexBytes(kAtqa);
  ApplyType4ContactlessHint(out);
}

// Read the Type 2 / Type 5 storage detail fields (version, CC, signature,
// AUTH0, system info) via GET DATA and apply them to the snapshot.
void ReadAndApplyStorageDetails(PcscCard& card, PcscTagSnapshot& out,
                                const std::vector<std::uint8_t>& uid,
                                std::vector<std::uint8_t>& type2_cc,
                                std::vector<std::uint8_t>& type4_cc,
                                std::vector<std::uint8_t>& type5_cc,
                                std::vector<std::uint8_t>& type5_system_info) {
  std::vector<std::uint8_t> type2_version;
  std::vector<std::uint8_t> type2_signature;
  std::optional<std::uint8_t> type2_auth0;

  if (IsPcscStorageType2(out)) {
    type2_version = TryGetDataBytes(card, NFC_PCSC_GET_DATA_TYPE2_VERSION,
                                    NFC_ISO7816_GET_DATA_P2_DEFAULT);
    if (type2_cc.empty()) {
      type2_cc = TryGetDataBytes(card, NFC_PCSC_GET_DATA_TYPE2_CC,
                                 NFC_ISO7816_GET_DATA_P2_DEFAULT);
    }
    /* NDEF reading only needs CC + READ pages. AUTH0/signature are optional
     * NXP commands, so keep them out of the automatic read path. */
  } else if (IsPcscStorageType5(out)) {
    if (type5_system_info.empty()) {
      type5_system_info =
          TryGetDataBytes(card, NFC_PCSC_GET_DATA_TYPE5_SYS_INFO,
                          NFC_ISO7816_GET_DATA_P2_DEFAULT);
    }
    if (type5_cc.empty()) {
      type5_cc = TryGetDataBytes(card, NFC_PCSC_GET_DATA_TYPE5_CC,
                                 NFC_ISO7816_GET_DATA_P2_DEFAULT);
    }
    if (type5_system_info.empty() && !out.ndef_message_.empty()) {
      std::string system_info_err;
      (void)Type5TransparentGetSystemInfo(card, uid, type5_system_info,
                                          system_info_err);
    }
  }
  out.type2_version_hex_ = HexBytes(type2_version);
  out.type2_signature_hex_ = HexBytes(type2_signature);
  out.type5_system_info_hex_ = HexBytes(type5_system_info);
  if (!type2_version.empty() || !type2_cc.empty() || type2_auth0.has_value()) {
    ApplyType2Details(out, uid, type2_version, type2_cc, type2_signature,
                      type2_auth0);
  }
  if (!type4_cc.empty() || out.tag_type_.find("Type 4") != std::string::npos ||
      out.tag_type_.find("FIDO") != std::string::npos) {
    ApplyType4Details(out, uid, type4_cc);
  }
  if (!type5_system_info.empty() || !type5_cc.empty()) {
    ApplyType5Details(out, uid, type5_system_info, type5_cc);
  }
}

}  // namespace

bool PcscReadConnectedTag(PcscCard& card, const std::string& reader,
                          PcscTagSnapshot& out, std::string& err) {
  std::vector<std::uint8_t> uid;
  std::vector<std::uint8_t> type2_cc;
  std::vector<std::uint8_t> type4_cc;
  std::vector<std::uint8_t> type5_cc;
  std::vector<std::uint8_t> type5_system_info;

  out = {};
  out.reader_name_ = reader;
  std::vector<std::uint8_t> atr;
  if (card.Status(atr, err)) {
    out.atr_hex_ = HexBytes(atr);
    ApplyStorageAtrHint(out);
  }
  const bool kStorageType2 = IsPcscStorageType2(out);
  const bool kStorageType5 = IsPcscStorageType5(out);

  if (kStorageType5) {
    uid = NormalizeType5Uid(TryGetDataBytes(card, NFC_PCSC_GET_DATA_UID,
                                            NFC_ISO7816_GET_DATA_P2_DEFAULT));
  }

  /* NDEF read before contactless enrichment GET DATA so storage tags avoid
   * extra RF traffic before the TLV read. */
  if (kStorageType2) {
    std::string storage_err;
    if (!ReadType2StorageNdef(card, out, type2_cc, storage_err) &&
        !storage_err.empty()) {
      AppendDetailLine(out, "PC/SC storage NDEF read failed: " + storage_err);
    }
  } else if (kStorageType5) {
    std::string storage_err;
    if (!ReadType5StorageNdef(card, uid, out, type5_cc, type5_system_info,
                              storage_err) &&
        !storage_err.empty()) {
      AppendDetailLine(out, "PC/SC storage NDEF read failed: " + storage_err);
    }
  }

  ProbeAndApplyContactlessFields(card, out, uid, kStorageType5);

  if (!kStorageType2 && !kStorageType5) {
    if (ShouldAttemptType4NdefIo(out, type4_cc)) {
      std::string type4_err;
      if (!ReadNdefFile(card, out, &type4_cc, type4_err) &&
          !type4_err.empty()) {
        AppendDetailLine(out, "PC/SC Type 4 NDEF read failed: " + type4_err);
      }
    } else {
      NotePassiveType4Probe(out);
    }
  }

  ReadAndApplyStorageDetails(card, out, uid, type2_cc, type4_cc, type5_cc,
                             type5_system_info);

  if (out.tag_type_.empty()) {
    out.tag_type_ = "PC/SC contactless tag";
  }
  if (uid.empty() && out.atr_hex_.empty()) {
    if (err.empty()) {
      err = "PC/SC tag read returned no identifying data";
    }
    return false;
  }
  err.clear();
  return true;
}

bool PcscReadTagWithCard(PcscCard& card, const std::string& reader,
                         const PcscReadOptions& options, PcscTagSnapshot& out,
                         std::string& err) {
  if (!card.Connect(reader, options.share_mode_, err)) {
    return false;
  }
  if (!card.BeginTransaction(err)) {
    card.Disconnect(SCARD_LEAVE_CARD);
    return false;
  }
  bool const kOk = PcscReadConnectedTag(card, reader, out, err);
  std::string end_err;
  if (!card.EndTransaction(end_err)) {
    err = end_err;
    return false;
  }
  return kOk;
}

bool PcscWriteTagWithCard(PcscCard& card, const std::string& reader,
                          const PcscWriteRequest& request, std::string& err) {
  if (!card.Connect(reader, request.share_mode_, err)) {
    return false;
  }
  if (!card.BeginTransaction(err)) {
    card.Disconnect(SCARD_LEAVE_CARD);
    return false;
  }
  if (WriteNdefFile(card, request.ndef_message_, err)) {
    if (!card.EndTransaction(err)) {
      card.Disconnect(SCARD_LEAVE_CARD);
      return false;
    }
    card.Disconnect();
    err.clear();
    return true;
  }
  std::string end_err;
  (void)card.EndTransaction(end_err);
  card.Disconnect();
  return false;
}

}  // namespace nero_nfc::pcsc_internal
#endif  // NERO_USERSPACE_HAVE_PCSC

namespace nero_nfc {

class WriterProgressSpinner {
 public:
  explicit WriterProgressSpinner(std::string_view message)
      : message_(message), worker_([this] { Run(); }) {}

  WriterProgressSpinner(const WriterProgressSpinner&) = delete;
  WriterProgressSpinner& operator=(const WriterProgressSpinner&) = delete;
  WriterProgressSpinner(WriterProgressSpinner&&) = delete;
  WriterProgressSpinner& operator=(WriterProgressSpinner&&) = delete;

  ~WriterProgressSpinner() { Stop(); }

  void Stop() {
    bool expected = false;
    if (!done_.compare_exchange_strong(expected, true)) {
      return;
    }
    if (worker_.joinable()) {
      worker_.join();
    }
    NeroNfcStderrLine(
        "\r                                                   "
        "                             \r");
  }

  void Finish() {
    bool expected = false;
    if (!done_.compare_exchange_strong(expected, true)) {
      return;
    }
    if (worker_.joinable()) {
      worker_.join();
    }
    NeroNfcStderrLine(message_.c_str());
  }

 private:
  static constexpr int kSpinnerFrameIntervalMs = 120;

  void Run() {
    static constexpr char kFrames[] = {'|', '/', '-', '\\'};
    std::size_t frame = 0u;
    while (!done_.load()) {
      NeroNfcStderrLine("{} {}\r", message_,
                        At(kFrames, frame % std::size(kFrames)));
      frame++;
      std::this_thread::sleep_for(
          std::chrono::milliseconds(kSpinnerFrameIntervalMs));
    }
  }

  std::string message_;
  std::atomic_bool done_{false};
  std::thread worker_;
};

std::optional<PcscShareMode> ParsePcscShareMode(std::string_view text) {
  std::string mode = pcsc_internal::LowerCopy(text);
  if (mode == "shared" || mode == "share" || mode == "scard_share_shared") {
    return PcscShareMode::kShared;
  }
  if (mode == "exclusive" || mode == "scard_share_exclusive") {
    return PcscShareMode::kExclusive;
  }
  return std::nullopt;
}

std::string_view PcscShareModeName(PcscShareMode mode) {
  return mode == PcscShareMode::kExclusive ? "exclusive" : "shared";
}

std::string PcscReaderSubstringFromEnv() {
  const char* env = std::getenv("NFC_PCSC_READER");
  if (env == NERO_NFC_NULL) {
    return {};
  }
  std::string_view sv{env};
  while (!sv.empty() &&
         (std::isspace(static_cast<unsigned char>(sv.front())) != 0)) {
    sv.remove_prefix(1u);
  }
  std::string value{sv};
  while (!value.empty() &&
         std::isspace(static_cast<unsigned char>(value.back())) != 0) {
    value.pop_back();
  }
  return value;
}

#ifdef NERO_HOST_UNIT_TEST_HOOKS
void NeroNfcUtestSetListPcscReadersOverride(
    const std::vector<std::string>* readers) {
  pcsc_internal::g_list_pcsc_readers_override = readers;
}

void NeroNfcUtestClearListPcscReadersOverride() {
  pcsc_internal::g_list_pcsc_readers_override = NERO_NFC_NULL;
}

bool NeroNfcUtestExtractStorageNdef(const std::vector<std::uint8_t>& tlv_area,
                                    std::uint16_t start_offset,
                                    PcscTagSnapshot& tag, std::string& err) {
  return pcsc_internal::ExtractNdefFromTlvArea(tlv_area, start_offset, tag,
                                               err);
}

bool NeroNfcUtestBuildStorageNdefTlv(const std::vector<std::uint8_t>& ndef,
                                     std::uint16_t data_area_size,
                                     std::vector<std::uint8_t>& tlv_area,
                                     std::string& err) {
  return pcsc_internal::BuildStorageNdefTlv(ndef, data_area_size, tlv_area,
                                            err);
}

std::uint16_t NeroNfcUtestStorageTlvPayloadCap(std::uint16_t data_area_size) {
  return pcsc_internal::StorageTlvPayloadCap(data_area_size);
}

bool NeroNfcUtestBuildSelectApdu(std::uint8_t p1, std::uint8_t p2,
                                 const std::vector<std::uint8_t>& data,
                                 std::vector<std::uint8_t>& capdu,
                                 std::string& err) {
  return pcsc_internal::BuildSelectApdu(p1, p2, data, capdu, err);
}

bool NeroNfcUtestType4NdefLenFitsShortBinary(std::size_t ndef_len) {
  return pcsc_internal::Type4NdefLenFitsShortBinary(ndef_len);
}

std::uint16_t NeroNfcUtestStorageType2ReadUnitLimit(
    std::uint16_t first_unit, std::uint8_t unit_size,
    std::uint16_t tlv_start_offset, std::uint16_t data_area_size) {
  return pcsc_internal::StorageType2ReadUnitLimit(
      first_unit, unit_size, tlv_start_offset, data_area_size);
}

std::uint8_t NeroNfcUtestType2StorageBulkReadLen(std::uint16_t data_area_size) {
  return pcsc_internal::Type2StorageBulkReadLen(data_area_size);
}

std::uint16_t NeroNfcUtestStorageType5ReadBlockLimit(
    std::uint16_t tlv_start_offset, std::uint16_t data_area_size) {
  return pcsc_internal::StorageType5ReadBlockLimit(tlv_start_offset,
                                                   data_area_size);
}

std::vector<std::uint8_t> NeroNfcUtestType5TransparentBlockCommand(
    bool write, const std::vector<std::uint8_t>& uid_lsb, std::uint16_t block) {
  return pcsc_internal::Type5AddressedBlockCommand(
      write ? NFC_TAG_T5T_ISO15693_CMD_WRITE_SINGLE
            : NFC_TAG_T5T_ISO15693_CMD_READ_SINGLE,
      write ? NFC_TAG_T5T_ISO15693_CMD_EXT_WRITE_SINGLE
            : NFC_TAG_T5T_ISO15693_CMD_EXT_READ_SINGLE,
      uid_lsb, block);
}

std::vector<std::uint8_t> NeroNfcUtestType5TransparentReadMultipleCommand(
    const std::vector<std::uint8_t>& uid_lsb, std::uint16_t first_block,
    std::uint16_t block_count) {
  return pcsc_internal::Type5AddressedReadMultipleCommand(uid_lsb, first_block,
                                                          block_count);
}

std::vector<std::uint8_t> NeroNfcUtestType5TransparentSystemInfoExtCommand(
    const std::vector<std::uint8_t>& uid_lsb) {
  return pcsc_internal::Type5AddressedSystemInfoExtCommand(uid_lsb);
}
#endif

bool ListPcscReaders(std::vector<std::string>& readers, std::string& err) {
#ifdef NERO_HOST_UNIT_TEST_HOOKS
  if (pcsc_internal::g_list_pcsc_readers_override != NERO_NFC_NULL) {
    readers = *pcsc_internal::g_list_pcsc_readers_override;
    std::ranges::sort(readers);
    if (readers.empty()) {
      err = "no PC/SC readers detected";
      return false;
    }
    err.clear();
    return true;
  }
#endif
#ifndef NERO_USERSPACE_HAVE_PCSC
  err =
      "PC/SC support was not compiled in (install "
      "libpcsclite-dev/pcsc-lite-devel and rebuild)";
  return false;
#else
  return pcsc_internal::ListReadersImpl(readers, err);
#endif
}

bool ChoosePcscReaderFromList(const std::vector<std::string>& readers,
                              std::string_view reader_substring,
                              std::string& reader, std::string& err) {
  reader.clear();
  if (readers.empty()) {
    err = "no PC/SC readers detected";
    return false;
  }
  std::vector<std::string> selectable =
      pcsc_internal::SelectablePcscReaders(readers);
  if (reader_substring.empty() && selectable.empty()) {
    err = "no selectable PC/SC readers detected; readers: " +
          pcsc_internal::JoinReaderNames(readers);
    return false;
  }
  if (reader_substring.empty() && selectable.size() == 1u) {
    reader = selectable.front();
    err.clear();
    return true;
  }

  std::vector<std::string> matches;
  const std::string kWant = pcsc_internal::LowerCopy(reader_substring);
  if (!kWant.empty()) {
    auto exact =
        std::ranges::find_if(readers, [&](const std::string& candidate) {
          return pcsc_internal::LowerCopy(candidate) == kWant;
        });
    if (exact != readers.end()) {
      reader = *exact;
      err.clear();
      return true;
    }
    std::ranges::copy_if(readers, std::back_inserter(matches),
                         [&](const std::string& candidate) {
                           return pcsc_internal::LowerCopy(candidate).find(
                                      kWant) != std::string::npos;
                         });
    if (matches.size() == 1u) {
      reader = matches.front();
      err.clear();
      return true;
    }
    if (matches.empty()) {
      err = "no PC/SC reader matched substring \"" +
            std::string(reader_substring) +
            "\"; readers: " + pcsc_internal::JoinReaderNames(readers);
      return false;
    }
    err = "ambiguous PC/SC reader substring \"" +
          std::string(reader_substring) + "\" matched multiple readers: " +
          pcsc_internal::JoinReaderNames(matches);
    return false;
  }

  std::ranges::copy_if(readers, std::back_inserter(matches),
                       pcsc_internal::IsPreferredNeroReader);
  if (matches.size() == 1u && selectable.size() == 1u) {
    reader = matches.front();
    err.clear();
    return true;
  }
  if (matches.empty()) {
    err =
        "multiple PC/SC readers detected; set NFC_PCSC_READER to a unique "
        "substring. Readers: " +
        pcsc_internal::JoinReaderNames(readers);
  } else {
    err =
        "multiple Nero-compatible PC/SC readers detected; set "
        "NFC_PCSC_READER to a unique substring. "
        "Readers: " +
        pcsc_internal::JoinReaderNames(readers);
  }
  return false;
}

bool ResolvePcscReader(std::string_view reader_substring, std::string& reader,
                       std::string& err) {
  std::vector<std::string> readers;
  if (!ListPcscReaders(readers, err)) {
    return false;
  }
  const std::string kEnvReader =
      reader_substring.empty() ? PcscReaderSubstringFromEnv() : std::string{};
  const std::string_view kRequested = reader_substring.empty()
                                          ? std::string_view(kEnvReader)
                                          : reader_substring;
  return ChoosePcscReaderFromList(readers, kRequested, reader, err);
}

bool PcscReadTag(std::string_view reader_substring,
                 const PcscReadOptions& options, PcscTagSnapshot& out,
                 std::string& err) {
#ifndef NERO_USERSPACE_HAVE_PCSC
  (void)reader_substring;
  (void)options;
  (void)out;
  err =
      "PC/SC support was not compiled in (install "
      "libpcsclite-dev/pcsc-lite-devel and rebuild)";
  return false;
#else
  std::string reader;
  pcsc_internal::PcscCard card;
  if (!card.EnsureContext(err)) {
    return false;
  }
  if (!pcsc_internal::ResolvePcscReaderForOperation(card, reader_substring,
                                                    reader, err)) {
    return false;
  }
  return pcsc_internal::PcscReadTagWithCard(card, reader, options, out, err);
#endif
}

bool PcscReadTag(std::string_view reader_substring, PcscTagSnapshot& out,
                 std::string& err) {
  return PcscReadTag(reader_substring, PcscReadOptions{}, out, err);
}

bool PcscWriteTag(std::string_view reader_substring,
                  const PcscWriteRequest& request, PcscTagSnapshot* after_write,
                  std::string& err) {
#ifndef NERO_USERSPACE_HAVE_PCSC
  (void)reader_substring;
  (void)request;
  (void)after_write;
  err =
      "PC/SC support was not compiled in (install "
      "libpcsclite-dev/pcsc-lite-devel and rebuild)";
  return false;
#else
  if (request.ndef_message_.empty()) {
    err = "refusing to write empty NDEF message";
    return false;
  }
  if (after_write != NERO_NFC_NULL) {
    *after_write = {};
  }
  std::string reader;
  pcsc_internal::PcscCard card;
  if (!card.EnsureContext(err)) {
    return false;
  }
  if (!pcsc_internal::ResolvePcscReaderForOperation(card, reader_substring,
                                                    reader, err)) {
    return false;
  }
  return pcsc_internal::PcscWriteTagWithCard(card, reader, request, err);
#endif
}

int RunPcscReader(std::string_view reader_substring,
                  const PcscReadOptions& options) {
#ifndef NERO_USERSPACE_HAVE_PCSC
  (void)reader_substring;
  (void)options;
  NeroNfcStderrLine(
      "error: PC/SC support was not compiled in (install "
      "libpcsclite-dev/pcsc-lite-devel and rebuild)");
  return 1;
#else
  std::string reader;
  std::string err;
  bool const kAutoReader = reader_substring.empty();
  pcsc_internal::PcscCard card;
  if (!card.EnsureContext(err)) {
    NeroNfcStderrLine("error: {}", err);
    return 1;
  }
  if (!kAutoReader) {
    if (!ResolvePcscReader(reader_substring, reader, err)) {
      NeroNfcStderrLine("error: {}", err);
      return 1;
    }
    pcsc_internal::PrimeReaderState(card.Context(), reader);
    NeroNfcStderrLine(
        "reader: PC/SC bridge on \"{}\"; ready to tap NFC "
        "tags (Ctrl+C to stop)",
        reader);
  } else {
    NeroNfcStderrLine(
        "reader: PC/SC bridge ready; tap NFC tags on any "
        "selectable reader (Ctrl+C to stop)");
  }
  bool first = true;
  bool saw_confirmed_absence = true;
  std::string last_fingerprint;
  bool first_cycle = true;
  for (;;) {
    if (!first_cycle) {
      NeroNfcStdoutLine("");
    }
    WriterProgressSpinner wait_spinner("reader: ready for next NFC tag");
    bool wait_ok = false;
    std::size_t present_count = 0u;
    if (kAutoReader) {
      wait_ok = pcsc_internal::ResolvePcscReaderForOperation(
          card, reader_substring, reader, err, false, &present_count);
    } else {
      wait_ok = pcsc_internal::WaitForCardPresent(card.Context(), reader,
                                                  std::nullopt, err);
    }
    wait_spinner.Finish();
    if (!wait_ok) {
      NeroNfcStderrLine("error: {}", err);
      return 1;
    }
    if (kAutoReader) {
      pcsc_internal::AnnouncePcscReaderSelection(present_count, reader);
    }
    PcscTagSnapshot tag;
    if (!first) {
      NeroNfcStdoutLine("");
    }
    if (!pcsc_internal::PcscReadTagWithCard(card, reader, options, tag, err)) {
      NeroNfcStderrLine("error: {}", err);
      card.Disconnect();
      if (!pcsc_internal::WaitForCardAbsentStable(card.Context(), reader,
                                                  err)) {
        NeroNfcStderrLine("error: {}", err);
        return 1;
      }
      saw_confirmed_absence = true;
      first_cycle = false;
      continue;
    }
    const std::string kFingerprint = pcsc_internal::TagFingerprint(tag);
    if (saw_confirmed_absence || kFingerprint != last_fingerprint) {
      NeroNfcStdoutLine(FormatPcscTagSnapshotHeader(tag).c_str());
      const std::string kBody = FormatPcscTagSnapshotBody(tag);
      if (!kBody.empty()) {
        NeroNfcStdoutLine(kBody.c_str());
      }
      first = false;
      last_fingerprint = kFingerprint;
    }
    card.Disconnect();
    if (!pcsc_internal::WaitForCardAbsentStable(card.Context(), reader, err)) {
      NeroNfcStderrLine("error: {}", err);
      return 1;
    }
    saw_confirmed_absence = true;
    first_cycle = false;
  }
#endif
}

int RunPcscReader(std::string_view reader_substring) {
  return RunPcscReader(reader_substring, PcscReadOptions{});
}

int RunPcscWriter(std::string_view reader_substring,
                  const PcscWriteRequest& request) {
#ifndef NERO_USERSPACE_HAVE_PCSC
  (void)reader_substring;
  (void)request;
  NeroNfcStderrLine(
      "error: PC/SC support was not compiled in (install "
      "libpcsclite-dev/pcsc-lite-devel and rebuild)");
  return 1;
#else
  if (request.ndef_message_.empty()) {
    NeroNfcStderrLine("error: refusing to write empty NDEF message");
    return 1;
  }
  std::string err;
  std::string reader;
  bool const kAutoReader = reader_substring.empty();
  pcsc_internal::PcscCard card;
  if (!card.EnsureContext(err)) {
    NeroNfcStderrLine("error: {}", err);
    return 1;
  }
  if (!kAutoReader) {
    if (!ResolvePcscReader(reader_substring, reader, err)) {
      NeroNfcStderrLine("error: {}", err);
      return 1;
    }
    pcsc_internal::PrimeReaderState(card.Context(), reader);
    NeroNfcStderrLine(
        "writer: PC/SC bridge on \"{}\"; ready to tap a writable NFC tag",
        reader);
  } else {
    NeroNfcStderrLine(
        "writer: PC/SC bridge ready; tap a writable NFC tag "
        "on any selectable reader");
  }
  bool first_cycle = true;
  for (;;) {
    if (!first_cycle) {
      NeroNfcStdoutLine("");
    }
    WriterProgressSpinner wait_spinner(
        "writer: ready for next writable NFC tag");
    bool wait_ok = false;
    std::size_t present_count = 0u;
    if (kAutoReader) {
      wait_ok = pcsc_internal::ResolvePcscReaderForOperation(
          card, reader_substring, reader, err, false, &present_count);
    } else {
      wait_ok = pcsc_internal::WaitForCardPresent(card.Context(), reader,
                                                  std::nullopt, err);
    }
    wait_spinner.Finish();
    if (!wait_ok) {
      NeroNfcStderrLine("error: {}", err);
      return 1;
    }
    if (kAutoReader) {
      pcsc_internal::AnnouncePcscReaderSelection(present_count, reader);
    }
    NeroNfcStderrLine("writer: writing NDEF to tag...");
    WriterProgressSpinner write_spinner("writer: writing NDEF");
    const bool kWriteOk =
        pcsc_internal::PcscWriteTagWithCard(card, reader, request, err);
    write_spinner.Stop();
    if (!kWriteOk) {
      NeroNfcStderrLine("error: {}", err);
      card.Disconnect();
      if (!pcsc_internal::WaitForCardAbsentStable(card.Context(), reader,
                                                  err)) {
        NeroNfcStderrLine("error: {}", err);
        return 1;
      }
      first_cycle = false;
      continue;
    }
    NeroNfcStdoutLine("*** SUCCESS - Wrote NDEF message ***");
    if (!pcsc_internal::WaitForCardAbsentStable(card.Context(), reader, err)) {
      NeroNfcStderrLine("error: {}", err);
      return 1;
    }
    first_cycle = false;
  }
#endif
}

}  // namespace nero_nfc
