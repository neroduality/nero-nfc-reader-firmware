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
#include "nero_nfc_hex.h"
#include "nero_nfc_io.h"
#include "nero_nfc_null.h"
#include "nero_nfc_pcsc_internal.h"
#include "nero_nfc_pcsc_tag_details.h"
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
void probe_and_apply_contactless_fields(PcscCard &card, PcscTagSnapshot &out,
                                        std::vector<std::uint8_t> &uid, bool storage_type5) {
  if (uid.empty()) {
    uid = try_get_data_bytes(card, NFC_PCSC_GET_DATA_UID, NFC_ISO7816_GET_DATA_P2_DEFAULT);
  }
  if (storage_type5) {
    uid = normalize_type5_uid(std::move(uid));
  }
  const std::vector<std::uint8_t> ats =
    try_get_data_bytes(card, NFC_PCSC_GET_DATA_ATS, NFC_ISO7816_GET_DATA_P2_DEFAULT);
  const std::vector<std::uint8_t> sak =
    try_get_data_bytes(card, NFC_PCSC_GET_DATA_SAK, NFC_ISO7816_GET_DATA_P2_DEFAULT);
  const std::vector<std::uint8_t> atqa =
    try_get_data_bytes(card, NFC_PCSC_GET_DATA_ATQA, NFC_ISO7816_GET_DATA_P2_DEFAULT);

  out.uid_hex = hex_bytes(uid);
  out.ats_hex = hex_bytes(ats);
  out.sak_hex = hex_bytes(sak, '\0');
  out.atqa_hex = hex_bytes(atqa);
  apply_type4_contactless_hint(out);
}

// Read the Type 2 / Type 5 storage detail fields (version, CC, signature,
// AUTH0, system info) via GET DATA and apply them to the snapshot.
void read_and_apply_storage_details(PcscCard &card, PcscTagSnapshot &out,
                                    const std::vector<std::uint8_t> &uid,
                                    std::vector<std::uint8_t> &type2_cc,
                                    std::vector<std::uint8_t> &type4_cc,
                                    std::vector<std::uint8_t> &type5_cc,
                                    std::vector<std::uint8_t> &type5_system_info) {
  std::vector<std::uint8_t> type2_version;
  std::vector<std::uint8_t> type2_signature;
  std::optional<std::uint8_t> type2_auth0;

  if (is_pcsc_storage_type2(out)) {
    type2_version =
      try_get_data_bytes(card, NFC_PCSC_GET_DATA_TYPE2_VERSION, NFC_ISO7816_GET_DATA_P2_DEFAULT);
    if (type2_cc.empty()) {
      type2_cc =
        try_get_data_bytes(card, NFC_PCSC_GET_DATA_TYPE2_CC, NFC_ISO7816_GET_DATA_P2_DEFAULT);
    }
    /* NDEF reading only needs CC + READ pages. AUTH0/signature are optional
     * NXP commands, so keep them out of the automatic read path. */
  } else if (is_pcsc_storage_type5(out)) {
    if (type5_system_info.empty()) {
      type5_system_info =
        try_get_data_bytes(card, NFC_PCSC_GET_DATA_TYPE5_SYS_INFO, NFC_ISO7816_GET_DATA_P2_DEFAULT);
    }
    if (type5_cc.empty()) {
      type5_cc =
        try_get_data_bytes(card, NFC_PCSC_GET_DATA_TYPE5_CC, NFC_ISO7816_GET_DATA_P2_DEFAULT);
    }
    if (type5_system_info.empty() && !out.ndef_message.empty()) {
      std::string system_info_err;
      (void)type5_transparent_get_system_info(card, uid, type5_system_info, system_info_err);
    }
  }
  out.type2_version_hex = hex_bytes(type2_version);
  out.type2_signature_hex = hex_bytes(type2_signature);
  out.type5_system_info_hex = hex_bytes(type5_system_info);
  if (!type2_version.empty() || !type2_cc.empty() || type2_auth0.has_value()) {
    apply_type2_details(out, uid, type2_version, type2_cc, type2_signature, type2_auth0);
  }
  if (!type4_cc.empty() || out.tag_type.find("Type 4") != std::string::npos ||
      out.tag_type.find("FIDO") != std::string::npos) {
    apply_type4_details(out, uid, type4_cc);
  }
  if (!type5_system_info.empty() || !type5_cc.empty()) {
    apply_type5_details(out, uid, type5_system_info, type5_cc);
  }
}

} // namespace

bool pcsc_read_connected_tag(PcscCard &card, const std::string &reader, PcscTagSnapshot &out,
                             std::string &err) {
  std::vector<std::uint8_t> uid;
  std::vector<std::uint8_t> type2_cc;
  std::vector<std::uint8_t> type4_cc;
  std::vector<std::uint8_t> type5_cc;
  std::vector<std::uint8_t> type5_system_info;

  out = {};
  out.reader_name = reader;
  std::vector<std::uint8_t> atr;
  if (card.status(atr, err)) {
    out.atr_hex = hex_bytes(atr);
    apply_storage_atr_hint(out);
  }
  const bool storage_type2 = is_pcsc_storage_type2(out);
  const bool storage_type5 = is_pcsc_storage_type5(out);

  if (storage_type5) {
    uid = normalize_type5_uid(
      try_get_data_bytes(card, NFC_PCSC_GET_DATA_UID, NFC_ISO7816_GET_DATA_P2_DEFAULT));
  }

  /* NDEF read before contactless enrichment GET DATA so storage tags avoid
   * extra RF traffic before the TLV read. */
  if (storage_type2) {
    std::string storage_err;
    if (!read_type2_storage_ndef(card, out, type2_cc, storage_err) && !storage_err.empty()) {
      append_detail_line(out, "PC/SC storage NDEF read failed: " + storage_err);
    }
  } else if (storage_type5) {
    std::string storage_err;
    if (!read_type5_storage_ndef(card, uid, out, type5_cc, type5_system_info, storage_err) &&
        !storage_err.empty()) {
      append_detail_line(out, "PC/SC storage NDEF read failed: " + storage_err);
    }
  }

  probe_and_apply_contactless_fields(card, out, uid, storage_type5);

  if (!storage_type2 && !storage_type5) {
    if (should_attempt_type4_ndef_io(out, type4_cc)) {
      std::string type4_err;
      if (!read_ndef_file(card, out, &type4_cc, type4_err) && !type4_err.empty()) {
        append_detail_line(out, "PC/SC Type 4 NDEF read failed: " + type4_err);
      }
    } else {
      note_passive_type4_probe(out);
    }
  }

  read_and_apply_storage_details(card, out, uid, type2_cc, type4_cc, type5_cc, type5_system_info);

  if (out.tag_type.empty()) {
    out.tag_type = "PC/SC contactless tag";
  }
  if (uid.empty() && out.atr_hex.empty()) {
    if (err.empty()) {
      err = "PC/SC tag read returned no identifying data";
    }
    return false;
  }
  err.clear();
  return true;
}

bool pcsc_read_tag_with_card(PcscCard &card, const std::string &reader,
                             const PcscReadOptions &options, PcscTagSnapshot &out,
                             std::string &err) {
  if (!card.connect(reader, options.share_mode, err)) {
    return false;
  }
  if (!card.beginTransaction(err)) {
    card.disconnect(SCARD_LEAVE_CARD);
    return false;
  }
  bool const ok = pcsc_read_connected_tag(card, reader, out, err);
  std::string end_err;
  if (!card.endTransaction(end_err)) {
    err = end_err;
    return false;
  }
  return ok;
}

bool pcsc_write_tag_with_card(PcscCard &card, const std::string &reader,
                              const PcscWriteRequest &request, std::string &err) {
  if (!card.connect(reader, request.share_mode, err)) {
    return false;
  }
  if (!card.beginTransaction(err)) {
    card.disconnect(SCARD_LEAVE_CARD);
    return false;
  }
  if (write_ndef_file(card, request.ndef_message, err)) {
    if (!card.endTransaction(err)) {
      card.disconnect(SCARD_LEAVE_CARD);
      return false;
    }
    card.disconnect();
    err.clear();
    return true;
  }
  std::string end_err;
  (void)card.endTransaction(end_err);
  card.disconnect();
  return false;
}

} // namespace nero_nfc::pcsc_internal
#endif // NERO_USERSPACE_HAVE_PCSC

namespace nero_nfc {

class WriterProgressSpinner {
public:
  explicit WriterProgressSpinner(std::string_view message)
      : message_(message), worker_([this] { run(); }) {}

  WriterProgressSpinner(const WriterProgressSpinner &) = delete;
  WriterProgressSpinner &operator=(const WriterProgressSpinner &) = delete;

  ~WriterProgressSpinner() { stop(); }

  void stop() {
    bool expected = false;
    if (!done_.compare_exchange_strong(expected, true)) {
      return;
    }
    if (worker_.joinable()) {
      worker_.join();
    }
    nero_nfc_stderr_line("\r                                                   "
                         "                             \r");
  }

  void finish() {
    bool expected = false;
    if (!done_.compare_exchange_strong(expected, true)) {
      return;
    }
    if (worker_.joinable()) {
      worker_.join();
    }
    nero_nfc_stderr_line(message_.c_str());
  }

private:
  static constexpr int kSpinnerFrameIntervalMs = 120;

  void run() {
    static constexpr char kFrames[] = {'|', '/', '-', '\\'};
    std::size_t frame = 0u;
    while (!done_.load()) {
      nero_nfc_stderr_line("{} {}\r", message_, kFrames[frame % std::size(kFrames)]);
      frame++;
      std::this_thread::sleep_for(std::chrono::milliseconds(kSpinnerFrameIntervalMs));
    }
  }

  std::string message_;
  std::atomic_bool done_{false};
  std::thread worker_;
};

std::optional<PcscShareMode> parse_pcsc_share_mode(std::string_view text) {
  std::string mode = pcsc_internal::lower_copy(text);
  if (mode == "shared" || mode == "share" || mode == "scard_share_shared") {
    return PcscShareMode::Shared;
  }
  if (mode == "exclusive" || mode == "scard_share_exclusive") {
    return PcscShareMode::Exclusive;
  }
  return std::nullopt;
}

std::string_view pcsc_share_mode_name(PcscShareMode mode) {
  return mode == PcscShareMode::Exclusive ? "exclusive" : "shared";
}

std::string pcsc_reader_substring_from_env() {
  const char *env = std::getenv("NFC_PCSC_READER");
  if (env == NERO_NFC_NULL) {
    return {};
  }
  while (std::isspace(static_cast<unsigned char>(*env)) != 0) {
    ++env;
  }
  std::string value(env);
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) {
    value.pop_back();
  }
  return value;
}

#ifdef NERO_HOST_UNIT_TEST_HOOKS
void nero_nfc_utest_set_list_pcsc_readers_override(const std::vector<std::string> *readers) {
  pcsc_internal::g_list_pcsc_readers_override = readers;
}

void nero_nfc_utest_clear_list_pcsc_readers_override() {
  pcsc_internal::g_list_pcsc_readers_override = NERO_NFC_NULL;
}

bool nero_nfc_utest_extract_storage_ndef(const std::vector<std::uint8_t> &tlv_area,
                                         std::uint16_t start_offset, PcscTagSnapshot &tag,
                                         std::string &err) {
  return pcsc_internal::extract_ndef_from_tlv_area(tlv_area, start_offset, tag, err);
}

bool nero_nfc_utest_build_storage_ndef_tlv(const std::vector<std::uint8_t> &ndef,
                                           std::uint16_t data_area_size,
                                           std::vector<std::uint8_t> &tlv_area, std::string &err) {
  return pcsc_internal::build_storage_ndef_tlv(ndef, data_area_size, tlv_area, err);
}

std::uint16_t nero_nfc_utest_storage_tlv_payload_cap(std::uint16_t data_area_size) {
  return pcsc_internal::storage_tlv_payload_cap(data_area_size);
}

bool nero_nfc_utest_build_select_apdu(std::uint8_t p1, std::uint8_t p2,
                                      const std::vector<std::uint8_t> &data,
                                      std::vector<std::uint8_t> &capdu, std::string &err) {
  return pcsc_internal::build_select_apdu(p1, p2, data, capdu, err);
}

bool nero_nfc_utest_type4_ndef_len_fits_short_binary(std::size_t ndef_len) {
  return pcsc_internal::type4_ndef_len_fits_short_binary(ndef_len);
}

std::uint16_t nero_nfc_utest_storage_type2_read_unit_limit(std::uint16_t first_unit,
                                                           std::uint8_t unit_size,
                                                           std::uint16_t tlv_start_offset,
                                                           std::uint16_t data_area_size) {
  return pcsc_internal::storage_type2_read_unit_limit(first_unit, unit_size, tlv_start_offset,
                                                      data_area_size);
}

std::uint8_t nero_nfc_utest_type2_storage_bulk_read_len(std::uint16_t data_area_size) {
  return pcsc_internal::type2_storage_bulk_read_len(data_area_size);
}

std::uint16_t nero_nfc_utest_storage_type5_read_block_limit(std::uint16_t tlv_start_offset,
                                                            std::uint16_t data_area_size) {
  return pcsc_internal::storage_type5_read_block_limit(tlv_start_offset, data_area_size);
}

std::vector<std::uint8_t>
nero_nfc_utest_type5_transparent_block_command(bool write, const std::vector<std::uint8_t> &uid_lsb,
                                               std::uint16_t block) {
  return pcsc_internal::type5_addressed_block_command(
    write ? NFC_TAG_T5T_ISO15693_CMD_WRITE_SINGLE : NFC_TAG_T5T_ISO15693_CMD_READ_SINGLE,
    write ? NFC_TAG_T5T_ISO15693_CMD_EXT_WRITE_SINGLE : NFC_TAG_T5T_ISO15693_CMD_EXT_READ_SINGLE,
    uid_lsb, block);
}

std::vector<std::uint8_t> nero_nfc_utest_type5_transparent_read_multiple_command(
  const std::vector<std::uint8_t> &uid_lsb, std::uint16_t first_block, std::uint16_t block_count) {
  return pcsc_internal::type5_addressed_read_multiple_command(uid_lsb, first_block, block_count);
}

std::vector<std::uint8_t>
nero_nfc_utest_type5_transparent_system_info_ext_command(const std::vector<std::uint8_t> &uid_lsb) {
  return pcsc_internal::type5_addressed_system_info_ext_command(uid_lsb);
}
#endif

bool list_pcsc_readers(std::vector<std::string> &readers, std::string &err) {
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
  err = "PC/SC support was not compiled in (install "
        "libpcsclite-dev/pcsc-lite-devel and rebuild)";
  return false;
#else
  return pcsc_internal::list_readers_impl(readers, err);
#endif
}

bool choose_pcsc_reader_from_list(const std::vector<std::string> &readers,
                                  std::string_view reader_substring, std::string &reader,
                                  std::string &err) {
  reader.clear();
  if (readers.empty()) {
    err = "no PC/SC readers detected";
    return false;
  }
  std::vector<std::string> selectable = pcsc_internal::selectable_pcsc_readers(readers);
  if (reader_substring.empty() && selectable.empty()) {
    err =
      "no selectable PC/SC readers detected; readers: " + pcsc_internal::join_reader_names(readers);
    return false;
  }
  if (reader_substring.empty() && selectable.size() == 1u) {
    reader = selectable.front();
    err.clear();
    return true;
  }

  std::vector<std::string> matches;
  const std::string want = pcsc_internal::lower_copy(reader_substring);
  if (!want.empty()) {
    auto exact = std::ranges::find_if(readers, [&](const std::string &candidate) {
      return pcsc_internal::lower_copy(candidate) == want;
    });
    if (exact != readers.end()) {
      reader = *exact;
      err.clear();
      return true;
    }
    std::ranges::copy_if(readers, std::back_inserter(matches), [&](const std::string &candidate) {
      return pcsc_internal::lower_copy(candidate).find(want) != std::string::npos;
    });
    if (matches.size() == 1u) {
      reader = matches.front();
      err.clear();
      return true;
    }
    if (matches.empty()) {
      err = "no PC/SC reader matched substring \"" + std::string(reader_substring) +
            "\"; readers: " + pcsc_internal::join_reader_names(readers);
      return false;
    }
    err = "ambiguous PC/SC reader substring \"" + std::string(reader_substring) +
          "\" matched multiple readers: " + pcsc_internal::join_reader_names(matches);
    return false;
  }

  std::ranges::copy_if(readers, std::back_inserter(matches),
                       pcsc_internal::is_preferred_nero_reader);
  if (matches.size() == 1u && selectable.size() == 1u) {
    reader = matches.front();
    err.clear();
    return true;
  }
  if (matches.empty()) {
    err = "multiple PC/SC readers detected; set NFC_PCSC_READER to a unique "
          "substring. Readers: " +
          pcsc_internal::join_reader_names(readers);
  } else {
    err = "multiple Nero-compatible PC/SC readers detected; set "
          "NFC_PCSC_READER to a unique substring. "
          "Readers: " +
          pcsc_internal::join_reader_names(readers);
  }
  return false;
}

bool resolve_pcsc_reader(std::string_view reader_substring, std::string &reader, std::string &err) {
  std::vector<std::string> readers;
  if (!list_pcsc_readers(readers, err)) {
    return false;
  }
  const std::string env_reader =
    reader_substring.empty() ? pcsc_reader_substring_from_env() : std::string{};
  const std::string_view requested =
    reader_substring.empty() ? std::string_view(env_reader) : reader_substring;
  return choose_pcsc_reader_from_list(readers, requested, reader, err);
}

bool pcsc_read_tag(std::string_view reader_substring, const PcscReadOptions &options,
                   PcscTagSnapshot &out, std::string &err) {
#ifndef NERO_USERSPACE_HAVE_PCSC
  (void)reader_substring;
  (void)options;
  (void)out;
  err = "PC/SC support was not compiled in (install "
        "libpcsclite-dev/pcsc-lite-devel and rebuild)";
  return false;
#else
  std::string reader;
  pcsc_internal::PcscCard card;
  if (!card.ensureContext(err)) {
    return false;
  }
  if (!pcsc_internal::resolve_pcsc_reader_for_operation(card, reader_substring, reader, err)) {
    return false;
  }
  return pcsc_internal::pcsc_read_tag_with_card(card, reader, options, out, err);
#endif
}

bool pcsc_read_tag(std::string_view reader_substring, PcscTagSnapshot &out, std::string &err) {
  return pcsc_read_tag(reader_substring, PcscReadOptions{}, out, err);
}

bool pcsc_write_tag(std::string_view reader_substring, const PcscWriteRequest &request,
                    PcscTagSnapshot *after_write, std::string &err) {
#ifndef NERO_USERSPACE_HAVE_PCSC
  (void)reader_substring;
  (void)request;
  (void)after_write;
  err = "PC/SC support was not compiled in (install "
        "libpcsclite-dev/pcsc-lite-devel and rebuild)";
  return false;
#else
  if (request.ndef_message.empty()) {
    err = "refusing to write empty NDEF message";
    return false;
  }
  if (after_write != NERO_NFC_NULL) {
    *after_write = {};
  }
  std::string reader;
  pcsc_internal::PcscCard card;
  if (!card.ensureContext(err)) {
    return false;
  }
  if (!pcsc_internal::resolve_pcsc_reader_for_operation(card, reader_substring, reader, err)) {
    return false;
  }
  return pcsc_internal::pcsc_write_tag_with_card(card, reader, request, err);
#endif
}

int run_pcsc_reader(std::string_view reader_substring, const PcscReadOptions &options) {
#ifndef NERO_USERSPACE_HAVE_PCSC
  (void)reader_substring;
  (void)options;
  nero_nfc_stderr_line("error: PC/SC support was not compiled in (install "
                       "libpcsclite-dev/pcsc-lite-devel and rebuild)");
  return 1;
#else
  std::string reader;
  std::string err;
  bool const auto_reader = reader_substring.empty();
  pcsc_internal::PcscCard card;
  if (!card.ensureContext(err)) {
    nero_nfc_stderr_line("error: {}", err);
    return 1;
  }
  if (!auto_reader) {
    if (!resolve_pcsc_reader(reader_substring, reader, err)) {
      nero_nfc_stderr_line("error: {}", err);
      return 1;
    }
    pcsc_internal::prime_reader_state(card.context(), reader);
    nero_nfc_stderr_line("reader: PC/SC bridge on \"{}\"; ready to tap NFC "
                         "tags (Ctrl+C to stop)",
                         reader);
  } else {
    nero_nfc_stderr_line("reader: PC/SC bridge ready; tap NFC tags on any "
                         "selectable reader (Ctrl+C to stop)");
  }
  bool first = true;
  bool saw_confirmed_absence = true;
  std::string last_fingerprint;
  bool first_cycle = true;
  for (;;) {
    if (!first_cycle) {
      nero_nfc_stdout_line("");
    }
    WriterProgressSpinner wait_spinner("reader: ready for next NFC tag");
    bool wait_ok = false;
    std::size_t present_count = 0u;
    if (auto_reader) {
      wait_ok = pcsc_internal::resolve_pcsc_reader_for_operation(card, reader_substring, reader,
                                                                 err, false, &present_count);
    } else {
      wait_ok = pcsc_internal::wait_for_card_present(card.context(), reader, std::nullopt, err);
    }
    wait_spinner.finish();
    if (!wait_ok) {
      nero_nfc_stderr_line("error: {}", err);
      return 1;
    }
    if (auto_reader) {
      pcsc_internal::announce_pcsc_reader_selection(present_count, reader);
    }
    PcscTagSnapshot tag;
    if (!first) {
      nero_nfc_stdout_line("");
    }
    if (!pcsc_internal::pcsc_read_tag_with_card(card, reader, options, tag, err)) {
      nero_nfc_stderr_line("error: {}", err);
      card.disconnect();
      if (!pcsc_internal::wait_for_card_absent_stable(card.context(), reader, err)) {
        nero_nfc_stderr_line("error: {}", err);
        return 1;
      }
      saw_confirmed_absence = true;
      first_cycle = false;
      continue;
    }
    const std::string fingerprint = pcsc_internal::tag_fingerprint(tag);
    if (saw_confirmed_absence || fingerprint != last_fingerprint) {
      nero_nfc_stdout_line(format_pcsc_tag_snapshot_header(tag).c_str());
      const std::string body = format_pcsc_tag_snapshot_body(tag);
      if (!body.empty()) {
        nero_nfc_stdout_line(body.c_str());
      }
      first = false;
      last_fingerprint = fingerprint;
    }
    card.disconnect();
    if (!pcsc_internal::wait_for_card_absent_stable(card.context(), reader, err)) {
      nero_nfc_stderr_line("error: {}", err);
      return 1;
    }
    saw_confirmed_absence = true;
    first_cycle = false;
  }
#endif
}

int run_pcsc_reader(std::string_view reader_substring) {
  return run_pcsc_reader(reader_substring, PcscReadOptions{});
}

int run_pcsc_writer(std::string_view reader_substring, const PcscWriteRequest &request) {
#ifndef NERO_USERSPACE_HAVE_PCSC
  (void)reader_substring;
  (void)request;
  nero_nfc_stderr_line("error: PC/SC support was not compiled in (install "
                       "libpcsclite-dev/pcsc-lite-devel and rebuild)");
  return 1;
#else
  if (request.ndef_message.empty()) {
    nero_nfc_stderr_line("error: refusing to write empty NDEF message");
    return 1;
  }
  std::string err;
  std::string reader;
  bool const auto_reader = reader_substring.empty();
  pcsc_internal::PcscCard card;
  if (!card.ensureContext(err)) {
    nero_nfc_stderr_line("error: {}", err);
    return 1;
  }
  if (!auto_reader) {
    if (!resolve_pcsc_reader(reader_substring, reader, err)) {
      nero_nfc_stderr_line("error: {}", err);
      return 1;
    }
    pcsc_internal::prime_reader_state(card.context(), reader);
    nero_nfc_stderr_line("writer: PC/SC bridge on \"{}\"; ready to tap a writable NFC tag", reader);
  } else {
    nero_nfc_stderr_line("writer: PC/SC bridge ready; tap a writable NFC tag "
                         "on any selectable reader");
  }
  bool first_cycle = true;
  for (;;) {
    if (!first_cycle) {
      nero_nfc_stdout_line("");
    }
    WriterProgressSpinner wait_spinner("writer: ready for next writable NFC tag");
    bool wait_ok = false;
    std::size_t present_count = 0u;
    if (auto_reader) {
      wait_ok = pcsc_internal::resolve_pcsc_reader_for_operation(card, reader_substring, reader,
                                                                 err, false, &present_count);
    } else {
      wait_ok = pcsc_internal::wait_for_card_present(card.context(), reader, std::nullopt, err);
    }
    wait_spinner.finish();
    if (!wait_ok) {
      nero_nfc_stderr_line("error: {}", err);
      return 1;
    }
    if (auto_reader) {
      pcsc_internal::announce_pcsc_reader_selection(present_count, reader);
    }
    nero_nfc_stderr_line("writer: writing NDEF to tag...");
    WriterProgressSpinner write_spinner("writer: writing NDEF");
    const bool write_ok = pcsc_internal::pcsc_write_tag_with_card(card, reader, request, err);
    write_spinner.stop();
    if (!write_ok) {
      nero_nfc_stderr_line("error: {}", err);
      card.disconnect();
      if (!pcsc_internal::wait_for_card_absent_stable(card.context(), reader, err)) {
        nero_nfc_stderr_line("error: {}", err);
        return 1;
      }
      first_cycle = false;
      continue;
    }
    nero_nfc_stdout_line("*** SUCCESS - Wrote NDEF message ***");
    if (!pcsc_internal::wait_for_card_absent_stable(card.context(), reader, err)) {
      nero_nfc_stderr_line("error: {}", err);
      return 1;
    }
    first_cycle = false;
  }
#endif
}

} // namespace nero_nfc
