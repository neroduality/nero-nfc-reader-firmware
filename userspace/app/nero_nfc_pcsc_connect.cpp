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

#include "nero_nfc_format.h"
#include "nero_nfc_hex.h"
#include "nero_nfc_io.h"
#include "nero_nfc_limits.h"
#include "nero_nfc_null.h"
#include "nero_nfc_pcsc.h"
#include "nero_nfc_pcsc_internal.h"
#include "nfc_pcsc_contactless.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <limits>
#include <optional>
#include <ranges>
#include <sstream>
#include <string_view>
#include <thread>
#include <utility>

#ifdef NERO_USERSPACE_HAVE_PCSC
#include <PCSC/winscard.h>
#endif

namespace nero_nfc::pcsc_internal {

namespace {

enum {
  kPcscReaderListBufMax = 4096u,
};

} // namespace

#ifdef NERO_HOST_UNIT_TEST_HOOKS
const std::vector<std::string> *g_list_pcsc_readers_override = NERO_NFC_NULL;
#endif

std::string lower_copy(std::string_view in) {
  std::string out(in);
  std::ranges::transform(out, out.begin(),
                         [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return out;
}

std::string join_reader_names(const std::vector<std::string> &readers) {
  std::string out;
  for (std::size_t i = 0; i < readers.size(); ++i) {
    if (i != 0u) {
      out += "; ";
    }
    out += '"';
    out += readers[i];
    out += '"';
  }
  return out;
}

bool is_preferred_nero_reader(std::string_view reader_name) {
  std::string const name = lower_copy(reader_name);
  if (name.find("nero") != std::string::npos || name.find("st25r") != std::string::npos) {
    return true;
  }
  return name.find("arduino") != std::string::npos && name.find("ccid") != std::string::npos;
}

bool is_sam_reader(std::string_view reader_name) {
  return lower_copy(reader_name).find("sam") != std::string::npos;
}

std::vector<std::string> selectable_pcsc_readers(const std::vector<std::string> &readers) {
  std::vector<std::string> selectable;
  std::ranges::copy_if(readers, std::back_inserter(selectable),
                       [](const std::string &reader) { return !is_sam_reader(reader); });
  return selectable;
}
bool is_type4_compatible(const PcscTagSnapshot &tag) {
  return tag.tag_type.find("Type 4") != std::string::npos ||
         tag.tag_type.find("ISO 14443-4") != std::string::npos || !tag.ats_hex.empty();
}

bool status_ok(const std::vector<std::uint8_t> &rapdu) {
  return nfc_iso7816_response_sw_ok(rapdu.data(), static_cast<int>(rapdu.size()));
}

std::vector<std::uint8_t> without_status(const std::vector<std::uint8_t> &rapdu) {
  if (rapdu.size() < static_cast<std::size_t>(NFC_PCSC_T4_NLEN_LEN)) {
    return {};
  }
  return {rapdu.begin(), rapdu.end() - static_cast<std::ptrdiff_t>(NFC_PCSC_T4_NLEN_LEN)};
}

#ifdef NERO_USERSPACE_HAVE_PCSC

DWORD pcsc_share_mode_to_scard(PcscShareMode mode) {
  return mode == PcscShareMode::Exclusive ? SCARD_SHARE_EXCLUSIVE : SCARD_SHARE_SHARED;
}

void pcsc_note(LONG rv, std::string &err, std::string_view stage) {
  char buf[NERO_NFC_PCSC_ERROR_MSG_MAX]{};
  if (stage.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    err = "PC/SC stage label too long";
    return;
  }
  const int n =
    nero_nfc_snprintf(buf, sizeof(buf), "%.*s: PC/SC 0x%08lX", static_cast<int>(stage.size()),
                      stage.data(), static_cast<unsigned long>(rv));
  if (n < 0 || static_cast<std::size_t>(n) >= sizeof(buf)) {
    err = "PC/SC error formatting failed";
    return;
  }
  err = buf;
}

std::string reader_state_summary(DWORD state) {
  std::string summary;
  auto append = [&](std::string_view name) {
    if (!summary.empty()) {
      summary.push_back('|');
    }
    summary.append(name);
  };
  if ((state & SCARD_STATE_PRESENT) != 0u) {
    append("present");
  }
  if ((state & SCARD_STATE_EMPTY) != 0u) {
    append("empty");
  }
  if ((state & SCARD_STATE_MUTE) != 0u) {
    append("mute");
  }
  if ((state & SCARD_STATE_INUSE) != 0u) {
    append("inuse");
  }
  if ((state & SCARD_STATE_EXCLUSIVE) != 0u) {
    append("exclusive");
  }
  if ((state & SCARD_STATE_UNAVAILABLE) != 0u) {
    append("unavailable");
  }
  if ((state & SCARD_STATE_CHANGED) != 0u) {
    append("changed");
  }
  if ((state & SCARD_STATE_UNKNOWN) != 0u) {
    append("unknown");
  }
  if ((state & SCARD_STATE_IGNORE) != 0u) {
    append("ignore");
  }
  if (summary.empty()) {
    summary = "none";
  }
  return summary;
}

bool wait_for_card_state(SCARDCONTEXT ctx, const std::string &reader, bool want_present,
                         std::optional<std::chrono::steady_clock::time_point> deadline,
                         std::string &err) {
  SCARD_READERSTATE rs{};
  rs.szReader = reader.c_str();
  rs.dwCurrentState = SCARD_STATE_UNAWARE;
  std::string last_state;

  while (!deadline.has_value() || (std::chrono::steady_clock::now() < *deadline)) {
    auto const now = std::chrono::steady_clock::now();
    auto const remaining_ms =
      deadline.has_value()
        ? std::chrono::duration_cast<std::chrono::milliseconds>(*deadline - now).count()
        : static_cast<long long>(kPcscPollSleep.count());
    DWORD const wait_ms = remaining_ms > static_cast<long long>(kPcscPollSleep.count())
                            ? static_cast<DWORD>(kPcscPollSleep.count())
                            : static_cast<DWORD>(std::max<long long>(remaining_ms, 0));
    LONG rv = SCardGetStatusChange(ctx, wait_ms, &rs, 1);
    if (rv == SCARD_E_TIMEOUT) {
      continue;
    }
    if (rv != SCARD_S_SUCCESS) {
      pcsc_note(rv, err, "SCardGetStatusChange");
      return false;
    }
    bool const present = ((rs.dwEventState & SCARD_STATE_PRESENT) != 0u) &&
                         ((rs.dwEventState & SCARD_STATE_EMPTY) == 0u) &&
                         ((rs.dwEventState & SCARD_STATE_UNAVAILABLE) == 0u);
    if (present == want_present) {
      err.clear();
      return true;
    }
    last_state = reader_state_summary(rs.dwEventState);
    rs.dwCurrentState = rs.dwEventState;
  }

  err = want_present ? "timed out waiting for tag presence" : "timed out waiting for tag removal";
  if (want_present && !last_state.empty()) {
    err += " (" + last_state + ")";
  }
  return false;
}

bool wait_for_card_present(SCARDCONTEXT ctx, const std::string &reader,
                           std::optional<std::chrono::steady_clock::time_point> deadline,
                           std::string &err) {
  return wait_for_card_state(ctx, reader, true, deadline, err);
}

bool wait_for_card_absent(SCARDCONTEXT ctx, const std::string &reader,
                          std::optional<std::chrono::steady_clock::time_point> deadline,
                          std::string &err) {
  return wait_for_card_state(ctx, reader, false, deadline, err);
}

bool wait_for_card_absent_stable(SCARDCONTEXT ctx, const std::string &reader, std::string &err) {
  for (;;) {
    if (!wait_for_card_absent(ctx, reader,
                              std::chrono::steady_clock::now() + kPcscRemovalPollWindow, err)) {
      if (err == "timed out waiting for tag removal") {
        continue;
      }
      return false;
    }

    std::string settle_err;
    if (wait_for_card_present(
          ctx, reader, std::chrono::steady_clock::now() + kPcscRemovalSettleWindow, settle_err)) {
      continue;
    }
    if (settle_err.starts_with("timed out waiting for tag presence")) {
      err.clear();
      return true;
    }
    err = settle_err;
    return false;
  }
}

bool reader_state_has_present_card(const SCARD_READERSTATE &state) {
  return ((state.dwEventState & SCARD_STATE_PRESENT) != 0u) &&
         ((state.dwEventState & SCARD_STATE_EMPTY) == 0u) &&
         ((state.dwEventState & SCARD_STATE_UNAVAILABLE) == 0u);
}

bool wait_for_present_reader(SCARDCONTEXT ctx, const std::vector<std::string> &readers,
                             std::string &reader, std::string &err, bool announce_selection,
                             std::size_t *present_count_out) {
  std::vector<std::string> candidates = selectable_pcsc_readers(readers);
  if (candidates.empty()) {
    err = "no selectable PC/SC readers detected; readers: " + join_reader_names(readers);
    return false;
  }
  std::vector<SCARD_READERSTATE> states(candidates.size());
  for (std::size_t i = 0; i < candidates.size(); ++i) {
    states[i].szReader = candidates[i].c_str();
    states[i].dwCurrentState = SCARD_STATE_UNAWARE;
  }
  for (;;) {
    auto wait_ms = static_cast<DWORD>(kPcscPollSleep.count());
    LONG rv = SCardGetStatusChange(ctx, wait_ms, states.data(), static_cast<DWORD>(states.size()));
    if (rv != SCARD_E_TIMEOUT && rv != SCARD_S_SUCCESS) {
      pcsc_note(rv, err, "SCardGetStatusChange");
      return false;
    }
    std::vector<std::string> present;
    for (auto &state : states) {
      if (reader_state_has_present_card(state)) {
        present.emplace_back(state.szReader);
      }
      state.dwCurrentState = state.dwEventState;
    }
    if (!present.empty()) {
      reader = present.front();
      if (present_count_out != NERO_NFC_NULL) {
        *present_count_out = present.size();
      }
      if (announce_selection) {
        announce_pcsc_reader_selection(present.size(), reader);
      }
      err.clear();
      return true;
    }
  }
}

void announce_pcsc_reader_selection(std::size_t present_count, const std::string &reader) {
  if (present_count > 1u) {
    nero_nfc::nero_nfc_stderr_line(
      "PC/SC: {} readers have cards present; using \"{}\" for this operation", present_count,
      reader);
    return;
  }
  nero_nfc::nero_nfc_stderr_line("PC/SC: using reader \"{}\" (selected by card presence)", reader);
}

std::string tag_fingerprint(const PcscTagSnapshot &tag) {
  return tag.uid_hex + '\n' + tag.atr_hex + '\n' + tag.tag_type;
}

bool is_retryable_connect_error(LONG rv) {
  return rv == SCARD_E_NO_SMARTCARD || rv == SCARD_W_REMOVED_CARD || rv == SCARD_W_UNPOWERED_CARD ||
         rv == SCARD_W_UNRESPONSIVE_CARD || rv == SCARD_E_SHARING_VIOLATION;
}

void prime_reader_state(SCARDCONTEXT ctx, const std::string &reader) {
  SCARD_READERSTATE rs{};
  rs.szReader = reader.c_str();
  rs.dwCurrentState = SCARD_STATE_UNAWARE;
  (void)SCardGetStatusChange(ctx, 0u, &rs, 1);
}

bool list_readers_impl(std::vector<std::string> &readers, std::string &err) {
  SCARDCONTEXT ctx{};
  LONG rv = SCardEstablishContext(SCARD_SCOPE_USER, NERO_NFC_NULL, NERO_NFC_NULL, &ctx);
  if (rv != SCARD_S_SUCCESS) {
    pcsc_note(rv, err, "SCardEstablishContext");
    return false;
  }
  DWORD n = 0;
  rv = SCardListReaders(ctx, NERO_NFC_NULL, NERO_NFC_NULL, &n);
  if (rv != SCARD_S_SUCCESS || n == 0u) {
    pcsc_note(rv, err, "SCardListReaders");
    (void)SCardReleaseContext(ctx);
    return false;
  }
  if (n > kPcscReaderListBufMax) {
    err = "PC/SC reader list exceeds supported buffer cap";
    (void)SCardReleaseContext(ctx);
    return false;
  }
  std::vector<char> buf(n);
  rv = SCardListReaders(ctx, NERO_NFC_NULL, buf.data(), &n);
  (void)SCardReleaseContext(ctx);
  if (rv != SCARD_S_SUCCESS) {
    pcsc_note(rv, err, "SCardListReaders");
    return false;
  }
  for (auto it = buf.begin(); it != buf.end() && *it != '\0';) {
    auto const nul = std::ranges::find(it, buf.end(), '\0');
    if (nul == buf.end()) {
      err = "PC/SC reader list is not NUL-terminated";
      readers.clear();
      return false;
    }
    readers.emplace_back(it, nul);
    it = std::next(nul);
  }
  return !readers.empty();
}
PcscCard::~PcscCard() {
  disconnect();
  if (ctx_ != 0) {
    (void)SCardReleaseContext(ctx_);
  }
}

PcscCard::PcscCard() = default;

const std::string &PcscCard::readerName() const {
  return reader_name_;
}

SCARDCONTEXT PcscCard::context() const {
  return ctx_;
}

bool PcscCard::ensureContext(std::string &err) {
  if (ctx_ != 0) {
    err.clear();
    return true;
  }
  LONG rv = SCardEstablishContext(SCARD_SCOPE_USER, NERO_NFC_NULL, NERO_NFC_NULL, &ctx_);
  if (rv != SCARD_S_SUCCESS) {
    pcsc_note(rv, err, "SCardEstablishContext");
    return false;
  }
  err.clear();
  return true;
}

void PcscCard::disconnect(DWORD disposition) {
  if (card_ != 0) {
    if (transaction_active_) {
      (void)SCardEndTransaction(card_, SCARD_LEAVE_CARD);
      transaction_active_ = false;
    }
    (void)SCardDisconnect(card_, disposition);
    card_ = 0;
  }
  protocol_ = 0u;
  pci_ = SCARD_PCI_T1;
}

bool PcscCard::connect(const std::string &reader, PcscShareMode share_mode, std::string &err) {
  reader_name_ = reader;
  disconnect();
  if (!ensureContext(err)) {
    return false;
  }
  auto const started = std::chrono::steady_clock::now();
  for (;;) {
    LONG rv = SCardConnect(ctx_, reader.c_str(), pcsc_share_mode_to_scard(share_mode),
                           SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &card_, &protocol_);
    if (rv == SCARD_E_PROTO_MISMATCH) {
      rv = SCardConnect(ctx_, reader.c_str(), pcsc_share_mode_to_scard(share_mode),
                        SCARD_PROTOCOL_RAW, &card_, &protocol_);
    }
    if (rv == SCARD_S_SUCCESS) {
      if ((protocol_ & SCARD_PROTOCOL_T1) != 0u) {
        pci_ = SCARD_PCI_T1;
      } else if ((protocol_ & SCARD_PROTOCOL_T0) != 0u) {
        pci_ = SCARD_PCI_T0;
      } else if ((protocol_ & SCARD_PROTOCOL_RAW) != 0u) {
        pci_ = SCARD_PCI_RAW;
      } else {
        disconnect(SCARD_LEAVE_CARD);
        err = "connected PC/SC reader returned no usable protocol";
        return false;
      }
      err.clear();
      return true;
    }
    if (!is_retryable_connect_error(rv)) {
      pcsc_note(rv, err, "SCardConnect");
      return false;
    }
    err = "waiting for tag connectability";
    auto const now = std::chrono::steady_clock::now();
    std::this_thread::sleep_for((now - started) < kPcscFastRetryWindow ? kPcscFastRetrySleep
                                                                       : kPcscPollSleep);
  }
}

bool PcscCard::beginTransaction(std::string &err) {
  if (card_ == 0) {
    err = "PC/SC transaction requested before card connect";
    return false;
  }
  LONG rv = SCardBeginTransaction(card_);
  if (rv != SCARD_S_SUCCESS) {
    pcsc_note(rv, err, "SCardBeginTransaction");
    return false;
  }
  transaction_active_ = true;
  err.clear();
  return true;
}

bool PcscCard::endTransaction(std::string &err) {
  if (!transaction_active_) {
    err.clear();
    return true;
  }
  LONG rv = SCardEndTransaction(card_, SCARD_LEAVE_CARD);
  transaction_active_ = false;
  if (rv != SCARD_S_SUCCESS) {
    pcsc_note(rv, err, "SCardEndTransaction");
    return false;
  }
  err.clear();
  return true;
}

bool PcscCard::status(std::vector<std::uint8_t> &atr, std::string &err) {
  char name[NERO_NFC_PCSC_READER_NAME_MAX]{};
  DWORD name_len = sizeof(name);
  DWORD state = 0;
  DWORD atr_len = NERO_NFC_PCSC_ATR_HOST_MAX;
  std::array<std::uint8_t, NERO_NFC_PCSC_ATR_HOST_MAX> atr_buf{};
  LONG rv = SCardStatus(card_, name, &name_len, &state, &protocol_, atr_buf.data(), &atr_len);
  if (rv != SCARD_S_SUCCESS) {
    pcsc_note(rv, err, "SCardStatus");
    return false;
  }
  if (atr_len > atr_buf.size()) {
    err = "PC/SC ATR exceeds host buffer";
    return false;
  }
  atr.assign(atr_buf.begin(), atr_buf.begin() + static_cast<std::ptrdiff_t>(atr_len));
  return true;
}

bool PcscCard::transmit(const std::vector<std::uint8_t> &capdu, std::vector<std::uint8_t> &rapdu,
                        std::string &err) {
  std::array<std::uint8_t, NERO_NFC_PCSC_APDU_RX_MAX> rx{};
  if (capdu.empty()) {
    err = "APDU command is empty";
    return false;
  }
  if (capdu.size() > std::numeric_limits<DWORD>::max()) {
    err = "APDU command exceeds PC/SC DWORD length cap";
    return false;
  }
  auto rx_len = static_cast<DWORD>(rx.size());
  LONG rv = SCardTransmit(card_, pci_, capdu.data(), static_cast<DWORD>(capdu.size()),
                          NERO_NFC_NULL, rx.data(), &rx_len);
  if (rv != SCARD_S_SUCCESS) {
    pcsc_note(rv, err, "SCardTransmit");
    return false;
  }
  if (rx_len > rx.size()) {
    err = "APDU response exceeds host receive buffer";
    return false;
  }
  rapdu.assign(rx.begin(), rx.begin() + static_cast<std::ptrdiff_t>(rx_len));
  return true;
}

bool transmit_ok(PcscCard &card, const std::vector<std::uint8_t> &capdu,
                 std::vector<std::uint8_t> &data, std::string &err) {
  std::vector<std::uint8_t> rapdu;
  if (!card.transmit(capdu, rapdu, err)) {
    return false;
  }
  if (!status_ok(rapdu)) {
    if (rapdu.size() >= static_cast<std::size_t>(NFC_PCSC_T4_NLEN_LEN)) {
      std::ostringstream msg;
      const auto sw_off = rapdu.size() - static_cast<std::size_t>(NFC_PCSC_T4_NLEN_LEN);
      if (!nero_nfc_span_ok(sw_off, static_cast<std::size_t>(NFC_PCSC_T4_NLEN_LEN), rapdu.size())) {
        err = "APDU response status word out of range";
        return false;
      }
      msg << "APDU SW=" << hex_bytes({rapdu[sw_off], rapdu[sw_off + 1u]}, '\0');
      err = msg.str();
    } else {
      err = "APDU response missing status word";
    }
    return false;
  }
  data = without_status(rapdu);
  return true;
}

std::vector<std::uint8_t> try_get_data_bytes(PcscCard &card, std::uint8_t p1, std::uint8_t p2) {
  std::vector<std::uint8_t> data;
  std::string err;
  if (!transmit_ok(card,
                   {static_cast<std::uint8_t>(NFC_ISO7816_CLA_PROPRIETARY),
                    static_cast<std::uint8_t>(NFC_ISO7816_INS_GET_DATA), p1, p2,
                    static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS)},
                   data, err)) {
    data.clear();
  }
  return data;
}

bool select_bytes(PcscCard &card, std::uint8_t p1, std::uint8_t p2,
                  const std::vector<std::uint8_t> &data, std::string &err) {
  std::vector<std::uint8_t> capdu;
  if (!build_select_apdu(p1, p2, data, capdu, err)) {
    return false;
  }
  std::vector<std::uint8_t> response;
  return transmit_ok(card, capdu, response, err);
}

bool select_file(PcscCard &card, std::uint8_t hi, std::uint8_t lo, std::string &err) {
  if (select_bytes(card, static_cast<std::uint8_t>(NFC_ISO7816_CLA_ISO),
                   static_cast<std::uint8_t>(NFC_ISO7816_P2_SELECT_NO_FCI), {hi, lo}, err)) {
    return true;
  }
  return select_bytes(card, static_cast<std::uint8_t>(NFC_ISO7816_CLA_ISO),
                      static_cast<std::uint8_t>(NFC_ISO7816_P2_SELECT_FIRST), {hi, lo}, err);
}

bool read_binary(PcscCard &card, std::uint16_t offset, std::uint8_t len,
                 std::vector<std::uint8_t> &data, std::string &err) {
  auto read_with_len = [&](std::uint8_t le, std::uint8_t &sw1, std::uint8_t &sw2) -> bool {
    std::vector<std::uint8_t> rapdu;
    if (!card.transmit(
          {static_cast<std::uint8_t>(NFC_ISO7816_CLA_ISO),
           static_cast<std::uint8_t>(NFC_ISO7816_INS_READ_BINARY),
           static_cast<std::uint8_t>(offset >>
                                     static_cast<unsigned>(NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES)),
           static_cast<std::uint8_t>(offset & static_cast<unsigned>(NFC_BYTE_VALUE_MAX)), le},
          rapdu, err)) {
      return false;
    }
    if (status_ok(rapdu)) {
      data = without_status(rapdu);
      err.clear();
      return true;
    }
    if (rapdu.size() >= static_cast<std::size_t>(NFC_PCSC_T4_NLEN_LEN)) {
      sw1 = rapdu[rapdu.size() - static_cast<std::size_t>(NFC_PCSC_T4_NLEN_LEN)];
      sw2 = rapdu.back();
      std::ostringstream msg;
      msg << "APDU SW=" << hex_bytes({sw1, sw2}, '\0');
      err = msg.str();
    } else {
      sw1 = 0u;
      sw2 = 0u;
      err = "APDU response missing status word";
    }
    return false;
  };

  std::uint8_t sw1 = 0u;
  std::uint8_t sw2 = 0u;
  data.clear();
  if (read_with_len(len, sw1, sw2)) {
    return true;
  }
  if (sw1 == static_cast<std::uint8_t>(NFC_ISO7816_SW1_WRONG_LENGTH) && sw2 != len) {
    return read_with_len(sw2, sw1, sw2);
  }
  if (sw1 == static_cast<std::uint8_t>(NFC_ISO7816_SW1_WRONG_LENGTH_ALT) &&
      sw2 == static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS) &&
      len != static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS)) {
    return read_with_len(static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS), sw1, sw2);
  }
  return false;
}

bool update_binary(PcscCard &card, std::uint16_t offset, const std::vector<std::uint8_t> &bytes,
                   std::string &err) {
  if (bytes.empty() || bytes.size() > static_cast<std::size_t>(NFC_BYTE_VALUE_MAX)) {
    err = "short UPDATE BINARY chunk too large";
    return false;
  }
  std::vector<std::uint8_t> capdu = {
    static_cast<std::uint8_t>(NFC_ISO7816_CLA_ISO),
    static_cast<std::uint8_t>(NFC_ISO7816_INS_UPDATE_BINARY),
    static_cast<std::uint8_t>(offset >> static_cast<unsigned>(NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES)),
    static_cast<std::uint8_t>(offset & static_cast<unsigned>(NFC_BYTE_VALUE_MAX)),
    static_cast<std::uint8_t>(bytes.size())};
  capdu.insert(capdu.end(), bytes.begin(), bytes.end());
  std::vector<std::uint8_t> data;
  return transmit_ok(card, capdu, data, err);
}

bool resolve_pcsc_reader_for_operation(const PcscCard &card, std::string_view requested,
                                       std::string &reader, std::string &err,
                                       bool announce_selection, std::size_t *present_count_out) {
  if (!requested.empty()) {
    return nero_nfc::resolve_pcsc_reader(requested, reader, err);
  }
  std::vector<std::string> readers;
  if (!nero_nfc::list_pcsc_readers(readers, err)) {
    return false;
  }
  return wait_for_present_reader(card.context(), readers, reader, err, announce_selection,
                                 present_count_out);
}

#endif // NERO_USERSPACE_HAVE_PCSC

} // namespace nero_nfc::pcsc_internal
