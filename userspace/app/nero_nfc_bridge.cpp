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

#include "nero_nfc_bridge.hpp"

#include <algorithm>
#include <cctype>
#include <vector>

#include "nero_nfc_detect.hpp"
#include "nero_nfc_pcsc.hpp"

namespace nero_nfc {
namespace {

std::string LowerCopy(std::string_view in) {
  std::string out(in);
  std::ranges::transform(out, out.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return out;
}

std::string CdcBridgeHint() {
  return "If the board is running the default PC/SC firmware, omit --bridge or "
         "use --bridge=pcsc.";
}

std::string PcscBridgeHint() {
  return "If the board is running the CDC serial firmware (make flash-cdc), "
         "use --bridge=cdc.";
}

}  // namespace

std::optional<HostBridge> ParseHostBridge(std::string_view value) {
  const auto kNormalized = LowerCopy(value);
  if (kNormalized == "cdc") {
    return HostBridge::kCdc;
  }
  if (kNormalized == "pcsc") {
    return HostBridge::kPcsc;
  }
  return std::nullopt;
}

std::string_view HostBridgeName(HostBridge bridge) {
  switch (bridge) {
    case HostBridge::kCdc:
      return "cdc";
    case HostBridge::kPcsc:
      return "pcsc";
  }
  return "cdc";
}

bool ChooseHostBridge(const std::optional<HostBridge>& requested_bridge,
                      const std::string& serial_port_arg,
                      const std::string& pcsc_reader_arg,
                      HostBridgeSelection& out, std::string& err,
                      bool pcsc_share_specified) {
  if (requested_bridge == HostBridge::kPcsc && !serial_port_arg.empty()) {
    err = "--port is only valid with the CDC bridge";
    return false;
  }
  if (requested_bridge == HostBridge::kCdc &&
      (!pcsc_reader_arg.empty() || pcsc_share_specified)) {
    err = "PC/SC options are only valid with the PC/SC bridge";
    return false;
  }
  if (!requested_bridge.has_value() && !serial_port_arg.empty() &&
      (!pcsc_reader_arg.empty() || pcsc_share_specified)) {
    err = "choose either --port (CDC) or PC/SC options, not both";
    return false;
  }

  const auto kSerialCandidate = DetectSerialPortCandidate(serial_port_arg);
  const auto kEnvPcscReader =
      pcsc_reader_arg.empty() ? PcscReaderSubstringFromEnv() : "";
  const std::string& pcsc_reader =
      pcsc_reader_arg.empty() ? kEnvPcscReader : pcsc_reader_arg;
  std::string resolved_pcsc_reader;
  std::string pcsc_err;
  bool have_pcsc_reader = false;
  if (!pcsc_reader.empty()) {
    have_pcsc_reader =
        ResolvePcscReader(pcsc_reader, resolved_pcsc_reader, pcsc_err);
  } else {
    std::vector<std::string> pcsc_readers;
    have_pcsc_reader = ListPcscReaders(pcsc_readers, pcsc_err);
    if (have_pcsc_reader) {
      resolved_pcsc_reader.clear();
      pcsc_err.clear();
    }
  }

  const bool kPreferCdc =
      (requested_bridge == HostBridge::kCdc) || !serial_port_arg.empty();
  const bool kPreferPcsc = (requested_bridge == HostBridge::kPcsc) ||
                           !pcsc_reader.empty() || pcsc_share_specified;

  if (kPreferCdc) {
    if (!kSerialCandidate.empty()) {
      out.bridge_ = HostBridge::kCdc;
      out.serial_port_ = kSerialCandidate;
      out.pcsc_reader_.clear();
      err.clear();
      return true;
    }
    err = "CDC bridge requested, but no serial port was detected. " +
          CdcBridgeHint();
    return false;
  }

  if (kPreferPcsc) {
    if (have_pcsc_reader) {
      out.bridge_ = HostBridge::kPcsc;
      out.serial_port_.clear();
      out.pcsc_reader_ = resolved_pcsc_reader;
      err.clear();
      return true;
    }
    err = "PC/SC bridge requested, but " + pcsc_err + ". " + PcscBridgeHint();
    return false;
  }

  if (have_pcsc_reader) {
    out.bridge_ = HostBridge::kPcsc;
    out.serial_port_.clear();
    out.pcsc_reader_ = resolved_pcsc_reader;
    err.clear();
    return true;
  }

  if (!kSerialCandidate.empty()) {
    out.bridge_ = HostBridge::kCdc;
    out.serial_port_ = kSerialCandidate;
    out.pcsc_reader_.clear();
    err.clear();
    return true;
  }

  err =
      "no compatible host bridge detected: no Nero CDC serial port was "
      "detected, and " +
      pcsc_err +
      ". Default firmware is USB CCID: on NUCLEO-WBA65RI plug USER USB-C "
      "(CN9), run "
      "`sudo make install-pcsc-driver` once, confirm `lsusb | rg -i "
      "'2341:006e'`, then "
      "`reader` or `reader --bridge=pcsc`. For serial shell use `make "
      "flash-cdc`.";
  return false;
}

}  // namespace nero_nfc
