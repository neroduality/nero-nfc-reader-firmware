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

#include "nero_nfc_bridge.h"

#include <algorithm>
#include <cctype>
#include <vector>

#include "nero_nfc_detect.h"
#include "nero_nfc_pcsc.h"

namespace nero_nfc {
namespace {

std::string lower_copy(std::string_view in) {
  std::string out(in);
  std::ranges::transform(out, out.begin(),
                         [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return out;
}

std::string cdc_bridge_hint() {
  return "If the board is running the default PC/SC firmware, omit --bridge or use --bridge=pcsc.";
}

std::string pcsc_bridge_hint() {
  return "If the board is running the CDC serial firmware (make flash-cdc), use --bridge=cdc.";
}

} // namespace

std::optional<HostBridge> parse_host_bridge(std::string_view value) {
  const auto normalized = lower_copy(value);
  if (normalized == "cdc") {
    return HostBridge::Cdc;
  }
  if (normalized == "pcsc") {
    return HostBridge::Pcsc;
  }
  return std::nullopt;
}

std::string_view host_bridge_name(HostBridge bridge) {
  switch (bridge) {
  case HostBridge::Cdc:
    return "cdc";
  case HostBridge::Pcsc:
    return "pcsc";
  }
  return "cdc";
}

bool choose_host_bridge(const std::optional<HostBridge> &requested_bridge,
                        const std::string &serial_port_arg, const std::string &pcsc_reader_arg,
                        HostBridgeSelection &out, std::string &err, bool pcsc_share_specified) {
  if (requested_bridge == HostBridge::Pcsc && !serial_port_arg.empty()) {
    err = "--port is only valid with the CDC bridge";
    return false;
  }
  if (requested_bridge == HostBridge::Cdc && (!pcsc_reader_arg.empty() || pcsc_share_specified)) {
    err = "PC/SC options are only valid with the PC/SC bridge";
    return false;
  }
  if (!requested_bridge.has_value() && !serial_port_arg.empty() &&
      (!pcsc_reader_arg.empty() || pcsc_share_specified)) {
    err = "choose either --port (CDC) or PC/SC options, not both";
    return false;
  }

  const auto serial_candidate = detect_serial_port_candidate(serial_port_arg);
  const auto env_pcsc_reader = pcsc_reader_arg.empty() ? pcsc_reader_substring_from_env() : "";
  const std::string &pcsc_reader = pcsc_reader_arg.empty() ? env_pcsc_reader : pcsc_reader_arg;
  std::string resolved_pcsc_reader;
  std::string pcsc_err;
  bool have_pcsc_reader = false;
  if (!pcsc_reader.empty()) {
    have_pcsc_reader = resolve_pcsc_reader(pcsc_reader, resolved_pcsc_reader, pcsc_err);
  } else {
    std::vector<std::string> pcsc_readers;
    have_pcsc_reader = list_pcsc_readers(pcsc_readers, pcsc_err);
    if (have_pcsc_reader) {
      resolved_pcsc_reader.clear();
      pcsc_err.clear();
    }
  }

  const bool prefer_cdc = (requested_bridge == HostBridge::Cdc) || !serial_port_arg.empty();
  const bool prefer_pcsc =
    (requested_bridge == HostBridge::Pcsc) || !pcsc_reader.empty() || pcsc_share_specified;

  if (prefer_cdc) {
    if (!serial_candidate.empty()) {
      out.bridge = HostBridge::Cdc;
      out.serial_port = serial_candidate;
      out.pcsc_reader.clear();
      err.clear();
      return true;
    }
    err = "CDC bridge requested, but no serial port was detected. " + cdc_bridge_hint();
    return false;
  }

  if (prefer_pcsc) {
    if (have_pcsc_reader) {
      out.bridge = HostBridge::Pcsc;
      out.serial_port.clear();
      out.pcsc_reader = resolved_pcsc_reader;
      err.clear();
      return true;
    }
    err = "PC/SC bridge requested, but " + pcsc_err + ". " + pcsc_bridge_hint();
    return false;
  }

  if (have_pcsc_reader) {
    out.bridge = HostBridge::Pcsc;
    out.serial_port.clear();
    out.pcsc_reader = resolved_pcsc_reader;
    err.clear();
    return true;
  }

  if (!serial_candidate.empty()) {
    out.bridge = HostBridge::Cdc;
    out.serial_port = serial_candidate;
    out.pcsc_reader.clear();
    err.clear();
    return true;
  }

  err = "no compatible host bridge detected: no Nero CDC serial port was detected, and " +
        pcsc_err +
        ". Default firmware is USB CCID: on NUCLEO-WBA65RI plug USER USB-C (CN9), run "
        "`sudo make install-pcsc-driver` once, confirm `lsusb | rg -i '2341:006e'`, then "
        "`reader` or `reader --bridge=pcsc`. For serial shell use `make flash-cdc`.";
  return false;
}

} // namespace nero_nfc
