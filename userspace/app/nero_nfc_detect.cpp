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

#include "nero_nfc_detect.hpp"
#include "nero_nfc_glob_raii.hpp"
#include "nero_nfc_null.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "nero_nfc_io.hpp"

namespace nero_nfc {
namespace {

constexpr std::string_view kDevPathPrefix = "/dev/";
constexpr int kSysfsDeviceParentSearchMaxDepth = 8;
constexpr std::string_view kStlinkUsbVendorId = "0483";

bool ReadSysfsToken(const std::string& path, std::string& out) {
  std::ifstream in(path);
  if (!in) {
    return false;
  }
  in >> out;
  return !out.empty();
}

std::optional<std::string> SerialPortUsbVendorId(const std::string& port) {
  if (!port.starts_with(kDevPathPrefix)) {
    return std::nullopt;
  }
  const std::string kTtyName = port.substr(kDevPathPrefix.size());
  std::filesystem::path node =
      std::filesystem::path("/sys/class/tty") / kTtyName / "device";
  for (int depth = 0; depth < kSysfsDeviceParentSearchMaxDepth; ++depth) {
    std::string vendor;
    if (ReadSysfsToken((node / "idVendor").string(), vendor)) {
      return vendor;
    }
    if (!node.has_parent_path() || node == node.parent_path()) {
      break;
    }
    node = node.parent_path();
  }
  return std::nullopt;
}

bool IsStlinkVirtualSerialPort(const std::string& port) {
  const auto kVendor = SerialPortUsbVendorId(port);
  return kVendor.has_value() && *kVendor == kStlinkUsbVendorId;
}

std::vector<std::string> FilterNeroCdcSerialPorts(
    const std::vector<std::string>& ports) {
  std::vector<std::string> filtered;
  filtered.reserve(ports.size());
  std::ranges::copy_if(
      ports, std::back_inserter(filtered),
      [](const std::string& port) { return !IsStlinkVirtualSerialPort(port); });
  return filtered;
}

}  // namespace

#ifdef NERO_HOST_UNIT_TEST_HOOKS
namespace {
const std::vector<std::string>* g_find_serial_ports_override = NERO_NFC_NULL;
}
void NeroNfcUtestSetFindSerialPortsOverride(
    const std::vector<std::string>* ports) {
  g_find_serial_ports_override = ports;
}
void NeroNfcUtestClearFindSerialPortsOverride() {
  g_find_serial_ports_override = NERO_NFC_NULL;
}
#endif

std::vector<std::string> FindSerialPorts() {
#ifdef NERO_HOST_UNIT_TEST_HOOKS
  if (g_find_serial_ports_override != NERO_NFC_NULL) {
    auto v = *g_find_serial_ports_override;
    std::ranges::sort(v);
    return v;
  }
#endif
  static constexpr std::size_t kGlobPatternCount = 2u;
  static constexpr std::array<const char*, kGlobPatternCount> kGlobPatterns = {
      "/dev/ttyACM*", "/dev/ttyUSB*"};

  std::vector<std::string> result;
  for (const char* pattern : kGlobPatterns) {
    GlobResult gr;
    if (gr.Match(pattern) == 0) {
      for (size_t i = 0; i < gr.Count(); ++i) {
        const char* path = gr.Path(i);
        if (path != NERO_NFC_NULL) {
          result.emplace_back(path);
        }
      }
    }
  }
  std::ranges::sort(result);
  return FilterNeroCdcSerialPorts(result);
}

std::string SelectBestPort(const std::vector<std::string>& ports) {
  if (ports.empty()) {
    return {};
  }
  // Prefer ttyACM over ttyUSB; within the same prefix, pick lowest index.
  const auto kTtyacm = std::ranges::find_if(
      ports, [](const std::string& p) { return p.contains("ttyACM"); });
  if (kTtyacm != ports.end()) {
    return *kTtyacm;
  }
  return ports.front();
}

std::string SerialPortFromEnv() {
  const char* env = std::getenv("PORT");
  if (env == NERO_NFC_NULL) {
    return {};
  }
  std::string_view sv{env};
  while (!sv.empty() &&
         (std::isspace(static_cast<unsigned char>(sv.front())) != 0)) {
    sv.remove_prefix(1u);
  }
  return sv.empty() ? std::string{} : std::string{sv};
}

std::string DetectSerialPortCandidate(const std::string& explicit_port) {
  if (!explicit_port.empty()) {
    return explicit_port;
  }
  auto env_port = SerialPortFromEnv();
  if (!env_port.empty()) {
    return env_port;
  }
  return SelectBestPort(FindSerialPorts());
}

std::string ResolveSerialPortChoice(
    const std::string& explicit_port,
    const std::vector<std::string>& discovered_ports) {
  if (!explicit_port.empty()) {
    return explicit_port;
  }
  auto best = SelectBestPort(discovered_ports);
  if (best.empty()) {
    nero_nfc::NeroNfcStderrLine(
        "error: no serial port detected (set PORT=/dev/ttyACM0 or use --port)");
  }
  return best;
}

}  // namespace nero_nfc
