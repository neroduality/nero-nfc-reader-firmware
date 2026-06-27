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

#include "nero_nfc_detect.h"
#include "nero_nfc_glob_raii.h"
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

#include "nero_nfc_io.h"

namespace nero_nfc {
namespace {

constexpr std::string_view kDevPathPrefix = "/dev/";
constexpr int kSysfsDeviceParentSearchMaxDepth = 8;
constexpr std::string_view kStlinkUsbVendorId = "0483";

bool read_sysfs_token(const std::string &path, std::string &out) {
  std::ifstream in(path);
  if (!in) {
    return false;
  }
  in >> out;
  return !out.empty();
}

std::optional<std::string> serial_port_usb_vendor_id(const std::string &port) {
  if (!port.starts_with(kDevPathPrefix)) {
    return std::nullopt;
  }
  const std::string tty_name = port.substr(kDevPathPrefix.size());
  std::filesystem::path node = std::filesystem::path("/sys/class/tty") / tty_name / "device";
  for (int depth = 0; depth < kSysfsDeviceParentSearchMaxDepth; ++depth) {
    std::string vendor;
    if (read_sysfs_token((node / "idVendor").string(), vendor)) {
      return vendor;
    }
    if (!node.has_parent_path() || node == node.parent_path()) {
      break;
    }
    node = node.parent_path();
  }
  return std::nullopt;
}

bool is_stlink_virtual_serial_port(const std::string &port) {
  const auto vendor = serial_port_usb_vendor_id(port);
  return vendor.has_value() && *vendor == kStlinkUsbVendorId;
}

std::vector<std::string> filter_nero_cdc_serial_ports(const std::vector<std::string> &ports) {
  std::vector<std::string> filtered;
  filtered.reserve(ports.size());
  std::copy_if(ports.begin(), ports.end(), std::back_inserter(filtered),
               [](const std::string &port) { return !is_stlink_virtual_serial_port(port); });
  return filtered;
}

} // namespace

#ifdef NERO_HOST_UNIT_TEST_HOOKS
namespace {
const std::vector<std::string> *g_find_serial_ports_override = NERO_NFC_NULL;
}
void nero_nfc_utest_set_find_serial_ports_override(const std::vector<std::string> *ports) {
  g_find_serial_ports_override = ports;
}
void nero_nfc_utest_clear_find_serial_ports_override() {
  g_find_serial_ports_override = NERO_NFC_NULL;
}
#endif

std::vector<std::string> find_serial_ports() {
#ifdef NERO_HOST_UNIT_TEST_HOOKS
  if (g_find_serial_ports_override != NERO_NFC_NULL) {
    auto v = *g_find_serial_ports_override;
    std::ranges::sort(v);
    return v;
  }
#endif
  static constexpr std::size_t kGlobPatternCount = 2u;
  static constexpr std::array<const char *, kGlobPatternCount> kGlobPatterns = {"/dev/ttyACM*",
                                                                                "/dev/ttyUSB*"};

  std::vector<std::string> result;
  for (const char *pattern : kGlobPatterns) {
    GlobResult gr;
    if (gr.match(pattern) == 0) {
      for (size_t i = 0; i < gr.count(); ++i) {
        result.emplace_back(gr.path(i));
      }
    }
  }
  std::ranges::sort(result);
  return filter_nero_cdc_serial_ports(result);
}

std::string select_best_port(const std::vector<std::string> &ports) {
  if (ports.empty()) {
    return {};
  }
  // Prefer ttyACM over ttyUSB; within the same prefix, pick lowest index.
  const auto ttyacm =
    std::ranges::find_if(ports, [](const std::string &p) { return p.contains("ttyACM"); });
  if (ttyacm != ports.end()) {
    return *ttyacm;
  }
  return ports.front();
}

std::string serial_port_from_env() {
  const char *env = std::getenv("PORT");
  if (env == NERO_NFC_NULL) {
    return {};
  }
  while (std::isspace(static_cast<unsigned char>(*env)) != 0) {
    ++env;
  }
  return (*env == '\0') ? std::string{} : std::string{env};
}

std::string detect_serial_port_candidate(const std::string &explicit_port) {
  if (!explicit_port.empty()) {
    return explicit_port;
  }
  auto env_port = serial_port_from_env();
  if (!env_port.empty()) {
    return env_port;
  }
  return select_best_port(find_serial_ports());
}

std::string resolve_serial_port_choice(const std::string &explicit_port,
                                       const std::vector<std::string> &discovered_ports) {
  if (!explicit_port.empty()) {
    return explicit_port;
  }
  auto best = select_best_port(discovered_ports);
  if (best.empty()) {
    nero_nfc::nero_nfc_stderr_line(
      "error: no serial port detected (set PORT=/dev/ttyACM0 or use --port)");
  }
  return best;
}

} // namespace nero_nfc
