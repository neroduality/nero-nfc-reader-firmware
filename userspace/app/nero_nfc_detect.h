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

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace nero_nfc {

// Return all serial ports matching the Nero NFC device patterns, sorted.
// Patterns searched (in priority order): /dev/ttyACM*, /dev/ttyUSB*
std::vector<std::string> find_serial_ports();

// Return the highest-priority port from a sorted list.
// Priority: ttyACM before ttyUSB; lower device number before higher.
// Returns empty string when the list is empty.
std::string select_best_port(const std::vector<std::string> &ports);

// Return the current PORT environment override with leading whitespace trimmed.
// Returns empty string when PORT is unset or blank.
std::string serial_port_from_env();

// Quietly resolve which serial path would be used: explicit port wins, then
// PORT, then auto-discovery. Returns empty string when no candidate exists.
std::string detect_serial_port_candidate(const std::string &explicit_port);

// Resolve which serial path to use: explicit port wins; otherwise pick from
// discovered_ports (typically from find_serial_ports). Prints a hint to stderr
// when auto-detection yields no port.
std::string resolve_serial_port_choice(const std::string &explicit_port,
                                       const std::vector<std::string> &discovered_ports);

#ifdef NERO_HOST_UNIT_TEST_HOOKS
// When non-null, find_serial_ports() returns a sorted copy of *ports and skips
// glob.
void nero_nfc_utest_set_find_serial_ports_override(const std::vector<std::string> *ports);
void nero_nfc_utest_clear_find_serial_ports_override();
#endif

} // namespace nero_nfc
