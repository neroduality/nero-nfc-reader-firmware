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

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace nero_nfc {

enum class HostBridge : std::uint8_t {
  kCdc,
  kPcsc,
};

struct HostBridgeSelection {
  HostBridge bridge_{HostBridge::kCdc};
  std::string serial_port_;
  std::string pcsc_reader_;
};

std::optional<HostBridge> ParseHostBridge(std::string_view value);
std::string_view HostBridgeName(HostBridge bridge);

NERO_NFC_NODISCARD bool ChooseHostBridge(
    const std::optional<HostBridge>& requested_bridge,
    const std::string& serial_port_arg, const std::string& pcsc_reader_arg,
    HostBridgeSelection& out, std::string& err,
    bool pcsc_share_specified = false);

}  // namespace nero_nfc
