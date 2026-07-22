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

#include "nero_nfc_pcsc.hpp"
#include "nero_nfc_attrs.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace nero_nfc {

void ApplyStorageAtrHint(PcscTagSnapshot& tag);
void ApplyType4ContactlessHint(PcscTagSnapshot& tag);
NERO_NFC_NODISCARD bool HasPcscStorageHint(const PcscTagSnapshot& tag);
NERO_NFC_NODISCARD bool IsPcscStorageType2(const PcscTagSnapshot& tag);
NERO_NFC_NODISCARD bool IsPcscStorageType5(const PcscTagSnapshot& tag);
NERO_NFC_NODISCARD bool LooksLikeNtag21xVersion(
    const std::vector<std::uint8_t>& version);
void AppendDetailLine(PcscTagSnapshot& tag, std::string line);
void ApplyType2Details(PcscTagSnapshot& tag,
                       const std::vector<std::uint8_t>& uid,
                       const std::vector<std::uint8_t>& version,
                       const std::vector<std::uint8_t>& cc,
                       const std::vector<std::uint8_t>& signature,
                       const std::optional<std::uint8_t>& auth0);
void ApplyType4Details(PcscTagSnapshot& tag,
                       const std::vector<std::uint8_t>& uid,
                       const std::vector<std::uint8_t>& cc);
void ApplyType5Details(PcscTagSnapshot& tag,
                       const std::vector<std::uint8_t>& uid,
                       const std::vector<std::uint8_t>& system_info,
                       const std::vector<std::uint8_t>& cc);

}  // namespace nero_nfc
