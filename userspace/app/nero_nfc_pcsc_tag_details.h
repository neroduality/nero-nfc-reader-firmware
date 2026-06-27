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

#include "nero_nfc_pcsc.h"
#include "nero_nfc_attrs.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace nero_nfc {

void apply_storage_atr_hint(PcscTagSnapshot &tag);
void apply_type4_contactless_hint(PcscTagSnapshot &tag);
NERO_NFC_NODISCARD bool has_pcsc_storage_hint(const PcscTagSnapshot &tag);
NERO_NFC_NODISCARD bool is_pcsc_storage_type2(const PcscTagSnapshot &tag);
NERO_NFC_NODISCARD bool is_pcsc_storage_type5(const PcscTagSnapshot &tag);
NERO_NFC_NODISCARD bool looks_like_ntag21x_version(const std::vector<std::uint8_t> &version);
void append_detail_line(PcscTagSnapshot &tag, std::string line);
void apply_type2_details(PcscTagSnapshot &tag, const std::vector<std::uint8_t> &uid,
                         const std::vector<std::uint8_t> &version,
                         const std::vector<std::uint8_t> &cc,
                         const std::vector<std::uint8_t> &signature,
                         const std::optional<std::uint8_t> &auth0);
void apply_type4_details(PcscTagSnapshot &tag, const std::vector<std::uint8_t> &uid,
                         const std::vector<std::uint8_t> &cc);
void apply_type5_details(PcscTagSnapshot &tag, const std::vector<std::uint8_t> &uid,
                         const std::vector<std::uint8_t> &system_info,
                         const std::vector<std::uint8_t> &cc);

} // namespace nero_nfc
