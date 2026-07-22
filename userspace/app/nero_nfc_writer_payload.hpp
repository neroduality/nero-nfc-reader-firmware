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

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace nero_nfc {

std::string WriterUrlComponentEncode(std::string_view text);
std::vector<std::uint8_t> BuildWriterVcardRecord(std::string_view spec);
std::vector<std::uint8_t> BuildWriterMailRecord(std::string_view spec);
std::vector<std::uint8_t> BuildWriterSmsRecord(std::string_view spec);
std::vector<std::uint8_t> BuildWriterBluetoothRecord(std::string_view value);
std::vector<std::uint8_t> BuildWriterWifiRecord(std::string_view spec);
void NormalizeWriterNdefHexPayload(std::vector<std::uint8_t>& bytes);

}  // namespace nero_nfc
