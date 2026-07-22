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
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace nero_nfc {

struct NdefRecordSummary {
  std::uint8_t tnf_{};
  std::string type_;
  std::vector<std::uint8_t> payload_;
  std::optional<std::string> decoded_;
};

std::vector<std::uint8_t> BuildNdefTextRecord(std::string_view text,
                                              std::string_view lang = "en");
std::vector<std::uint8_t> BuildNdefUriRecord(std::string_view uri);
std::vector<std::uint8_t> BuildNdefMimeRecord(
    std::string_view mime, const std::vector<std::uint8_t>& payload);
std::vector<std::uint8_t> BuildNdefMessage(
    const std::vector<std::vector<std::uint8_t>>& records);
std::vector<NdefRecordSummary> ParseNdefRecords(
    const std::vector<std::uint8_t>& ndef);

}  // namespace nero_nfc
