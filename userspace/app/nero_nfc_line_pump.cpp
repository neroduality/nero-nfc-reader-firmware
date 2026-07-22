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

#include "nero_nfc_line_pump.hpp"

#include "nero_nfc_null.h"

#include <span>
#include <string_view>

namespace nero_nfc {

bool IsBrowserLine(const std::string& line) {
  return line.starts_with(kBrowserTrigger);
}

std::string ExtractBrowserUrl(const std::string& line) {
  if (!IsBrowserLine(line)) {
    return {};
  }
  return line.substr(std::string_view(kBrowserTrigger).size());
}

std::string StripCr(const std::string& line) {
  if (!line.empty() && line.back() == '\r') {
    return line.substr(0, line.size() - 1);
  }
  return line;
}

LinePump::LinePump(LineCallback cb) : line_callback_(std::move(cb)) {}

void LinePump::Feed(const char* data, size_t len) {
  if ((data == NERO_NFC_NULL) && (len != 0u)) {
    return;
  }
  const auto kBytes = std::span<const char>(data, len);
  for (char c : kBytes) {
    if (c == '\n') {
      if (!dropping_oversized_line_ && line_callback_) {
        line_callback_(StripCr(line_buffer_));
      }
      line_buffer_.clear();
      dropping_oversized_line_ = false;
    } else {
      if (!dropping_oversized_line_ && line_buffer_.size() < kMaxBufBytes) {
        line_buffer_.push_back(c);
      } else {
        line_buffer_.clear();
        dropping_oversized_line_ = true;
      }
    }
  }
}

}  // namespace nero_nfc
