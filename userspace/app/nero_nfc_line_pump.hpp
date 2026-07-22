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

#include <functional>
#include "nero_nfc_attrs.h"
#include "nero_nfc_limits.h"

#include <string>

namespace nero_nfc {

static constexpr const char* kBrowserTrigger = "BROWSER_OPEN:";

// Return true when a complete line starts with the browser-open trigger.
NERO_NFC_NODISCARD bool IsBrowserLine(const std::string& line);

// Extract the URL from a browser-open line (everything after "BROWSER_OPEN:").
std::string ExtractBrowserUrl(const std::string& line);

// Strip a trailing carriage return from a line.
std::string StripCr(const std::string& line);

// Line-oriented accumulator. Feed raw bytes; on each complete line the
// callback is invoked. Lines are split on '\n'; a trailing '\r' is stripped.
// Internal buffer is capped at kMaxBufBytes; lines that exceed the cap are
// dropped through the next newline (not truncated and emitted).
class LinePump {
 public:
  static constexpr size_t kMaxBufBytes = NERO_NFC_HOST_SERIAL_LINE_MAX;

  using LineCallback = std::function<void(const std::string&)>;

  explicit LinePump(LineCallback cb);

  // Ingest raw bytes. Calls callback for every complete line found.
  void Feed(const char* data, size_t len);

  // Return how many bytes are buffered without a terminating newline.
  [[nodiscard]] size_t PendingBytes() const { return line_buffer_.size(); }

 private:
  std::string line_buffer_;
  LineCallback line_callback_;
  bool dropping_oversized_line_{false};
};

}  // namespace nero_nfc
