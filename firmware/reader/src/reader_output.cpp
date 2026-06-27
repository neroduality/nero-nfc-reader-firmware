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

#include "nero_nfc_null.h"
#include "reader_output.h"

#include <cstring>

enum {
  kReaderOutputUrlHttpsPrefixLen = 8u,
  kReaderOutputUrlHttpPrefixLen = 7u,
};

bool reader_is_url_safe_char(uint8_t ch) {
  if (((ch >= (uint8_t)'a') && (ch <= (uint8_t)'z')) ||
      ((ch >= (uint8_t)'A') && (ch <= (uint8_t)'Z')) ||
      ((ch >= (uint8_t)'0') && (ch <= (uint8_t)'9'))) {
    return true;
  }
  return std::strchr("-._~:/?#[]@!$&'()*+,;=%", static_cast<int>(ch)) != NERO_NFC_NULL;
}

bool reader_is_browser_safe_url(const char *url) {
  if (url == NERO_NFC_NULL) {
    return false;
  }
  return (strncmp(url, "https://", kReaderOutputUrlHttpsPrefixLen) == 0) ||
         (strncmp(url, "http://", kReaderOutputUrlHttpPrefixLen) == 0);
}
