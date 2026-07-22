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
#include "nero_nfc_limits.h"
#include "nero_nfc_mem_util.h"
#include "nero_nfc_null.h"

#include <cstddef>
#include <glob.h>
#include <span>

namespace nero_nfc {

// RAII wrapper for POSIX glob(3)/globfree(3). Raw glob/globfree calls belong
// only in canonical RAII impl files (see RESOURCE_LIFETIME_PAIRS /
// helper-resource-lifetime.py).
class GlobResult {
 public:
  GlobResult() = default;
  ~GlobResult() { Release(); }

  GlobResult(const GlobResult&) = delete;
  GlobResult& operator=(const GlobResult&) = delete;
  GlobResult(GlobResult&&) = delete;
  GlobResult& operator=(GlobResult&&) = delete;

  NERO_NFC_NODISCARD int Match(const char* pattern) {
    size_t pattern_len = 0u;
    Release();
    if (pattern == NERO_NFC_NULL ||
        !nero_nfc_bounded_strlen(pattern, NERO_NFC_HOST_SERIAL_LINE_MAX,
                                 &pattern_len) ||
        pattern_len == 0u) {
      return GLOB_NOMATCH;
    }
    const int kRc = ::glob(pattern, 0, NERO_NFC_NULL, &g_);
    if (kRc == 0) {
      owned_ = true;
    } else {
      /* glob() may leave partial allocations on failure (notably
       * GLOB_NOSPACE); release them before resetting the result. */
      ::globfree(&g_);
      g_ = {};
    }
    return kRc;
  }

  void Release() {
    if (owned_) {
      ::globfree(&g_);
      owned_ = false;
      g_ = {};
    }
  }

  [[nodiscard]] size_t Count() const { return owned_ ? g_.gl_pathc : 0u; }

  [[nodiscard]] const char* Path(size_t index) const {
    if (!owned_ || g_.gl_pathv == NERO_NFC_NULL || index >= g_.gl_pathc) {
      return NERO_NFC_NULL;
    }
    const auto kPaths =
        std::span<char* const>{g_.gl_pathv, static_cast<size_t>(g_.gl_pathc)};
    return kPaths[index];
  }

 private:
  glob_t g_{};
  bool owned_{false};
};

}  // namespace nero_nfc
