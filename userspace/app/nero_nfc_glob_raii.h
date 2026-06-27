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
#include "nero_nfc_null.h"

#include <cstddef>
#include <glob.h>

namespace nero_nfc {

// RAII wrapper for POSIX glob(3)/globfree(3). Raw glob/globfree calls belong only
// in canonical RAII impl files (see RESOURCE_LIFETIME_PAIRS / helper-resource-lifetime.py).
class GlobResult {
public:
  GlobResult() = default;
  ~GlobResult() { globfree(&g_); }

  GlobResult(const GlobResult &) = delete;
  GlobResult &operator=(const GlobResult &) = delete;
  GlobResult(GlobResult &&) = delete;
  GlobResult &operator=(GlobResult &&) = delete;

  NERO_NFC_NODISCARD int match(const char *pattern) { return glob(pattern, 0, NERO_NFC_NULL, &g_); }

  [[nodiscard]] size_t count() const { return g_.gl_pathc; }

  [[nodiscard]] const char *path(size_t index) const { return g_.gl_pathv[index]; }

private:
  glob_t g_{};
};

} // namespace nero_nfc
