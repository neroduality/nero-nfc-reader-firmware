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

#include <cstdio>

namespace nero_nfc {

// RAII wrapper for stdio fopen(3)/fclose(3). Raw fopen/fclose calls belong only in
// canonical RAII impl files (see RESOURCE_LIFETIME_PAIRS / helper-resource-lifetime.py).
class FileHandle {
public:
  FileHandle() = default;
  ~FileHandle() { close(); }

  FileHandle(const FileHandle &) = delete;
  FileHandle &operator=(const FileHandle &) = delete;
  FileHandle(FileHandle &&) = delete;
  FileHandle &operator=(FileHandle &&) = delete;

  NERO_NFC_NODISCARD FILE *open(const char *path, const char *mode) {
    close();
    fp_ = std::fopen(path, mode);
    return fp_;
  }

  void close() {
    if (fp_ != NERO_NFC_NULL) {
      (void)std::fclose(fp_);
      fp_ = NERO_NFC_NULL;
    }
  }

  [[nodiscard]] FILE *get() const { return fp_; }

  [[nodiscard]] explicit operator bool() const { return fp_ != NERO_NFC_NULL; }

private:
  FILE *fp_{NERO_NFC_NULL};
};

} // namespace nero_nfc
