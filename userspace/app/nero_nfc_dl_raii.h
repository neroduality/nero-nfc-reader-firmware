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

#include <dlfcn.h>

namespace nero_nfc {

// RAII wrapper for dlopen(3)/dlclose(3). Raw dlopen/dlclose calls belong only in
// canonical RAII impl files (see RESOURCE_LIFETIME_PAIRS / helper-resource-lifetime.py).
class DlHandle {
public:
  DlHandle() = default;
  ~DlHandle() { close(); }

  DlHandle(const DlHandle &) = delete;
  DlHandle &operator=(const DlHandle &) = delete;
  DlHandle(DlHandle &&) = delete;
  DlHandle &operator=(DlHandle &&) = delete;

  NERO_NFC_NODISCARD void *open(const char *path, int flags) {
    close();
    handle_ = ::dlopen(path, flags);
    return handle_;
  }

  void close() {
    if (handle_ != NERO_NFC_NULL) {
      (void)::dlclose(handle_);
      handle_ = NERO_NFC_NULL;
    }
  }

  [[nodiscard]] void *get() const { return handle_; }

  [[nodiscard]] explicit operator bool() const { return handle_ != NERO_NFC_NULL; }

private:
  void *handle_{NERO_NFC_NULL};
};

} // namespace nero_nfc
