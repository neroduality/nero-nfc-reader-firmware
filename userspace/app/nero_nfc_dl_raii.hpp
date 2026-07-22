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

#include <dlfcn.h>

namespace nero_nfc {

// RAII wrapper for dlopen(3)/dlclose(3). Raw dlopen/dlclose calls belong only
// in canonical RAII impl files (see RESOURCE_LIFETIME_PAIRS /
// helper-resource-lifetime.py).
class DlHandle {
 public:
  DlHandle() = default;
  ~DlHandle() { Close(); }

  DlHandle(const DlHandle&) = delete;
  DlHandle& operator=(const DlHandle&) = delete;
  DlHandle(DlHandle&&) = delete;
  DlHandle& operator=(DlHandle&&) = delete;

  NERO_NFC_NODISCARD void* Open(const char* path, int flags) {
    size_t path_len = 0u;
    Close();
    if (path == NERO_NFC_NULL ||
        !nero_nfc_bounded_strlen(path, NERO_NFC_HOST_SERIAL_LINE_MAX,
                                 &path_len) ||
        path_len == 0u ||
        (((flags & RTLD_LAZY) != 0) == ((flags & RTLD_NOW) != 0))) {
      return NERO_NFC_NULL;
    }
    /* Never export dynamically loaded symbols into the global namespace. */
    flags = (flags & ~RTLD_GLOBAL) | RTLD_LOCAL;
    handle_ = ::dlopen(path, flags);
    return handle_;
  }

  void Close() {
    if (handle_ != NERO_NFC_NULL) {
      (void)::dlclose(handle_);
      handle_ = NERO_NFC_NULL;
    }
  }

  [[nodiscard]] void* Get() const { return handle_; }

  [[nodiscard]] explicit operator bool() const {
    return handle_ != NERO_NFC_NULL;
  }

 private:
  void* handle_{NERO_NFC_NULL};
};

}  // namespace nero_nfc
