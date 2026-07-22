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

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

namespace nero_nfc {

// RAII wrapper for POSIX opendir(3)/closedir(3). Raw opendir/closedir calls
// belong only in canonical RAII impl files (see RESOURCE_LIFETIME_PAIRS /
// helper-resource-lifetime.py).
class DirHandle {
 public:
  DirHandle() = default;
  ~DirHandle() { Close(); }

  DirHandle(const DirHandle&) = delete;
  DirHandle& operator=(const DirHandle&) = delete;
  DirHandle(DirHandle&&) = delete;
  DirHandle& operator=(DirHandle&&) = delete;

  NERO_NFC_NODISCARD DIR* Open(const char* path) {
    DIR* next = NERO_NFC_NULL;
    int fd = -1;
    if (path == NERO_NFC_NULL) {
      return NERO_NFC_NULL;
    }
    fd = ::open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
      return NERO_NFC_NULL;
    }
    next = ::fdopendir(fd);
    if (next == NERO_NFC_NULL) {
      (void)::close(fd);
      return NERO_NFC_NULL;
    }
    Close();
    dir_ = next;
    return dir_;
  }

  void Close() {
    if (dir_ != NERO_NFC_NULL) {
      (void)::closedir(dir_);
      dir_ = NERO_NFC_NULL;
    }
  }

  [[nodiscard]] DIR* Get() const { return dir_; }

  [[nodiscard]] explicit operator bool() const { return dir_ != NERO_NFC_NULL; }

 private:
  DIR* dir_{NERO_NFC_NULL};
};

}  // namespace nero_nfc
