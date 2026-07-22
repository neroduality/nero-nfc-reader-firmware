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

#include "nero_nfc_io.hpp"

#include "nero_nfc_limits.h"
#include "nero_nfc_mem_util.h"
#include "nero_nfc_null.h"

#include <cstdio>
#include <string_view>

namespace {

bool NeroNfcWriteAll(FILE* stream, std::string_view s) {
  std::size_t written = 0;
  if (stream == NERO_NFC_NULL) {
    return false;
  }
  while (written < s.size()) {
    const std::string_view kRemaining = s.substr(written);
    const std::size_t kN =
        std::fwrite(kRemaining.data(), 1, kRemaining.size(), stream);
    if (kN == 0) {
      return false;
    }
    written += kN;
  }
  return true;
}

void NeroNfcWriteLine(FILE* stream, std::string_view s, bool preserve_cr) {
  if (stream == NERO_NFC_NULL) {
    return;
  }
  ::flockfile(stream);
  if (!NeroNfcWriteAll(stream, s)) {
    ::funlockfile(stream);
    return;
  }
  if ((!preserve_cr || s.empty() || s.back() != '\r') &&
      std::fputc('\n', stream) != '\n') {
    ::funlockfile(stream);
    return;
  }
  (void)std::fflush(stream);
  ::funlockfile(stream);
}

void NeroNfcWriteStderrLineImpl(std::string_view s) {
  NeroNfcWriteLine(stderr, s, true);
}

void NeroNfcWriteStdoutLineImpl(std::string_view s) {
  NeroNfcWriteLine(stdout, s, false);
}

}  // namespace

namespace nero_nfc {

void NeroNfcStderrLine(std::string_view s) { NeroNfcWriteStderrLineImpl(s); }

void NeroNfcStderrLine(const char* s) {
  std::size_t len = 0u;
  if (s == NERO_NFC_NULL) {
    return;
  }
  if (!nero_nfc_bounded_strlen(s, NERO_NFC_HOST_SERIAL_LINE_MAX, &len)) {
    return;
  }
  NeroNfcWriteStderrLineImpl(std::string_view(s, len));
}

void NeroNfcStdoutLine(std::string_view s) { NeroNfcWriteStdoutLineImpl(s); }

void NeroNfcStdoutLine(const char* s) {
  std::size_t len = 0u;
  if (s == NERO_NFC_NULL) {
    return;
  }
  if (!nero_nfc_bounded_strlen(s, NERO_NFC_HOST_SERIAL_LINE_MAX, &len)) {
    return;
  }
  NeroNfcWriteStdoutLineImpl(std::string_view(s, len));
}

int NeroNfcStdoutFlush() { return std::fflush(stdout); }

}  // namespace nero_nfc
