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

#include "nero_nfc_io.h"

#include "nero_nfc_null.h"

#include <cstdio>
#include <print>
#include <string_view>

namespace {

void nero_nfc_write_stderr_line_impl(std::string_view s) {
  if (!s.empty() && s.back() == '\r') {
    std::fwrite(s.data(), 1, s.size(), stderr);
    std::fflush(stderr);
    return;
  }
  std::println(stderr, "{}", s);
}

void nero_nfc_write_stdout_line_impl(std::string_view s) {
  std::println("{}", s);
  std::fflush(stdout);
}

} // namespace

namespace nero_nfc {

void nero_nfc_stderr_line(std::string_view s) {
  nero_nfc_write_stderr_line_impl(s);
}

void nero_nfc_stderr_line(const char *s) {
  if (s == NERO_NFC_NULL) {
    return;
  }
  nero_nfc_write_stderr_line_impl(std::string_view(s));
}

void nero_nfc_stdout_line(std::string_view s) {
  nero_nfc_write_stdout_line_impl(s);
}

void nero_nfc_stdout_line(const char *s) {
  if (s == NERO_NFC_NULL) {
    return;
  }
  nero_nfc_write_stdout_line_impl(std::string_view(s));
}

} // namespace nero_nfc
