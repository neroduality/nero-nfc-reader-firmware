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

#include <format>
#include <string_view>
#include <utility>

namespace nero_nfc {

void nero_nfc_stderr_line(const char *s);
void nero_nfc_stderr_line(std::string_view s);
void nero_nfc_stdout_line(const char *s);
void nero_nfc_stdout_line(std::string_view s);

template <typename... Args>
  requires(sizeof...(Args) > 0)
void nero_nfc_stderr_line(std::format_string<Args...> fmt, Args &&...args) {
  nero_nfc_stderr_line(std::format(fmt, std::forward<Args>(args)...));
}

template <typename... Args>
  requires(sizeof...(Args) > 0)
void nero_nfc_stdout_line(std::format_string<Args...> fmt, Args &&...args) {
  nero_nfc_stdout_line(std::format(fmt, std::forward<Args>(args)...));
}

} // namespace nero_nfc
