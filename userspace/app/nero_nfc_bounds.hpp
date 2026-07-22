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

#include "nero_nfc_null.h"

#include <cstddef>
#include <span>
#include <stdexcept>
#include <string_view>

namespace nero_nfc {

/* Bounds helpers for cppcoreguidelines-pro-bounds-* on host C++23. */

template <typename T, std::size_t N>
[[nodiscard]] constexpr std::span<T, N> AsSpan(T (&arr)[N]) noexcept {
  return std::span<T, N>{arr};
}

template <typename T, std::size_t N>
[[nodiscard]] constexpr std::span<const T, N> AsSpan(
    const T (&arr)[N]) noexcept {
  return std::span<const T, N>{arr};
}

template <typename T, std::size_t N>
[[nodiscard]] constexpr T& At(T (&arr)[N], std::size_t index) {
  if (index >= N) {
    throw std::out_of_range("nero_nfc::At");
  }
  return AsSpan(arr)[index];
}

template <typename T, std::size_t N>
[[nodiscard]] constexpr const T& At(const T (&arr)[N], std::size_t index) {
  if (index >= N) {
    throw std::out_of_range("nero_nfc::At");
  }
  return AsSpan(arr)[index];
}

[[nodiscard]] inline bool CstrEmpty(const char* s) noexcept {
  if (s == NERO_NFC_NULL) {
    return true;
  }
  return std::string_view{s}.empty();
}

[[nodiscard]] inline const char* CstrData(const char* s) noexcept {
  return s == NERO_NFC_NULL ? "" : s;
}

}  // namespace nero_nfc
