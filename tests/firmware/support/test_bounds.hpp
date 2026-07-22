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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>

namespace nero_nfc_test {

inline void FillBytes(uint8_t* dst, std::size_t len, uint8_t value) {
  std::fill_n(dst, len, value);
}

template <typename T, std::size_t N>
[[nodiscard]] constexpr T& At(T (&arr)[N], std::size_t index) {
  if (index >= N) {
    throw std::out_of_range("nero_nfc_test::At");
  }
  return arr[index];
}

template <typename T, std::size_t N>
[[nodiscard]] constexpr const T& At(const T (&arr)[N], std::size_t index) {
  if (index >= N) {
    throw std::out_of_range("nero_nfc_test::At");
  }
  return arr[index];
}

}  // namespace nero_nfc_test
