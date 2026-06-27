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

#include <cstdint>

/*
 * GCC stack protector runtime hooks for bare-metal Arduino builds.
 * These symbols must use C linkage — the compiler emits unmangled references.
 *
 * The guard is non-zero and includes its own address to avoid a fully static
 * literal value across link layouts.
 */
namespace {

enum : std::uintptr_t {
  kNeroStackChkGuard = 0xA5F39C1Du,
};

} // namespace

extern "C" {

uintptr_t __stack_chk_guard = static_cast<uintptr_t>(kNeroStackChkGuard);

__attribute__((noreturn)) void __stack_chk_fail(void) {
  while (true) {}
}
}

namespace {

__attribute__((constructor)) void stack_chk_guard_init(void) {
  __stack_chk_guard ^= reinterpret_cast<uintptr_t>(&__stack_chk_guard);
  if (__stack_chk_guard == 0u) {
    __stack_chk_guard = static_cast<uintptr_t>(kNeroStackChkGuard);
  }
}

} // namespace
