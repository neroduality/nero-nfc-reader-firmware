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

#include <stdint.h>

/*
 * GCC stack protector runtime hooks for bare-metal Arduino builds.
 * The compiler emits unmangled references to `__stack_chk_guard` /
 * `__stack_chk_fail`. Bind GNU assembler aliases to non-reserved C identifiers.
 */

#define NERO_STACK_CHK_GUARD_VALUE UINT32_C(0xA5F39C1D)

uintptr_t nero_stack_chk_guard = (uintptr_t)NERO_STACK_CHK_GUARD_VALUE;

__asm__(
    ".global __stack_chk_guard\n"
    ".set __stack_chk_guard, nero_stack_chk_guard\n"
    ".global __stack_chk_fail\n"
    ".set __stack_chk_fail, nero_stack_chk_fail");

__attribute__((noreturn)) void nero_stack_chk_fail(void) {
  for (;;) {
  }
}

__attribute__((constructor)) static void nero_stack_chk_guard_init(void) {
  nero_stack_chk_guard ^= (uintptr_t)&nero_stack_chk_guard;
  if (nero_stack_chk_guard == 0u) {
    nero_stack_chk_guard = (uintptr_t)NERO_STACK_CHK_GUARD_VALUE;
  }
}
