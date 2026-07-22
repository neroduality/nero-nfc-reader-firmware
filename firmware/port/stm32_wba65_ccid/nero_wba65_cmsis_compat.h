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

/*
 * STM32 Arduino core 2.12.0 ships STM32WBA65xx CMSIS headers that rename some
 * classic CMSIS-5 identifiers (IRQn → IR_QN; system header declares
 * system_core_clock while system_stm32wbaxx.c still defines SystemCoreClock).
 * TinyUSB and owned WBA USB setup still use the classic names.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Vendor object file still exports the classic CMSIS symbol name. TinyUSB
 * compile flags map SystemCoreClock → system_core_clock (-D), so this header
 * stays C-identifier clean for clang-tidy.
 */
extern uint32_t system_core_clock __asm__("SystemCoreClock");

#ifdef __cplusplus
}
#endif

#if defined(USB_OTG_HS_IR_QN) && !defined(USB_OTG_HS_IRQn)
#define USB_OTG_HS_IRQn USB_OTG_HS_IR_QN
#endif
