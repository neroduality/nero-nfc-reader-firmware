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

#include <stdbool.h>
#include <stdint.h>

typedef uint32_t (*st25_now_ticks_fn_t)(void);
typedef bool (*st25_irq_active_fn_t)(void);
typedef uint32_t (*st25_read_irq_regs_fn_t)(void);
typedef void (*st25_service_fn_t)(void);

uint32_t st25_wait_for_irqs(uint32_t timeout_ticks,
                            st25_now_ticks_fn_t now_ticks,
                            st25_irq_active_fn_t irq_active,
                            st25_read_irq_regs_fn_t read_irq_regs,
                            st25_service_fn_t service);
void st25_clear_irqs(st25_read_irq_regs_fn_t read_irq_regs);
uint8_t st25_irq_main(uint32_t status);
uint8_t st25_irq_timer(uint32_t status);
uint8_t st25_irq_target(uint32_t status);
