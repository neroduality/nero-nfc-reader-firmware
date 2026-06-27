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

static inline uint32_t st25_wait_for_irqs(uint32_t timeout_ticks, st25_now_ticks_fn_t now_ticks,
                                          st25_irq_active_fn_t irq_active,
                                          st25_read_irq_regs_fn_t read_irq_regs,
                                          st25_service_fn_t service) {
  uint32_t start;

  if ((now_ticks == (st25_now_ticks_fn_t)0) || (irq_active == (st25_irq_active_fn_t)0) ||
      (read_irq_regs == (st25_read_irq_regs_fn_t)0)) {
    return 0u;
  }

  start = now_ticks();
  while ((now_ticks() - start) < timeout_ticks) {
    if (service != (st25_service_fn_t)0) {
      service();
    }
    if (irq_active()) {
      uint32_t status = 0u;
      while (irq_active()) {
        /* [ST25R3916] Bound the drain loop by the overall timeout so a stuck-high
         * IRQ line cannot hang the reader forever. */
        if ((now_ticks() - start) >= timeout_ticks) {
          break;
        }
        if (service != (st25_service_fn_t)0) {
          service();
        }
        status |= read_irq_regs();
      }
      return status;
    }
  }
  return 0u;
}

static inline void st25_clear_irqs(st25_read_irq_regs_fn_t read_irq_regs) {
  if (read_irq_regs != (st25_read_irq_regs_fn_t)0) {
    (void)read_irq_regs();
  }
}

static inline uint8_t st25_irq_main(uint32_t status) {
  return (uint8_t)(status & 0xFFu);
}

static inline uint8_t st25_irq_timer(uint32_t status) {
  return (uint8_t)((status >> 8) & 0xFFu);
}

static inline uint8_t st25_irq_target(uint32_t status) {
  return (uint8_t)((status >> 24) & 0xFFu);
}
