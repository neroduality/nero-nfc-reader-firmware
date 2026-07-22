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

#include "st25r3916_irq.h"

#include "nero_nfc_null.h"
#include "nfc_tag_geometry_limits.h"

uint32_t st25_wait_for_irqs(uint32_t timeout_ticks,
                            st25_now_ticks_fn_t now_ticks,
                            st25_irq_active_fn_t irq_active,
                            st25_read_irq_regs_fn_t read_irq_regs,
                            st25_service_fn_t service) {
  uint32_t start;
  if ((now_ticks == NERO_NFC_NULL) || (irq_active == NERO_NFC_NULL) ||
      (read_irq_regs == NERO_NFC_NULL)) {
    return 0u;
  }
  start = now_ticks();
  while ((now_ticks() - start) < timeout_ticks) {
    if (service != NERO_NFC_NULL) {
      service();
    }
    if (irq_active()) {
      uint32_t status = 0u;
      while (irq_active()) {
        if ((now_ticks() - start) >= timeout_ticks) {
          break;
        }
        if (service != NERO_NFC_NULL) {
          service();
        }
        status |= read_irq_regs();
      }
      return status;
    }
  }
  return 0u;
}

void st25_clear_irqs(st25_read_irq_regs_fn_t read_irq_regs) {
  if (read_irq_regs != NERO_NFC_NULL) {
    (void)read_irq_regs();
  }
}

uint8_t st25_irq_main(uint32_t status) {
  return (uint8_t)(status & NFC_BYTE_VALUE_MAX);
}

uint8_t st25_irq_timer(uint32_t status) {
  return (uint8_t)((status >> NFC_BYTE_SHIFT_8) & NFC_BYTE_VALUE_MAX);
}

uint8_t st25_irq_target(uint32_t status) {
  return (uint8_t)((status >> NFC_BYTE_SHIFT_24) & NFC_BYTE_VALUE_MAX);
}
