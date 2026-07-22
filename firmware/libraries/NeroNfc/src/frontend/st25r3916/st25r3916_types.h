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

#include <stdint.h>

typedef void (*st25_cmd_fn_t)(uint8_t cmd);
typedef void (*st25_write_reg_fn_t)(uint8_t reg, uint8_t value);
typedef uint8_t (*st25_read_reg_fn_t)(uint8_t reg);
typedef void (*st25_reg_bits_fn_t)(uint8_t reg, uint8_t mask);
typedef void (*st25_write_fifo_fn_t)(const uint8_t* data, uint16_t len);
typedef uint16_t (*st25_read_fifo_fn_t)(uint8_t* buffer, uint16_t max_len);
typedef void (*st25_void_fn_t)(void);
typedef uint32_t (*st25_wait_irqs_fn_t)(uint32_t timeout_ticks);
typedef uint32_t (*st25_read_irq_regs_fn_t)(void);
typedef uint8_t (*st25_irq_extract_fn_t)(uint32_t status);
typedef void (*st25_delay_ms_fn_t)(uint32_t ms);
typedef uint32_t (*st25_millis_fn_t)(void);
