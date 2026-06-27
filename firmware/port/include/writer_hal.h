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

#include "nero_nfc_attrs.h"

#ifdef __cplusplus
#include <cstdint>
#else
#include <stdint.h>
#include <stdbool.h>
#endif

enum {
  WRITER_HAL_PIN_OUTPUT = 1,
};

void writer_hal_serial_begin(unsigned long baud);
NERO_NFC_NODISCARD bool writer_hal_serial_ready(void);
void writer_hal_serial_write_char(char c);
NERO_NFC_NODISCARD bool writer_hal_serial_available(void);
int writer_hal_serial_read_byte(void);

void writer_hal_delay_ms(uint32_t ms);
void writer_hal_delay_us(uint32_t us);
uint32_t writer_hal_millis(void);
uint32_t writer_hal_micros(void);

void writer_hal_pin_mode(uint8_t pin, uint8_t mode);
void writer_hal_digital_write(uint8_t pin, uint8_t value);
int writer_hal_digital_read(uint8_t pin);

void writer_hal_spi_begin(void);
void writer_hal_spi_begin_transaction(void);
void writer_hal_spi_end_transaction(void);
uint8_t writer_hal_spi_transfer(uint8_t data);
