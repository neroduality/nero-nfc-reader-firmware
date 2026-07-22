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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
  NERO_NFC_PLATFORM_OPS_ABI_VERSION = 1u,
};

enum {
  NERO_NFC_PIN_INPUT = 0,
  NERO_NFC_PIN_OUTPUT = 1,
};

typedef struct nero_nfc_platform_ops {
  uint32_t abi_version;
  uint32_t struct_size;
  void* context;
  uint32_t (*millis)(void* context);
  uint32_t (*micros)(void* context);
  void (*delay_ms)(void* context, uint32_t ms);
  void (*delay_us)(void* context, uint32_t us);
  void (*service)(void* context);
  void (*serial_begin)(void* context, uint32_t baud);
  bool (*serial_ready)(void* context);
  void (*serial_write_char)(void* context, char c);
  int (*serial_available)(void* context);
  int (*serial_read_byte)(void* context);
  void (*pin_mode)(void* context, uint8_t pin, uint8_t mode);
  void (*digital_write)(void* context, uint8_t pin, uint8_t value);
  int (*digital_read)(void* context, uint8_t pin);
  void (*spi_begin)(void* context);
  void (*spi_begin_transaction)(void* context);
  void (*spi_end_transaction)(void* context);
  uint8_t (*spi_transfer)(void* context, uint8_t data);
} nero_nfc_platform_ops_t;

NERO_NFC_NODISCARD bool nero_nfc_platform_ops_validate(
    const nero_nfc_platform_ops_t* ops);
void nero_nfc_platform_ops_copy(nero_nfc_platform_ops_t* dst,
                                const nero_nfc_platform_ops_t* src);

uint32_t nero_nfc_platform_millis(void);
uint32_t nero_nfc_platform_micros(void);
void nero_nfc_platform_delay_ms(uint32_t ms);
void nero_nfc_platform_delay_us(uint32_t us);
void nero_nfc_platform_service(void);
void nero_nfc_platform_serial_begin(uint32_t baud);
NERO_NFC_NODISCARD bool nero_nfc_platform_serial_ready(void);
void nero_nfc_platform_serial_write_char(char c);
int nero_nfc_platform_serial_available(void);
int nero_nfc_platform_serial_read_byte(void);
void nero_nfc_platform_pin_mode(uint8_t pin, uint8_t mode);
void nero_nfc_platform_digital_write(uint8_t pin, uint8_t value);
int nero_nfc_platform_digital_read(uint8_t pin);
void nero_nfc_platform_spi_begin(void);
void nero_nfc_platform_spi_begin_transaction(void);
void nero_nfc_platform_spi_end_transaction(void);
uint8_t nero_nfc_platform_spi_transfer(uint8_t data);

#ifdef __cplusplus
}
#endif
