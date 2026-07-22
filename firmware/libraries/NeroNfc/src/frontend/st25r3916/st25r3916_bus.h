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

typedef struct {
  void (*bus_begin)(void);
  void (*bus_end)(void);
  void (*cs_low)(void);
  void (*cs_high)(void);
  uint8_t (*spi_xfer)(uint8_t value);
} st25_spi_ops_t;

void st25_bus_write_reg(const st25_spi_ops_t* spi, uint8_t reg, uint8_t value);
uint8_t st25_bus_read_reg(const st25_spi_ops_t* spi, uint8_t reg);
void st25_bus_set_reg_bits(const st25_spi_ops_t* spi, uint8_t reg,
                           uint8_t mask);
void st25_bus_clr_reg_bits(const st25_spi_ops_t* spi, uint8_t reg,
                           uint8_t mask);
void st25_bus_write_reg_b(const st25_spi_ops_t* spi, uint8_t reg,
                          uint8_t value);
uint8_t st25_bus_read_reg_b(const st25_spi_ops_t* spi, uint8_t reg);
void st25_bus_set_reg_b_bits(const st25_spi_ops_t* spi, uint8_t reg,
                             uint8_t mask);
void st25_bus_direct_cmd(const st25_spi_ops_t* spi, uint8_t cmd);
void st25_bus_write_fifo(const st25_spi_ops_t* spi, const uint8_t* data,
                         uint16_t len);
uint16_t st25_bus_read_fifo(const st25_spi_ops_t* spi, uint8_t* buffer,
                            uint16_t max_len);
uint32_t st25_bus_read_irq_regs(const st25_spi_ops_t* spi);
