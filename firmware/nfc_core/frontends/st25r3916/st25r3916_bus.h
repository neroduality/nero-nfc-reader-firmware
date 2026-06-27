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

#include "st25_sketch_spi.h"

/*
 * Required platform hooks:
 *   ST25_BUS_BEGIN() / ST25_BUS_END()
 *   ST25_CS_LOW() / ST25_CS_HIGH()
 *   ST25_SPI_XFER(value)
 */
#ifndef ST25_BUS_BEGIN
#error "Define ST25_BUS_BEGIN() before including st25r3916_bus.h"
#endif
#ifndef ST25_BUS_END
#error "Define ST25_BUS_END() before including st25r3916_bus.h"
#endif
#ifndef ST25_CS_LOW
#error "Define ST25_CS_LOW() before including st25r3916_bus.h"
#endif
#ifndef ST25_CS_HIGH
#error "Define ST25_CS_HIGH() before including st25r3916_bus.h"
#endif
#ifndef ST25_SPI_XFER
#error "Define ST25_SPI_XFER() before including st25r3916_bus.h"
#endif

static inline void st25_bus_write_reg(uint8_t reg, uint8_t value) {
  ST25_BUS_BEGIN();
  ST25_CS_LOW();
  ST25_SPI_XFER(SPI_WRITE_REG(reg));
  ST25_SPI_XFER(value);
  ST25_CS_HIGH();
  ST25_BUS_END();
}

static inline uint8_t st25_bus_read_reg(uint8_t reg) {
  uint8_t value;
  ST25_BUS_BEGIN();
  ST25_CS_LOW();
  ST25_SPI_XFER(SPI_READ_REG(reg));
  value = ST25_SPI_XFER(0x00u);
  ST25_CS_HIGH();
  ST25_BUS_END();
  return value;
}

static inline void st25_bus_set_reg_bits(uint8_t reg, uint8_t mask) {
  st25_bus_write_reg(reg, (uint8_t)(st25_bus_read_reg(reg) | mask));
}

static inline void st25_bus_clr_reg_bits(uint8_t reg, uint8_t mask) {
  st25_bus_write_reg(reg, (uint8_t)(st25_bus_read_reg(reg) & (uint8_t)~mask));
}

static inline void st25_bus_write_reg_b(uint8_t reg, uint8_t value) {
  ST25_BUS_BEGIN();
  ST25_CS_LOW();
  ST25_SPI_XFER(ST25R3916_CMD_SPACE_B_ACCESS);
  ST25_SPI_XFER(SPI_WRITE_REG(reg));
  ST25_SPI_XFER(value);
  ST25_CS_HIGH();
  ST25_BUS_END();
}

static inline uint8_t st25_bus_read_reg_b(uint8_t reg) {
  uint8_t value;
  ST25_BUS_BEGIN();
  ST25_CS_LOW();
  ST25_SPI_XFER(ST25R3916_CMD_SPACE_B_ACCESS);
  ST25_SPI_XFER(SPI_READ_REG(reg));
  value = ST25_SPI_XFER(0x00u);
  ST25_CS_HIGH();
  ST25_BUS_END();
  return value;
}

static inline void st25_bus_set_reg_b_bits(uint8_t reg, uint8_t mask) {
  st25_bus_write_reg_b(reg, (uint8_t)(st25_bus_read_reg_b(reg) | mask));
}

static inline void st25_bus_direct_cmd(uint8_t cmd) {
  ST25_BUS_BEGIN();
  ST25_CS_LOW();
  ST25_SPI_XFER(cmd);
  ST25_CS_HIGH();
  ST25_BUS_END();
}

static inline void st25_bus_write_fifo(const uint8_t *data, uint16_t len) {
  uint16_t i;
  ST25_BUS_BEGIN();
  ST25_CS_LOW();
  ST25_SPI_XFER(SPI_FIFO_LOAD);
  for (i = 0u; i < len; i++) {
    ST25_SPI_XFER(data[i]);
  }
  ST25_CS_HIGH();
  ST25_BUS_END();
}

static inline uint16_t st25_bus_read_fifo(uint8_t *buffer, uint16_t max_len) {
  uint16_t i;
  uint16_t fifo_len;
  uint8_t fs1 = st25_bus_read_reg(ST25R3916_REG_FIFO_STATUS1);
  uint8_t fs2 = st25_bus_read_reg(ST25R3916_REG_FIFO_STATUS2);

  /* [ST25R3916] FIFO byte count is 10 bits: low 8 in FIFO_STATUS1, high 2 in
   * FIFO_STATUS2[7:6] (fifo_b9/fifo_b8). Bit 0 of FIFO_STATUS2 is a status flag,
   * not part of the count. */
  fifo_len =
    (uint16_t)fs1 | (uint16_t)(((uint16_t)((fs2 & ST25R3916_REG_FIFO_STATUS2_fifo_b_mask) >>
                                           ST25R3916_REG_FIFO_STATUS2_fifo_b_shift))
                               << 8);
  if (fifo_len > max_len) {
    fifo_len = max_len;
  }
  if (fifo_len == 0u) {
    return 0u;
  }

  ST25_BUS_BEGIN();
  ST25_CS_LOW();
  ST25_SPI_XFER(SPI_FIFO_READ);
  for (i = 0u; i < fifo_len; i++) {
    buffer[i] = ST25_SPI_XFER(0x00u);
  }
  ST25_CS_HIGH();
  ST25_BUS_END();
  return fifo_len;
}

static inline uint32_t st25_bus_read_irq_regs(void) {
  uint8_t m;
  uint8_t t;
  uint8_t e;
  uint8_t tg;

  ST25_BUS_BEGIN();
  ST25_CS_LOW();
  ST25_SPI_XFER(SPI_READ_REG(ST25R3916_REG_IRQ_MAIN));
  m = ST25_SPI_XFER(0x00u);
  t = ST25_SPI_XFER(0x00u);
  e = ST25_SPI_XFER(0x00u);
  tg = ST25_SPI_XFER(0x00u);
  ST25_CS_HIGH();
  ST25_BUS_END();

  return (uint32_t)m | ((uint32_t)t << 8) | ((uint32_t)e << 16) | ((uint32_t)tg << 24);
}
