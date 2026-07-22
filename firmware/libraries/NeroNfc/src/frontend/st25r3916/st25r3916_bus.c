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

#include "st25r3916_bus.h"

#include "nfc_tag_geometry_limits.h"
#include "st25_sketch_spi.h"

#define SPI_FIFO_LOAD 0x80u
#define SPI_FIFO_READ 0x9Fu

void st25_bus_write_reg(const st25_spi_ops_t* spi, uint8_t reg, uint8_t value) {
  spi->bus_begin();
  spi->cs_low();
  spi->spi_xfer(SPI_WRITE_REG(reg));
  spi->spi_xfer(value);
  spi->cs_high();
  spi->bus_end();
}

uint8_t st25_bus_read_reg(const st25_spi_ops_t* spi, uint8_t reg) {
  uint8_t value;
  spi->bus_begin();
  spi->cs_low();
  spi->spi_xfer(SPI_READ_REG(reg));
  value = spi->spi_xfer(0x00u);
  spi->cs_high();
  spi->bus_end();
  return value;
}

void st25_bus_set_reg_bits(const st25_spi_ops_t* spi, uint8_t reg,
                           uint8_t mask) {
  st25_bus_write_reg(spi, reg, (uint8_t)(st25_bus_read_reg(spi, reg) | mask));
}

void st25_bus_clr_reg_bits(const st25_spi_ops_t* spi, uint8_t reg,
                           uint8_t mask) {
  st25_bus_write_reg(spi, reg,
                     (uint8_t)(st25_bus_read_reg(spi, reg) & (uint8_t)(~mask)));
}

void st25_bus_write_reg_b(const st25_spi_ops_t* spi, uint8_t reg,
                          uint8_t value) {
  spi->bus_begin();
  spi->cs_low();
  spi->spi_xfer(ST25R3916_CMD_SPACE_B_ACCESS);
  spi->spi_xfer(SPI_WRITE_REG(reg));
  spi->spi_xfer(value);
  spi->cs_high();
  spi->bus_end();
}

uint8_t st25_bus_read_reg_b(const st25_spi_ops_t* spi, uint8_t reg) {
  uint8_t value;
  spi->bus_begin();
  spi->cs_low();
  spi->spi_xfer(ST25R3916_CMD_SPACE_B_ACCESS);
  spi->spi_xfer(SPI_READ_REG(reg));
  value = spi->spi_xfer(0x00u);
  spi->cs_high();
  spi->bus_end();
  return value;
}

void st25_bus_set_reg_b_bits(const st25_spi_ops_t* spi, uint8_t reg,
                             uint8_t mask) {
  st25_bus_write_reg_b(spi, reg,
                       (uint8_t)(st25_bus_read_reg_b(spi, reg) | mask));
}

void st25_bus_direct_cmd(const st25_spi_ops_t* spi, uint8_t cmd) {
  spi->bus_begin();
  spi->cs_low();
  spi->spi_xfer(cmd);
  spi->cs_high();
  spi->bus_end();
}

void st25_bus_write_fifo(const st25_spi_ops_t* spi, const uint8_t* data,
                         uint16_t len) {
  uint16_t i;
  spi->bus_begin();
  spi->cs_low();
  spi->spi_xfer(SPI_FIFO_LOAD);
  for (i = 0u; i < len; i++) {
    spi->spi_xfer(data[i]);
  }
  spi->cs_high();
  spi->bus_end();
}

uint16_t st25_bus_read_fifo(const st25_spi_ops_t* spi, uint8_t* buffer,
                            uint16_t max_len) {
  uint16_t i;
  uint16_t fifo_len;
  uint8_t fs1 = st25_bus_read_reg(spi, ST25R3916_REG_FIFO_STATUS1);
  uint8_t fs2 = st25_bus_read_reg(spi, ST25R3916_REG_FIFO_STATUS2);

  fifo_len =
      (uint16_t)((uint16_t)(fs1) |
                 (uint16_t)(((uint16_t)((fs2 &
                                         ST25R3916_REG_FIFO_STATUS2_fifo_b_mask) >>
                                        ST25R3916_REG_FIFO_STATUS2_fifo_b_shift))
                            << NFC_BYTE_SHIFT_8));
  if (fifo_len > max_len) {
    fifo_len = max_len;
  }
  if (fifo_len == 0u) {
    return 0u;
  }
  spi->bus_begin();
  spi->cs_low();
  spi->spi_xfer(SPI_FIFO_READ);
  for (i = 0u; i < fifo_len; i++) {
    buffer[i] = spi->spi_xfer(0x00u);
  }
  spi->cs_high();
  spi->bus_end();
  return fifo_len;
}

uint32_t st25_bus_read_irq_regs(const st25_spi_ops_t* spi) {
  uint8_t m;
  uint8_t t;
  uint8_t e;
  uint8_t tg;
  spi->bus_begin();
  spi->cs_low();
  spi->spi_xfer(SPI_READ_REG(ST25R3916_REG_IRQ_MAIN));
  m = spi->spi_xfer(0x00u);
  t = spi->spi_xfer(0x00u);
  e = spi->spi_xfer(0x00u);
  tg = spi->spi_xfer(0x00u);
  spi->cs_high();
  spi->bus_end();
  return (uint32_t)(m) | ((uint32_t)(t) << NFC_BYTE_SHIFT_8) |
         ((uint32_t)(e) << NFC_BYTE_SHIFT_16) |
         ((uint32_t)(tg) << NFC_BYTE_SHIFT_24);
}
