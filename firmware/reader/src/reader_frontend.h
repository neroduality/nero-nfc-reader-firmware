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

#include "nfc_board_defaults.h"
#include "nero_nfc_attrs.h"
#include "nero_nfc_mem_util.h"
#include "reader_hal.h"

#include <stdbool.h>
#include <stdint.h>

#define ST25_CS_LOW() reader_hal_digital_write(NFC_BOARD_CS_PIN, 0u)
#define ST25_CS_HIGH() reader_hal_digital_write(NFC_BOARD_CS_PIN, 1u)
#define ST25_BUS_BEGIN() reader_hal_spi_begin_transaction()
#define ST25_BUS_END() reader_hal_spi_end_transaction()
#define ST25_SPI_XFER(v) reader_hal_spi_transfer((v))
#include "nfc_frontend_includes.h"
#undef ST25_CS_LOW
#undef ST25_CS_HIGH
#undef ST25_BUS_BEGIN
#undef ST25_BUS_END
#undef ST25_SPI_XFER

static uint32_t reader_frontend_now_ticks_us(void) {
  return reader_hal_micros();
}

static bool reader_frontend_irq_active(void) {
  return reader_hal_digital_read(NFC_BOARD_IRQ_PIN) != 0;
}

static void reader_frontend_clear_irqs(void) {
  nfc_frontend_clear_irqs(nfc_frontend_bus_read_irq_regs);
}

static uint32_t reader_frontend_wait_for_irqs(uint32_t timeout_us) {
  return nfc_frontend_wait_for_irqs(timeout_us, reader_frontend_now_ticks_us,
                                    reader_frontend_irq_active, nfc_frontend_bus_read_irq_regs,
                                    reader_hal_service);
}

static uint32_t reader_frontend_millis(void) {
  return reader_hal_millis();
}

static const nfc_frontend_ops_t READER_FRONTEND_OPS = {
  nfc_frontend_bus_direct_cmd,     nfc_frontend_bus_write_reg,
  nfc_frontend_bus_read_reg,       nfc_frontend_bus_set_reg_bits,
  nfc_frontend_bus_clr_reg_bits,   nfc_frontend_bus_write_reg_b,
  nfc_frontend_bus_set_reg_b_bits, nfc_frontend_bus_write_fifo,
  nfc_frontend_bus_read_fifo,      reader_frontend_clear_irqs,
  reader_frontend_wait_for_irqs,   nfc_frontend_bus_read_irq_regs,
  nfc_frontend_irq_main,           nfc_frontend_irq_timer,
  nfc_frontend_irq_target,         reader_hal_delay_ms,
  reader_frontend_millis,
};

static inline const nfc_frontend_ops_t *reader_frontend_ops(void) {
  return &READER_FRONTEND_OPS;
}

static inline uint8_t reader_frontend_measure_amplitude(void) {
  return nfc_frontend_measure_amplitude(reader_frontend_ops());
}

static inline nfc_frontend_init_status_t reader_frontend_init(uint8_t *chip_id_out,
                                                              uint16_t *vdd_mv_out) {
  return nfc_frontend_init(reader_frontend_ops(), chip_id_out, vdd_mv_out);
}

static inline void reader_frontend_configure_iso14443a(void) {
  nfc_frontend_configure_iso14443a(nfc_frontend_bus_direct_cmd, nfc_frontend_bus_set_reg_bits,
                                   nfc_frontend_bus_write_reg, nfc_frontend_bus_write_reg_b,
                                   nfc_frontend_bus_clr_reg_bits, reader_hal_delay_ms);
}

static inline void reader_frontend_configure_iso15693(void) {
  nfc_frontend_configure_iso15693(nfc_frontend_bus_write_reg, nfc_frontend_bus_write_reg_b,
                                  nfc_frontend_bus_set_reg_bits, nfc_frontend_bus_clr_reg_bits,
                                  reader_hal_delay_ms);
}

static inline nfc_frontend_field_on_status_t reader_frontend_field_on(bool *used_direct) {
  return nfc_frontend_field_on(reader_frontend_ops(), false, true, used_direct);
}

static inline int reader_frontend_transceive(const uint8_t *tx, uint16_t tx_len, uint8_t *rx,
                                             uint16_t rx_max, bool with_crc, uint16_t timeout_ms,
                                             bool anticol, bool no_rx_par, bool extended_nrt_16bit,
                                             bool poll_rx_until_event,
                                             bool clear_nfc_before_fifo_read) {
  return nfc_frontend_transceive(reader_frontend_ops(), tx, tx_len, rx, rx_max, with_crc,
                                 timeout_ms, anticol, no_rx_par, extended_nrt_16bit,
                                 poll_rx_until_event, clear_nfc_before_fifo_read);
}

static inline int reader_frontend_transceive_diag(const uint8_t *tx, uint16_t tx_len, uint8_t *rx,
                                                  uint16_t rx_max, bool with_crc,
                                                  uint16_t timeout_ms, bool anticol, bool no_rx_par,
                                                  bool extended_nrt_16bit, bool poll_rx_until_event,
                                                  bool clear_nfc_before_fifo_read,
                                                  nfc_frontend_transceive_diag_t *diag) {
  return nfc_frontend_transceive_diag(reader_frontend_ops(), tx, tx_len, rx, rx_max, with_crc,
                                      timeout_ms, anticol, no_rx_par, extended_nrt_16bit,
                                      poll_rx_until_event, clear_nfc_before_fifo_read, diag);
}

NERO_NFC_NODISCARD static inline bool reader_frontend_send_wupa(uint8_t *atqa) {
  if (atqa == NERO_NFC_NULL) {
    return false;
  }
  return nfc_frontend_send_short_frame(
    NFC_FRONTEND_CMD_TRANSMIT_WUPA, atqa, nfc_frontend_bus_direct_cmd,
    nfc_frontend_bus_set_reg_bits, nfc_frontend_bus_write_reg, reader_frontend_clear_irqs,
    reader_frontend_wait_for_irqs, reader_hal_delay_ms, nfc_frontend_bus_read_irq_regs,
    nfc_frontend_irq_main, nfc_frontend_bus_read_fifo);
}

NERO_NFC_NODISCARD static inline bool reader_frontend_send_reqa(uint8_t *atqa) {
  if (atqa == NERO_NFC_NULL) {
    return false;
  }
  return nfc_frontend_send_short_frame(
    NFC_FRONTEND_CMD_TRANSMIT_REQA, atqa, nfc_frontend_bus_direct_cmd,
    nfc_frontend_bus_set_reg_bits, nfc_frontend_bus_write_reg, reader_frontend_clear_irqs,
    reader_frontend_wait_for_irqs, reader_hal_delay_ms, nfc_frontend_bus_read_irq_regs,
    nfc_frontend_irq_main, nfc_frontend_bus_read_fifo);
}

static inline int reader_frontend_iso15693_transceive(const uint8_t *tx, uint16_t tx_len,
                                                      uint8_t *rx, uint16_t rx_max,
                                                      uint16_t timeout_ms) {
  uint8_t encoded[NFC_FRONTEND_ISO15693_MAX_STREAM_FRAME];
  uint8_t raw[NFC_FRONTEND_ISO15693_MAX_STREAM_FRAME];
  uint16_t encoded_len = 0u;
  int raw_len;

  if ((tx == NERO_NFC_NULL) || (rx == NERO_NFC_NULL) || (tx_len == 0u) || (rx_max == 0u)) {
    return 0;
  }
  if (!nfc_frontend_iso15693_stream_encode(tx, tx_len, encoded, sizeof(encoded), &encoded_len)) {
    return 0;
  }
  raw_len = reader_frontend_transceive(encoded, encoded_len, raw, sizeof(raw), false, timeout_ms,
                                       false, false, true, true, true);
  if (raw_len <= 0) {
    return 0;
  }
  return nfc_frontend_iso15693_stream_decode(raw, (uint16_t)raw_len, rx, rx_max);
}

static inline void reader_frontend_quiesce(void) {
  nfc_frontend_quiesce(reader_frontend_ops());
}

static inline void reader_frontend_ensure_tx_rx(void) {
  nfc_frontend_ensure_tx_rx(reader_frontend_ops());
}

static inline void reader_frontend_enable_tx_rx(void) {
  nfc_frontend_enable_tx_rx(reader_frontend_ops());
}
