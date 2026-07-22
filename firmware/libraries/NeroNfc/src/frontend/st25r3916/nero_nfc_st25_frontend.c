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

/*
 * Shared ST25R3916 frontend binding for reader and writer (§3).
 * Uses nero_nfc_platform_* so both products share one physical frontend.
 */

#include "nero_nfc_app.h"
#include "nero_nfc_attrs.h"
#include "nero_nfc_frontend.h"
#include "nero_nfc_mem_util.h"
#include "nero_nfc_null.h"
#include "nero_nfc_platform.h"
#include "nfc_frontend_includes.h"
#include "reader_hal.h"
#include "st25_sketch_spi.h"

#include <stdbool.h>
#include <stdint.h>

enum {
  ST25_CONFIGURED_PROTOCOL_ISO14443A = 1u,
  ST25_CONFIGURED_PROTOCOL_ISO15693 = 2u,
};

static const nero_nfc_board_config_t* st25_bind_board(void) {
  return nero_nfc_app_board(nero_nfc_app_active());
}

// Reader SPI bus binding: the st25_bus_* primitives call through these into the
// reader HAL. Per-mode wrappers adapt the (const st25_spi_ops_t*, ...) bus
// signatures to the fixed st25_frontend_ops_t function-pointer types.
static inline void st25_bind_cs_low(void) {
  const nero_nfc_board_config_t* board = st25_bind_board();
  if (board == NERO_NFC_NULL) {
    return;
  }
  nero_nfc_platform_digital_write(board->cs_pin, 0u);
}
static inline void st25_bind_cs_high(void) {
  const nero_nfc_board_config_t* board = st25_bind_board();
  if (board == NERO_NFC_NULL) {
    return;
  }
  nero_nfc_platform_digital_write(board->cs_pin, 1u);
}
static const st25_spi_ops_t ST25_BIND_SPI = {
    nero_nfc_platform_spi_begin_transaction,
    nero_nfc_platform_spi_end_transaction, st25_bind_cs_low, st25_bind_cs_high,
    nero_nfc_platform_spi_transfer};

static inline void st25_bind_bus_direct_cmd(uint8_t cmd) {
  st25_bus_direct_cmd(&ST25_BIND_SPI, cmd);
}
static inline void st25_bind_bus_write_reg(uint8_t reg, uint8_t value) {
  st25_bus_write_reg(&ST25_BIND_SPI, reg, value);
}
static inline uint8_t st25_bind_bus_read_reg(uint8_t reg) {
  return st25_bus_read_reg(&ST25_BIND_SPI, reg);
}
static inline void st25_bind_bus_set_reg_bits(uint8_t reg, uint8_t mask) {
  st25_bus_set_reg_bits(&ST25_BIND_SPI, reg, mask);
}
static inline void st25_bind_bus_clr_reg_bits(uint8_t reg, uint8_t mask) {
  st25_bus_clr_reg_bits(&ST25_BIND_SPI, reg, mask);
}
static inline void st25_bind_bus_write_reg_b(uint8_t reg, uint8_t value) {
  st25_bus_write_reg_b(&ST25_BIND_SPI, reg, value);
}
static inline void st25_bind_bus_set_reg_b_bits(uint8_t reg, uint8_t mask) {
  st25_bus_set_reg_b_bits(&ST25_BIND_SPI, reg, mask);
}
static inline void st25_bind_bus_write_fifo(const uint8_t* data, uint16_t len) {
  st25_bus_write_fifo(&ST25_BIND_SPI, data, len);
}
static inline uint16_t st25_bind_bus_read_fifo(uint8_t* buffer,
                                               uint16_t max_len) {
  return st25_bus_read_fifo(&ST25_BIND_SPI, buffer, max_len);
}
static inline uint32_t st25_bind_bus_read_irq_regs(void) {
  return st25_bus_read_irq_regs(&ST25_BIND_SPI);
}

static uint32_t st25_bind_frontend_now_ticks_us(void) {
  return nero_nfc_platform_micros();
}

static bool st25_bind_frontend_irq_active(void) {
  const nero_nfc_board_config_t* board = st25_bind_board();
  if (board == NERO_NFC_NULL) {
    return false;
  }
  return nero_nfc_platform_digital_read(board->irq_pin) != 0;
}

static void st25_bind_frontend_clear_irqs(void) {
  st25_frontend_clear_irqs(st25_bind_bus_read_irq_regs);
}

static uint32_t st25_bind_frontend_wait_for_irqs(uint32_t timeout_us) {
  return st25_frontend_wait_for_irqs(
      timeout_us, st25_bind_frontend_now_ticks_us,
      st25_bind_frontend_irq_active, st25_bind_bus_read_irq_regs,
      reader_hal_service);
}

static uint32_t st25_bind_frontend_millis(void) {
  return nero_nfc_platform_millis();
}

static const st25_frontend_ops_t ST25_BIND_FRONTEND_OPS_TABLE = {
    st25_bind_bus_direct_cmd,         st25_bind_bus_write_reg,
    st25_bind_bus_read_reg,           st25_bind_bus_set_reg_bits,
    st25_bind_bus_clr_reg_bits,       st25_bind_bus_write_reg_b,
    st25_bind_bus_set_reg_b_bits,     st25_bind_bus_write_fifo,
    st25_bind_bus_read_fifo,          st25_bind_frontend_clear_irqs,
    st25_bind_frontend_wait_for_irqs, st25_bind_bus_read_irq_regs,
    st25_frontend_irq_main,           st25_frontend_irq_timer,
    st25_frontend_irq_target,         reader_hal_delay_ms,
    st25_bind_frontend_millis,
};

static inline const st25_frontend_ops_t* st25_bind_frontend_ops(void) {
  return &ST25_BIND_FRONTEND_OPS_TABLE;
}

static uint8_t st25_impl_measure_amplitude(void* state) {
  (void)state;
  return st25_frontend_measure_amplitude(st25_bind_frontend_ops());
}

static nfc_frontend_init_status_t st25_impl_init(void* state,
                                                 uint8_t* chip_id_out,
                                                 uint16_t* vdd_mv_out) {
  st25r3916_t* st25 = (st25r3916_t*)state;
  nfc_frontend_init_status_t result =
      st25_frontend_init(st25_bind_frontend_ops(), chip_id_out, vdd_mv_out);
  if (st25 != NERO_NFC_NULL) {
    st25->chip_id = (chip_id_out == NERO_NFC_NULL) ? 0u : *chip_id_out;
    st25->vdd_mv = (vdd_mv_out == NERO_NFC_NULL) ? 0u : *vdd_mv_out;
    st25->initialized = result == NFC_FRONTEND_INIT_OK;
  }
  return result;
}

static void st25_impl_configure_iso14443a(void* state) {
  st25r3916_t* st25 = (st25r3916_t*)state;
  st25_frontend_configure_iso14443a(
      st25_bind_bus_direct_cmd, st25_bind_bus_set_reg_bits,
      st25_bind_bus_write_reg, st25_bind_bus_write_reg_b,
      st25_bind_bus_clr_reg_bits, reader_hal_delay_ms);
  if (st25 != NERO_NFC_NULL) {
    st25->configured_protocol = ST25_CONFIGURED_PROTOCOL_ISO14443A;
  }
}

static void st25_impl_configure_iso15693(void* state) {
  st25r3916_t* st25 = (st25r3916_t*)state;
  st25_frontend_configure_iso15693(
      st25_bind_bus_write_reg, st25_bind_bus_write_reg_b,
      st25_bind_bus_set_reg_bits, st25_bind_bus_clr_reg_bits,
      reader_hal_delay_ms);
  if (st25 != NERO_NFC_NULL) {
    st25->configured_protocol = ST25_CONFIGURED_PROTOCOL_ISO15693;
  }
}

static nfc_frontend_field_on_status_t st25_impl_field_on(void* state,
                                                         bool* used_direct) {
  st25r3916_t* st25 = (st25r3916_t*)state;
  nfc_frontend_field_on_status_t result = st25_frontend_field_on(
      st25_bind_frontend_ops(), false, true, used_direct);
  if (st25 != NERO_NFC_NULL) {
    st25->field_enabled = result == NFC_FRONTEND_FIELD_ON_OK;
  }
  return result;
}

static int st25_impl_transceive(void* state, const uint8_t* tx, uint16_t tx_len,
                                uint8_t* rx, uint16_t rx_max, bool with_crc,
                                uint16_t timeout_ms, bool anticol,
                                bool no_rx_par, bool extended_nrt_16bit,
                                bool poll_rx_until_event,
                                bool clear_nfc_before_fifo_read) {
  st25r3916_t* st25 = (st25r3916_t*)state;
  if (st25 != NERO_NFC_NULL) {
    st25->transceive_count++;
  }
  return st25_frontend_transceive(
      st25_bind_frontend_ops(), tx, tx_len, rx, rx_max, with_crc, timeout_ms,
      anticol, no_rx_par, extended_nrt_16bit, poll_rx_until_event,
      clear_nfc_before_fifo_read);
}

static int st25_impl_transceive_diag(
    void* state, const uint8_t* tx, uint16_t tx_len, uint8_t* rx,
    uint16_t rx_max, bool with_crc, uint16_t timeout_ms, bool anticol,
    bool no_rx_par, bool extended_nrt_16bit, bool poll_rx_until_event,
    bool clear_nfc_before_fifo_read, nfc_frontend_transceive_diag_t* diag) {
  st25r3916_t* st25 = (st25r3916_t*)state;
  if (st25 != NERO_NFC_NULL) {
    st25->transceive_count++;
  }
  return st25_frontend_transceive_diag(
      st25_bind_frontend_ops(), tx, tx_len, rx, rx_max, with_crc, timeout_ms,
      anticol, no_rx_par, extended_nrt_16bit, poll_rx_until_event,
      clear_nfc_before_fifo_read, diag);
}

static bool st25_impl_send_wupa(void* state, uint8_t* atqa) {
  (void)state;
  if (atqa == NERO_NFC_NULL) {
    return false;
  }
  return st25_frontend_send_short_frame(
      NFC_FRONTEND_CMD_TRANSMIT_WUPA, atqa, st25_bind_bus_direct_cmd,
      st25_bind_bus_set_reg_bits, st25_bind_bus_write_reg,
      st25_bind_frontend_clear_irqs, st25_bind_frontend_wait_for_irqs,
      reader_hal_delay_ms, st25_bind_bus_read_irq_regs, st25_frontend_irq_main,
      st25_bind_bus_read_fifo);
}

static bool st25_impl_send_reqa(void* state, uint8_t* atqa) {
  (void)state;
  if (atqa == NERO_NFC_NULL) {
    return false;
  }
  return st25_frontend_send_short_frame(
      NFC_FRONTEND_CMD_TRANSMIT_REQA, atqa, st25_bind_bus_direct_cmd,
      st25_bind_bus_set_reg_bits, st25_bind_bus_write_reg,
      st25_bind_frontend_clear_irqs, st25_bind_frontend_wait_for_irqs,
      reader_hal_delay_ms, st25_bind_bus_read_irq_regs, st25_frontend_irq_main,
      st25_bind_bus_read_fifo);
}

static void st25_impl_quiesce(void* state) {
  st25r3916_t* st25 = (st25r3916_t*)state;
  st25_frontend_quiesce(st25_bind_frontend_ops());
  if (st25 != NERO_NFC_NULL) {
    st25->quiesce_count++;
    st25->field_enabled = false;
  }
}

static void st25_impl_ensure_tx_rx(void* state) {
  st25_frontend_ensure_tx_rx(st25_bind_frontend_ops());
  if (state != NERO_NFC_NULL) {
    ((st25r3916_t*)state)->field_enabled = true;
  }
}

static void st25_impl_enable_tx_rx(void* state) {
  st25_frontend_enable_tx_rx(st25_bind_frontend_ops());
  if (state != NERO_NFC_NULL) {
    ((st25r3916_t*)state)->field_enabled = true;
  }
}

static const nfc_frontend_ops_t ST25_NFC_FRONTEND_OPS = {
    st25_impl_measure_amplitude,
    st25_impl_init,
    st25_impl_configure_iso14443a,
    st25_impl_configure_iso15693,
    st25_impl_field_on,
    st25_impl_transceive,
    st25_impl_transceive_diag,
    st25_impl_send_wupa,
    st25_impl_send_reqa,
    st25_impl_quiesce,
    st25_impl_ensure_tx_rx,
    st25_impl_enable_tx_rx,
};

void nero_nfc_st25_frontend_bind(nfc_frontend_t* frontend, st25r3916_t* state,
                                 const nero_nfc_platform_ops_t* platform,
                                 const nero_nfc_board_config_t* board) {
  if ((frontend == NERO_NFC_NULL) || (state == NERO_NFC_NULL)) {
    return;
  }
  state->platform = platform;
  state->board = board;
  frontend->ops = &ST25_NFC_FRONTEND_OPS;
  frontend->state = state;
}

bool nfc_frontend_ready(const nfc_frontend_t* frontend) {
  return (frontend != NERO_NFC_NULL) && (frontend->ops != NERO_NFC_NULL) &&
         (frontend->state != NERO_NFC_NULL);
}

uint8_t nfc_frontend_measure_amplitude(nfc_frontend_t* frontend) {
  return nfc_frontend_ready(frontend)
             ? frontend->ops->measure_amplitude(frontend->state)
             : 0u;
}

nfc_frontend_init_status_t nfc_frontend_init(nfc_frontend_t* frontend,
                                             uint8_t* chip_id_out,
                                             uint16_t* vdd_mv_out) {
  if (!nfc_frontend_ready(frontend)) {
    return NFC_FRONTEND_INIT_CHIP_ID_FAIL;
  }
  return frontend->ops->init(frontend->state, chip_id_out, vdd_mv_out);
}

void nfc_frontend_configure_iso14443a(nfc_frontend_t* frontend) {
  if (nfc_frontend_ready(frontend)) {
    frontend->ops->configure_iso14443a(frontend->state);
  }
}

void nfc_frontend_configure_iso15693(nfc_frontend_t* frontend) {
  if (nfc_frontend_ready(frontend)) {
    frontend->ops->configure_iso15693(frontend->state);
  }
}

nfc_frontend_field_on_status_t nfc_frontend_field_on(nfc_frontend_t* frontend,
                                                     bool* used_direct) {
  return nfc_frontend_ready(frontend)
             ? frontend->ops->field_on(frontend->state, used_direct)
             : NFC_FRONTEND_FIELD_ON_TXRX_VERIFY_FAIL;
}

int nfc_frontend_transceive(nfc_frontend_t* frontend, const uint8_t* tx,
                            uint16_t tx_len, uint8_t* rx, uint16_t rx_max,
                            bool with_crc, uint16_t timeout_ms, bool anticol,
                            bool no_rx_par, bool extended_nrt_16bit,
                            bool poll_rx_until_event,
                            bool clear_nfc_before_fifo_read) {
  if (!nfc_frontend_ready(frontend)) {
    return 0;
  }
  return frontend->ops->transceive(frontend->state, tx, tx_len, rx, rx_max,
                                   with_crc, timeout_ms, anticol, no_rx_par,
                                   extended_nrt_16bit, poll_rx_until_event,
                                   clear_nfc_before_fifo_read);
}

int nfc_frontend_transceive_diag(
    nfc_frontend_t* frontend, const uint8_t* tx, uint16_t tx_len, uint8_t* rx,
    uint16_t rx_max, bool with_crc, uint16_t timeout_ms, bool anticol,
    bool no_rx_par, bool extended_nrt_16bit, bool poll_rx_until_event,
    bool clear_nfc_before_fifo_read, nfc_frontend_transceive_diag_t* diag) {
  if (!nfc_frontend_ready(frontend)) {
    return 0;
  }
  return frontend->ops->transceive_diag(
      frontend->state, tx, tx_len, rx, rx_max, with_crc, timeout_ms, anticol,
      no_rx_par, extended_nrt_16bit, poll_rx_until_event,
      clear_nfc_before_fifo_read, diag);
}

bool nfc_frontend_send_wupa(nfc_frontend_t* frontend, uint8_t* atqa) {
  return nfc_frontend_ready(frontend) &&
         frontend->ops->send_wupa(frontend->state, atqa);
}

bool nfc_frontend_send_reqa(nfc_frontend_t* frontend, uint8_t* atqa) {
  return nfc_frontend_ready(frontend) &&
         frontend->ops->send_reqa(frontend->state, atqa);
}

int nfc_frontend_iso15693_transceive(nfc_frontend_t* frontend,
                                     const uint8_t* tx, uint16_t tx_len,
                                     uint8_t* rx, uint16_t rx_max,
                                     uint16_t timeout_ms) {
  uint8_t encoded[NFC_FRONTEND_ISO15693_MAX_STREAM_FRAME];
  uint8_t raw[NFC_FRONTEND_ISO15693_MAX_STREAM_FRAME];
  uint16_t encoded_len = 0u;
  int raw_len;

  if ((tx == NERO_NFC_NULL) || (rx == NERO_NFC_NULL) || (tx_len == 0u) ||
      (rx_max == 0u)) {
    return 0;
  }
  if (!st25_frontend_iso15693_stream_encode(tx, tx_len, encoded,
                                            sizeof(encoded), &encoded_len)) {
    return 0;
  }
  raw_len = nfc_frontend_transceive(frontend, encoded, encoded_len, raw,
                                    sizeof(raw), false, timeout_ms, false,
                                    false, true, true, true);
  if (raw_len <= 0) {
    return 0;
  }
  return st25_frontend_iso15693_stream_decode(raw, (uint16_t)raw_len, rx,
                                              rx_max);
}

bool nfc_frontend_iso15693_inventory(
    nfc_frontend_iso15693_transceive_fn_t transceive, void* context,
    uint8_t uid_out[NFC_FRONTEND_ISO15693_UID_LEN]) {
  return st25_frontend_iso15693_inventory(transceive, context, uid_out);
}

int nfc_frontend_iso15693_read_block(
    nfc_frontend_iso15693_transceive_fn_t transceive, void* context,
    const uint8_t uid[NFC_FRONTEND_ISO15693_UID_LEN], uint8_t block_addr,
    uint8_t* buf, uint8_t buf_len) {
  return st25_frontend_iso15693_read_block(transceive, context, uid, block_addr,
                                           buf, buf_len);
}

bool nfc_frontend_iso15693_write_block(
    nfc_frontend_iso15693_transceive_fn_t transceive, void* context,
    const uint8_t uid[NFC_FRONTEND_ISO15693_UID_LEN], uint8_t block_addr,
    const uint8_t* data, uint8_t data_len) {
  return st25_frontend_iso15693_write_block(transceive, context, uid,
                                            block_addr, data, data_len);
}

bool nfc_frontend_iso15693_get_system_info(
    nfc_frontend_iso15693_transceive_fn_t transceive, void* context,
    const uint8_t uid[NFC_FRONTEND_ISO15693_UID_LEN], uint16_t* nb_blocks_out,
    uint8_t* block_size_out) {
  return st25_frontend_iso15693_get_system_info(transceive, context, uid,
                                                nb_blocks_out, block_size_out);
}

int nfc_frontend_iso15693_ext_read_block(
    nfc_frontend_iso15693_transceive_fn_t transceive, void* context,
    const uint8_t uid[NFC_FRONTEND_ISO15693_UID_LEN], uint16_t block_addr,
    uint8_t* buf, uint8_t buf_len) {
  return st25_frontend_iso15693_ext_read_block(transceive, context, uid,
                                               block_addr, buf, buf_len);
}

bool nfc_frontend_iso15693_ext_write_block(
    nfc_frontend_iso15693_transceive_fn_t transceive, void* context,
    const uint8_t uid[NFC_FRONTEND_ISO15693_UID_LEN], uint16_t block_addr,
    const uint8_t* data, uint8_t data_len) {
  return st25_frontend_iso15693_ext_write_block(transceive, context, uid,
                                                block_addr, data, data_len);
}

void nfc_frontend_quiesce(nfc_frontend_t* frontend) {
  if (nfc_frontend_ready(frontend)) {
    frontend->ops->quiesce(frontend->state);
  }
}

void nfc_frontend_ensure_tx_rx(nfc_frontend_t* frontend) {
  if (nfc_frontend_ready(frontend)) {
    frontend->ops->ensure_tx_rx(frontend->state);
  }
}

void nfc_frontend_enable_tx_rx(nfc_frontend_t* frontend) {
  if (nfc_frontend_ready(frontend)) {
    frontend->ops->enable_tx_rx(frontend->state);
  }
}

int nfc_frontend_anticollision_select(
    uint8_t sel_cmd, uint8_t* uid_out,
    nfc_frontend_iso14443a_transceive_fn_t transceive, void* context) {
  return st25_frontend_anticollision_select(sel_cmd, uid_out, transceive,
                                            context);
}

bool nfc_frontend_activate_iso14443a(
    nfc_frontend_send_short_frame_fn_t send_wupa,
    nfc_frontend_send_short_frame_fn_t send_reqa,
    nfc_frontend_delay_ms_fn_t delay_ms, void* context,
    bool retry_with_reqa_on_second_try,
    nfc_frontend_anticollision_select_fn_t select_uid, uint8_t* uid_out,
    uint8_t uid_out_capacity, uint8_t* uid_len_out, uint8_t* sak_out) {
  return st25_frontend_activate_iso14443a(
      send_wupa, send_reqa, delay_ms, context, retry_with_reqa_on_second_try,
      select_uid, uid_out, uid_out_capacity, uid_len_out, sak_out);
}
