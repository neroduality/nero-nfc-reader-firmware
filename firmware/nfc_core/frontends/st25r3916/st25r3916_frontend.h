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

#include "nero_nfc_mem_util.h"
#include "nfc_frontend.h"
#include "st25r3916_bus.h"
#include "st25r3916_irq.h"
#include "st25r3916_iso14443a.h"
#include "st25r3916_iso15693.h"
#include "st25r3916_runtime.h"

typedef st25_runtime_ops_t nfc_frontend_ops_t;

#define NFC_FRONTEND_MODEL_NAME "ST25R3916B"
#define NFC_FRONTEND_REFERENCE_BOARD_NAME "X-NUCLEO-NFC08A1"

#define NFC_FRONTEND_CMD_TRANSMIT_WUPA ST25R3916_CMD_TRANSMIT_WUPA
#define NFC_FRONTEND_CMD_TRANSMIT_REQA ST25R3916_CMD_TRANSMIT_REQA

#define nfc_frontend_bus_write_reg st25_bus_write_reg
#define nfc_frontend_bus_read_reg st25_bus_read_reg
#define nfc_frontend_bus_set_reg_bits st25_bus_set_reg_bits
#define nfc_frontend_bus_clr_reg_bits st25_bus_clr_reg_bits
#define nfc_frontend_bus_write_reg_b st25_bus_write_reg_b
#define nfc_frontend_bus_set_reg_b_bits st25_bus_set_reg_b_bits
#define nfc_frontend_bus_direct_cmd st25_bus_direct_cmd
#define nfc_frontend_bus_write_fifo st25_bus_write_fifo
#define nfc_frontend_bus_read_fifo st25_bus_read_fifo
#define nfc_frontend_bus_read_irq_regs st25_bus_read_irq_regs

static inline void nfc_frontend_clear_irqs(st25_read_irq_regs_fn_t read_irq_regs) {
  st25_clear_irqs(read_irq_regs);
}

static inline uint32_t nfc_frontend_wait_for_irqs(uint32_t timeout_us,
                                                  uint32_t (*now_ticks_us)(void),
                                                  bool (*irq_active)(void),
                                                  st25_read_irq_regs_fn_t read_irq_regs,
                                                  st25_service_fn_t service) {
  return st25_wait_for_irqs(timeout_us, now_ticks_us, irq_active, read_irq_regs, service);
}

static inline uint8_t nfc_frontend_irq_main(uint32_t status) {
  return st25_irq_main(status);
}

static inline uint8_t nfc_frontend_irq_timer(uint32_t status) {
  return st25_irq_timer(status);
}

static inline uint8_t nfc_frontend_irq_target(uint32_t status) {
  return st25_irq_target(status);
}

static inline nfc_frontend_init_status_t
nfc_frontend_init(const nfc_frontend_ops_t *ops, uint8_t *chip_id_out, uint16_t *vdd_mv_out) {
  return (nfc_frontend_init_status_t)st25_runtime_init_common(ops, chip_id_out, vdd_mv_out);
}

static inline nfc_frontend_field_on_status_t nfc_frontend_field_on(const nfc_frontend_ops_t *ops,
                                                                   bool fail_on_collision,
                                                                   bool verify_txrx,
                                                                   bool *used_direct) {
  return (nfc_frontend_field_on_status_t)st25_runtime_field_on_common(ops, fail_on_collision,
                                                                      verify_txrx, used_direct);
}

static inline void
nfc_frontend_configure_iso14443a(st25_cmd_fn_t direct_cmd, st25_reg_bits_fn_t set_reg_bits,
                                 st25_write_reg_fn_t write_reg, st25_write_reg_fn_t write_reg_b,
                                 st25_reg_bits_fn_t clr_reg_bits, st25_delay_ms_fn_t delay_ms) {
  st25_iso14443a_configure_defaults(direct_cmd, set_reg_bits, write_reg, write_reg_b, clr_reg_bits,
                                    delay_ms);
}

static inline void nfc_frontend_configure_iso15693(st25_write_reg_fn_t write_reg,
                                                   st25_write_reg_fn_t write_reg_b,
                                                   st25_reg_bits_fn_t set_reg_bits,
                                                   st25_reg_bits_fn_t clr_reg_bits,
                                                   st25_delay_ms_fn_t delay_ms) {
  st25_iso15693_configure_defaults(write_reg, write_reg_b, set_reg_bits, clr_reg_bits, delay_ms);
}

static inline int nfc_frontend_transceive(const nfc_frontend_ops_t *ops, const uint8_t *tx_data,
                                          uint16_t tx_len, uint8_t *rx_buffer,
                                          uint16_t rx_buffer_len, bool with_crc,
                                          uint16_t timeout_ms, bool anticol, bool no_rx_par,
                                          bool extended_nrt_16bit, bool poll_rx_until_event,
                                          bool clear_nfc_before_fifo_read) {
  return st25_runtime_transceive_common(ops, tx_data, tx_len, rx_buffer, rx_buffer_len, with_crc,
                                        timeout_ms, anticol, no_rx_par, extended_nrt_16bit,
                                        poll_rx_until_event, clear_nfc_before_fifo_read);
}

static inline int nfc_frontend_transceive_diag(
  const nfc_frontend_ops_t *ops, const uint8_t *tx_data, uint16_t tx_len, uint8_t *rx_buffer,
  uint16_t rx_buffer_len, bool with_crc, uint16_t timeout_ms, bool anticol, bool no_rx_par,
  bool extended_nrt_16bit, bool poll_rx_until_event, bool clear_nfc_before_fifo_read,
  nfc_frontend_transceive_diag_t *diag) {
  st25_runtime_transceive_diag_t st_diag;
  (void)nero_nfc_zero_bytes(static_cast<void *>(&st_diag), sizeof(st_diag));
  st25_runtime_transceive_diag_t *st_diag_out = (diag == NERO_NFC_NULL) ? NERO_NFC_NULL : &st_diag;
  int rlen = st25_runtime_transceive_common_diag(
    ops, tx_data, tx_len, rx_buffer, rx_buffer_len, with_crc, timeout_ms, anticol, no_rx_par,
    extended_nrt_16bit, poll_rx_until_event, clear_nfc_before_fifo_read, st_diag_out);

  if (diag != NERO_NFC_NULL) {
    diag->requested_timeout_ms = st_diag.requested_timeout_ms;
    diag->nrt_steps_programmed = st_diag.nrt_steps_programmed;
    diag->tx_wait_us = st_diag.tx_wait_us;
    diag->tx_irq_status = st_diag.tx_irq_status;
    diag->final_irq_status = st_diag.final_irq_status;
    diag->extended_nrt_16bit = st_diag.extended_nrt_16bit;
    diag->nrt_clamped = st_diag.nrt_clamped;
    diag->got_txe = st_diag.got_txe;
    diag->got_rxe = st_diag.got_rxe;
    diag->got_nre = st_diag.got_nre;
  }
  return rlen;
}

NERO_NFC_NODISCARD static inline bool
nfc_frontend_send_short_frame(uint8_t cmd_short_frame, uint8_t *atqa, st25_cmd_fn_t direct_cmd,
                              st25_reg_bits_fn_t set_reg_bits, st25_write_reg_fn_t write_reg,
                              st25_clear_irqs_fn_t clear_irqs, st25_wait_irqs_fn_t wait_for_irqs,
                              st25_delay_ms_fn_t delay_ms, st25_read_irq_regs_fn_t read_irq_regs,
                              st25_irq_extract_fn_t irq_main, st25_read_fifo_fn_t read_fifo) {
  return st25_iso14443a_send_short_frame(cmd_short_frame, atqa, direct_cmd, set_reg_bits, write_reg,
                                         clear_irqs, wait_for_irqs, delay_ms, read_irq_regs,
                                         irq_main, read_fifo);
}

static inline int nfc_frontend_anticollision_select(uint8_t sel_cmd, uint8_t *uid_out,
                                                    st25_transceive_i_fn_t transceive_i) {
  return st25_iso14443a_anticollision_select(sel_cmd, uid_out, transceive_i);
}

NERO_NFC_NODISCARD static inline bool
nfc_frontend_activate_iso14443a(st25_send_short_frame_fn_t send_wupa,
                                st25_send_short_frame_fn_t send_reqa, st25_delay_ms_fn_t delay_ms,
                                bool retry_with_reqa_on_second_try,
                                st25_anticollision_select_fn_t select_uid, uint8_t *uid_out,
                                uint8_t uid_out_capacity, uint8_t *uid_len_out, uint8_t *sak_out) {
  return st25_iso14443a_activate_tag(send_wupa, send_reqa, delay_ms, retry_with_reqa_on_second_try,
                                     select_uid, uid_out, uid_out_capacity, uid_len_out, sak_out);
}

NERO_NFC_NODISCARD static inline bool
nfc_frontend_iso15693_stream_encode(const uint8_t *tx, uint16_t tx_len, uint8_t *out,
                                    uint16_t out_max, uint16_t *out_len) {
  return st25_iso15693_stream_encode(tx, tx_len, out, out_max, out_len);
}

static inline int nfc_frontend_iso15693_stream_decode(const uint8_t *in, uint16_t in_len,
                                                      uint8_t *out, uint16_t out_max) {
  return st25_iso15693_stream_decode(in, in_len, out, out_max);
}

NERO_NFC_NODISCARD static inline bool
nfc_frontend_iso15693_inventory(nfc_frontend_iso15693_transceive_fn_t transceive,
                                uint8_t uid_out[NFC_FRONTEND_ISO15693_UID_LEN]) {
  return st25_iso15693_inventory(transceive, uid_out);
}

static inline int nfc_frontend_iso15693_read_block(nfc_frontend_iso15693_transceive_fn_t transceive,
                                                   const uint8_t uid[NFC_FRONTEND_ISO15693_UID_LEN],
                                                   uint8_t block_addr, uint8_t *buf,
                                                   uint8_t buf_len) {
  return st25_iso15693_read_block(transceive, uid, block_addr, buf, buf_len);
}

NERO_NFC_NODISCARD static inline bool
nfc_frontend_iso15693_write_block(nfc_frontend_iso15693_transceive_fn_t transceive,
                                  const uint8_t uid[NFC_FRONTEND_ISO15693_UID_LEN],
                                  uint8_t block_addr, const uint8_t *data, uint8_t data_len) {
  return st25_iso15693_write_block(transceive, uid, block_addr, data, data_len);
}

NERO_NFC_NODISCARD static inline bool
nfc_frontend_iso15693_get_system_info(nfc_frontend_iso15693_transceive_fn_t transceive,
                                      const uint8_t uid[NFC_FRONTEND_ISO15693_UID_LEN],
                                      uint16_t *nb_blocks_out, uint8_t *block_size_out) {
  return st25_iso15693_get_system_info(transceive, uid, nb_blocks_out, block_size_out);
}

static inline int
nfc_frontend_iso15693_ext_read_block(nfc_frontend_iso15693_transceive_fn_t transceive,
                                     const uint8_t uid[NFC_FRONTEND_ISO15693_UID_LEN],
                                     uint16_t block_addr, uint8_t *buf, uint8_t buf_len) {
  return st25_iso15693_ext_read_block(transceive, uid, block_addr, buf, buf_len);
}

NERO_NFC_NODISCARD static inline bool
nfc_frontend_iso15693_ext_write_block(nfc_frontend_iso15693_transceive_fn_t transceive,
                                      const uint8_t uid[NFC_FRONTEND_ISO15693_UID_LEN],
                                      uint16_t block_addr, const uint8_t *data, uint8_t data_len) {
  return st25_iso15693_ext_write_block(transceive, uid, block_addr, data, data_len);
}

static inline uint8_t nfc_frontend_measure_amplitude(const nfc_frontend_ops_t *ops) {
  ops->cmd(ST25R3916_CMD_MEASURE_AMPLITUDE);
  ops->delay_ms(3u);
  return ops->read_reg(ST25R3916_REG_AD_RESULT);
}

static inline void nfc_frontend_quiesce(const nfc_frontend_ops_t *ops) {
  ops->cmd(ST25R3916_CMD_STOP);
  ops->cmd(ST25R3916_CMD_CLEAR_FIFO);
  ops->clear_irqs();
}

static inline void nfc_frontend_ensure_tx_rx(const nfc_frontend_ops_t *ops) {
  uint8_t op = ops->read_reg(ST25R3916_REG_OP_CONTROL);
  if ((op & (ST25R3916_REG_OP_CONTROL_tx_en | ST25R3916_REG_OP_CONTROL_rx_en)) !=
      (ST25R3916_REG_OP_CONTROL_tx_en | ST25R3916_REG_OP_CONTROL_rx_en)) {
    ops->set_reg_bits(ST25R3916_REG_OP_CONTROL,
                      ST25R3916_REG_OP_CONTROL_tx_en | ST25R3916_REG_OP_CONTROL_rx_en);
    ops->delay_ms(5u);
  }
}

static inline void nfc_frontend_enable_tx_rx(const nfc_frontend_ops_t *ops) {
  ops->set_reg_bits(ST25R3916_REG_OP_CONTROL,
                    ST25R3916_REG_OP_CONTROL_tx_en | ST25R3916_REG_OP_CONTROL_rx_en);
}
