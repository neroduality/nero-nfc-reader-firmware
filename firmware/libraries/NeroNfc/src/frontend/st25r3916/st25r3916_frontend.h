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

#include "nero_nfc_frontend.h"
#include "nero_nfc_mem_util.h"
#include "nero_nfc_null.h"
#include "st25r3916_bus.h"
#include "st25r3916_irq.h"
#include "st25r3916_iso14443a.h"
#include "st25r3916_iso15693.h"
#include "st25r3916_runtime.h"

typedef st25_runtime_ops_t st25_frontend_ops_t;

#define NFC_FRONTEND_MODEL_NAME "ST25R3916B"
#define NFC_FRONTEND_REFERENCE_BOARD_NAME "X-NUCLEO-NFC08A1"

#define NFC_FRONTEND_CMD_TRANSMIT_WUPA ST25R3916_CMD_TRANSMIT_WUPA
#define NFC_FRONTEND_CMD_TRANSMIT_REQA ST25R3916_CMD_TRANSMIT_REQA

void st25_frontend_clear_irqs(st25_read_irq_regs_fn_t read_irq_regs);

uint32_t st25_frontend_wait_for_irqs(uint32_t timeout_us,
                                     uint32_t (*now_ticks_us)(void),
                                     bool (*irq_active)(void),
                                     st25_read_irq_regs_fn_t read_irq_regs,
                                     st25_service_fn_t service);

uint8_t st25_frontend_irq_main(uint32_t status);

uint8_t st25_frontend_irq_timer(uint32_t status);

uint8_t st25_frontend_irq_target(uint32_t status);

nfc_frontend_init_status_t st25_frontend_init(const st25_frontend_ops_t* ops,
                                              uint8_t* chip_id_out,
                                              uint16_t* vdd_mv_out);

nfc_frontend_field_on_status_t st25_frontend_field_on(
    const st25_frontend_ops_t* ops, bool fail_on_collision, bool verify_txrx,
    bool* used_direct);

void st25_frontend_configure_iso14443a(st25_cmd_fn_t direct_cmd,
                                       st25_reg_bits_fn_t set_reg_bits,
                                       st25_write_reg_fn_t write_reg,
                                       st25_write_reg_fn_t write_reg_b,
                                       st25_reg_bits_fn_t clr_reg_bits,
                                       st25_delay_ms_fn_t delay_ms);

void st25_frontend_configure_iso15693(st25_write_reg_fn_t write_reg,
                                      st25_write_reg_fn_t write_reg_b,
                                      st25_reg_bits_fn_t set_reg_bits,
                                      st25_reg_bits_fn_t clr_reg_bits,
                                      st25_delay_ms_fn_t delay_ms);

int st25_frontend_transceive(const st25_frontend_ops_t* ops,
                             const uint8_t* tx_data, uint16_t tx_len,
                             uint8_t* rx_buffer, uint16_t rx_buffer_len,
                             bool with_crc, uint16_t timeout_ms, bool anticol,
                             bool no_rx_par, bool extended_nrt_16bit,
                             bool poll_rx_until_event,
                             bool clear_nfc_before_fifo_read);

int st25_frontend_transceive_diag(
    const st25_frontend_ops_t* ops, const uint8_t* tx_data, uint16_t tx_len,
    uint8_t* rx_buffer, uint16_t rx_buffer_len, bool with_crc,
    uint16_t timeout_ms, bool anticol, bool no_rx_par, bool extended_nrt_16bit,
    bool poll_rx_until_event, bool clear_nfc_before_fifo_read,
    nfc_frontend_transceive_diag_t* diag);

NERO_NFC_NODISCARD bool st25_frontend_send_short_frame(
    uint8_t cmd_short_frame, uint8_t* atqa, st25_cmd_fn_t direct_cmd,
    st25_reg_bits_fn_t set_reg_bits, st25_write_reg_fn_t write_reg,
    st25_clear_irqs_fn_t clear_irqs, st25_wait_irqs_fn_t wait_for_irqs,
    st25_delay_ms_fn_t delay_ms, st25_read_irq_regs_fn_t read_irq_regs,
    st25_irq_extract_fn_t irq_main, st25_read_fifo_fn_t read_fifo);

int st25_frontend_anticollision_select(uint8_t sel_cmd, uint8_t* uid_out,
                                       st25_transceive_i_fn_t transceive_i,
                                       void* context);

NERO_NFC_NODISCARD bool st25_frontend_activate_iso14443a(
    st25_send_short_frame_fn_t send_wupa, st25_send_short_frame_fn_t send_reqa,
    st25_delay_context_fn_t delay_ms, void* context,
    bool retry_with_reqa_on_second_try,
    st25_anticollision_select_fn_t select_uid, uint8_t* uid_out,
    uint8_t uid_out_capacity, uint8_t* uid_len_out, uint8_t* sak_out);

NERO_NFC_NODISCARD bool st25_frontend_iso15693_stream_encode(const uint8_t* tx,
                                                             uint16_t tx_len,
                                                             uint8_t* out,
                                                             uint16_t out_max,
                                                             uint16_t* out_len);

int st25_frontend_iso15693_stream_decode(const uint8_t* in, uint16_t in_len,
                                         uint8_t* out, uint16_t out_max);

NERO_NFC_NODISCARD bool st25_frontend_iso15693_inventory(
    nfc_frontend_iso15693_transceive_fn_t transceive, void* context,
    uint8_t uid_out[NFC_FRONTEND_ISO15693_UID_LEN]);

int st25_frontend_iso15693_read_block(
    nfc_frontend_iso15693_transceive_fn_t transceive, void* context,
    const uint8_t uid[NFC_FRONTEND_ISO15693_UID_LEN], uint8_t block_addr,
    uint8_t* buf, uint8_t buf_len);

NERO_NFC_NODISCARD bool st25_frontend_iso15693_write_block(
    nfc_frontend_iso15693_transceive_fn_t transceive, void* context,
    const uint8_t uid[NFC_FRONTEND_ISO15693_UID_LEN], uint8_t block_addr,
    const uint8_t* data, uint8_t data_len);

NERO_NFC_NODISCARD bool st25_frontend_iso15693_get_system_info(
    nfc_frontend_iso15693_transceive_fn_t transceive, void* context,
    const uint8_t uid[NFC_FRONTEND_ISO15693_UID_LEN], uint16_t* nb_blocks_out,
    uint8_t* block_size_out);

int st25_frontend_iso15693_ext_read_block(
    nfc_frontend_iso15693_transceive_fn_t transceive, void* context,
    const uint8_t uid[NFC_FRONTEND_ISO15693_UID_LEN], uint16_t block_addr,
    uint8_t* buf, uint8_t buf_len);

NERO_NFC_NODISCARD bool st25_frontend_iso15693_ext_write_block(
    nfc_frontend_iso15693_transceive_fn_t transceive, void* context,
    const uint8_t uid[NFC_FRONTEND_ISO15693_UID_LEN], uint16_t block_addr,
    const uint8_t* data, uint8_t data_len);

uint8_t st25_frontend_measure_amplitude(const st25_frontend_ops_t* ops);

void st25_frontend_quiesce(const st25_frontend_ops_t* ops);

void st25_frontend_ensure_tx_rx(const st25_frontend_ops_t* ops);

void st25_frontend_enable_tx_rx(const st25_frontend_ops_t* ops);
