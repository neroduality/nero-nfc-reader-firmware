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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "nero_nfc_attrs.h"
#include "nero_nfc_null.h"
#include "st25r3916_types.h"

#include "nfc_tag_geometry_limits.h"

enum {
  K_ST25_IRQ_MASK_ALL = NFC_BYTE_VALUE_MAX,
  K_ST25_FIELD_ON_SETTLE_MS = 10u,
  K_ST25_FIELD_ON_POST_SETTLE_MS = 5u,
};

typedef struct {
  st25_cmd_fn_t cmd;
  st25_write_reg_fn_t write_reg;
  st25_read_reg_fn_t read_reg;
  st25_reg_bits_fn_t set_reg_bits;
  st25_reg_bits_fn_t clr_reg_bits;
  st25_write_reg_fn_t write_reg_b;
  st25_reg_bits_fn_t set_reg_b_bits;
  st25_write_fifo_fn_t write_fifo;
  st25_read_fifo_fn_t read_fifo;
  st25_void_fn_t clear_irqs;
  st25_wait_irqs_fn_t wait_for_irqs;
  st25_read_irq_regs_fn_t read_irq_regs;
  st25_irq_extract_fn_t irq_main;
  st25_irq_extract_fn_t irq_timer;
  st25_irq_extract_fn_t irq_target;
  st25_delay_ms_fn_t delay_ms;
  st25_millis_fn_t millis;
} st25_runtime_ops_t;

typedef enum {
  K_S_T25_INIT_OK = 0,
  K_S_T25_INIT_CHIP_ID_FAIL = 1,
  K_S_T25_INIT_OSC_FAIL = 2,
} st25_init_status_t;

typedef enum {
  K_S_T25_FIELD_ON_OK = 0,
  K_S_T25_FIELD_ON_COLLISION = 1,
  K_S_T25_FIELD_ON_TXRX_VERIFY_FAIL = 2,
} st25_field_on_status_t;

typedef struct {
  uint16_t requested_timeout_ms;
  uint16_t nrt_steps_programmed;
  uint32_t tx_wait_us;
  uint32_t tx_irq_status;
  uint32_t final_irq_status;
  bool extended_nrt_16bit;
  bool nrt_clamped;
  bool got_txe;
  bool got_rxe;
  bool got_nre;
} st25_runtime_transceive_diag_t;

NERO_NFC_NODISCARD bool st25_runtime_ops_ready(const st25_runtime_ops_t* ops);

st25_init_status_t st25_runtime_init_common(const st25_runtime_ops_t* ops,
                                            uint8_t* chip_id_out,
                                            uint16_t* vdd_mv_out);

st25_field_on_status_t st25_runtime_field_on_common(
    const st25_runtime_ops_t* ops, bool fail_on_collision, bool verify_txrx,
    bool* used_direct);

uint32_t st25_runtime_tx_wait_budget_us(uint16_t tx_len);

int st25_runtime_transceive_common_diag(
    const st25_runtime_ops_t* ops, const uint8_t* tx_data, uint16_t tx_len,
    uint8_t* rx_buffer, uint16_t rx_buffer_len, bool with_crc,
    uint16_t timeout_ms, bool anticol, bool no_rx_par, bool extended_nrt_16bit,
    bool poll_rx_until_event, bool clear_nfc_before_fifo_read,
    st25_runtime_transceive_diag_t* diag);

int st25_runtime_transceive_common(
    const st25_runtime_ops_t* ops, const uint8_t* tx_data, uint16_t tx_len,
    uint8_t* rx_buffer, uint16_t rx_buffer_len, bool with_crc,
    uint16_t timeout_ms, bool anticol, bool no_rx_par, bool extended_nrt_16bit,
    bool poll_rx_until_event, bool clear_nfc_before_fifo_read);
