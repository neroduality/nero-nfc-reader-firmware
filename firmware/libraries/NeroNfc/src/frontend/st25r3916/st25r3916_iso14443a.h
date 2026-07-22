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
#include "st25r3916_iso14443a_uid.h"
#include "st25r3916_types.h"
#include "nfc_tag_geometry_limits.h"
#include "nfc_tag_info.h"

typedef void (*st25_clear_irqs_fn_t)(void);
typedef int (*st25_transceive_i_fn_t)(void* context, const uint8_t* tx_data,
                                      uint16_t tx_len, uint8_t* rx_buffer,
                                      uint16_t rx_buffer_len, int with_crc,
                                      uint16_t timeout_ms, int anticol,
                                      int no_rx_par);
typedef bool (*st25_send_short_frame_fn_t)(void* context, uint8_t* atqa_out);
typedef void (*st25_delay_context_fn_t)(void* context, uint32_t ms);
typedef int (*st25_anticollision_select_fn_t)(void* context, uint8_t sel_cmd,
                                              uint8_t* uid_out);

enum {
  K_ST25_A_IRQ_MASK_ALL = NFC_BYTE_VALUE_MAX,
  K_ST25_A_ATQA_LEN = NFC_TAG_TYPEA_ATQA_LEN,
};

void st25_iso14443a_configure_defaults(st25_cmd_fn_t direct_cmd,
                                       st25_reg_bits_fn_t set_reg_bits,
                                       st25_write_reg_fn_t write_reg,
                                       st25_write_reg_fn_t write_reg_b,
                                       st25_reg_bits_fn_t clr_reg_bits,
                                       st25_delay_ms_fn_t delay_ms);

NERO_NFC_NODISCARD bool st25_iso14443a_send_short_frame(
    uint8_t cmd_short_frame, uint8_t* atqa, st25_cmd_fn_t direct_cmd,
    st25_reg_bits_fn_t set_reg_bits, st25_write_reg_fn_t write_reg,
    st25_clear_irqs_fn_t clear_irqs, st25_wait_irqs_fn_t wait_for_irqs,
    st25_delay_ms_fn_t delay_ms, st25_read_irq_regs_fn_t read_irq_regs,
    st25_irq_extract_fn_t irq_main, st25_read_fifo_fn_t read_fifo);

int st25_iso14443a_anticollision_select(uint8_t sel_cmd, uint8_t* uid_out,
                                        st25_transceive_i_fn_t transceive_i,
                                        void* context);

NERO_NFC_NODISCARD bool st25_iso14443a_activate_tag(
    st25_send_short_frame_fn_t send_wupa, st25_send_short_frame_fn_t send_reqa,
    st25_delay_context_fn_t delay_ms, void* context,
    bool retry_with_reqa_on_second_try,
    st25_anticollision_select_fn_t select_uid, uint8_t* uid_out,
    uint8_t uid_out_capacity, uint8_t* uid_len_out, uint8_t* sak_out);
