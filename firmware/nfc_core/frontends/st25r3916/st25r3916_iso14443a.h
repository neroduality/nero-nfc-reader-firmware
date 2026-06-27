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
#include "st25_sketch_spi.h"

typedef void (*st25_cmd_fn_t)(uint8_t cmd);
typedef void (*st25_write_reg_fn_t)(uint8_t reg, uint8_t value);
typedef void (*st25_reg_bits_fn_t)(uint8_t reg, uint8_t mask);
typedef void (*st25_delay_ms_fn_t)(uint32_t ms);
typedef void (*st25_clear_irqs_fn_t)(void);
typedef uint32_t (*st25_wait_irqs_fn_t)(uint32_t timeout_ticks);
typedef uint32_t (*st25_read_irq_regs_fn_t)(void);
typedef uint8_t (*st25_irq_extract_fn_t)(uint32_t status);
typedef uint16_t (*st25_read_fifo_fn_t)(uint8_t *buffer, uint16_t max_len);
typedef int (*st25_transceive_i_fn_t)(const uint8_t *tx_data, uint16_t tx_len, uint8_t *rx_buffer,
                                      uint16_t rx_buffer_len, int with_crc, uint16_t timeout_ms,
                                      int anticol, int no_rx_par);
typedef bool (*st25_send_short_frame_fn_t)(uint8_t *atqa_out);
typedef int (*st25_anticollision_select_fn_t)(uint8_t sel_cmd, uint8_t *uid_out);

static inline void
st25_iso14443a_configure_defaults(st25_cmd_fn_t direct_cmd, st25_reg_bits_fn_t set_reg_bits,
                                  st25_write_reg_fn_t write_reg, st25_write_reg_fn_t write_reg_b,
                                  st25_reg_bits_fn_t clr_reg_bits, st25_delay_ms_fn_t delay_ms) {
  direct_cmd(ST25R3916_CMD_STOP);
  direct_cmd(ST25R3916_CMD_CLEAR_FIFO);
  set_reg_bits(ST25R3916_REG_OP_CONTROL, ST25R3916_REG_OP_CONTROL_rx_en);
  delay_ms(1u);

  write_reg(ST25R3916_REG_MODE, ST25R3916_REG_MODE_om_iso14443a | ST25R3916_REG_MODE_tr_am_ook);
  write_reg(ST25R3916_REG_BIT_RATE, 0x00u);
  write_reg(ST25R3916_REG_ISO14443A_NFC, 0x00u);
  write_reg(ST25R3916_REG_RX_CONF1, 0x08u);
  write_reg(ST25R3916_REG_RX_CONF2, 0xEDu);
  write_reg(ST25R3916_REG_RX_CONF3, 0x00u);
  write_reg(ST25R3916_REG_RX_CONF4, 0x00u);

  write_reg_b(REGB_CORR_CONF1, 0x51u);
  write_reg_b(REGB_CORR_CONF2, 0x00u);

  clr_reg_bits(ST25R3916_REG_AUX, ST25R3916_REG_AUX_dis_corr);
  set_reg_bits(ST25R3916_REG_AUX, ST25R3916_REG_AUX_no_crc_rx);

  write_reg(ST25R3916_REG_TIMER_EMV_CONTROL, ST25R3916_REG_TIMER_EMV_CONTROL_nrt_step_4096_fc |
                                               ST25R3916_REG_TIMER_EMV_CONTROL_nrt_nfc_on);
  write_reg(ST25R3916_REG_NO_RESPONSE_TIMER1, 0x00u);
  write_reg(ST25R3916_REG_NO_RESPONSE_TIMER2, 0x11u);
  write_reg(ST25R3916_REG_MASK_RX_TIMER, 0x01u);

  write_reg(ST25R3916_REG_IRQ_MASK_MAIN,
            (uint8_t)~(IRQ_MAIN_TXE | IRQ_MAIN_RXE | IRQ_MAIN_RXS | IRQ_MAIN_COL | IRQ_MAIN_FWL));
  write_reg(ST25R3916_REG_IRQ_MASK_TIMER_NFC, (uint8_t)~IRQ_TIMER_NRE);
  write_reg(ST25R3916_REG_IRQ_MASK_ERROR_WUP,
            (uint8_t)~(IRQ_ERROR_CRC | IRQ_ERROR_PAR | IRQ_ERROR_ERR1 | IRQ_ERROR_ERR2));
  write_reg(ST25R3916_REG_IRQ_MASK_TARGET, 0xFFu);
}

NERO_NFC_NODISCARD static inline bool
st25_iso14443a_send_short_frame(uint8_t cmd_short_frame, uint8_t *atqa, st25_cmd_fn_t direct_cmd,
                                st25_reg_bits_fn_t set_reg_bits, st25_write_reg_fn_t write_reg,
                                st25_clear_irqs_fn_t clear_irqs, st25_wait_irqs_fn_t wait_for_irqs,
                                st25_delay_ms_fn_t delay_ms, st25_read_irq_regs_fn_t read_irq_regs,
                                st25_irq_extract_fn_t irq_main, st25_read_fifo_fn_t read_fifo) {
  uint32_t tx_irqs;
  uint32_t rx_irqs;
  uint16_t len;

  direct_cmd(ST25R3916_CMD_STOP);
  direct_cmd(ST25R3916_CMD_CLEAR_FIFO);
  direct_cmd(ST25R3916_CMD_RESET_RXGAIN);
  set_reg_bits(ST25R3916_REG_OP_CONTROL, ST25R3916_REG_OP_CONTROL_rx_en);
  clear_irqs();

  write_reg(ST25R3916_REG_NUM_TX_BYTES2, 0x00u);
  write_reg(ST25R3916_REG_TIMER_EMV_CONTROL, ST25R3916_REG_TIMER_EMV_CONTROL_nrt_step_4096_fc |
                                               ST25R3916_REG_TIMER_EMV_CONTROL_nrt_nfc_on);
  write_reg(ST25R3916_REG_NO_RESPONSE_TIMER1, 0x00u);
  write_reg(ST25R3916_REG_NO_RESPONSE_TIMER2, 0x10u);
  clear_irqs();

  direct_cmd(cmd_short_frame);

  tx_irqs = wait_for_irqs(5000u);
  if ((irq_main(tx_irqs) & IRQ_MAIN_TXE) == 0u) {
    return false;
  }

  delay_ms(7u);
  rx_irqs = read_irq_regs();
  if ((irq_main(rx_irqs) & (IRQ_MAIN_RXE | IRQ_MAIN_COL)) == 0u) {
    return false;
  }

  len = read_fifo(atqa, 2u);
  return len >= 2u;
}

static inline int st25_iso14443a_anticollision_select(uint8_t sel_cmd, uint8_t *uid_out,
                                                      st25_transceive_i_fn_t transceive_i) {
  uint8_t tx_buffer[9];
  uint8_t rx_buffer[8];
  int rx_len;
  uint8_t bcc;
  int sak_len;

  if (uid_out != NERO_NFC_NULL) {
    for (uint8_t i = 0u; i < 4u; i++) {
      uid_out[i] = 0u;
    }
  }
  if ((uid_out == NERO_NFC_NULL) || (transceive_i == NERO_NFC_NULL)) {
    return -1;
  }
  tx_buffer[0] = sel_cmd;
  tx_buffer[1] = 0x20u;

  rx_len = transceive_i(tx_buffer, 2u, rx_buffer, sizeof(rx_buffer), 0, 20u, 1, 0);
  if (rx_len < 5) {
    return -1;
  }

  bcc = (uint8_t)(rx_buffer[0] ^ rx_buffer[1] ^ rx_buffer[2] ^ rx_buffer[3]);
  if (bcc != rx_buffer[4]) {
    return -1;
  }

  uid_out[0] = rx_buffer[0];
  uid_out[1] = rx_buffer[1];
  uid_out[2] = rx_buffer[2];
  uid_out[3] = rx_buffer[3];

  tx_buffer[0] = sel_cmd;
  tx_buffer[1] = 0x70u;
  tx_buffer[2] = rx_buffer[0];
  tx_buffer[3] = rx_buffer[1];
  tx_buffer[4] = rx_buffer[2];
  tx_buffer[5] = rx_buffer[3];
  tx_buffer[6] = rx_buffer[4];

  sak_len = transceive_i(tx_buffer, 7u, rx_buffer, sizeof(rx_buffer), 1, 20u, 0, 0);
  if (sak_len < 1) {
    return -1;
  }

  return rx_buffer[0];
}

NERO_NFC_NODISCARD static inline bool
st25_iso14443a_activate_tag(st25_send_short_frame_fn_t send_wupa,
                            st25_send_short_frame_fn_t send_reqa, st25_delay_ms_fn_t delay_ms,
                            bool retry_with_reqa_on_second_try,
                            st25_anticollision_select_fn_t select_uid, uint8_t *uid_out,
                            uint8_t uid_out_capacity, uint8_t *uid_len_out, uint8_t *sak_out) {
  uint8_t atqa[2];
  uint8_t cl1_uid[4];
  int sak1;

  if ((uid_out != NERO_NFC_NULL) && (uid_out_capacity >= 7u)) {
    for (uint8_t i = 0u; i < 7u; i++) {
      uid_out[i] = 0u;
    }
  }
  if (uid_len_out != NERO_NFC_NULL) {
    *uid_len_out = 0u;
  }
  if (sak_out != NERO_NFC_NULL) {
    *sak_out = 0u;
  }
  if ((send_wupa == NERO_NFC_NULL) || (delay_ms == NERO_NFC_NULL) ||
      (select_uid == NERO_NFC_NULL) || (uid_out == NERO_NFC_NULL) ||
      (uid_len_out == NERO_NFC_NULL) || (sak_out == NERO_NFC_NULL) || (uid_out_capacity < 7u)) {
    return false;
  }

  if (!send_wupa(atqa)) {
    delay_ms(5u);
    if (retry_with_reqa_on_second_try) {
      if ((send_reqa == NERO_NFC_NULL) || !send_reqa(atqa)) {
        return false;
      }
    } else {
      if (!send_wupa(atqa)) {
        return false;
      }
    }
  }

  sak1 = select_uid(ISO14443_CMD_SEL_CL1, cl1_uid);
  if (sak1 < 0) {
    return false;
  }

  {
    uint8_t cl2_uid[ST25_ISO14443A_SEL_RESP_LEN];
    uint8_t cl3_uid[ST25_ISO14443A_SEL_RESP_LEN];
    int sak2 = -1;
    int sak3 = -1;
    uint8_t levels = 1u;

    if ((sak1 & ST25_ISO14443A_SAK_CASCADE_BIT) != 0) {
      sak2 = select_uid(ISO14443_CMD_SEL_CL2, cl2_uid);
      if (sak2 < 0) {
        return false;
      }
      levels = 2u;
      if ((sak2 & ST25_ISO14443A_SAK_CASCADE_BIT) != 0) {
        sak3 = select_uid(ISO14443_CMD_SEL_CL3, cl3_uid);
        if (sak3 < 0) {
          return false;
        }
        levels = 3u;
      }
    }

    {
      uint8_t uid_len = st25_iso14443a_assemble_cascaded_uid(
        levels, cl1_uid, sak1, cl2_uid, sak2, cl3_uid, sak3, uid_out, uid_out_capacity, sak_out);
      if (uid_len == 0u) {
        return false;
      }
      *uid_len_out = uid_len;
    }
  }

  return true;
}
