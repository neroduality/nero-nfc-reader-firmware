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

#include "st25r3916_iso14443a.h"

#include "nero_nfc_null.h"
#include "st25_sketch_spi.h"

#define ISO14443_CMD_SEL_CL1 0x93u
#define ISO14443_CMD_SEL_CL2 0x95u

enum {
  K_ST25_A_RX_CONF1 = 0x08u,
  K_ST25_A_RX_CONF2 = 0xEDu,
  K_ST25_A_CORR_CONF1 = 0x51u,
  K_ST25_A_NO_RESPONSE_TIMER_WUP = 0x11u,
  K_ST25_A_NO_RESPONSE_TIMER_ANTICOLL = 0x10u,
  K_ST25_A_WUP_IRQ_WAIT_TICKS = 5000u,
  K_ST25_A_WUP_SETTLE_MS = 7u,
  K_ST25_A_SELECT_TX_CAP = 9u,
  K_ST25_A_SELECT_RX_CAP = 8u,
  K_ST25_A_CASCADE_UID_FRAME_LEN = 4u,
  K_ST25_A_ANTICOLL_CL1_CODE = 0x20u,
  K_ST25_A_SELECT_CL1_CODE = 0x70u,
  K_ST25_A_ANTICOLL_TX_LEN = 2u,
  K_ST25_A_SELECT_TX_LEN = 7u,
  K_ST25_A_TRANSCEIVE_TIMEOUT_MS = 20u,
  K_ST25_A_SAK_MIN_RX_LEN = 5u,
  K_ST25_A_BCC_INDEX = 4u,
  K_ST25_A_CASCADE_SETTLE_MS = 5u,
  K_ST25_A_UID_LEVELS_DOUBLE = 2u,
  K_ST25_A_UID_LEVELS_TRIPLE = 3u,
  K_ST25_A_UID_LEN_DOUBLE = 7u,
  K_IDX0 = 0u,
  K_IDX1 = 1u,
  K_IDX2 = 2u,
  K_IDX3 = 3u,
  K_IDX4 = 4u,
  K_IDX5 = 5u,
  K_IDX6 = 6u,
};

void st25_iso14443a_configure_defaults(st25_cmd_fn_t direct_cmd,
                                       st25_reg_bits_fn_t set_reg_bits,
                                       st25_write_reg_fn_t write_reg,
                                       st25_write_reg_fn_t write_reg_b,
                                       st25_reg_bits_fn_t clr_reg_bits,
                                       st25_delay_ms_fn_t delay_ms) {
  direct_cmd(ST25R3916_CMD_STOP);
  direct_cmd(ST25R3916_CMD_CLEAR_FIFO);
  set_reg_bits(ST25R3916_REG_OP_CONTROL, ST25R3916_REG_OP_CONTROL_rx_en);
  delay_ms(1u);

  write_reg(ST25R3916_REG_MODE,
            ST25R3916_REG_MODE_om_iso14443a | ST25R3916_REG_MODE_tr_am_ook);
  write_reg(ST25R3916_REG_BIT_RATE, 0x00u);
  write_reg(ST25R3916_REG_ISO14443A_NFC, 0x00u);
  write_reg(ST25R3916_REG_RX_CONF1, K_ST25_A_RX_CONF1);
  write_reg(ST25R3916_REG_RX_CONF2, K_ST25_A_RX_CONF2);
  write_reg(ST25R3916_REG_RX_CONF3, 0x00u);
  write_reg(ST25R3916_REG_RX_CONF4, 0x00u);

  write_reg_b(REGB_CORR_CONF1, K_ST25_A_CORR_CONF1);
  write_reg_b(REGB_CORR_CONF2, 0x00u);

  clr_reg_bits(ST25R3916_REG_AUX, ST25R3916_REG_AUX_dis_corr);
  set_reg_bits(ST25R3916_REG_AUX, ST25R3916_REG_AUX_no_crc_rx);

  write_reg(ST25R3916_REG_TIMER_EMV_CONTROL,
            ST25R3916_REG_TIMER_EMV_CONTROL_nrt_step_4096_fc |
                ST25R3916_REG_TIMER_EMV_CONTROL_nrt_nfc_on);
  write_reg(ST25R3916_REG_NO_RESPONSE_TIMER1, 0x00u);
  write_reg(ST25R3916_REG_NO_RESPONSE_TIMER2, K_ST25_A_NO_RESPONSE_TIMER_WUP);
  write_reg(ST25R3916_REG_MASK_RX_TIMER, 0x01u);

  write_reg(ST25R3916_REG_IRQ_MASK_MAIN,
            (uint8_t)(~(IRQ_MAIN_TXE | IRQ_MAIN_RXE | IRQ_MAIN_RXS |
                        IRQ_MAIN_COL | IRQ_MAIN_FWL)));
  write_reg(ST25R3916_REG_IRQ_MASK_TIMER_NFC, (uint8_t)(~IRQ_TIMER_NRE));
  write_reg(ST25R3916_REG_IRQ_MASK_ERROR_WUP,
            (uint8_t)(~(IRQ_ERROR_CRC | IRQ_ERROR_PAR | IRQ_ERROR_ERR1 |
                        IRQ_ERROR_ERR2)));
  write_reg(ST25R3916_REG_IRQ_MASK_TARGET, K_ST25_A_IRQ_MASK_ALL);
}

NERO_NFC_NODISCARD bool st25_iso14443a_send_short_frame(
    uint8_t cmd_short_frame, uint8_t* atqa, st25_cmd_fn_t direct_cmd,
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
  write_reg(ST25R3916_REG_TIMER_EMV_CONTROL,
            ST25R3916_REG_TIMER_EMV_CONTROL_nrt_step_4096_fc |
                ST25R3916_REG_TIMER_EMV_CONTROL_nrt_nfc_on);
  write_reg(ST25R3916_REG_NO_RESPONSE_TIMER1, 0x00u);
  write_reg(ST25R3916_REG_NO_RESPONSE_TIMER2,
            K_ST25_A_NO_RESPONSE_TIMER_ANTICOLL);
  clear_irqs();

  direct_cmd(cmd_short_frame);

  tx_irqs = wait_for_irqs(K_ST25_A_WUP_IRQ_WAIT_TICKS);
  if ((irq_main(tx_irqs) & IRQ_MAIN_TXE) == 0u) {
    return false;
  }

  delay_ms(K_ST25_A_WUP_SETTLE_MS);
  rx_irqs = read_irq_regs();
  if ((irq_main(rx_irqs) & (IRQ_MAIN_RXE | IRQ_MAIN_COL)) == 0u) {
    return false;
  }

  len = read_fifo(atqa, K_ST25_A_ATQA_LEN);
  return len >= K_ST25_A_ATQA_LEN;
}

int st25_iso14443a_anticollision_select(uint8_t sel_cmd, uint8_t* uid_out,
                                        st25_transceive_i_fn_t transceive_i,
                                        void* context) {
  uint8_t tx_buffer[K_ST25_A_SELECT_TX_CAP];
  uint8_t rx_buffer[K_ST25_A_SELECT_RX_CAP];
  int rx_len;
  uint8_t bcc;
  int sak_len;

  if (uid_out != NERO_NFC_NULL) {
    for (unsigned i = 0u; i < (unsigned)K_ST25_A_CASCADE_UID_FRAME_LEN; i++) {
      if (!nero_nfc_store_u8(uid_out, (size_t)(K_ST25_A_CASCADE_UID_FRAME_LEN),
                             (size_t)(i), (uint8_t)(0u))) {
        return -1;
      }
    }
  }
  if ((uid_out == NERO_NFC_NULL) || (transceive_i == NERO_NFC_NULL)) {
    return -1;
  }
  tx_buffer[0] = sel_cmd;
  tx_buffer[K_IDX1] = K_ST25_A_ANTICOLL_CL1_CODE;

  rx_len =
      transceive_i(context, tx_buffer, K_ST25_A_ANTICOLL_TX_LEN, rx_buffer,
                   sizeof(rx_buffer), 0, K_ST25_A_TRANSCEIVE_TIMEOUT_MS, 1, 0);
  if (rx_len < K_ST25_A_SAK_MIN_RX_LEN) {
    return -1;
  }

  bcc = (uint8_t)(rx_buffer[K_IDX0] ^ rx_buffer[K_IDX1] ^ rx_buffer[K_IDX2] ^
                  rx_buffer[K_IDX3]);
  if (bcc != rx_buffer[K_ST25_A_BCC_INDEX]) {
    return -1;
  }

  if (!nero_nfc_store_u8(uid_out, (size_t)(K_ST25_A_CASCADE_UID_FRAME_LEN),
                         (size_t)(K_IDX0), rx_buffer[K_IDX0]) ||
      !nero_nfc_store_u8(uid_out, (size_t)(K_ST25_A_CASCADE_UID_FRAME_LEN),
                         (size_t)(K_IDX1), rx_buffer[K_IDX1]) ||
      !nero_nfc_store_u8(uid_out, (size_t)(K_ST25_A_CASCADE_UID_FRAME_LEN),
                         (size_t)(K_IDX2), rx_buffer[K_IDX2]) ||
      !nero_nfc_store_u8(uid_out, (size_t)(K_ST25_A_CASCADE_UID_FRAME_LEN),
                         (size_t)(K_IDX3), rx_buffer[K_IDX3])) {
    return -1;
  }

  tx_buffer[0] = sel_cmd;
  tx_buffer[K_IDX1] = K_ST25_A_SELECT_CL1_CODE;
  tx_buffer[K_IDX2] = rx_buffer[K_IDX0];
  tx_buffer[K_IDX3] = rx_buffer[K_IDX1];
  tx_buffer[K_IDX4] = rx_buffer[K_IDX2];
  tx_buffer[K_IDX5] = rx_buffer[K_IDX3];
  tx_buffer[K_IDX6] = rx_buffer[K_ST25_A_BCC_INDEX];

  sak_len =
      transceive_i(context, tx_buffer, K_ST25_A_SELECT_TX_LEN, rx_buffer,
                   sizeof(rx_buffer), 1, K_ST25_A_TRANSCEIVE_TIMEOUT_MS, 0, 0);
  if (sak_len < 1) {
    return -1;
  }

  return rx_buffer[0];
}

NERO_NFC_NODISCARD bool st25_iso14443a_activate_tag(
    st25_send_short_frame_fn_t send_wupa, st25_send_short_frame_fn_t send_reqa,
    st25_delay_context_fn_t delay_ms, void* context,
    bool retry_with_reqa_on_second_try,
    st25_anticollision_select_fn_t select_uid, uint8_t* uid_out,
    uint8_t uid_out_capacity, uint8_t* uid_len_out, uint8_t* sak_out) {
  uint8_t atqa[K_ST25_A_ATQA_LEN];
  uint8_t cl1_uid[K_ST25_A_CASCADE_UID_FRAME_LEN];
  int sak1;

  if ((uid_out != NERO_NFC_NULL) &&
      (uid_out_capacity >= K_ST25_A_UID_LEN_DOUBLE)) {
    for (unsigned i = 0u; i < (unsigned)K_ST25_A_UID_LEN_DOUBLE; i++) {
      if (!nero_nfc_store_u8(uid_out, (size_t)(uid_out_capacity), (size_t)(i),
                             (uint8_t)(0u))) {
        return false;
      }
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
      (uid_len_out == NERO_NFC_NULL) || (sak_out == NERO_NFC_NULL) ||
      (uid_out_capacity < K_ST25_A_UID_LEN_DOUBLE)) {
    return false;
  }

  if (!send_wupa(context, atqa)) {
    delay_ms(context, K_ST25_A_CASCADE_SETTLE_MS);
    if (retry_with_reqa_on_second_try) {
      if ((send_reqa == NERO_NFC_NULL) || !send_reqa(context, atqa)) {
        return false;
      }
    } else {
      if (!send_wupa(context, atqa)) {
        return false;
      }
    }
  }

  sak1 = select_uid(context, ISO14443_CMD_SEL_CL1, cl1_uid);
  if (sak1 < 0) {
    return false;
  }

  {
    uint8_t cl2_uid[K_S_T25_ISO14443_A_SEL_RESP_LEN];
    uint8_t cl3_uid[K_S_T25_ISO14443_A_SEL_RESP_LEN];
    int sak2 = -1;
    int sak3 = -1;
    uint8_t levels = 1u;

    if ((sak1 & K_S_T25_ISO14443_A_SAK_CASCADE_BIT) != 0) {
      sak2 = select_uid(context, ISO14443_CMD_SEL_CL2, cl2_uid);
      if (sak2 < 0) {
        return false;
      }
      levels = K_ST25_A_UID_LEVELS_DOUBLE;
      if ((sak2 & K_S_T25_ISO14443_A_SAK_CASCADE_BIT) != 0) {
        sak3 = select_uid(context, ISO14443_CMD_SEL_CL3, cl3_uid);
        if (sak3 < 0) {
          return false;
        }
        levels = K_ST25_A_UID_LEVELS_TRIPLE;
      }
    }

    {
      uint8_t uid_len = st25_iso14443a_assemble_cascaded_uid(
          levels, cl1_uid, sak1, cl2_uid, sak2, cl3_uid, sak3, uid_out,
          uid_out_capacity, sak_out);
      if (uid_len == 0u) {
        return false;
      }
      *uid_len_out = uid_len;
    }
  }

  return true;
}
