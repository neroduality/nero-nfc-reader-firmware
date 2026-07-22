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

#include "st25r3916_runtime.h"

#include "nero_nfc_null.h"
#include "st25_sketch_spi.h"

enum {
  K_S_T25_R3916_OSC_STARTUP_POLL_ATTEMPTS = 50u,
  K_ST25_INIT_SETTLE_MS = 5u,
  K_ST25_OSC_POLL_DELAY_MS = 10u,
  K_ST25_IO_CONF1_DEFAULTS = 0x07u,
  K_ST25_REGULATOR_CTL_KEEP_MASK = 0xF0u,
  K_ST25_REGULATOR_CTL_TARGET = 0x01u,
  K_ST25_VDD_MV_SCALE_MAJOR = 23u,
  K_ST25_VDD_MV_SCALE_FRAC_NUM = 4u,
  K_ST25_VDD_MV_SCALE_FRAC_ADD = 5u,
  K_ST25_VDD_MV_SCALE_FRAC_DEN = 10u,
  K_ST25_VDD_MV_SUP3V_THRESHOLD = 3600u,
  K_ST25_REGULATOR_ADJUST_BIT = 0x80u,
  K_ST25_TX_DRIVER_DEFAULT = 0xF0u,
  K_ST25_RES_AM_MOD_DEFAULT = 0x80u,
  K_ST25_FIELD_THRESH_ACTV = 0x13u,
  K_ST25_FIELD_THRESH_DEACTV = 0x02u,
  K_ST25_AUX_MOD_DEFAULT = 0x94u,
  K_ST25_PASSIVE_TARGET_DEFAULT = 0x50u,
  K_ST25_PT_MOD_DEFAULT = 0x2Eu,
  K_ST25_EMD_SUP_CONF_BIT = 0x40u,
  K_ST25_ANT_TUNE_A_DEFAULT = 0xC5u,
  K_ST25_ANT_TUNE_B_DEFAULT = 0xE3u,
  K_ST25_AWS_CONF1_DEFAULT = 0x09u,
  K_ST25_AWS_CONF2_DEFAULT = 0x18u,
  K_ST25_AWS_TIME3_DEFAULT = 0x79u,
  K_ST25_AWS_TIME4_DEFAULT = 0x07u,
  K_ST25_FIELD_ON_IRQ_WAIT_TICKS = 200000u,
  K_ST25_TX_LEN_BITS_HIGH_MASK = 0x1Fu,
  K_ST25_NRT_MS_TO_STEPS_NUM = 33u,
  K_ST25_NRT_MS_TO_STEPS_DEN = 10u,
  K_ST25_NRT_MS_TO_STEPS_ADD = 5u,
  K_ST25_NRT_STEPS_MAX16 = 0xFFFFu,
  K_ST25_NRT_MS_TO_STEPS_SHORT_MUL = 3u,
  K_ST25_NRT_MS_TO_STEPS_SHORT_ADD = 5u,
  K_ST25_TRANSCEIVE_TIMEOUT_SLACK_MS = 10u,
  K_ST25_TRANSCEIVE_DELAY_SLACK_MS = 2u,
};

NERO_NFC_NODISCARD bool st25_runtime_ops_ready(const st25_runtime_ops_t* ops) {
  return (ops != NERO_NFC_NULL) && (ops->cmd != NERO_NFC_NULL) &&
         (ops->write_reg != NERO_NFC_NULL) &&
         (ops->read_reg != NERO_NFC_NULL) &&
         (ops->set_reg_bits != NERO_NFC_NULL) &&
         (ops->clr_reg_bits != NERO_NFC_NULL) &&
         (ops->write_reg_b != NERO_NFC_NULL) &&
         (ops->set_reg_b_bits != NERO_NFC_NULL) &&
         (ops->write_fifo != NERO_NFC_NULL) &&
         (ops->read_fifo != NERO_NFC_NULL) &&
         (ops->clear_irqs != NERO_NFC_NULL) &&
         (ops->wait_for_irqs != NERO_NFC_NULL) &&
         (ops->read_irq_regs != NERO_NFC_NULL) &&
         (ops->irq_main != NERO_NFC_NULL) &&
         (ops->irq_timer != NERO_NFC_NULL) &&
         (ops->irq_target != NERO_NFC_NULL) && (ops->delay_ms != NERO_NFC_NULL);
}

st25_init_status_t st25_runtime_init_common(const st25_runtime_ops_t* ops,
                                            uint8_t* chip_id_out,
                                            uint16_t* vdd_mv_out) {
  uint8_t chip_id;
  uint8_t reg_ctl;
  uint8_t ad_result;
  uint16_t vdd_mv;
  bool osc_ok = false;
  int i;

  if (chip_id_out != NERO_NFC_NULL) {
    *chip_id_out = 0x00u;
  }
  if (vdd_mv_out != NERO_NFC_NULL) {
    *vdd_mv_out = 0u;
  }
  if (!st25_runtime_ops_ready(ops)) {
    return K_S_T25_INIT_CHIP_ID_FAIL;
  }

  ops->cmd(ST25R3916_CMD_SET_DEFAULT);
  ops->delay_ms(K_ST25_INIT_SETTLE_MS);

  ops->write_reg(ST25R3916_REG_IO_CONF2, ST25R3916_REG_IO_CONF2_io_drv_lvl);

  chip_id = ops->read_reg(ST25R3916_REG_IC_IDENTITY);
  if (chip_id_out != NERO_NFC_NULL) {
    *chip_id_out = chip_id;
  }
  /* [ST25R3916] IC_IDENTITY bits 7:3 are ic_type. Accept only the ST25R3916 and
   * ST25R3916B identities and fail closed on anything else (this also rejects
   * the all-zero / all-one bus-stuck patterns). */
  {
    const uint8_t k_ic_type =
        (uint8_t)(chip_id & ST25R3916_REG_IC_IDENTITY_ic_type_mask);
    if ((k_ic_type != ST25R3916_REG_IC_IDENTITY_ic_type_st25r3916) &&
        (k_ic_type != ST25R3916_REG_IC_IDENTITY_ic_type_st25r3916B)) {
      return K_S_T25_INIT_CHIP_ID_FAIL;
    }
  }

  ops->write_reg(ST25R3916_REG_IO_CONF1, K_ST25_IO_CONF1_DEFAULTS);
  ops->set_reg_bits(ST25R3916_REG_IO_CONF2,
                    ST25R3916_REG_IO_CONF2_miso_pd1 |
                        ST25R3916_REG_IO_CONF2_miso_pd2 |
                        ST25R3916_REG_IO_CONF2_aat_en);

  ops->clear_irqs();
  ops->write_reg(ST25R3916_REG_IRQ_MASK_MAIN, (uint8_t)(~IRQ_MAIN_OSC));
  ops->set_reg_bits(ST25R3916_REG_OP_CONTROL, ST25R3916_REG_OP_CONTROL_en);

  for (i = 0; i < K_S_T25_R3916_OSC_STARTUP_POLL_ATTEMPTS; i++) {
    ops->delay_ms(K_ST25_OSC_POLL_DELAY_MS);
    if ((ops->read_reg(ST25R3916_REG_AUX_DISPLAY) &
         ST25R3916_REG_AUX_DISPLAY_osc_ok) != 0u) {
      osc_ok = true;
      break;
    }
  }
  if (!osc_ok) {
    return K_S_T25_INIT_OSC_FAIL;
  }

  ops->write_reg(ST25R3916_REG_IRQ_MASK_MAIN, K_ST25_IRQ_MASK_ALL);
  ops->write_reg(ST25R3916_REG_IRQ_MASK_TIMER_NFC, K_ST25_IRQ_MASK_ALL);
  ops->write_reg(ST25R3916_REG_IRQ_MASK_ERROR_WUP, K_ST25_IRQ_MASK_ALL);
  ops->write_reg(ST25R3916_REG_IRQ_MASK_TARGET, K_ST25_IRQ_MASK_ALL);
  ops->clear_irqs();

  ops->cmd(ST25R3916_CMD_RC_CAL);
  ops->delay_ms(K_ST25_INIT_SETTLE_MS);

  reg_ctl = ops->read_reg(ST25R3916_REG_REGULATOR_CONTROL);
  reg_ctl = (uint8_t)((reg_ctl & K_ST25_REGULATOR_CTL_KEEP_MASK) |
                      K_ST25_REGULATOR_CTL_TARGET);
  ops->write_reg(ST25R3916_REG_REGULATOR_CONTROL, reg_ctl);
  ops->cmd(ST25R3916_CMD_MEASURE_VDD);
  ops->delay_ms(K_ST25_INIT_SETTLE_MS);
  ad_result = ops->read_reg(ST25R3916_REG_AD_RESULT);
  vdd_mv = (uint16_t)(((unsigned)(ad_result)*K_ST25_VDD_MV_SCALE_MAJOR) +
                      (((unsigned)(ad_result)*K_ST25_VDD_MV_SCALE_FRAC_NUM +
                        K_ST25_VDD_MV_SCALE_FRAC_ADD) /
                       K_ST25_VDD_MV_SCALE_FRAC_DEN));
  if (vdd_mv_out != NERO_NFC_NULL) {
    *vdd_mv_out = vdd_mv;
  }
  if (vdd_mv < K_ST25_VDD_MV_SUP3V_THRESHOLD) {
    ops->set_reg_bits(ST25R3916_REG_IO_CONF2, ST25R3916_REG_IO_CONF2_sup3V);
  } else {
    ops->clr_reg_bits(ST25R3916_REG_IO_CONF2, ST25R3916_REG_IO_CONF2_sup3V);
  }

  ops->set_reg_bits(ST25R3916_REG_REGULATOR_CONTROL,
                    K_ST25_REGULATOR_ADJUST_BIT);
  ops->clr_reg_bits(ST25R3916_REG_REGULATOR_CONTROL,
                    K_ST25_REGULATOR_ADJUST_BIT);
  ops->cmd(ST25R3916_CMD_ADJUST_REGULATORS);
  ops->delay_ms(K_ST25_OSC_POLL_DELAY_MS);

  ops->write_reg(ST25R3916_REG_TX_DRIVER, K_ST25_TX_DRIVER_DEFAULT);
  ops->write_reg_b(REGB_RES_AM_MOD, K_ST25_RES_AM_MOD_DEFAULT);
  ops->write_reg(ST25R3916_REG_FIELD_THRESHOLD_ACTV, K_ST25_FIELD_THRESH_ACTV);
  ops->write_reg(ST25R3916_REG_FIELD_THRESHOLD_DEACTV,
                 K_ST25_FIELD_THRESH_DEACTV);
  ops->write_reg_b(REGB_AUX_MOD, K_ST25_AUX_MOD_DEFAULT);
  ops->write_reg(ST25R3916_REG_PASSIVE_TARGET, K_ST25_PASSIVE_TARGET_DEFAULT);
  ops->write_reg(ST25R3916_REG_PT_MOD, K_ST25_PT_MOD_DEFAULT);
  ops->set_reg_b_bits(REGB_EMD_SUP_CONF, K_ST25_EMD_SUP_CONF_BIT);
  ops->write_reg(ST25R3916_REG_ANT_TUNE_A, K_ST25_ANT_TUNE_A_DEFAULT);
  ops->write_reg(ST25R3916_REG_ANT_TUNE_B, K_ST25_ANT_TUNE_B_DEFAULT);
  ops->write_reg_b(REGB_AWS_CONF1, K_ST25_AWS_CONF1_DEFAULT);
  ops->write_reg_b(REGB_AWS_CONF2, K_ST25_AWS_CONF2_DEFAULT);
  ops->write_reg_b(REGB_AWS_TIME1, 0x01u);
  ops->write_reg_b(REGB_AWS_TIME3, K_ST25_AWS_TIME3_DEFAULT);
  ops->write_reg_b(REGB_AWS_TIME4, K_ST25_AWS_TIME4_DEFAULT);
  ops->clr_reg_bits(
      ST25R3916_REG_OP_CONTROL,
      ST25R3916_REG_OP_CONTROL_tx_en | ST25R3916_REG_OP_CONTROL_rx_en);

  return K_S_T25_INIT_OK;
}

st25_field_on_status_t st25_runtime_field_on_common(
    const st25_runtime_ops_t* ops, bool fail_on_collision, bool verify_txrx,
    bool* used_direct) {
  bool field_ok = false;
  uint32_t irqs;

  if (used_direct != NERO_NFC_NULL) {
    *used_direct = false;
  }
  if (!st25_runtime_ops_ready(ops)) {
    return K_S_T25_FIELD_ON_TXRX_VERIFY_FAIL;
  }

  ops->write_reg(ST25R3916_REG_FIELD_THRESHOLD_ACTV, K_ST25_FIELD_THRESH_ACTV);
  ops->write_reg(ST25R3916_REG_FIELD_THRESHOLD_DEACTV,
                 K_ST25_FIELD_THRESH_DEACTV);
  ops->clear_irqs();
  ops->write_reg(ST25R3916_REG_IRQ_MASK_TARGET, (uint8_t)(~IRQ_TARGET_APON));
  ops->write_reg(ST25R3916_REG_IRQ_MASK_TIMER_NFC,
                 (uint8_t)(~(IRQ_TIMER_CAT | IRQ_TIMER_CAC)));
  ops->cmd(ST25R3916_CMD_INITIAL_RF_COLLISION);

  irqs = ops->wait_for_irqs(K_ST25_FIELD_ON_IRQ_WAIT_TICKS);
  if ((ops->irq_target(irqs) & IRQ_TARGET_APON) != 0u) {
    uint32_t irqs2 = ops->wait_for_irqs(K_ST25_FIELD_ON_IRQ_WAIT_TICKS);
    if ((ops->irq_timer(irqs2) & IRQ_TIMER_CAT) != 0u) {
      field_ok = true;
    }
  }
  if (((ops->irq_timer(irqs) & IRQ_TIMER_CAC) != 0u) && fail_on_collision) {
    return K_S_T25_FIELD_ON_COLLISION;
  }
  if (!field_ok) {
    if (used_direct != NERO_NFC_NULL) {
      *used_direct = true;
    }
    ops->set_reg_bits(ST25R3916_REG_OP_CONTROL, ST25R3916_REG_OP_CONTROL_tx_en);
    ops->delay_ms(K_ST25_OSC_POLL_DELAY_MS);
  }

  ops->set_reg_bits(
      ST25R3916_REG_OP_CONTROL,
      ST25R3916_REG_OP_CONTROL_tx_en | ST25R3916_REG_OP_CONTROL_rx_en);
  ops->delay_ms(K_ST25_INIT_SETTLE_MS);

  if (verify_txrx) {
    uint8_t op_ctl = ops->read_reg(ST25R3916_REG_OP_CONTROL);
    if ((op_ctl &
         (ST25R3916_REG_OP_CONTROL_tx_en | ST25R3916_REG_OP_CONTROL_rx_en)) !=
        (ST25R3916_REG_OP_CONTROL_tx_en | ST25R3916_REG_OP_CONTROL_rx_en)) {
      return K_S_T25_FIELD_ON_TXRX_VERIFY_FAIL;
    }
  }

  return K_S_T25_FIELD_ON_OK;
}

int st25_runtime_transceive_common_diag(
    const st25_runtime_ops_t* ops, const uint8_t* tx_data, uint16_t tx_len,
    uint8_t* rx_buffer, uint16_t rx_buffer_len, bool with_crc,
    uint16_t timeout_ms, bool anticol, bool no_rx_par, bool extended_nrt_16bit,
    bool poll_rx_until_event, bool clear_nfc_before_fifo_read,
    st25_runtime_transceive_diag_t* diag) {
  uint8_t nfc_reg = 0x00u;
  uint16_t tx_bits;
  uint32_t all_irqs;
  uint32_t tx_wait_us;
  bool got_rxe;
  bool got_nre;

  if (diag != NERO_NFC_NULL) {
    diag->requested_timeout_ms = timeout_ms;
    diag->nrt_steps_programmed = 0u;
    diag->tx_wait_us = 0u;
    diag->tx_irq_status = 0u;
    diag->final_irq_status = 0u;
    diag->extended_nrt_16bit = extended_nrt_16bit;
    diag->nrt_clamped = false;
    diag->got_txe = false;
    diag->got_rxe = false;
    diag->got_nre = false;
  }

  if (!st25_runtime_ops_ready(ops)) {
    return 0;
  }
  if (poll_rx_until_event && (ops->millis == NERO_NFC_NULL)) {
    return 0;
  }
  /* Fail closed on inconsistent buffers so we never transmit stale FIFO bytes
   * or receive into a null buffer. */
  if (((tx_len > 0u) && (tx_data == NERO_NFC_NULL)) ||
      ((rx_buffer_len > 0u) && (rx_buffer == NERO_NFC_NULL))) {
    return 0;
  }

  ops->cmd(ST25R3916_CMD_STOP);
  ops->cmd(ST25R3916_CMD_CLEAR_FIFO);
  ops->cmd(ST25R3916_CMD_RESET_RXGAIN);
  ops->set_reg_bits(ST25R3916_REG_OP_CONTROL, ST25R3916_REG_OP_CONTROL_rx_en);
  ops->clear_irqs();

  if (anticol) {
    nfc_reg |= ST25R3916_REG_ISO14443A_NFC_antcl;
  }
  if (no_rx_par) {
    nfc_reg |= ST25R3916_REG_ISO14443A_NFC_no_rx_par;
  }
  ops->write_reg(ST25R3916_REG_ISO14443A_NFC, nfc_reg);

  if ((tx_len > 0u) && (tx_data != NERO_NFC_NULL)) {
    ops->write_fifo(tx_data, tx_len);
  }

  tx_bits = (uint16_t)(tx_len * NFC_BITS_PER_BYTE);
  ops->write_reg(ST25R3916_REG_NUM_TX_BYTES2,
                 (uint8_t)(tx_bits & NFC_BYTE_VALUE_MAX));
  ops->write_reg(
      ST25R3916_REG_NUM_TX_BYTES1,
      (uint8_t)((tx_bits >> NFC_BYTE_SHIFT_8) & K_ST25_TX_LEN_BITS_HIGH_MASK));

  ops->write_reg(ST25R3916_REG_TIMER_EMV_CONTROL,
                 ST25R3916_REG_TIMER_EMV_CONTROL_nrt_step_4096_fc |
                     ST25R3916_REG_TIMER_EMV_CONTROL_nrt_nfc_on);
  if (extended_nrt_16bit) {
    uint32_t nrt_steps_u32 =
        (((uint32_t)(timeout_ms)*K_ST25_NRT_MS_TO_STEPS_NUM) /
         K_ST25_NRT_MS_TO_STEPS_DEN) +
        K_ST25_NRT_MS_TO_STEPS_ADD;
    const uint32_t k_nrt_steps_max = (uint32_t)(K_ST25_NRT_STEPS_MAX16);
    uint16_t nrt_steps = (nrt_steps_u32 > k_nrt_steps_max)
                             ? (uint16_t)(k_nrt_steps_max)
                             : (uint16_t)(nrt_steps_u32);

    if ((diag != NERO_NFC_NULL) && (nrt_steps_u32 > k_nrt_steps_max)) {
      diag->nrt_clamped = true;
    }
    if (diag != NERO_NFC_NULL) {
      diag->nrt_steps_programmed = nrt_steps;
    }
    ops->write_reg(ST25R3916_REG_NO_RESPONSE_TIMER1,
                   (uint8_t)(nrt_steps >> NFC_BYTE_SHIFT_8));
    ops->write_reg(ST25R3916_REG_NO_RESPONSE_TIMER2,
                   (uint8_t)(nrt_steps & NFC_BYTE_VALUE_MAX));
  } else {
    uint16_t nrt_calc =
        (uint16_t)(((uint32_t)(timeout_ms)*K_ST25_NRT_MS_TO_STEPS_SHORT_MUL) +
                   K_ST25_NRT_MS_TO_STEPS_SHORT_ADD);
    uint8_t nrt = (nrt_calc > NFC_BYTE_VALUE_MAX) ? NFC_BYTE_VALUE_MAX
                                                  : (uint8_t)(nrt_calc);

    if (diag != NERO_NFC_NULL) {
      diag->nrt_steps_programmed = nrt;
      diag->nrt_clamped = nrt_calc > NFC_BYTE_VALUE_MAX;
    }
    ops->write_reg(ST25R3916_REG_NO_RESPONSE_TIMER1, 0x00u);
    ops->write_reg(ST25R3916_REG_NO_RESPONSE_TIMER2, nrt);
  }

  ops->clear_irqs();
  ops->cmd(with_crc ? ST25R3916_CMD_TRANSMIT_WITH_CRC
                    : ST25R3916_CMD_TRANSMIT_WITHOUT_CRC);

  tx_wait_us = st25_runtime_tx_wait_budget_us(tx_len);
  all_irqs = ops->wait_for_irqs(tx_wait_us);
  if ((ops->irq_main(all_irqs) & IRQ_MAIN_TXE) == 0u) {
    /* IRQ pin fallback: IRQ registers are latched on the ST25R3916 so TXE
     * remains pending even if the IRQ pin was not observed to assert HIGH.
     * Read directly to cover the case where the IRQ pin is disconnected. */
    all_irqs |= ops->read_irq_regs();
  }
  if (diag != NERO_NFC_NULL) {
    diag->tx_wait_us = tx_wait_us;
    diag->tx_irq_status = all_irqs;
    diag->got_txe = (ops->irq_main(all_irqs) & IRQ_MAIN_TXE) != 0u;
  }
  if ((ops->irq_main(all_irqs) & IRQ_MAIN_TXE) == 0u) {
    return 0;
  }

  if (poll_rx_until_event) {
    uint32_t start = ops->millis();
    while ((ops->millis() - start) <
           (uint32_t)(timeout_ms + K_ST25_TRANSCEIVE_TIMEOUT_SLACK_MS)) {
      all_irqs |= ops->read_irq_regs();
      if ((ops->irq_main(all_irqs) & IRQ_MAIN_RXE) != 0u) {
        break;
      }
      if ((ops->irq_timer(all_irqs) & IRQ_TIMER_NRE) != 0u) {
        break;
      }
      ops->delay_ms(1u);
    }
  } else {
    ops->delay_ms((uint32_t)(timeout_ms) + K_ST25_TRANSCEIVE_DELAY_SLACK_MS);
    all_irqs |= ops->read_irq_regs();
  }

  got_rxe = (ops->irq_main(all_irqs) & IRQ_MAIN_RXE) != 0u;
  got_nre = (ops->irq_timer(all_irqs) & IRQ_TIMER_NRE) != 0u;
  if (diag != NERO_NFC_NULL) {
    diag->final_irq_status = all_irqs;
    diag->got_rxe = got_rxe;
    diag->got_nre = got_nre;
  }
  if (got_nre && !got_rxe) {
    return 0;
  }
  if (!got_rxe) {
    return 0;
  }

  if (clear_nfc_before_fifo_read) {
    ops->write_reg(ST25R3916_REG_ISO14443A_NFC, 0x00u);
  }
  {
    int rx_len = (int)(ops->read_fifo(rx_buffer, rx_buffer_len));
    if (!clear_nfc_before_fifo_read) {
      ops->write_reg(ST25R3916_REG_ISO14443A_NFC, 0x00u);
    }
    return rx_len;
  }
}

int st25_runtime_transceive_common(
    const st25_runtime_ops_t* ops, const uint8_t* tx_data, uint16_t tx_len,
    uint8_t* rx_buffer, uint16_t rx_buffer_len, bool with_crc,
    uint16_t timeout_ms, bool anticol, bool no_rx_par, bool extended_nrt_16bit,
    bool poll_rx_until_event, bool clear_nfc_before_fifo_read) {
  return st25_runtime_transceive_common_diag(
      ops, tx_data, tx_len, rx_buffer, rx_buffer_len, with_crc, timeout_ms,
      anticol, no_rx_par, extended_nrt_16bit, poll_rx_until_event,
      clear_nfc_before_fifo_read, NERO_NFC_NULL);
}
