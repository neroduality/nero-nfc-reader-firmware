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
#include "st25_sketch_spi.h"

typedef void (*st25_cmd_fn_t)(uint8_t cmd);
typedef void (*st25_write_reg_fn_t)(uint8_t reg, uint8_t value);
typedef uint8_t (*st25_read_reg_fn_t)(uint8_t reg);
typedef void (*st25_reg_bits_fn_t)(uint8_t reg, uint8_t mask);
typedef void (*st25_write_fifo_fn_t)(const uint8_t *data, uint16_t len);
typedef uint16_t (*st25_read_fifo_fn_t)(uint8_t *buffer, uint16_t max_len);
typedef void (*st25_void_fn_t)(void);
typedef uint32_t (*st25_wait_irqs_fn_t)(uint32_t timeout_ticks);
typedef uint32_t (*st25_read_irq_regs_fn_t)(void);
typedef uint8_t (*st25_irq_extract_fn_t)(uint32_t status);
typedef void (*st25_delay_ms_fn_t)(uint32_t ms);
typedef uint32_t (*st25_millis_fn_t)(void);

enum {
  ST25R3916_OSC_STARTUP_POLL_ATTEMPTS = 50u,
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
  ST25_INIT_OK = 0,
  ST25_INIT_CHIP_ID_FAIL = 1,
  ST25_INIT_OSC_FAIL = 2,
} st25_init_status_t;

typedef enum {
  ST25_FIELD_ON_OK = 0,
  ST25_FIELD_ON_COLLISION = 1,
  ST25_FIELD_ON_TXRX_VERIFY_FAIL = 2,
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

NERO_NFC_NODISCARD static inline bool st25_runtime_ops_ready(const st25_runtime_ops_t *ops) {
  return (ops != NERO_NFC_NULL) && (ops->cmd != NERO_NFC_NULL) &&
         (ops->write_reg != NERO_NFC_NULL) && (ops->read_reg != NERO_NFC_NULL) &&
         (ops->set_reg_bits != NERO_NFC_NULL) && (ops->clr_reg_bits != NERO_NFC_NULL) &&
         (ops->write_reg_b != NERO_NFC_NULL) && (ops->set_reg_b_bits != NERO_NFC_NULL) &&
         (ops->write_fifo != NERO_NFC_NULL) && (ops->read_fifo != NERO_NFC_NULL) &&
         (ops->clear_irqs != NERO_NFC_NULL) && (ops->wait_for_irqs != NERO_NFC_NULL) &&
         (ops->read_irq_regs != NERO_NFC_NULL) && (ops->irq_main != NERO_NFC_NULL) &&
         (ops->irq_timer != NERO_NFC_NULL) && (ops->irq_target != NERO_NFC_NULL) &&
         (ops->delay_ms != NERO_NFC_NULL);
}

static inline st25_init_status_t st25_runtime_init_common(const st25_runtime_ops_t *ops,
                                                          uint8_t *chip_id_out,
                                                          uint16_t *vdd_mv_out) {
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
    return ST25_INIT_CHIP_ID_FAIL;
  }

  ops->cmd(ST25R3916_CMD_SET_DEFAULT);
  ops->delay_ms(5u);

  ops->write_reg(ST25R3916_REG_IO_CONF2, ST25R3916_REG_IO_CONF2_io_drv_lvl);

  chip_id = ops->read_reg(ST25R3916_REG_IC_IDENTITY);
  if (chip_id_out != NERO_NFC_NULL) {
    *chip_id_out = chip_id;
  }
  /* [ST25R3916] IC_IDENTITY bits 7:3 are ic_type. Accept only the ST25R3916 and
   * ST25R3916B identities and fail closed on anything else (this also rejects
   * the all-zero / all-one bus-stuck patterns). */
  {
    const uint8_t ic_type = (uint8_t)(chip_id & ST25R3916_REG_IC_IDENTITY_ic_type_mask);
    if ((ic_type != ST25R3916_REG_IC_IDENTITY_ic_type_st25r3916) &&
        (ic_type != ST25R3916_REG_IC_IDENTITY_ic_type_st25r3916B)) {
      return ST25_INIT_CHIP_ID_FAIL;
    }
  }

  ops->write_reg(ST25R3916_REG_IO_CONF1, 0x07u);
  ops->set_reg_bits(ST25R3916_REG_IO_CONF2, ST25R3916_REG_IO_CONF2_miso_pd1 |
                                              ST25R3916_REG_IO_CONF2_miso_pd2 |
                                              ST25R3916_REG_IO_CONF2_aat_en);

  ops->clear_irqs();
  ops->write_reg(ST25R3916_REG_IRQ_MASK_MAIN, (uint8_t)~IRQ_MAIN_OSC);
  ops->set_reg_bits(ST25R3916_REG_OP_CONTROL, ST25R3916_REG_OP_CONTROL_en);

  for (i = 0; i < ST25R3916_OSC_STARTUP_POLL_ATTEMPTS; i++) {
    ops->delay_ms(10u);
    if ((ops->read_reg(ST25R3916_REG_AUX_DISPLAY) & ST25R3916_REG_AUX_DISPLAY_osc_ok) != 0u) {
      osc_ok = true;
      break;
    }
  }
  if (!osc_ok) {
    return ST25_INIT_OSC_FAIL;
  }

  ops->write_reg(ST25R3916_REG_IRQ_MASK_MAIN, 0xFFu);
  ops->write_reg(ST25R3916_REG_IRQ_MASK_TIMER_NFC, 0xFFu);
  ops->write_reg(ST25R3916_REG_IRQ_MASK_ERROR_WUP, 0xFFu);
  ops->write_reg(ST25R3916_REG_IRQ_MASK_TARGET, 0xFFu);
  ops->clear_irqs();

  ops->cmd(ST25R3916_CMD_RC_CAL);
  ops->delay_ms(5u);

  reg_ctl = ops->read_reg(ST25R3916_REG_REGULATOR_CONTROL);
  reg_ctl = (uint8_t)((reg_ctl & 0xF0u) | 0x01u);
  ops->write_reg(ST25R3916_REG_REGULATOR_CONTROL, reg_ctl);
  ops->cmd(ST25R3916_CMD_MEASURE_VDD);
  ops->delay_ms(5u);
  ad_result = ops->read_reg(ST25R3916_REG_AD_RESULT);
  vdd_mv = (uint16_t)ad_result * 23u + (((uint16_t)ad_result * 4u + 5u) / 10u);
  if (vdd_mv_out != NERO_NFC_NULL) {
    *vdd_mv_out = vdd_mv;
  }
  if (vdd_mv < 3600u) {
    ops->set_reg_bits(ST25R3916_REG_IO_CONF2, ST25R3916_REG_IO_CONF2_sup3V);
  } else {
    ops->clr_reg_bits(ST25R3916_REG_IO_CONF2, ST25R3916_REG_IO_CONF2_sup3V);
  }

  ops->set_reg_bits(ST25R3916_REG_REGULATOR_CONTROL, 0x80u);
  ops->clr_reg_bits(ST25R3916_REG_REGULATOR_CONTROL, 0x80u);
  ops->cmd(ST25R3916_CMD_ADJUST_REGULATORS);
  ops->delay_ms(10u);

  ops->write_reg(ST25R3916_REG_TX_DRIVER, 0xF0u);
  ops->write_reg_b(REGB_RES_AM_MOD, 0x80u);
  ops->write_reg(ST25R3916_REG_FIELD_THRESHOLD_ACTV, 0x13u);
  ops->write_reg(ST25R3916_REG_FIELD_THRESHOLD_DEACTV, 0x02u);
  ops->write_reg_b(REGB_AUX_MOD, 0x94u);
  ops->write_reg(ST25R3916_REG_PASSIVE_TARGET, 0x50u);
  ops->write_reg(ST25R3916_REG_PT_MOD, 0x2Eu);
  ops->set_reg_b_bits(REGB_EMD_SUP_CONF, 0x40u);
  ops->write_reg(ST25R3916_REG_ANT_TUNE_A, 0xC5u);
  ops->write_reg(ST25R3916_REG_ANT_TUNE_B, 0xE3u);
  ops->write_reg_b(REGB_AWS_CONF1, 0x09u);
  ops->write_reg_b(REGB_AWS_CONF2, 0x18u);
  ops->write_reg_b(REGB_AWS_TIME1, 0x01u);
  ops->write_reg_b(REGB_AWS_TIME3, 0x79u);
  ops->write_reg_b(REGB_AWS_TIME4, 0x07u);
  ops->clr_reg_bits(ST25R3916_REG_OP_CONTROL,
                    ST25R3916_REG_OP_CONTROL_tx_en | ST25R3916_REG_OP_CONTROL_rx_en);

  return ST25_INIT_OK;
}

static inline st25_field_on_status_t st25_runtime_field_on_common(const st25_runtime_ops_t *ops,
                                                                  bool fail_on_collision,
                                                                  bool verify_txrx,
                                                                  bool *used_direct) {
  bool field_ok = false;
  uint32_t irqs;

  if (used_direct != NERO_NFC_NULL) {
    *used_direct = false;
  }
  if (!st25_runtime_ops_ready(ops)) {
    return ST25_FIELD_ON_TXRX_VERIFY_FAIL;
  }

  ops->write_reg(ST25R3916_REG_FIELD_THRESHOLD_ACTV, 0x13u);
  ops->write_reg(ST25R3916_REG_FIELD_THRESHOLD_DEACTV, 0x02u);
  ops->clear_irqs();
  ops->write_reg(ST25R3916_REG_IRQ_MASK_TARGET, (uint8_t)~IRQ_TARGET_APON);
  ops->write_reg(ST25R3916_REG_IRQ_MASK_TIMER_NFC, (uint8_t)~(IRQ_TIMER_CAT | IRQ_TIMER_CAC));
  ops->cmd(ST25R3916_CMD_INITIAL_RF_COLLISION);

  irqs = ops->wait_for_irqs(200000u);
  if ((ops->irq_target(irqs) & IRQ_TARGET_APON) != 0u) {
    uint32_t irqs2 = ops->wait_for_irqs(200000u);
    if ((ops->irq_timer(irqs2) & IRQ_TIMER_CAT) != 0u) {
      field_ok = true;
    }
  }
  if (((ops->irq_timer(irqs) & IRQ_TIMER_CAC) != 0u) && fail_on_collision) {
    return ST25_FIELD_ON_COLLISION;
  }
  if (!field_ok) {
    if (used_direct != NERO_NFC_NULL) {
      *used_direct = true;
    }
    ops->set_reg_bits(ST25R3916_REG_OP_CONTROL, ST25R3916_REG_OP_CONTROL_tx_en);
    ops->delay_ms(10u);
  }

  ops->set_reg_bits(ST25R3916_REG_OP_CONTROL,
                    ST25R3916_REG_OP_CONTROL_tx_en | ST25R3916_REG_OP_CONTROL_rx_en);
  ops->delay_ms(5u);

  if (verify_txrx) {
    uint8_t op_ctl = ops->read_reg(ST25R3916_REG_OP_CONTROL);
    if ((op_ctl & (ST25R3916_REG_OP_CONTROL_tx_en | ST25R3916_REG_OP_CONTROL_rx_en)) !=
        (ST25R3916_REG_OP_CONTROL_tx_en | ST25R3916_REG_OP_CONTROL_rx_en)) {
      return ST25_FIELD_ON_TXRX_VERIFY_FAIL;
    }
  }

  return ST25_FIELD_ON_OK;
}

static inline uint32_t st25_runtime_tx_wait_budget_us(uint16_t tx_len) {
  /*
   * IRQ_MAIN_TXE is raised after the full frame leaves the FIFO. At 106 kbps a
   * 60+ byte ISO-DEP frame can take longer than the old fixed 5 ms wait, so
   * budget from the wire length with extra guard time.
   */
  uint32_t tx_bits = ((uint32_t)tx_len * 10u) + 64u;
  uint32_t tx_us = (tx_bits * 1000000u + 105999u) / 106000u;
  uint32_t budget = tx_us + 4000u;

  return (budget < 5000u) ? 5000u : budget;
}

static inline int st25_runtime_transceive_common_diag(
  const st25_runtime_ops_t *ops, const uint8_t *tx_data, uint16_t tx_len, uint8_t *rx_buffer,
  uint16_t rx_buffer_len, bool with_crc, uint16_t timeout_ms, bool anticol, bool no_rx_par,
  bool extended_nrt_16bit, bool poll_rx_until_event, bool clear_nfc_before_fifo_read,
  st25_runtime_transceive_diag_t *diag) {
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

  tx_bits = (uint16_t)(tx_len * 8u);
  ops->write_reg(ST25R3916_REG_NUM_TX_BYTES2, (uint8_t)(tx_bits & 0xFFu));
  ops->write_reg(ST25R3916_REG_NUM_TX_BYTES1, (uint8_t)((tx_bits >> 8) & 0x1Fu));

  ops->write_reg(ST25R3916_REG_TIMER_EMV_CONTROL, ST25R3916_REG_TIMER_EMV_CONTROL_nrt_step_4096_fc |
                                                    ST25R3916_REG_TIMER_EMV_CONTROL_nrt_nfc_on);
  if (extended_nrt_16bit) {
    uint32_t nrt_steps_u32 = (((uint32_t)timeout_ms * 33u) / 10u) + 5u;
    uint16_t nrt_steps = (nrt_steps_u32 > 0xFFFFu) ? 0xFFFFu : (uint16_t)nrt_steps_u32;

    if ((diag != NERO_NFC_NULL) && (nrt_steps_u32 > 0xFFFFu)) {
      diag->nrt_clamped = true;
    }
    if (diag != NERO_NFC_NULL) {
      diag->nrt_steps_programmed = nrt_steps;
    }
    ops->write_reg(ST25R3916_REG_NO_RESPONSE_TIMER1, (uint8_t)(nrt_steps >> 8));
    ops->write_reg(ST25R3916_REG_NO_RESPONSE_TIMER2, (uint8_t)(nrt_steps & 0xFFu));
  } else {
    uint16_t nrt_calc = (uint16_t)((uint32_t)timeout_ms * 3u + 5u);
    uint8_t nrt = (nrt_calc > 0xFFu) ? 0xFFu : (uint8_t)nrt_calc;

    if (diag != NERO_NFC_NULL) {
      diag->nrt_steps_programmed = nrt;
      diag->nrt_clamped = nrt_calc > 0xFFu;
    }
    ops->write_reg(ST25R3916_REG_NO_RESPONSE_TIMER1, 0x00u);
    ops->write_reg(ST25R3916_REG_NO_RESPONSE_TIMER2, nrt);
  }

  ops->clear_irqs();
  ops->cmd(with_crc ? ST25R3916_CMD_TRANSMIT_WITH_CRC : ST25R3916_CMD_TRANSMIT_WITHOUT_CRC);

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
    while ((ops->millis() - start) < (uint32_t)(timeout_ms + 10u)) {
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
    ops->delay_ms((uint32_t)timeout_ms + 2u);
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
    int rx_len = (int)ops->read_fifo(rx_buffer, rx_buffer_len);
    if (!clear_nfc_before_fifo_read) {
      ops->write_reg(ST25R3916_REG_ISO14443A_NFC, 0x00u);
    }
    return rx_len;
  }
}

static inline int st25_runtime_transceive_common(
  const st25_runtime_ops_t *ops, const uint8_t *tx_data, uint16_t tx_len, uint8_t *rx_buffer,
  uint16_t rx_buffer_len, bool with_crc, uint16_t timeout_ms, bool anticol, bool no_rx_par,
  bool extended_nrt_16bit, bool poll_rx_until_event, bool clear_nfc_before_fifo_read) {
  return st25_runtime_transceive_common_diag(
    ops, tx_data, tx_len, rx_buffer, rx_buffer_len, with_crc, timeout_ms, anticol, no_rx_par,
    extended_nrt_16bit, poll_rx_until_event, clear_nfc_before_fifo_read, NERO_NFC_NULL);
}
