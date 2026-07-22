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

#include "st25r3916_iso15693.h"

#include "nero_nfc_null.h"
#include "st25_sketch_spi.h"

enum {
  K_ST25_V_ISO14443A_NFC_REG = 0x1Cu,
  K_ST25_V_RX_CONF1 = 0x13u,
  K_ST25_V_RX_CONF2 = 0xEDu,
  K_ST25_V_CORR_CONF1 = 0x13u,
  K_ST25_V_MODE_SETTLE_MS = 5u,
};

void st25_iso15693_configure_defaults(st25_write_reg_fn_t write_reg,
                                      st25_write_reg_fn_t write_reg_b,
                                      st25_reg_bits_fn_t set_reg_bits,
                                      st25_reg_bits_fn_t clr_reg_bits,
                                      st25_delay_ms_fn_t delay_ms) {
  if ((write_reg == NERO_NFC_NULL) || (write_reg_b == NERO_NFC_NULL) ||
      (set_reg_bits == NERO_NFC_NULL) || (clr_reg_bits == NERO_NFC_NULL) ||
      (delay_ms == NERO_NFC_NULL)) {
    return;
  }
  write_reg(ST25R3916_REG_MODE, ST25R3916_REG_MODE_om_subcarrier_stream);
  write_reg(ST25R3916_REG_BIT_RATE, BR_TX_26 | BR_RX_26);
  write_reg(ST25R3916_REG_STREAM_MODE, STREAM_MODE_ISO15693_26KBPS);
  write_reg(ST25R3916_REG_ISO14443A_NFC, K_ST25_V_ISO14443A_NFC_REG);
  write_reg(ST25R3916_REG_RX_CONF1, K_ST25_V_RX_CONF1);
  write_reg(ST25R3916_REG_RX_CONF2, K_ST25_V_RX_CONF2);
  write_reg(ST25R3916_REG_RX_CONF3, 0x00u);
  write_reg(ST25R3916_REG_RX_CONF4, 0x00u);
  write_reg_b(REGB_CORR_CONF1, K_ST25_V_CORR_CONF1);
  write_reg_b(REGB_CORR_CONF2, 0x01u);
  clr_reg_bits(ST25R3916_REG_AUX, ST25R3916_REG_AUX_dis_corr);
  set_reg_bits(ST25R3916_REG_OP_CONTROL,
               ST25R3916_REG_OP_CONTROL_tx_en | ST25R3916_REG_OP_CONTROL_rx_en);
  delay_ms(K_ST25_V_MODE_SETTLE_MS);
}
