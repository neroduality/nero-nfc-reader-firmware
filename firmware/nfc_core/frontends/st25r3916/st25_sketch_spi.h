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

/*
 * Thin glue on top of vendored ST reader headers for this sketch’s raw SPI HAL:
 * - SPI framing bytes (same encoding as STMicroelectronics ST25R3916 Arduino
 * driver).
 * - IRQ masks folded into single-register-byte form used by
 * st25_bus_read_irq_regs().
 * - Space-B offsets for SPI space-B access sequences.
 * - A few NFC/NTAG wire constants not exported as macros in those trees.
 *
 * Manifest prefixes in this frontend shim:
 *   [ISO14443-3] SELECT cascade-level command bytes.
 *   [ISO14443-4] RATS command byte.
 *   [T2T-ISO14443-A] Type 2 READ/WRITE command bytes.
 *   [T2T-ISO14443-A-NTAG21x] NTAG GET_VERSION command byte.
 */

#include "nfc_frontend_model.h"

#include "st25r3916.h"
#include "st25r3916_interrupt.h"

#define SPI_WRITE_REG(r) ((uint8_t)((r) & 0x3Fu))
#define SPI_READ_REG(r) ((uint8_t)(((r) & 0x3Fu) | (1u << 6)))
#define SPI_FIFO_LOAD 0x80u
#define SPI_FIFO_READ 0x9Fu
#define SPI_DIRECT_CMD(c) (c)

#define BR_TX_26 ((uint8_t)(ST25R3916_BR_424 << 4))
#define BR_RX_26 ((uint8_t)ST25R3916_BR_424)

#define STREAM_MODE_ISO15693_26KBPS                                                                \
  ((uint8_t)(ST25R3916_REG_STREAM_MODE_scf_sc424 | ST25R3916_REG_STREAM_MODE_scp_8pulses |         \
             ST25R3916_REG_STREAM_MODE_stx_106))

#define REGB_EMD_SUP_CONF ((uint8_t)(ST25R3916_REG_EMD_SUP_CONF & 0x3Fu))
#define REGB_CORR_CONF1 ((uint8_t)(ST25R3916_REG_CORR_CONF1 & 0x3Fu))
#define REGB_CORR_CONF2 ((uint8_t)(ST25R3916_REG_CORR_CONF2 & 0x3Fu))
#define REGB_AUX_MOD ((uint8_t)(ST25R3916_REG_AUX_MOD & 0x3Fu))
#define REGB_RES_AM_MOD ((uint8_t)(ST25R3916_REG_RES_AM_MOD & 0x3Fu))
#define REGB_AWS_CONF1 ((uint8_t)(ST25R3916_REG_AWS_CONF1 & 0x3Fu))
#define REGB_AWS_CONF2 ((uint8_t)(ST25R3916_REG_AWS_CONF2 & 0x3Fu))
#define REGB_AWS_TIME1 ((uint8_t)(ST25R3916_REG_AWS_TIME1 & 0x3Fu))
#define REGB_AWS_TIME3 ((uint8_t)(ST25R3916_REG_AWS_TIME3 & 0x3Fu))
#define REGB_AWS_TIME4 ((uint8_t)(ST25R3916_REG_AWS_TIME4 & 0x3Fu))

#define IRQ_MAIN_OSC ((uint8_t)(ST25R3916_IRQ_MASK_OSC & 0xFFu))
#define IRQ_MAIN_FWL ((uint8_t)(ST25R3916_IRQ_MASK_FWL & 0xFFu))
#define IRQ_MAIN_RXS ((uint8_t)(ST25R3916_IRQ_MASK_RXS & 0xFFu))
#define IRQ_MAIN_RXE ((uint8_t)(ST25R3916_IRQ_MASK_RXE & 0xFFu))
#define IRQ_MAIN_TXE ((uint8_t)(ST25R3916_IRQ_MASK_TXE & 0xFFu))
#define IRQ_MAIN_COL ((uint8_t)(ST25R3916_IRQ_MASK_COL & 0xFFu))

#define IRQ_TIMER_NRE ((uint8_t)((ST25R3916_IRQ_MASK_NRE >> 8) & 0xFFu))
#define IRQ_TIMER_CAC ((uint8_t)((ST25R3916_IRQ_MASK_CAC >> 8) & 0xFFu))
#define IRQ_TIMER_CAT ((uint8_t)((ST25R3916_IRQ_MASK_CAT >> 8) & 0xFFu))

#define IRQ_ERROR_CRC ((uint8_t)((ST25R3916_IRQ_MASK_CRC >> 16) & 0xFFu))
#define IRQ_ERROR_PAR ((uint8_t)((ST25R3916_IRQ_MASK_PAR >> 16) & 0xFFu))
#define IRQ_ERROR_ERR2 ((uint8_t)((ST25R3916_IRQ_MASK_ERR2 >> 16) & 0xFFu))
#define IRQ_ERROR_ERR1 ((uint8_t)((ST25R3916_IRQ_MASK_ERR1 >> 16) & 0xFFu))

#define IRQ_TARGET_APON ((uint8_t)((ST25R3916_IRQ_MASK_APON >> 24) & 0xFFu))

#define ISO14443_CMD_SEL_CL1 0x93u
#define ISO14443_CMD_SEL_CL2 0x95u
/* [ISO14443-3] section 6.5.4 — cascade level 3 SELECT (10-byte UID tags). */
#define ISO14443_CMD_SEL_CL3 0x97u
#define ISO14443_CMD_RATS 0xE0u

#define NTAG_CMD_READ 0x30u
#define NTAG_CMD_WRITE 0xA2u
#define NTAG_CMD_GET_VERSION 0x60u
