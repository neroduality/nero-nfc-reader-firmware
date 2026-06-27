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
#include <stdint.h>

/*
 * Stable app-facing contract for the NFC reader analogue front end.
 *
 * Manifest prefixes in this frontend contract:
 *   [ISO14443-3] SELECT cascade-level command bytes.
 *   [ISO14443-4] RATS command byte.
 *   [T2T-ISO14443-A] Type 2 READ/WRITE command bytes.
 *   [T2T-ISO14443-A-NTAG21x] NTAG FAST_READ/GET_VERSION/READ_SIG commands.
 *   [T5T-ISO15693] ISO15693 UID width.
 *
 * Application code should use these names rather than chip-specific register
 * names so target adapters can implement the same surface.
 */

#define NFC_FRONTEND_ISO14443A_SEL_CL1 0x93u
#define NFC_FRONTEND_ISO14443A_SEL_CL2 0x95u
#define NFC_FRONTEND_ISO14443_CMD_RATS 0xE0u
#define NFC_FRONTEND_NTAG_CMD_READ 0x30u
#define NFC_FRONTEND_NTAG_CMD_FAST_READ 0x3Au
#define NFC_FRONTEND_NTAG_CMD_WRITE 0xA2u
#define NFC_FRONTEND_NTAG_CMD_GET_VERSION 0x60u
#define NFC_FRONTEND_NTAG_CMD_READ_SIG 0x3Cu
#define NFC_FRONTEND_ISO15693_UID_LEN 8u
#define NFC_FRONTEND_ISO15693_MAX_STREAM_FRAME 128u

/* ISO 14443-4 ATS / FSC sizing shared by tag info and ISO-DEP state. */
enum {
  NFC_ISO14443_ATS_MAX = 64u,
  NFC_ISO14443_FSC_MAX = 256u,
};

// C/C++ shared header: keep typedef forms for C translation units.
// NOLINTBEGIN(modernize-use-using)

typedef enum {
  NFC_FRONTEND_INIT_OK = 0,
  NFC_FRONTEND_INIT_CHIP_ID_FAIL = 1,
  NFC_FRONTEND_INIT_OSC_FAIL = 2,
} nfc_frontend_init_status_t;

typedef enum {
  NFC_FRONTEND_FIELD_ON_OK = 0,
  NFC_FRONTEND_FIELD_ON_COLLISION = 1,
  NFC_FRONTEND_FIELD_ON_TXRX_VERIFY_FAIL = 2,
} nfc_frontend_field_on_status_t;

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
} nfc_frontend_transceive_diag_t;

typedef int (*nfc_frontend_iso15693_transceive_fn_t)(const uint8_t *tx, uint16_t tx_len,
                                                     uint8_t *rx, uint16_t rx_max,
                                                     uint16_t timeout_ms);

// NOLINTEND(modernize-use-using)
