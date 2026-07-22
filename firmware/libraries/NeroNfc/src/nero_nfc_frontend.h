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

#include "nero_nfc_attrs.h"
#include "nero_nfc_board.h"
#include "nero_nfc_platform.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

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
/* Chip model string for logs/banners (C ABI; chip binding lives in frontend).
 */
#ifndef NFC_FRONTEND_MODEL_NAME
#define NFC_FRONTEND_MODEL_NAME "ST25R3916B"
#endif
#ifndef NFC_FRONTEND_REFERENCE_BOARD_NAME
#define NFC_FRONTEND_REFERENCE_BOARD_NAME "X-NUCLEO-NFC08A1"
#endif

/* ISO 14443-4 ATS / FSC sizing shared by tag info and ISO-DEP state. */
enum {
  NFC_ISO14443_ATS_MAX = 64u,
  NFC_ISO14443_FSC_MAX = 256u,
};

// C/C++ shared header: keep typedef forms for C translation units.

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

typedef int (*nfc_frontend_iso15693_transceive_fn_t)(
    void* context, const uint8_t* tx, uint16_t tx_len, uint8_t* rx,
    uint16_t rx_max, uint16_t timeout_ms);

/*
 * Frontend-neutral handle (§3). `ops` points at the active frontend ops table
 * (the ST25 runtime operations). `state` points at the
 * application-owned chip context.
 */
typedef struct st25r3916 {
  const nero_nfc_platform_ops_t* platform;
  const nero_nfc_board_config_t* board;
  uint32_t transceive_count;
  uint32_t quiesce_count;
  uint16_t vdd_mv;
  uint8_t chip_id;
  uint8_t configured_protocol;
  bool initialized;
  bool field_enabled;
} st25r3916_t;

typedef struct nfc_frontend nfc_frontend_t;

typedef struct nfc_frontend_ops {
  uint8_t (*measure_amplitude)(void* state);
  nfc_frontend_init_status_t (*init)(void* state, uint8_t* chip_id_out,
                                     uint16_t* vdd_mv_out);
  void (*configure_iso14443a)(void* state);
  void (*configure_iso15693)(void* state);
  nfc_frontend_field_on_status_t (*field_on)(void* state, bool* used_direct);
  int (*transceive)(void* state, const uint8_t* tx, uint16_t tx_len,
                    uint8_t* rx, uint16_t rx_max, bool with_crc,
                    uint16_t timeout_ms, bool anticol, bool no_rx_par,
                    bool extended_nrt_16bit, bool poll_rx_until_event,
                    bool clear_nfc_before_fifo_read);
  int (*transceive_diag)(void* state, const uint8_t* tx, uint16_t tx_len,
                         uint8_t* rx, uint16_t rx_max, bool with_crc,
                         uint16_t timeout_ms, bool anticol, bool no_rx_par,
                         bool extended_nrt_16bit, bool poll_rx_until_event,
                         bool clear_nfc_before_fifo_read,
                         nfc_frontend_transceive_diag_t* diag);
  bool (*send_wupa)(void* state, uint8_t* atqa);
  bool (*send_reqa)(void* state, uint8_t* atqa);
  void (*quiesce)(void* state);
  void (*ensure_tx_rx)(void* state);
  void (*enable_tx_rx)(void* state);
} nfc_frontend_ops_t;

struct nfc_frontend {
  const nfc_frontend_ops_t* ops;
  void* state;
};

void nero_nfc_st25_frontend_bind(nfc_frontend_t* frontend, st25r3916_t* state,
                                 const nero_nfc_platform_ops_t* platform,
                                 const nero_nfc_board_config_t* board);

/* Shared ST25 frontend entry points (was nfc_frontend_* façade). */
typedef int (*nfc_frontend_iso14443a_transceive_fn_t)(
    void* context, const uint8_t* tx_data, uint16_t tx_len, uint8_t* rx_buffer,
    uint16_t rx_buffer_len, int with_crc, uint16_t timeout_ms, int anticol,
    int no_rx_par);
typedef bool (*nfc_frontend_send_short_frame_fn_t)(void* context,
                                                   uint8_t* atqa_out);
typedef void (*nfc_frontend_delay_ms_fn_t)(void* context, uint32_t ms);
typedef int (*nfc_frontend_anticollision_select_fn_t)(void* context,
                                                      uint8_t sel_cmd,
                                                      uint8_t* uid_out);

NERO_NFC_NODISCARD bool nfc_frontend_ready(const nfc_frontend_t* frontend);
uint8_t nfc_frontend_measure_amplitude(nfc_frontend_t* frontend);
nfc_frontend_init_status_t nfc_frontend_init(nfc_frontend_t* frontend,
                                             uint8_t* chip_id_out,
                                             uint16_t* vdd_mv_out);
void nfc_frontend_configure_iso14443a(nfc_frontend_t* frontend);
void nfc_frontend_configure_iso15693(nfc_frontend_t* frontend);
nfc_frontend_field_on_status_t nfc_frontend_field_on(nfc_frontend_t* frontend,
                                                     bool* used_direct);
int nfc_frontend_transceive(nfc_frontend_t* frontend, const uint8_t* tx,
                            uint16_t tx_len, uint8_t* rx, uint16_t rx_max,
                            bool with_crc, uint16_t timeout_ms, bool anticol,
                            bool no_rx_par, bool extended_nrt_16bit,
                            bool poll_rx_until_event,
                            bool clear_nfc_before_fifo_read);
int nfc_frontend_transceive_diag(
    nfc_frontend_t* frontend, const uint8_t* tx, uint16_t tx_len, uint8_t* rx,
    uint16_t rx_max, bool with_crc, uint16_t timeout_ms, bool anticol,
    bool no_rx_par, bool extended_nrt_16bit, bool poll_rx_until_event,
    bool clear_nfc_before_fifo_read, nfc_frontend_transceive_diag_t* diag);
NERO_NFC_NODISCARD bool nfc_frontend_send_wupa(nfc_frontend_t* frontend,
                                               uint8_t* atqa);
NERO_NFC_NODISCARD bool nfc_frontend_send_reqa(nfc_frontend_t* frontend,
                                               uint8_t* atqa);
int nfc_frontend_iso15693_transceive(nfc_frontend_t* frontend,
                                     const uint8_t* tx, uint16_t tx_len,
                                     uint8_t* rx, uint16_t rx_max,
                                     uint16_t timeout_ms);
NERO_NFC_NODISCARD bool nfc_frontend_iso15693_inventory(
    nfc_frontend_iso15693_transceive_fn_t transceive, void* context,
    uint8_t uid_out[NFC_FRONTEND_ISO15693_UID_LEN]);
int nfc_frontend_iso15693_read_block(
    nfc_frontend_iso15693_transceive_fn_t transceive, void* context,
    const uint8_t uid[NFC_FRONTEND_ISO15693_UID_LEN], uint8_t block_addr,
    uint8_t* buf, uint8_t buf_len);
NERO_NFC_NODISCARD bool nfc_frontend_iso15693_write_block(
    nfc_frontend_iso15693_transceive_fn_t transceive, void* context,
    const uint8_t uid[NFC_FRONTEND_ISO15693_UID_LEN], uint8_t block_addr,
    const uint8_t* data, uint8_t data_len);
NERO_NFC_NODISCARD bool nfc_frontend_iso15693_get_system_info(
    nfc_frontend_iso15693_transceive_fn_t transceive, void* context,
    const uint8_t uid[NFC_FRONTEND_ISO15693_UID_LEN], uint16_t* nb_blocks_out,
    uint8_t* block_size_out);
int nfc_frontend_iso15693_ext_read_block(
    nfc_frontend_iso15693_transceive_fn_t transceive, void* context,
    const uint8_t uid[NFC_FRONTEND_ISO15693_UID_LEN], uint16_t block_addr,
    uint8_t* buf, uint8_t buf_len);
NERO_NFC_NODISCARD bool nfc_frontend_iso15693_ext_write_block(
    nfc_frontend_iso15693_transceive_fn_t transceive, void* context,
    const uint8_t uid[NFC_FRONTEND_ISO15693_UID_LEN], uint16_t block_addr,
    const uint8_t* data, uint8_t data_len);
void nfc_frontend_quiesce(nfc_frontend_t* frontend);
void nfc_frontend_ensure_tx_rx(nfc_frontend_t* frontend);
void nfc_frontend_enable_tx_rx(nfc_frontend_t* frontend);
int nfc_frontend_anticollision_select(
    uint8_t sel_cmd, uint8_t* uid_out,
    nfc_frontend_iso14443a_transceive_fn_t transceive, void* context);
NERO_NFC_NODISCARD bool nfc_frontend_activate_iso14443a(
    nfc_frontend_send_short_frame_fn_t send_wupa,
    nfc_frontend_send_short_frame_fn_t send_reqa,
    nfc_frontend_delay_ms_fn_t delay_ms, void* context,
    bool retry_with_reqa_on_second_try,
    nfc_frontend_anticollision_select_fn_t select_uid, uint8_t* uid_out,
    uint8_t uid_out_capacity, uint8_t* uid_len_out, uint8_t* sak_out);

#ifdef __cplusplus
}
#endif
