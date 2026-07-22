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

#ifdef __cplusplus
extern "C" {
#endif

#include "nfc_ccid_frame.h"
#include "nero_nfc_null.h"
#include "nero_nfc_limits.h"
#include "nfc_pcsc_contactless.h"
#include "nfc_tag_geometry_limits.h"
#include "reader_ccid_context.h"
#include "reader_tags.h"

#include <stdint.h>

enum {
  CCID_REMOVE_DEFER_MS = 250u,
  CCID_RAW_T2_CMD_READ = 0x30u,
  CCID_RAW_T2_CMD_FAST_READ = 0x3Au,
  CCID_RAW_T2_CMD_READ_SIG = 0x3Cu,
  CCID_RAW_T2_CMD_GET_VERSION = 0x60u,
  CCID_RAW_T5_CMD_INVENTORY = 0x01u,
  CCID_RAW_T5_CMD_STAY_QUIET = 0x02u,
  CCID_RAW_T5_CMD_SELECT = 0x25u,
  CCID_RAW_T5_CMD_RESET_TO_READY = 0x26u,
  CCID_RAW_T5_CMD_GET_MULTIPLE_BLOCK_SECURITY_STATUS = 0x2Cu,
  CCID_RAW_T5_CMD_EXT_GET_MULTIPLE_BLOCK_SECURITY_STATUS = 0x3Cu,
};

NERO_NFC_STATIC_ASSERT(
    CCID_APDU_RSP_BUF_MAX <= (unsigned)NFC_CCID_MAX_XFR_PAYLOAD,
    "extended APDU response buffer must fit CCID XfrBlock payload cap");

void reader_ccid_note_host_session_activity(void);
NERO_NFC_NODISCARD bool reader_ccid_abort_requested(void);

uint16_t reader_ccid_append_status(uint8_t* dst, uint16_t data_len,
                                   uint16_t dst_cap, uint8_t sw1, uint8_t sw2);

static inline uint16_t reader_ccid_append_success_status(uint8_t* dst,
                                                         uint16_t data_len,
                                                         uint16_t dst_cap) {
  return reader_ccid_append_status(dst, data_len, dst_cap,
                                   (uint8_t)(NFC_ISO7816_SW1_SUCCESS),
                                   (uint8_t)(NFC_ISO7816_SW2_SUCCESS));
}

/* ISO7816-4 general error when an internal bounds/copy invariant fails. */
static inline uint16_t reader_ccid_apdu_failure_response(uint8_t* rsp,
                                                         uint16_t rsp_cap) {
  return reader_ccid_append_status(rsp, 0u, rsp_cap,
                                   (uint8_t)(NFC_ISO7816_SW1_GENERAL_ERROR),
                                   (uint8_t)(NFC_ISO7816_SW2_SUCCESS));
}

uint16_t reader_ccid_handle_get_data_apdu(const uint8_t* apdu,
                                          uint16_t apdu_len, uint8_t* rsp,
                                          uint16_t rsp_cap);
uint16_t reader_ccid_handle_escape_transparent_apdu(const uint8_t* apdu,
                                                    uint16_t apdu_len,
                                                    uint8_t* rsp,
                                                    uint16_t rsp_cap);
uint16_t reader_ccid_handle_read_binary_apdu(const uint8_t* apdu,
                                             uint16_t apdu_len, uint8_t* rsp,
                                             uint16_t rsp_cap);
uint16_t reader_ccid_handle_update_binary_apdu(const uint8_t* apdu,
                                               uint16_t apdu_len, uint8_t* rsp,
                                               uint16_t rsp_cap);

uint16_t reader_ccid_handle_acr122_direct_apdu(const uint8_t* apdu,
                                               uint16_t apdu_len, uint8_t* rsp,
                                               uint16_t rsp_cap);
uint16_t reader_ccid_dispatch_host_payload(const uint8_t* payload,
                                           uint16_t payload_len, uint8_t* rsp,
                                           uint16_t rsp_cap);

NERO_NFC_NODISCARD bool reader_ccid_type2_raw_transceive_allowed(
    const uint8_t* tx, uint16_t tx_len);
NERO_NFC_NODISCARD bool reader_ccid_type5_raw_transceive_allowed(
    const uint8_t* tx, uint16_t tx_len);

#ifdef __cplusplus
}
#endif
