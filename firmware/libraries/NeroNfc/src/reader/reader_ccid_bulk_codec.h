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

#include "reader_ccid_protocol.h"
#include "nero_nfc_mem_util.h"
#include "nero_nfc_attrs.h"

#include <stddef.h>
#include <stdint.h>

/* USB CCID Rev 1.10 — bulk command classification and failure response
 * encoding. */

static inline uint8_t reader_ccid_response_msg_for_bulk_command(
    uint8_t msg_type) {
  switch (msg_type) {
    case (uint8_t)(NFC_CCID_MSG_PC_TO_RDR_ICC_POWER_ON):
    case (uint8_t)(NFC_CCID_MSG_PC_TO_RDR_XFR):
    case (uint8_t)(NFC_CCID_MSG_PC_TO_RDR_SECURE):
      return (uint8_t)(NFC_CCID_MSG_RDR_TO_PC_DATABLOCK);
    case (uint8_t)(NFC_CCID_MSG_PC_TO_RDR_GET_PARAMETERS):
    case (uint8_t)(NFC_CCID_MSG_PC_TO_RDR_RESET_PARAMETERS):
    case (uint8_t)(NFC_CCID_MSG_PC_TO_RDR_SET_PARAMETERS):
      return (uint8_t)(NFC_CCID_MSG_RDR_TO_PC_PARAMETERS);
    case (uint8_t)(NFC_CCID_MSG_PC_TO_RDR_ESCAPE):
      return (uint8_t)(NFC_CCID_MSG_RDR_TO_PC_ESCAPE);
    case (uint8_t)(NFC_CCID_MSG_PC_TO_RDR_SET_DATA_RATE_AND_CLOCK):
      return (uint8_t)(NFC_CCID_MSG_RDR_TO_PC_DATA_RATE_AND_CLOCK);
    default:
      return (uint8_t)(NFC_CCID_MSG_RDR_TO_PC_SLOTSTATUS);
  }
}

NERO_NFC_NODISCARD static inline bool
reader_ccid_bulk_command_requires_zero_length(uint8_t msg_type) {
  switch (msg_type) {
    case (uint8_t)(NFC_CCID_MSG_PC_TO_RDR_SLOTSTATUS):
    case (uint8_t)(NFC_CCID_MSG_PC_TO_RDR_ICC_POWER_ON):
    case (uint8_t)(NFC_CCID_MSG_PC_TO_RDR_ICC_POWER_OFF):
    case (uint8_t)(NFC_CCID_MSG_PC_TO_RDR_GET_PARAMETERS):
    case (uint8_t)(NFC_CCID_MSG_PC_TO_RDR_RESET_PARAMETERS):
    case (uint8_t)(NFC_CCID_MSG_PC_TO_RDR_ABORT):
    case (uint8_t)(NFC_CCID_MSG_PC_TO_RDR_ICC_CLOCK):
    case (uint8_t)(NFC_CCID_MSG_PC_TO_RDR_T0_APDU):
    case (uint8_t)(NFC_CCID_MSG_PC_TO_RDR_MECHANICAL):
      return true;
    default:
      return false;
  }
}

NERO_NFC_NODISCARD static inline bool
reader_ccid_bulk_command_requires_rfu_zero(uint8_t msg_type) {
  switch (msg_type) {
    case (uint8_t)(NFC_CCID_MSG_PC_TO_RDR_SLOTSTATUS):
    case (uint8_t)(NFC_CCID_MSG_PC_TO_RDR_ICC_POWER_OFF):
    case (uint8_t)(NFC_CCID_MSG_PC_TO_RDR_GET_PARAMETERS):
    case (uint8_t)(NFC_CCID_MSG_PC_TO_RDR_RESET_PARAMETERS):
    case (uint8_t)(NFC_CCID_MSG_PC_TO_RDR_ABORT):
      return true;
    default:
      return false;
  }
}

static inline uint16_t reader_ccid_bulk_xfr_level_parameter(
    const uint8_t* frame, uint16_t frame_len) {
  if (frame == NERO_NFC_NULL) {
    return 0u;
  }
  if (!nero_nfc_span_ok(NFC_CCID_BULK_LEVEL_PARAM2_OFFSET,
                        NFC_CCID_BULK_LEVEL_PARAM_TAIL_LEN, frame_len)) {
    return 0u;
  }
  return (uint16_t)(((uint16_t)(nero_nfc_u8_at(
                        frame, frame_len, NFC_CCID_BULK_LEVEL_PARAM2_OFFSET))) |
                    ((uint16_t)(nero_nfc_u8_at(
                         frame, frame_len, NFC_CCID_BULK_LEVEL_PARAM3_OFFSET))
                     << NFC_CCID_U32_SHIFT_BYTE1));
}

static inline uint16_t reader_ccid_encode_command_failed_response(
    uint8_t* work, size_t work_cap, uint8_t msg_type, uint8_t seq8,
    uint8_t icclvl, uint8_t err_code) {
  if (work == NERO_NFC_NULL) {
    return 0u;
  }
  const uint8_t rsp_msg = reader_ccid_response_msg_for_bulk_command(msg_type);
  const uint8_t failed_icclvl = (uint8_t)(NFC_CCID_ICC_CMD_FAIL | icclvl);

  if (rsp_msg == (uint8_t)(NFC_CCID_MSG_RDR_TO_PC_DATA_RATE_AND_CLOCK)) {
    (void)reader_ccid_encode_data_rate_clock_response(
        work, work_cap, rsp_msg, seq8, failed_icclvl, err_code);
    return (uint16_t)(NFC_CCID_BULK_HEADER_LEN +
                      NFC_CCID_DATA_RATE_CLOCK_PAYLOAD_LEN);
  }
  if ((rsp_msg == (uint8_t)(NFC_CCID_MSG_RDR_TO_PC_DATABLOCK)) ||
      (rsp_msg == (uint8_t)(NFC_CCID_MSG_RDR_TO_PC_ESCAPE))) {
    nfc_ccid_encode_data_block_header(work, rsp_msg, seq8, 0u, failed_icclvl,
                                      0u);
    (void)nero_nfc_store_u8(work, work_cap, NFC_CCID_BULK_LEVEL_PARAM2_OFFSET,
                            err_code);
    return (uint16_t)(NFC_CCID_BULK_HEADER_LEN);
  }
  nfc_ccid_encode_slot_status(work, rsp_msg, seq8, failed_icclvl, err_code);
  return (uint16_t)(NFC_CCID_BULK_HEADER_LEN);
}

static inline uint16_t reader_ccid_encode_slot_absent_response(
    uint8_t* work, size_t work_cap, uint8_t msg_type, uint8_t slot8,
    uint8_t seq8, uint8_t slot_missing_error) {
  if (work == NERO_NFC_NULL) {
    return 0u;
  }
  if (work_cap < NFC_CCID_BULK_HEADER_LEN) {
    return 0u;
  }
  const uint8_t rsp_msg = reader_ccid_response_msg_for_bulk_command(msg_type);
  const uint8_t icclvl = (uint8_t)(NFC_CCID_ICC_CMD_FAIL | NFC_CCID_ICC_NO_ICC);

  if (rsp_msg == (uint8_t)(NFC_CCID_MSG_RDR_TO_PC_DATA_RATE_AND_CLOCK)) {
    (void)reader_ccid_encode_data_rate_clock_response(
        work, work_cap, rsp_msg, seq8, icclvl, slot_missing_error);
    (void)nero_nfc_store_u8(work, work_cap, NFC_CCID_BULK_SLOT_OFFSET, slot8);
    return (uint16_t)(NFC_CCID_BULK_HEADER_LEN +
                      NFC_CCID_DATA_RATE_CLOCK_PAYLOAD_LEN);
  }
  nfc_ccid_encode_slot_status(work, rsp_msg, seq8, icclvl, slot_missing_error);
  (void)nero_nfc_store_u8(work, work_cap, NFC_CCID_BULK_SLOT_OFFSET, slot8);
  return (uint16_t)(NFC_CCID_BULK_HEADER_LEN);
}

#ifdef __cplusplus
}
#endif
