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
#include "nero_nfc_mem_util.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* [CCID1.10] USB CCID Rev 1.10 — bulk header, extended APDU message ceiling,
 * response chunking, control requests, slot status, and message type values. */
enum {
  NFC_CCID_BULK_HEADER_LEN = 10u,
  NFC_CCID_WORK_BUF_SIZE = 2060u,
  NFC_CCID_MAX_XFR_PAYLOAD = 2050u,
  NFC_CCID_RSP_DATA_CAP = 510u, /* 520-byte response chunk minus 10-byte CCID header */
  NFC_CCID_EXTENDED_RSP_BUF_SIZE = 2050u,
  NFC_CCID_TIME_EXTENSION_APDU_LEN_THRESHOLD = 64u,
  NFC_CCID_TIME_EXTENSION_BWT_MULTIPLIER = 0x0Au,
  NFC_CCID_HAL_SEND_TIMEOUT_MS = 120000u,
  NFC_CCID_DATA_RATE_CLOCK_PAYLOAD_LEN = 8u,
  NFC_CCID_BULK_SLOT_OFFSET = 5u,
  NFC_CCID_BULK_SEQ_OFFSET = 6u,
  NFC_CCID_BULK_LEVEL_PARAM_OFFSET = 7u,
  NFC_CCID_BULK_LEVEL_PARAM_LEN = 3u,
  NFC_CCID_BULK_LEVEL_PARAM2_OFFSET = 8u,
  NFC_CCID_BULK_LEVEL_PARAM3_OFFSET = 9u,
  NFC_CCID_BULK_PAYLOAD_OFFSET = 10u,
  NFC_CCID_T0_PARAMS_LEN = 5u,
  NFC_CCID_T1_PARAMS_LEN = 7u,
  /* [DERIVED] Little-endian byte helpers; intentionally not standalone SPEC entries. */
  NFC_CCID_U32_BYTE2 = 2u,
  NFC_CCID_U32_BYTE3 = 3u,
  NFC_CCID_U32_SHIFT_BYTE1 = 8u,
  NFC_CCID_U32_SHIFT_BYTE2 = 16u,
  NFC_CCID_U32_SHIFT_BYTE3 = 24u,
  NFC_CCID_BYTE_MASK = 0xFFu,
  NFC_CCID_DATA_RATE_CLOCK_OFFSET_DEFAULT_CLOCK = 10u,
  NFC_CCID_DATA_RATE_CLOCK_OFFSET_DEFAULT_DATA_RATE = 14u,
};

NERO_NFC_STATIC_ASSERT(NFC_CCID_BULK_HEADER_LEN == 10u, "CCID bulk header is 10 bytes");
NERO_NFC_STATIC_ASSERT(NFC_CCID_BULK_PAYLOAD_OFFSET == NFC_CCID_BULK_HEADER_LEN,
                       "CCID bulk APDU payload follows the 10-byte header");
NERO_NFC_STATIC_ASSERT(NFC_CCID_RSP_DATA_CAP + NFC_CCID_BULK_HEADER_LEN == 520u,
                       "CCID response chunk is 520 bytes including header");
NERO_NFC_STATIC_ASSERT(NFC_CCID_MAX_XFR_PAYLOAD <= NFC_CCID_WORK_BUF_SIZE,
                       "CCID transfer payload must fit work buffer");

enum {
  NFC_CCID_MSG_RDR_TO_PC_NOTIFY_SLOT_CHANGE = 0x50u,
  NFC_CCID_MSG_RDR_TO_PC_DATABLOCK = 0x80u,
  NFC_CCID_MSG_RDR_TO_PC_SLOTSTATUS = 0x81u,
  NFC_CCID_MSG_RDR_TO_PC_PARAMETERS = 0x82u,
  NFC_CCID_MSG_RDR_TO_PC_ESCAPE = 0x83u,
  NFC_CCID_MSG_RDR_TO_PC_DATA_RATE_AND_CLOCK = 0x84u,
  NFC_CCID_MSG_PC_TO_RDR_ICC_POWER_ON = 0x62u,
  NFC_CCID_MSG_PC_TO_RDR_ICC_POWER_OFF = 0x63u,
  NFC_CCID_MSG_PC_TO_RDR_XFR = 0x6Fu,
  NFC_CCID_MSG_PC_TO_RDR_SLOTSTATUS = 0x65u,
  NFC_CCID_MSG_PC_TO_RDR_GET_PARAMETERS = 0x6Cu,
  NFC_CCID_MSG_PC_TO_RDR_RESET_PARAMETERS = 0x6Du,
  NFC_CCID_MSG_PC_TO_RDR_SET_PARAMETERS = 0x61u,
  NFC_CCID_MSG_PC_TO_RDR_ESCAPE = 0x6Bu,
  NFC_CCID_MSG_PC_TO_RDR_ABORT = 0x72u,
  NFC_CCID_MSG_PC_TO_RDR_ICC_CLOCK = 0x6Eu,
  NFC_CCID_MSG_PC_TO_RDR_T0_APDU = 0x6Au,
  NFC_CCID_MSG_PC_TO_RDR_SECURE = 0x69u,
  NFC_CCID_MSG_PC_TO_RDR_MECHANICAL = 0x71u,
  NFC_CCID_MSG_PC_TO_RDR_SET_DATA_RATE_AND_CLOCK = 0x73u,
};

enum {
  NFC_CCID_CONTROL_BMREQ_ABORT = 0x21u,
  NFC_CCID_CONTROL_BMREQ_GET = 0xA1u,
  NFC_CCID_CONTROL_ABORT = 0x01u,
  NFC_CCID_CONTROL_GET_CLOCK_FREQUENCIES = 0x02u,
  NFC_CCID_CONTROL_GET_DATA_RATES = 0x03u,
};

enum {
  NFC_CCID_XFR_LEVEL_SINGLE = 0x00u,
  NFC_CCID_XFR_LEVEL_CHAIN_BEGIN = 0x01u,
  NFC_CCID_XFR_LEVEL_CHAIN_END = 0x02u,
  NFC_CCID_XFR_LEVEL_CHAIN_MIDDLE = 0x03u,
  NFC_CCID_XFR_RESPONSE_CONTINUE = 0x10u,
};

enum {
  NFC_CCID_ICC_ACTIVE = 0x00u,
  NFC_CCID_ICC_INACTIVE = 0x01u,
  NFC_CCID_ICC_NO_ICC = 0x02u,
  NFC_CCID_ICC_CMD_FAIL = 0x40u,
  NFC_CCID_ICC_CMD_TIME_EXTENSION = 0x80u,
};

/* Interrupt-IN NotifySlotChange bmSlotICCState (slot 0): bit1=present, bit0=changed. */
enum {
  NFC_CCID_NOTIFY_SLOT_PRESENT_CHANGED = 0x03u,
  NFC_CCID_NOTIFY_SLOT_ABSENT_CHANGED = 0x01u,
};

uint32_t nfc_ccid_u32_load_le(const uint8_t *src);
void nfc_ccid_u32_store_le(uint8_t *dst, uint32_t value);

NERO_NFC_NODISCARD bool nfc_ccid_bulk_frame_validate(const uint8_t *frame, uint16_t nbytes,
                                                     uint32_t *data_len_out);

NERO_NFC_NODISCARD bool nfc_ccid_xfr_payload_needs_time_extension(const uint8_t *payload,
                                                                  uint16_t payload_len);
NERO_NFC_NODISCARD bool nfc_ccid_xfr_frame_requests_response_continuation(const uint8_t *frame,
                                                                          uint16_t frame_len);

NERO_NFC_NODISCARD static inline bool nfc_ccid_control_abort_request_matches(
  uint8_t bm_request_type, uint8_t b_request, uint16_t w_value, uint16_t w_index, uint16_t w_length,
  uint8_t interface_number, uint8_t *slot_out, uint8_t *seq_out) {
  if (slot_out != NERO_NFC_NULL) {
    *slot_out = 0u;
  }
  if (seq_out != NERO_NFC_NULL) {
    *seq_out = 0u;
  }
  if (bm_request_type != NFC_CCID_CONTROL_BMREQ_ABORT || b_request != NFC_CCID_CONTROL_ABORT ||
      w_index != (uint16_t)interface_number || w_length != 0u) {
    return false;
  }
  if (slot_out != NERO_NFC_NULL) {
    *slot_out = (uint8_t)(w_value & NFC_CCID_BYTE_MASK);
  }
  if (seq_out != NERO_NFC_NULL) {
    *seq_out = (uint8_t)((w_value >> NFC_CCID_U32_SHIFT_BYTE1) & NFC_CCID_BYTE_MASK);
  }
  return true;
}

NERO_NFC_NODISCARD static inline bool nfc_ccid_control_abort_request_matches_slot(
  uint8_t bm_request_type, uint8_t b_request, uint16_t w_value, uint16_t w_index, uint16_t w_length,
  uint8_t interface_number, uint8_t max_slot_index, uint8_t *slot_out, uint8_t *seq_out) {
  uint8_t slot = 0u;
  uint8_t seq = 0u;

  if (slot_out != NERO_NFC_NULL) {
    *slot_out = 0u;
  }
  if (seq_out != NERO_NFC_NULL) {
    *seq_out = 0u;
  }
  if (!nfc_ccid_control_abort_request_matches(bm_request_type, b_request, w_value, w_index,
                                              w_length, interface_number, &slot, &seq) ||
      (slot > max_slot_index)) {
    return false;
  }
  if (slot_out != NERO_NFC_NULL) {
    *slot_out = slot;
  }
  if (seq_out != NERO_NFC_NULL) {
    *seq_out = seq;
  }
  return true;
}

void nfc_ccid_encode_slot_status(uint8_t *buf10, uint8_t msg_type, uint8_t seq, uint8_t icc_level,
                                 uint8_t err_code);

void nfc_ccid_encode_data_block_header(uint8_t *buf10, uint8_t msg_type, uint8_t seq,
                                       uint32_t data_bytes, uint8_t icc_level, uint8_t chain);

#ifdef __cplusplus
}
#endif
