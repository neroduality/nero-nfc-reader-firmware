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

#include "nero_nfc_null.h"
#include "nfc_ccid_frame.h"

#include "nfc_ctap_codec.h"

uint32_t nfc_ccid_u32_load_le(const uint8_t* src) {
  if (src == NERO_NFC_NULL) {
    return 0u;
  }
  return ((uint32_t)src[0]) | (((uint32_t)src[1]) << NFC_CCID_U32_SHIFT_BYTE1) |
         (((uint32_t)src[NFC_CCID_U32_BYTE2]) << NFC_CCID_U32_SHIFT_BYTE2) |
         (((uint32_t)src[NFC_CCID_U32_BYTE3]) << NFC_CCID_U32_SHIFT_BYTE3);
}

void nfc_ccid_u32_store_le(uint8_t* dst, uint32_t value) {
  if (dst == NERO_NFC_NULL) {
    return;
  }
  dst[0] = (uint8_t)(value & NFC_CCID_BYTE_MASK);
  dst[1] = (uint8_t)((value >> NFC_CCID_U32_SHIFT_BYTE1) & NFC_CCID_BYTE_MASK);
  dst[NFC_CCID_U32_BYTE2] =
      (uint8_t)((value >> NFC_CCID_U32_SHIFT_BYTE2) & NFC_CCID_BYTE_MASK);
  dst[NFC_CCID_U32_BYTE3] =
      (uint8_t)((value >> NFC_CCID_U32_SHIFT_BYTE3) & NFC_CCID_BYTE_MASK);
}

bool nfc_ccid_bulk_frame_validate(const uint8_t* frame, uint16_t nbytes,
                                  uint32_t* data_len_out) {
  uint32_t datalen_bytes;
  size_t frame_len = 0u;

  if (data_len_out != NERO_NFC_NULL) {
    *data_len_out = 0u;
  }
  if ((frame == NERO_NFC_NULL) || (nbytes < NFC_CCID_BULK_HEADER_LEN)) {
    return false;
  }

  datalen_bytes = nfc_ccid_u32_load_le(&frame[1]);
  if (datalen_bytes > NFC_CCID_MAX_XFR_PAYLOAD) {
    return false;
  }
  if (!nero_nfc_try_add_size((size_t)NFC_CCID_BULK_HEADER_LEN,
                             (size_t)datalen_bytes, &frame_len) ||
      frame_len != (size_t)nbytes) {
    return false;
  }

  if (data_len_out != NERO_NFC_NULL) {
    *data_len_out = datalen_bytes;
  }
  return true;
}

bool nfc_ccid_xfr_payload_needs_time_extension(const uint8_t* payload,
                                               uint16_t payload_len) {
  if (payload == NERO_NFC_NULL) {
    return false;
  }
  return (payload_len >= NFC_CCID_TIME_EXTENSION_APDU_LEN_THRESHOLD) ||
         nfc_ctap_apdu_needs_ccid_time_extension(payload, payload_len);
}

bool nfc_ccid_xfr_frame_requests_response_continuation(const uint8_t* frame,
                                                       uint16_t frame_len) {
  uint32_t data_len = 0u;

  if (!nfc_ccid_bulk_frame_validate(frame, frame_len, &data_len)) {
    return false;
  }
  return frame[0] == NFC_CCID_MSG_PC_TO_RDR_XFR && data_len == 0u &&
         frame[NFC_CCID_BULK_LEVEL_PARAM2_OFFSET] ==
             NFC_CCID_XFR_RESPONSE_CONTINUE &&
         frame[NFC_CCID_BULK_LEVEL_PARAM3_OFFSET] == 0u;
}

void nfc_ccid_encode_slot_status(uint8_t* buf10, uint8_t msg_type, uint8_t seq,
                                 uint8_t icc_level, uint8_t err_code) {
  if (buf10 == NERO_NFC_NULL) {
    return;
  }
  buf10[0] = msg_type;
  nfc_ccid_u32_store_le(&buf10[1], 0u);
  buf10[NFC_CCID_BULK_SLOT_OFFSET] = 0u;
  buf10[NFC_CCID_BULK_SEQ_OFFSET] = seq;
  buf10[NFC_CCID_BULK_LEVEL_PARAM_OFFSET] = icc_level;
  buf10[NFC_CCID_BULK_LEVEL_PARAM2_OFFSET] = err_code;
  buf10[NFC_CCID_BULK_LEVEL_PARAM3_OFFSET] = 0u;
}

void nfc_ccid_encode_data_block_header(uint8_t* buf10, uint8_t msg_type,
                                       uint8_t seq, uint32_t data_bytes,
                                       uint8_t icc_level, uint8_t chain) {
  if (buf10 == NERO_NFC_NULL) {
    return;
  }
  buf10[0] = msg_type;
  nfc_ccid_u32_store_le(&buf10[1], data_bytes);
  buf10[NFC_CCID_BULK_SLOT_OFFSET] = 0u;
  buf10[NFC_CCID_BULK_SEQ_OFFSET] = seq;
  buf10[NFC_CCID_BULK_LEVEL_PARAM_OFFSET] = icc_level;
  buf10[NFC_CCID_BULK_LEVEL_PARAM2_OFFSET] = 0u;
  buf10[NFC_CCID_BULK_LEVEL_PARAM3_OFFSET] = chain;
}
