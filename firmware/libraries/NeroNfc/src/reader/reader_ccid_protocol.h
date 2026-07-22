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

#include "ccid_usb_desc.h"
#include "nfc_ccid_frame.h"
#include "nero_nfc_mem_util.h"
#include "nero_nfc_attrs.h"

#include <stddef.h>
#include <stdint.h>

enum {
  READER_CCID_PARAM_IDX_BGUARDTIME = 2u,
  READER_CCID_PARAM_IDX_BWAITING = 3u,
  READER_CCID_PARAM_IDX_BCLKSTOP = 4u,
  READER_CCID_PARAM_IDX_BIFSC = 5u,
  READER_CCID_PARAM_IDX_BNAD = 6u,
  READER_CCID_PARAM_BUF_CAP = 8u,
  READER_CCID_PARAM_BM_FINDEX_DINDEX = 0x11u,
  READER_CCID_PARAM_BWAITING_T0 = 0x0Au,
  READER_CCID_PARAM_BWAITING_T1 = 0x4Du,
  READER_CCID_PARAM_BIFSC = 0xFEu,
  READER_CCID_POWER_SELECT_MAX = 0x03u,
  /*
   * [CCID1.10] Rev 1.10 section 6.2.6 — when a parameter error fails the
   * command, bError carries the byte offset of the first offending field in the
   * command message header. These are those field offsets, not abstract error
   * codes.
   */
  READER_CCID_PARAM_ERR_OFFSET_DWLENGTH = 0x01u,     /* dwLength (bytes 1..4) */
  READER_CCID_PARAM_ERR_OFFSET_BPROTOCOLNUM = 0x07u, /* bProtocolNum */
  READER_CCID_PARAM_ERR_OFFSET_ABRFU0 = 0x08u,       /* abRFU[0] */
  READER_CCID_PARAM_ERR_OFFSET_ABRFU1 = 0x09u,       /* abRFU[1] */
};

NERO_NFC_NODISCARD static inline bool reader_ccid_store_u32_le(uint8_t* dst,
                                                               size_t dst_cap,
                                                               size_t dst_off,
                                                               uint32_t value) {
  uint8_t encoded[sizeof(value)];
  nfc_ccid_u32_store_le(encoded, value);
  return nero_nfc_copy_bytes(dst, dst_cap, dst_off, encoded, sizeof(encoded));
}

NERO_NFC_NODISCARD static inline bool reader_ccid_load_u32_le(
    const uint8_t* src, size_t src_cap, size_t src_off, uint32_t* value_out) {
  uint8_t encoded[sizeof(*value_out)];
  if ((value_out == NERO_NFC_NULL) ||
      !nero_nfc_copy_from(encoded, sizeof(encoded), 0u, src, src_cap, src_off,
                          sizeof(encoded))) {
    return false;
  }
  *value_out = nfc_ccid_u32_load_le(encoded);
  return true;
}

static inline uint16_t reader_ccid_build_t0_params(uint8_t* param,
                                                   unsigned cap) {
  /* [CCID1.10] Rev 1.10 section 6.2.3 RDR_to_PC_Parameters — T=0 protocol data
   * structure. */
  if (cap < (unsigned)NFC_CCID_T0_PARAMS_LEN || param == NERO_NFC_NULL) {
    return 0u;
  }
  if (!nero_nfc_store_u8(param, (size_t)(cap), (size_t)(0),
                         (uint8_t)(READER_CCID_PARAM_BM_FINDEX_DINDEX))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(param, (size_t)(cap), (size_t)(1), (uint8_t)(0u))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(param, (size_t)(cap),
                         (size_t)(READER_CCID_PARAM_IDX_BGUARDTIME),
                         (uint8_t)(0u))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(param, (size_t)(cap),
                         (size_t)(READER_CCID_PARAM_IDX_BWAITING),
                         (uint8_t)(READER_CCID_PARAM_BWAITING_T0))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(param, (size_t)(cap),
                         (size_t)(READER_CCID_PARAM_IDX_BCLKSTOP),
                         (uint8_t)(0u))) {
    return 0u;
  }
  return (uint16_t)NFC_CCID_T0_PARAMS_LEN;
}

static inline uint16_t reader_ccid_build_t1_params(uint8_t* param,
                                                   unsigned cap) {
  /* [CCID1.10] Rev 1.10 section 6.2.3 RDR_to_PC_Parameters — T=1 protocol data
   * structure. */
  if (cap < (unsigned)NFC_CCID_T1_PARAMS_LEN || param == NERO_NFC_NULL) {
    return 0u;
  }
  if (!nero_nfc_store_u8(param, (size_t)(cap), (size_t)(0),
                         (uint8_t)(READER_CCID_PARAM_BM_FINDEX_DINDEX))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(param, (size_t)(cap), (size_t)(1), (uint8_t)(0u))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(param, (size_t)(cap),
                         (size_t)(READER_CCID_PARAM_IDX_BGUARDTIME),
                         (uint8_t)(0u))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(param, (size_t)(cap),
                         (size_t)(READER_CCID_PARAM_IDX_BWAITING),
                         (uint8_t)(READER_CCID_PARAM_BWAITING_T1))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(param, (size_t)(cap),
                         (size_t)(READER_CCID_PARAM_IDX_BCLKSTOP),
                         (uint8_t)(0u))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(param, (size_t)(cap),
                         (size_t)(READER_CCID_PARAM_IDX_BIFSC),
                         (uint8_t)(READER_CCID_PARAM_BIFSC))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(param, (size_t)(cap),
                         (size_t)(READER_CCID_PARAM_IDX_BNAD), (uint8_t)(0u))) {
    return 0u;
  }
  return (uint16_t)NFC_CCID_T1_PARAMS_LEN;
}

NERO_NFC_NODISCARD static inline bool reader_ccid_encode_params_response(
    uint8_t* buf, size_t buf_cap, uint8_t rdr_pc_parameters, uint8_t seq8,
    uint8_t icclvl, uint8_t err_code, uint8_t protocol_num,
    uint8_t protocol_t1) {
  uint8_t param[READER_CCID_PARAM_BUF_CAP];
  uint16_t parm_len = (protocol_num == protocol_t1)
                          ? reader_ccid_build_t1_params(param, sizeof(param))
                          : reader_ccid_build_t0_params(param, sizeof(param));
  size_t response_len = 0u;
  if (buf == NERO_NFC_NULL ||
      !nero_nfc_try_add_size((size_t)NFC_CCID_BULK_HEADER_LEN, (size_t)parm_len,
                             &response_len) ||
      response_len > buf_cap) {
    return false;
  }
  if (!nero_nfc_store_u8(buf, buf_cap, (size_t)(0), rdr_pc_parameters)) {
    return 0u;
  }
  if (!reader_ccid_store_u32_le(buf, buf_cap, 1u, parm_len)) {
    return false;
  }
  if (!nero_nfc_store_u8(buf, buf_cap, (size_t)(NFC_CCID_BULK_SLOT_OFFSET),
                         (uint8_t)(0u))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(buf, buf_cap, (size_t)(NFC_CCID_BULK_SEQ_OFFSET),
                         seq8)) {
    return 0u;
  }
  if (!nero_nfc_store_u8(buf, buf_cap,
                         (size_t)(NFC_CCID_BULK_LEVEL_PARAM_OFFSET), icclvl)) {
    return 0u;
  }
  if (!nero_nfc_store_u8(buf, buf_cap,
                         (size_t)(NFC_CCID_BULK_LEVEL_PARAM2_OFFSET),
                         err_code)) {
    return 0u;
  }
  if (!nero_nfc_store_u8(buf, buf_cap,
                         (size_t)(NFC_CCID_BULK_LEVEL_PARAM3_OFFSET),
                         protocol_num)) {
    return 0u;
  }
  if (parm_len != 0u) {
    return nero_nfc_copy_bytes(buf, buf_cap, NFC_CCID_BULK_HEADER_LEN, param,
                               parm_len);
  }
  return true;
}

static inline uint8_t reader_ccid_param_error_for_request(
    const uint8_t* frame, uint16_t nbytes, uint8_t set_params_msg,
    uint8_t protocol_t1) {
  uint32_t data_len = 0u;
  if ((frame != NERO_NFC_NULL) && (nbytes >= NFC_CCID_BULK_HEADER_LEN) &&
      (nero_nfc_u8_at(frame, (size_t)(nbytes), (size_t)(0)) ==
       set_params_msg)) {
    /* [CCID1.10] Rev 1.10 section 6.2.6 — report the lowest offending byte
     * offset first: dwLength (1), then bProtocolNum (7), then abRFU[0]/[1]
     * (8/9). */
    if (!reader_ccid_load_u32_le(frame, nbytes, 1u, &data_len) ||
        (data_len != NFC_CCID_T1_PARAMS_LEN)) {
      return (uint8_t)READER_CCID_PARAM_ERR_OFFSET_DWLENGTH;
    }
    if (frame[NFC_CCID_BULK_LEVEL_PARAM_OFFSET] != protocol_t1) {
      return (uint8_t)READER_CCID_PARAM_ERR_OFFSET_BPROTOCOLNUM;
    }
    if (frame[NFC_CCID_BULK_LEVEL_PARAM2_OFFSET] != 0u) {
      return (uint8_t)READER_CCID_PARAM_ERR_OFFSET_ABRFU0;
    }
    if (frame[NFC_CCID_BULK_LEVEL_PARAM3_OFFSET] != 0u) {
      return (uint8_t)READER_CCID_PARAM_ERR_OFFSET_ABRFU1;
    }
  }
  return 0u;
}

static inline uint8_t reader_ccid_param_icc_level(
    const uint8_t* frame, uint16_t nbytes, uint8_t current_status,
    uint8_t command_fail_bit, uint8_t set_params_msg, uint8_t protocol_t1) {
  if (frame == NERO_NFC_NULL) {
    return (uint8_t)(command_fail_bit | current_status);
  }
  if (reader_ccid_param_error_for_request(frame, nbytes, set_params_msg,
                                          protocol_t1) != 0u) {
    return (uint8_t)(command_fail_bit | current_status);
  }
  return current_status;
}

static inline uint8_t reader_ccid_xfr_level_error(uint16_t level_param,
                                                  uint32_t data_len,
                                                  uint8_t bad_length_error,
                                                  uint8_t bad_level_error) {
  if (level_param == NFC_CCID_XFR_RESPONSE_CONTINUE) {
    return (data_len == 0u) ? 0u : bad_length_error;
  }
  if ((level_param == NFC_CCID_XFR_LEVEL_SINGLE) ||
      (level_param == NFC_CCID_XFR_LEVEL_CHAIN_BEGIN) ||
      (level_param == NFC_CCID_XFR_LEVEL_CHAIN_MIDDLE) ||
      (level_param == NFC_CCID_XFR_LEVEL_CHAIN_END)) {
    return 0u;
  }
  return bad_level_error;
}

static inline uint8_t reader_ccid_power_select_error(
    uint8_t power_select, uint8_t unsupported_error) {
  return (power_select <= READER_CCID_POWER_SELECT_MAX) ? 0u
                                                        : unsupported_error;
}

NERO_NFC_NODISCARD static inline bool
reader_ccid_encode_data_rate_clock_response(uint8_t* buf18, size_t buf_cap,
                                            uint8_t rdr_msg_type, uint8_t seq8,
                                            uint8_t icc_level,
                                            uint8_t err_code) {
  if (buf18 == NERO_NFC_NULL ||
      buf_cap <
          (NFC_CCID_BULK_HEADER_LEN + NFC_CCID_DATA_RATE_CLOCK_PAYLOAD_LEN)) {
    return false;
  }
  if (!nero_nfc_store_u8(buf18, buf_cap, 0u, rdr_msg_type) ||
      !reader_ccid_store_u32_le(buf18, buf_cap, 1u,
                                NFC_CCID_DATA_RATE_CLOCK_PAYLOAD_LEN) ||
      !nero_nfc_store_u8(buf18, buf_cap, NFC_CCID_BULK_SLOT_OFFSET, 0u) ||
      !nero_nfc_store_u8(buf18, buf_cap, NFC_CCID_BULK_SEQ_OFFSET, seq8) ||
      !nero_nfc_store_u8(buf18, buf_cap, NFC_CCID_BULK_LEVEL_PARAM_OFFSET,
                         icc_level) ||
      !nero_nfc_store_u8(buf18, buf_cap,
                         (size_t)(NFC_CCID_BULK_LEVEL_PARAM2_OFFSET),
                         err_code)) {
    return false;
  }
  return nero_nfc_store_u8(buf18, buf_cap, NFC_CCID_BULK_LEVEL_PARAM3_OFFSET,
                           0u) &&
         reader_ccid_store_u32_le(buf18, buf_cap,
                                  NFC_CCID_DATA_RATE_CLOCK_OFFSET_DEFAULT_CLOCK,
                                  NERO_CCID_DESC_DEFAULT_CLOCK_KHZ) &&
         reader_ccid_store_u32_le(
             buf18, buf_cap, NFC_CCID_DATA_RATE_CLOCK_OFFSET_DEFAULT_DATA_RATE,
             NERO_CCID_DESC_DEFAULT_DATA_RATE_BPS);
}
