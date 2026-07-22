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

#if defined(NERO_CCID_USB_BUILD)

#include "reader_ccid_cmd_codes.h"
#include "nero_nfc_null.h"
#include "reader_ccid_internal.h"
#include "reader_ccid_xfr.h"

#include "nero_nfc_mem_util.h"
#include "nfc_ccid_frame.h"
#include "nfc_pcsc_contactless.h"
#include "nfc_session_owner.h"
#include "reader_ccid_bulk_codec.h"
#include "reader_ccid_protocol.h"
#include "reader_hal.h"
#include "reader_security_key.h"

#include <stdint.h>

static bool storage_xfr_needs_time_extension(const uint8_t* apdu,
                                             uint16_t apdu_len) {
  uint8_t cla;
  uint8_t ins;

  if (((G_TAG_KIND != READER_TAG_KIND_TYPE2) &&
       (G_TAG_KIND != READER_TAG_KIND_TYPE5)) ||
      (apdu == NERO_NFC_NULL) ||
      !nero_nfc_span_ok(0u, 2u, (size_t)(apdu_len))) {
    return false;
  }
  cla = nero_nfc_u8_at(apdu, (size_t)(apdu_len), (size_t)(0));
  ins = nero_nfc_u8_at(apdu, (size_t)(apdu_len), (size_t)(1));
  if (cla != (uint8_t)(NFC_ISO7816_CLA_PROPRIETARY)) {
    return false;
  }
  return (ins == (uint8_t)(NFC_ISO7816_INS_READ_BINARY)) ||
         (ins == (uint8_t)(NFC_ISO7816_INS_UPDATE_BINARY));
}

void reader_ccid_handle_bulk(const uint8_t* frame, uint16_t nbytes) {
  uint8_t* work = G_CCID_RSP;
  uint32_t datalen_bytes;
  uint8_t seq;
  unsigned pay_bytes;

  nero_nfc_zero_bytes(work, sizeof(G_CCID_RSP));
  if (!nfc_ccid_bulk_frame_validate(frame, nbytes, &datalen_bytes)) {
    if ((frame != NERO_NFC_NULL) &&
        nero_nfc_span_ok(0u, NFC_CCID_BULK_HEADER_LEN, nbytes)) {
      const uint16_t rsp_len = reader_ccid_encode_command_failed_response(
          work, sizeof(G_CCID_RSP), frame[0], frame[NFC_CCID_BULK_SEQ_OFFSET],
          reader_ccid_current_icc_level(), CCID_ERR_BAD_DWLENGTH);
      (void)reader_hal_ccid_send(work, rsp_len,
                                 (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
    }
    return;
  }
  seq = nero_nfc_u8_at(frame, (size_t)(nbytes),
                       (size_t)(NFC_CCID_BULK_SEQ_OFFSET));
  pay_bytes = (unsigned)(datalen_bytes);

  if (frame[NFC_CCID_BULK_SLOT_OFFSET] != 0u) {
    const uint16_t rsp_len = reader_ccid_encode_slot_absent_response(
        work, sizeof(G_CCID_RSP), frame[0], frame[NFC_CCID_BULK_SLOT_OFFSET],
        seq, CCID_ERR_SLOT_DOES_NOT_EXIST);
    (void)reader_hal_ccid_send(work, rsp_len,
                               (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
    return;
  }

  if (reader_ccid_bulk_command_requires_zero_length(frame[0]) &&
      (datalen_bytes != 0u)) {
    const uint16_t rsp_len = reader_ccid_encode_command_failed_response(
        work, sizeof(G_CCID_RSP), frame[0], seq,
        reader_ccid_current_icc_level(), CCID_ERR_BAD_DWLENGTH);
    (void)reader_hal_ccid_send(work, rsp_len,
                               (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
    return;
  }

  if (reader_ccid_bulk_command_requires_rfu_zero(frame[0]) &&
      ((frame[NFC_CCID_BULK_LEVEL_PARAM_OFFSET] != 0u) ||
       (frame[NFC_CCID_BULK_LEVEL_PARAM2_OFFSET] != 0u) ||
       (nero_nfc_u8_at(frame, (size_t)(nbytes),
                       (size_t)(NFC_CCID_BULK_LEVEL_PARAM3_OFFSET)) != 0u))) {
    const uint16_t rsp_len = reader_ccid_encode_command_failed_response(
        work, sizeof(G_CCID_RSP), frame[0], seq,
        reader_ccid_current_icc_level(), CCID_ERR_POWER_SELECT_UNSUPPORTED);
    (void)reader_hal_ccid_send(work, rsp_len,
                               (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
    return;
  }

  if (frame[0] == CCID_PC_XFR) {
    const uint16_t level_param =
        reader_ccid_bulk_xfr_level_parameter(frame, nbytes);
    const uint8_t xfr_err = reader_ccid_xfr_level_error(
        level_param, datalen_bytes, CCID_ERR_BAD_DWLENGTH,
        CCID_ERR_BAD_LEVEL_PARAMETER);
    if (xfr_err != 0u) {
      const uint16_t rsp_len = reader_ccid_encode_command_failed_response(
          work, sizeof(G_CCID_RSP), frame[0], seq,
          reader_ccid_current_icc_level(), xfr_err);
      (void)reader_hal_ccid_send(work, rsp_len,
                                 (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
      return;
    }
  }

  if ((frame[0] == CCID_PC_ICC_ON) &&
      ((frame[NFC_CCID_BULK_LEVEL_PARAM2_OFFSET] != 0u) ||
       (nero_nfc_u8_at(frame, (size_t)(nbytes),
                       (size_t)(NFC_CCID_BULK_LEVEL_PARAM3_OFFSET)) != 0u))) {
    const uint16_t rsp_len = reader_ccid_encode_command_failed_response(
        work, sizeof(G_CCID_RSP), frame[0], seq,
        reader_ccid_current_icc_level(), CCID_ERR_BAD_LEVEL_PARAMETER);
    (void)reader_hal_ccid_send(work, rsp_len,
                               (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
    return;
  }

  if ((frame[0] == CCID_PC_SET_RATE_CLOCK) &&
      ((frame[NFC_CCID_BULK_LEVEL_PARAM_OFFSET] != 0u) ||
       (frame[NFC_CCID_BULK_LEVEL_PARAM2_OFFSET] != 0u) ||
       (nero_nfc_u8_at(frame, (size_t)(nbytes),
                       (size_t)(NFC_CCID_BULK_LEVEL_PARAM3_OFFSET)) != 0u))) {
    uint8_t err = (uint8_t)(CCID_ERR_PARAMS_PROTOCOL_TYPE);
    if (nero_nfc_span_ok(NFC_CCID_BULK_LEVEL_PARAM_OFFSET, 1u, nbytes) &&
        frame[NFC_CCID_BULK_LEVEL_PARAM_OFFSET] != 0u) {
      err = (uint8_t)(CCID_ERR_POWER_SELECT_UNSUPPORTED);
    } else if (nero_nfc_span_ok(NFC_CCID_BULK_LEVEL_PARAM2_OFFSET, 1u,
                                nbytes) &&
               frame[NFC_CCID_BULK_LEVEL_PARAM2_OFFSET] != 0u) {
      err = (uint8_t)(CCID_ERR_BAD_LEVEL_PARAMETER);
    }
    const uint16_t rsp_len = reader_ccid_encode_command_failed_response(
        work, sizeof(G_CCID_RSP), frame[0], seq,
        reader_ccid_current_icc_level(), err);
    (void)reader_hal_ccid_send(work, rsp_len,
                               (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
    return;
  }

  if (nfc_ccid_xfr_frame_requests_response_continuation(frame, nbytes)) {
    if (G_CCID_CHAIN_ACTIVE) {
      reader_ccid_send_xfr_chain_chunk(work, seq);
    } else {
      const uint16_t rsp_len = reader_ccid_encode_command_failed_response(
          work, sizeof(G_CCID_RSP), frame[0], seq,
          reader_ccid_current_icc_level(), CCID_ERR_BAD_LEVEL_PARAMETER);
      (void)reader_hal_ccid_send(work, rsp_len,
                                 (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
    }
    return;
  }
  if (G_CCID_CHAIN_ACTIVE) {
    reader_ccid_clear_xfr_response_chain();
  }
  if ((frame[0] != CCID_PC_XFR) && G_CCID_CMD_CHAIN_ACTIVE) {
    reader_ccid_clear_xfr_command_chain();
  }

  {
    uint8_t abort_slot = 0;
    uint8_t abort_seq = 0;
    if (reader_hal_ccid_abort_request_pending(&abort_slot, &abort_seq) &&
        nero_nfc_span_ok(NFC_CCID_BULK_SLOT_OFFSET, 1u, nbytes) &&
        frame[NFC_CCID_BULK_SLOT_OFFSET] == abort_slot &&
        (frame[0] != CCID_PC_ABORT || seq != abort_seq)) {
      const uint16_t rsp_len = reader_ccid_encode_command_failed_response(
          work, sizeof(G_CCID_RSP), frame[0], seq,
          reader_ccid_current_icc_level(), CCID_ERR_CMD_ABORTED);
      (void)reader_hal_ccid_send(work, rsp_len,
                                 (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
      return;
    }
  }

  switch (frame[0]) {
    case CCID_PC_SLOT_STATUS: {
      uint8_t icclvl = reader_ccid_current_icc_level();
      reader_ccid_reply_slot_stat(work, seq, icclvl, 0u);
      (void)reader_hal_ccid_send(work, (uint16_t)(NFC_CCID_BULK_HEADER_LEN),
                                 (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
      break;
    }
    case CCID_PC_ICC_OFF: {
      reader_ccid_teardown_session();
      G_PROTOCOL_NUM = CCID_PROTOCOL_NUM_T1;
      reader_ccid_reply_slot_stat(
          work, seq, G_CARD_PRESENT ? CCICC_INACTIVE : CCICC_NO_ICC, 0u);
      (void)reader_hal_ccid_send(work, (uint16_t)(NFC_CCID_BULK_HEADER_LEN),
                                 (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
      break;
    }
    case CCID_PC_ICC_ON: {
      uint16_t atr_len = 0u;
      const uint8_t power_err = reader_ccid_power_select_error(
          frame[NFC_CCID_BULK_LEVEL_PARAM_OFFSET],
          CCID_ERR_POWER_SELECT_UNSUPPORTED);
      if (power_err != 0u) {
        reader_ccid_reply_data_block_error(
            work, seq, (uint8_t)(CCICC_CMD_FAIL | CCICC_INACTIVE), power_err);
        (void)reader_hal_ccid_send(work, (uint16_t)(NFC_CCID_BULK_HEADER_LEN),
                                   (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
        break;
      }
      reader_ccid_teardown_session();
      if (!G_CARD_PRESENT || G_TAG_KIND == READER_TAG_KIND_NONE) {
        reader_ccid_reply_data_block_error(
            work, seq, (uint8_t)(CCICC_CMD_FAIL | CCICC_NO_ICC),
            CCID_ERR_ICC_MUTE);
        (void)reader_hal_ccid_send(work, (uint16_t)(NFC_CCID_BULK_HEADER_LEN),
                                   (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
        break;
      }
      if (G_TAG_KIND == READER_TAG_KIND_TYPE4) {
        /* No BWT exists until ATR/protocol activation completes. A CCID
         * time-extension response here would carry an undefined multiplier. */
        reader_ccid_begin_time_extension(seq, false);
        G_PROTOCOL_NUM = CCID_PROTOCOL_NUM_T1;
        if (!reader_security_key_ccid_open_iso_session() ||
            !reader_security_key_pcsc_contactless_copy_atr(
                work + NFC_CCID_BULK_PAYLOAD_OFFSET,
                (uint16_t)(sizeof(G_CCID_RSP) - NFC_CCID_BULK_PAYLOAD_OFFSET),
                &atr_len)) {
          reader_ccid_teardown_session();
          reader_ccid_reply_data_block_error(
              work, seq, (uint8_t)(CCICC_CMD_FAIL | CCICC_INACTIVE),
              CCID_ERR_ICC_MUTE);
          (void)reader_hal_ccid_send(work, (uint16_t)(NFC_CCID_BULK_HEADER_LEN),
                                     (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
          reader_ccid_end_time_extension();
          break;
        }
        G_ISO_SESSION_OPEN = true;
        G_TYPE4_SECURITY_KEY_APP = false;
        reader_ccid_end_time_extension();
      } else {
        G_PROTOCOL_NUM = nfc_pcsc_protocol_for_tag(G_TAG_KIND);
        if (!reader_ccid_prepare_tag_for_power_on(G_TAG_KIND)) {
          reader_ccid_teardown_session();
          reader_ccid_reply_data_block_error(
              work, seq, (uint8_t)(CCICC_CMD_FAIL | CCICC_INACTIVE),
              CCID_ERR_ICC_MUTE);
          (void)reader_hal_ccid_send(work, (uint16_t)(NFC_CCID_BULK_HEADER_LEN),
                                     (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
          break;
        }
        if (!nfc_pcsc_copy_storage_card_atr(
                G_TAG_KIND, work + NFC_CCID_BULK_PAYLOAD_OFFSET,
                (uint16_t)(sizeof(G_CCID_RSP) - NFC_CCID_BULK_PAYLOAD_OFFSET),
                &atr_len)) {
          reader_ccid_reply_data_block_error(
              work, seq, (uint8_t)(CCICC_CMD_FAIL | CCICC_NO_ICC),
              CCID_ERR_ICC_MUTE);
          (void)reader_hal_ccid_send(work, (uint16_t)(NFC_CCID_BULK_HEADER_LEN),
                                     (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
          break;
        }
      }

      reader_ccid_reply_data_preface(work, seq, atr_len, 0u);
      (void)reader_hal_ccid_send(work,
                                 (uint16_t)(NFC_CCID_BULK_HEADER_LEN + atr_len),
                                 (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
      G_SESS = true;
      nfc_session_owner_set(NFC_SESSION_OWNER_CCID);
      reader_ccid_note_host_session_activity();
      break;
    }
    case CCID_PC_GET_PARAMS:
    case CCID_PC_RESET_PARAMS:
    case CCID_PC_SET_PARAMS: {
      uint8_t err = reader_ccid_param_error_for_request(
          frame, nbytes, CCID_PC_SET_PARAMS, CCID_PROTOCOL_NUM_T1);
      uint8_t icclvl = reader_ccid_param_icc_level(
          frame, nbytes, reader_ccid_reply_param_status(), CCICC_CMD_FAIL,
          CCID_PC_SET_PARAMS, CCID_PROTOCOL_NUM_T1);
      uint8_t protocol_num = G_PROTOCOL_NUM;
      uint16_t parm_len;

      if (!G_CARD_PRESENT) {
        err = CCID_ERR_ICC_MUTE;
        icclvl = (uint8_t)(CCICC_CMD_FAIL | CCICC_NO_ICC);
      } else if (frame[0] == CCID_PC_RESET_PARAMS) {
        protocol_num = CCID_PROTOCOL_NUM_T1;
        G_PROTOCOL_NUM = protocol_num;
      }
      if (G_CARD_PRESENT && (frame[0] == CCID_PC_SET_PARAMS) && (err == 0u) &&
          nero_nfc_span_ok(NFC_CCID_BULK_LEVEL_PARAM_OFFSET, 1u, nbytes)) {
        protocol_num = frame[NFC_CCID_BULK_LEVEL_PARAM_OFFSET];
        G_PROTOCOL_NUM = protocol_num;
      }
      (void)reader_ccid_encode_params_response(
          work, sizeof(G_CCID_RSP), RDR_PC_PARAMETERS, seq, icclvl, err,
          protocol_num, CCID_PROTOCOL_NUM_T1);
      parm_len = (protocol_num == CCID_PROTOCOL_NUM_T1)
                     ? (uint16_t)(NFC_CCID_T1_PARAMS_LEN)
                     : (uint16_t)(NFC_CCID_T0_PARAMS_LEN);
      (void)reader_hal_ccid_send(
          work, (uint16_t)(NFC_CCID_BULK_HEADER_LEN + parm_len),
          (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
      reader_ccid_note_host_session_activity();
      break;
    }
    case CCID_PC_ABORT: {
      uint8_t icclvl = reader_ccid_current_icc_level();
      reader_ccid_clear_xfr_response_chain();
      reader_ccid_clear_xfr_command_chain();
      reader_security_key_set_ccid_time_extension_callback(NERO_NFC_NULL,
                                                           NERO_NFC_NULL);
      if (!nero_nfc_span_ok(NFC_CCID_BULK_SLOT_OFFSET, 1u, nbytes)) {
        reader_ccid_reply_command_not_supported(work, RDR_PC_SLOTSTATUS, seq);
        (void)reader_hal_ccid_send(work, (uint16_t)(NFC_CCID_BULK_HEADER_LEN),
                                   (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
        break;
      }
      reader_hal_ccid_clear_abort_request(frame[NFC_CCID_BULK_SLOT_OFFSET],
                                          seq);
      reader_ccid_reply_slot_stat(work, seq, icclvl, 0u);
      (void)reader_hal_ccid_send(work, (uint16_t)(NFC_CCID_BULK_HEADER_LEN),
                                 (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
      break;
    }
    case CCID_PC_ICC_CLOCK:
    case CCID_PC_T0_APDU:
    case CCID_PC_MECHANICAL: {
      reader_ccid_reply_command_not_supported(work, RDR_PC_SLOTSTATUS, seq);
      (void)reader_hal_ccid_send(work, (uint16_t)(NFC_CCID_BULK_HEADER_LEN),
                                 (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
      break;
    }
    case CCID_PC_SECURE: {
      reader_ccid_reply_command_not_supported(work, RDR_PC_DATABLOCK, seq);
      (void)reader_hal_ccid_send(work, (uint16_t)(NFC_CCID_BULK_HEADER_LEN),
                                 (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
      break;
    }
    case CCID_PC_ESCAPE: {
      const uint16_t rsp_len = reader_ccid_encode_command_failed_response(
          work, sizeof(G_CCID_RSP), frame[0], seq,
          reader_ccid_current_icc_level(), 0u);
      (void)reader_hal_ccid_send(work, rsp_len,
                                 (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
      break;
    }
    case CCID_PC_SET_RATE_CLOCK: {
      uint8_t icclvl = reader_ccid_current_icc_level();
      uint8_t err = 0u;
      if (datalen_bytes != NFC_CCID_DATA_RATE_CLOCK_PAYLOAD_LEN) {
        icclvl = (uint8_t)(CCICC_CMD_FAIL | icclvl);
        err = CCID_ERR_BAD_DWLENGTH;
      }
      (void)reader_ccid_encode_data_rate_clock_response(
          work, sizeof(G_CCID_RSP), RDR_PC_DATA_RATE_AND_CLOCK, seq, icclvl,
          err);
      (void)reader_hal_ccid_send(
          work,
          (uint16_t)(NFC_CCID_BULK_HEADER_LEN +
                     NFC_CCID_DATA_RATE_CLOCK_PAYLOAD_LEN),
          (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
      break;
    }
    case CCID_PC_XFR: {
      const uint16_t level_param =
          reader_ccid_bulk_xfr_level_parameter(frame, nbytes);
      uint16_t rlen;
      const uint8_t* apdu_data = frame + NFC_CCID_BULK_PAYLOAD_OFFSET;
      uint16_t apdu_len = (uint16_t)(pay_bytes);
      uint8_t* rsp_data = (work + NFC_CCID_BULK_PAYLOAD_OFFSET);
      uint16_t rsp_cap =
          (uint16_t)(sizeof(G_CCID_RSP) - NFC_CCID_BULK_HEADER_LEN);

      if ((frame[0] == CCID_PC_XFR) && (G_TAG_KIND == READER_TAG_KIND_TYPE4)) {
        rsp_data = G_CCID_APDU_RSP;
        rsp_cap = (uint16_t)(sizeof(G_CCID_APDU_RSP));
      }

      if (!G_SESS) {
        const uint16_t rsp_len = reader_ccid_encode_command_failed_response(
            work, sizeof(G_CCID_RSP), frame[0], seq, CCICC_NO_ICC,
            CCID_ERR_ICC_MUTE);
        (void)reader_hal_ccid_send(work, rsp_len,
                                   (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
        break;
      }
      if (level_param == CCID_XFR_LEVEL_SINGLE) {
        if (G_CCID_CMD_CHAIN_ACTIVE) {
          reader_ccid_clear_xfr_command_chain();
          const uint16_t rsp_len = reader_ccid_encode_command_failed_response(
              work, sizeof(G_CCID_RSP), frame[0], seq,
              reader_ccid_current_icc_level(), CCID_ERR_BAD_LEVEL_PARAMETER);
          (void)reader_hal_ccid_send(work, rsp_len,
                                     (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
          break;
        }
      } else {
        const bool begin_chain = (level_param == CCID_XFR_LEVEL_CHAIN_BEGIN);
        if (!reader_ccid_append_xfr_command_chain(
                frame + NFC_CCID_BULK_PAYLOAD_OFFSET, (uint16_t)(pay_bytes),
                begin_chain)) {
          const uint16_t rsp_len = reader_ccid_encode_command_failed_response(
              work, sizeof(G_CCID_RSP), frame[0], seq,
              reader_ccid_current_icc_level(), CCID_ERR_BAD_DWLENGTH);
          (void)reader_hal_ccid_send(work, rsp_len,
                                     (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
          break;
        }
        if ((level_param == CCID_XFR_LEVEL_CHAIN_BEGIN) ||
            (level_param == CCID_XFR_LEVEL_CHAIN_MIDDLE)) {
          reader_ccid_send_xfr_command_continue(work, seq);
          break;
        }
        apdu_data = G_CCID_CMD_CHAIN_BUF;
        apdu_len = G_CCID_CMD_CHAIN_LEN;
      }

      const bool send_initial_time_extension =
          ((G_TAG_KIND == READER_TAG_KIND_TYPE4) &&
           reader_security_key_apdu_needs_ccid_time_extension(apdu_data,
                                                              apdu_len)) ||
          storage_xfr_needs_time_extension(apdu_data, apdu_len);
      const bool bind_time_extension =
          (G_TAG_KIND == READER_TAG_KIND_TYPE4) || send_initial_time_extension;
      if (bind_time_extension) {
        reader_ccid_begin_time_extension(seq, send_initial_time_extension);
      }
      rlen = reader_ccid_dispatch_host_payload(apdu_data, apdu_len, rsp_data,
                                               rsp_cap);
      if (level_param == CCID_XFR_LEVEL_CHAIN_END) {
        reader_ccid_clear_xfr_command_chain();
      }
      {
        uint8_t abort_slot = 0u;
        uint8_t abort_seq = 0u;
        if (reader_hal_ccid_abort_request_pending(&abort_slot, &abort_seq) &&
            abort_slot == frame[NFC_CCID_BULK_SLOT_OFFSET] &&
            abort_seq == seq) {
          const uint16_t rsp_len = reader_ccid_encode_command_failed_response(
              work, sizeof(G_CCID_RSP), frame[0], seq,
              reader_ccid_current_icc_level(), CCID_ERR_CMD_ABORTED);
          reader_ccid_end_time_extension();
          reader_ccid_clear_xfr_response_chain();
          (void)reader_hal_ccid_send(work, rsp_len,
                                     (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
          break;
        }
      }
      reader_ccid_send_xfr_data_response(work, seq, rsp_data, rlen);
      if (bind_time_extension) {
        reader_ccid_end_time_extension();
      }
      break;
    }
    default:
      reader_ccid_reply_command_not_supported(work, RDR_PC_SLOTSTATUS, seq);
      (void)reader_hal_ccid_send(work, (uint16_t)(NFC_CCID_BULK_HEADER_LEN),
                                 (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
      break;
  }
}

#endif /* NERO_CCID_USB_BUILD */
