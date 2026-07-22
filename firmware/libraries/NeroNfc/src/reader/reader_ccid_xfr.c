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

#include "nero_nfc_null.h"
#include "reader_ccid_internal.h"
#include "reader_ccid_cmd_codes.h"
#include "reader_ccid_xfr.h"

#include "nfc_ccid_frame.h"
#include "nfc_pcsc_contactless.h"
#include "nero_nfc_mem_util.h"
#include "nfc_session_owner.h"
#include "reader_hal.h"
#include "reader_security_key.h"

#include <stdint.h>

bool reader_ccid_deadline_elapsed(uint32_t deadline_ms) {
  return (int32_t)(reader_hal_millis() - deadline_ms) >= 0;
}

void reader_ccid_reply_slot_stat(uint8_t* buf10, uint8_t seq8, uint8_t icclvl,
                                 uint8_t err_code) {
  nfc_ccid_encode_slot_status(buf10, RDR_PC_SLOTSTATUS, seq8, icclvl, err_code);
}

void reader_ccid_reply_data_block_error(uint8_t* buf10, uint8_t seq8,
                                        uint8_t icclvl, uint8_t err_code) {
  /* [CCID1.10] Rev 1.10 section 6.2.1 — the response to PC_to_RDR_IccPowerOn
   * (and other DataBlock-bearing commands) is always RDR_to_PC_DataBlock, even
   * on failure: dwLength=0, bStatus carries bmCommandStatus=failed, bError is
   * set. */
  nfc_ccid_encode_slot_status(buf10, RDR_PC_DATABLOCK, seq8, icclvl, err_code);
}

static void reply_data_preface(uint8_t* buf10, uint8_t seq8, uint32_t databytes,
                               uint8_t chain) {
  nfc_ccid_encode_data_block_header(buf10, RDR_PC_DATABLOCK, seq8, databytes,
                                    CCICC_ACTIVE, chain);
}

void reader_ccid_reply_data_preface(uint8_t* buf10, uint8_t seq8,
                                    uint32_t databytes, uint8_t chain) {
  reply_data_preface(buf10, seq8, databytes, chain);
}

static void reply_data_time_extension(uint8_t* buf10, size_t buf_cap,
                                      uint8_t seq8) {
  if (buf_cap < NFC_CCID_BULK_HEADER_LEN) {
    return;
  }
  nfc_ccid_encode_data_block_header(
      buf10, RDR_PC_DATABLOCK, seq8, 0u,
      (uint8_t)(CCICC_CMD_TIME_EXTENSION | CCICC_ACTIVE), 0u);
  (void)nero_nfc_store_u8(buf10, buf_cap,
                          (size_t)(NFC_CCID_BULK_LEVEL_PARAM2_OFFSET),
                          CCICC_TIME_EXTENSION_BWT_MULTIPLIER);
}

static void send_ccid_time_extension(const void* ctx);

static void begin_ccid_time_extension(uint8_t seq8, bool send_initial) {
  G_CCID_TIME_EXTENSION_SEQ = seq8;
  reader_security_key_set_ccid_time_extension_callback(send_ccid_time_extension,
                                                       NERO_NFC_NULL);
  if (send_initial) {
    send_ccid_time_extension(NERO_NFC_NULL);
  }
}

void reader_ccid_begin_time_extension(uint8_t seq8, bool send_initial) {
  begin_ccid_time_extension(seq8, send_initial);
}

void reader_ccid_end_time_extension(void) {
  reader_security_key_set_ccid_time_extension_callback(NERO_NFC_NULL,
                                                       NERO_NFC_NULL);
}

void reader_ccid_clear_xfr_response_chain(void) {
  G_CCID_CHAIN_ACTIVE = false;
  G_CCID_CHAIN_LEN = 0u;
  G_CCID_CHAIN_OFF = 0u;
}

void reader_ccid_clear_xfr_command_chain(void) {
  G_CCID_CMD_CHAIN_ACTIVE = false;
  G_CCID_CMD_CHAIN_LEN = 0u;
}

bool reader_ccid_append_xfr_command_chain(const uint8_t* data, uint16_t len,
                                          bool begin_chain) {
  size_t next_len = 0u;
  if ((data == NERO_NFC_NULL) || (len == 0u)) {
    return false;
  }
  if (begin_chain) {
    reader_ccid_clear_xfr_command_chain();
  } else if (!G_CCID_CMD_CHAIN_ACTIVE) {
    return false;
  }
  if (!nero_nfc_try_add_size((size_t)(G_CCID_CMD_CHAIN_LEN), (size_t)(len),
                             &next_len) ||
      next_len > sizeof(G_CCID_CMD_CHAIN_BUF) ||
      !nero_nfc_copy_bytes(G_CCID_CMD_CHAIN_BUF, sizeof(G_CCID_CMD_CHAIN_BUF),
                           G_CCID_CMD_CHAIN_LEN, data, len)) {
    reader_ccid_clear_xfr_command_chain();
    return false;
  }
  G_CCID_CMD_CHAIN_LEN = (uint16_t)(next_len);
  G_CCID_CMD_CHAIN_ACTIVE = true;
  return true;
}

void reader_ccid_send_xfr_command_continue(uint8_t* work, uint8_t seq) {
  reply_data_preface(work, seq, 0u, NFC_CCID_XFR_RESPONSE_CONTINUE);
  (void)reader_hal_ccid_send(work, (uint16_t)(NFC_CCID_BULK_HEADER_LEN),
                             (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
}

uint8_t reader_ccid_current_icc_level(void) {
  if (!G_CARD_PRESENT) {
    return CCICC_NO_ICC;
  }
  return G_SESS ? CCICC_ACTIVE : CCICC_INACTIVE;
}

__attribute__((weak)) bool reader_ccid_prepare_tag_for_power_on(
    reader_tag_kind_t tag_kind) {
  (void)tag_kind;
  return true;
}

void reader_ccid_reply_command_not_supported(uint8_t* buf10, uint8_t msg_type,
                                             uint8_t seq8) {
  nfc_ccid_encode_slot_status(
      buf10, msg_type, seq8,
      (uint8_t)(CCICC_CMD_FAIL | reader_ccid_current_icc_level()), 0u);
}

void reader_ccid_send_xfr_chain_chunk(uint8_t* work, uint8_t seq) {
  uint16_t remaining;
  uint16_t chunk;
  uint8_t chain;

  if ((work == NERO_NFC_NULL) || !G_CCID_CHAIN_ACTIVE ||
      G_CCID_CHAIN_OFF >= G_CCID_CHAIN_LEN) {
    reader_ccid_clear_xfr_response_chain();
    return;
  }

  remaining = (uint16_t)(G_CCID_CHAIN_LEN - G_CCID_CHAIN_OFF);
  chunk = (remaining > (uint16_t)(NFC_CCID_RSP_DATA_CAP))
              ? (uint16_t)(NFC_CCID_RSP_DATA_CAP)
              : remaining;
  if (G_CCID_CHAIN_OFF == 0u) {
    chain = NFC_CCID_XFR_LEVEL_CHAIN_BEGIN;
  } else if ((uint16_t)(G_CCID_CHAIN_OFF + chunk) >= G_CCID_CHAIN_LEN) {
    chain = NFC_CCID_XFR_LEVEL_CHAIN_END;
  } else {
    chain = NFC_CCID_XFR_LEVEL_CHAIN_MIDDLE;
  }

  if (!nero_nfc_copy_bytes(work, sizeof(G_CCID_RSP), NFC_CCID_BULK_HEADER_LEN,
                           G_CCID_CHAIN_BUF + G_CCID_CHAIN_OFF, chunk)) {
    reader_ccid_clear_xfr_response_chain();
    return;
  }
  reply_data_preface(work, seq, chunk, chain);
  if (!reader_hal_ccid_send(work, (uint16_t)(NFC_CCID_BULK_HEADER_LEN + chunk),
                            (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS))) {
    reader_ccid_clear_xfr_response_chain();
    return;
  }
  G_CCID_CHAIN_OFF = (uint16_t)(G_CCID_CHAIN_OFF + chunk);
  if (G_CCID_CHAIN_OFF >= G_CCID_CHAIN_LEN) {
    reader_ccid_clear_xfr_response_chain();
  }
}

void reader_ccid_send_xfr_data_response(uint8_t* work, uint8_t seq,
                                        const uint8_t* data, uint16_t len) {
  if ((work == NERO_NFC_NULL) || (data == NERO_NFC_NULL && len != 0u)) {
    return;
  }
  reader_ccid_clear_xfr_response_chain();
  if (len <= NFC_CCID_RSP_DATA_CAP) {
    if ((len != 0u) &&
        !nero_nfc_copy_bytes(work, sizeof(G_CCID_RSP), NFC_CCID_BULK_HEADER_LEN,
                             data, len)) {
      const uint8_t err[] = {(uint8_t)(NFC_ISO7816_SW1_GENERAL_ERROR),
                             (uint8_t)(NFC_ISO7816_SW2_SUCCESS)};
      if (!nero_nfc_copy_bytes(work, sizeof(G_CCID_RSP),
                               NFC_CCID_BULK_HEADER_LEN, err,
                               (uint16_t)(sizeof(err)))) {
        return;
      }
      reply_data_preface(work, seq, (uint32_t)(sizeof(err)),
                         NFC_CCID_XFR_LEVEL_SINGLE);
      (void)reader_hal_ccid_send(
          work, (uint16_t)(NFC_CCID_BULK_HEADER_LEN + sizeof(err)),
          (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
      return;
    }
    reply_data_preface(work, seq, len, NFC_CCID_XFR_LEVEL_SINGLE);
    (void)reader_hal_ccid_send(work, (uint16_t)(NFC_CCID_BULK_HEADER_LEN + len),
                               (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
    return;
  }

  if (len > (uint16_t)(sizeof(G_CCID_CHAIN_BUF)) ||
      !nero_nfc_copy_bytes(G_CCID_CHAIN_BUF, sizeof(G_CCID_CHAIN_BUF), 0u, data,
                           len)) {
    uint8_t err[] = {(uint8_t)(NFC_ISO7816_SW1_GENERAL_ERROR),
                     (uint8_t)(NFC_ISO7816_SW2_SUCCESS)};
    if (!nero_nfc_copy_bytes(work, sizeof(G_CCID_RSP), NFC_CCID_BULK_HEADER_LEN,
                             err, (uint16_t)(sizeof(err)))) {
      return;
    }
    reply_data_preface(work, seq, (uint32_t)(sizeof(err)),
                       NFC_CCID_XFR_LEVEL_SINGLE);
    (void)reader_hal_ccid_send(
        work, (uint16_t)(NFC_CCID_BULK_HEADER_LEN + sizeof(err)),
        (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
    return;
  }
  G_CCID_CHAIN_LEN = len;
  G_CCID_CHAIN_OFF = 0u;
  G_CCID_CHAIN_ACTIVE = true;
  reader_ccid_send_xfr_chain_chunk(work, seq);
}

uint8_t reader_ccid_reply_param_status(void) {
  if (!G_CARD_PRESENT) {
    return CCICC_NO_ICC;
  }
  return G_SESS ? CCICC_ACTIVE : CCICC_INACTIVE;
}

void reader_ccid_teardown_session(void) {
  reader_ccid_clear_xfr_response_chain();
  reader_ccid_clear_xfr_command_chain();
  reader_security_key_set_ccid_time_extension_callback(NERO_NFC_NULL,
                                                       NERO_NFC_NULL);
  G_TYPE4_SECURITY_KEY_APP = false;
  if (G_ISO_SESSION_OPEN) {
    reader_security_key_ccid_release_iso_session();
    G_ISO_SESSION_OPEN = false;
  }
  G_SESS = false;
  if (nfc_session_owner_get() == NFC_SESSION_OWNER_CCID) {
    nfc_session_owner_set((nfc_session_owner_t)(0));
  }
}

void reader_ccid_complete_card_removal(void) {
  const bool was_present = G_CARD_PRESENT;

  G_CARD_PRESENT = false;
  G_REMOVE_DEFERRED = false;
  G_REMOVE_DEFER_UNTIL_MS = 0u;
  G_TAG_KIND = READER_TAG_KIND_NONE;
  G_TYPE4_SECURITY_KEY_APP = false;
  reader_ccid_teardown_session();
  if (was_present) {
    reader_hal_ccid_notify_slot_change(false);
  }
}
static void send_ccid_time_extension(const void* ctx) {
  uint8_t buf[NFC_CCID_BULK_HEADER_LEN];

  (void)ctx;
  reply_data_time_extension(buf, sizeof(buf), G_CCID_TIME_EXTENSION_SEQ);
  (void)reader_hal_ccid_send(buf, (uint16_t)(sizeof(buf)),
                             (uint32_t)(NFC_CCID_HAL_SEND_TIMEOUT_MS));
}

#endif /* NERO_CCID_USB_BUILD */
