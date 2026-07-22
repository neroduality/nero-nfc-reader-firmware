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
#include "nero_nfc_limits.h"
#include "nfc_ccid_frame.h"
#include "nfc_pcsc_contactless.h"
#include "nfc_tag_geometry_limits.h"
#include "reader_tags.h"

#include <stdbool.h>
#include <stdint.h>

enum {
  CCID_APDU_RSP_BUF_MAX = NERO_NFC_CCID_APDU_RSP_BUF_MAX,
  CCID_APDU_RSP_BYTES = (unsigned)(CCID_APDU_RSP_BUF_MAX) +
                        (unsigned)(NFC_ISO7816_SW_STATUS_WORD_LEN),
  CCID_RSP_FRAME_BYTES =
      (unsigned)(NFC_CCID_RSP_DATA_CAP) + (unsigned)(NFC_CCID_BULK_HEADER_LEN),
};

typedef struct reader_ccid_context {
  bool sess;
  bool card_present;
  bool iso_session_open;
  bool type4_security_key_app;
  bool remove_deferred;
  uint32_t remove_defer_until_ms;
  reader_tag_kind_t tag_kind;
  uint8_t protocol_num;
  uint8_t apdu_rsp[CCID_APDU_RSP_BYTES];
  uint8_t time_extension_seq;
  uint8_t frame[NFC_CCID_WORK_BUF_SIZE];
  uint8_t rsp[CCID_RSP_FRAME_BYTES];
  uint8_t chain_buf[NFC_CCID_EXTENDED_RSP_BUF_SIZE];
  uint16_t chain_len;
  uint16_t chain_off;
  bool chain_active;
  uint8_t cmd_chain_buf[NFC_CCID_EXTENDED_RSP_BUF_SIZE];
  uint16_t cmd_chain_len;
  bool cmd_chain_active;
} reader_ccid_context_t;

#ifdef __cplusplus
extern "C" {
#endif

NERO_NFC_NODISCARD reader_ccid_context_t* reader_ccid_context_active(void);
void reader_ccid_context_reset(reader_ccid_context_t* ctx);

#ifdef __cplusplus
}
#endif

#define G_SESS (reader_ccid_context_active()->sess)
#define G_CARD_PRESENT (reader_ccid_context_active()->card_present)
#define G_ISO_SESSION_OPEN (reader_ccid_context_active()->iso_session_open)
#define G_TYPE4_SECURITY_KEY_APP \
  (reader_ccid_context_active()->type4_security_key_app)
#define G_REMOVE_DEFERRED (reader_ccid_context_active()->remove_deferred)
#define G_REMOVE_DEFER_UNTIL_MS \
  (reader_ccid_context_active()->remove_defer_until_ms)
#define G_TAG_KIND (reader_ccid_context_active()->tag_kind)
#define G_PROTOCOL_NUM (reader_ccid_context_active()->protocol_num)
#define G_CCID_APDU_RSP (reader_ccid_context_active()->apdu_rsp)
#define G_CCID_TIME_EXTENSION_SEQ \
  (reader_ccid_context_active()->time_extension_seq)
#define G_CCID_FRAME (reader_ccid_context_active()->frame)
#define G_CCID_RSP (reader_ccid_context_active()->rsp)
#define G_CCID_CHAIN_BUF (reader_ccid_context_active()->chain_buf)
#define G_CCID_CHAIN_LEN (reader_ccid_context_active()->chain_len)
#define G_CCID_CHAIN_OFF (reader_ccid_context_active()->chain_off)
#define G_CCID_CHAIN_ACTIVE (reader_ccid_context_active()->chain_active)
#define G_CCID_CMD_CHAIN_BUF (reader_ccid_context_active()->cmd_chain_buf)
#define G_CCID_CMD_CHAIN_LEN (reader_ccid_context_active()->cmd_chain_len)
#define G_CCID_CMD_CHAIN_ACTIVE (reader_ccid_context_active()->cmd_chain_active)
