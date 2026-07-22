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
#include "nero_nfc_frontend.h"
#include "nfc_tag_info.h"
#include "writer_payload.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct writer_context {
  nfc_frontend_t* frontend;
  writer_payload_config_t payload;
  char cli_line[WRITER_CLI_LINE_CAP];
  uint8_t raw_ndef[WRITER_NDEF_MAX_BYTES];
  uint16_t cli_line_len;
  bool cli_line_overflow;
  uint8_t uid14[NFC_TAG_TYPEA_UID_MAX];
  uint8_t uid14_len;
  uint8_t atqa[NFC_TAG_ATQA_LEN];
  bool atqa_valid;
  uint8_t sak;
  uint8_t ats[NFC_ISO14443_ATS_MAX];
  uint8_t ats_len;
  uint8_t uid15[NFC_FRONTEND_ISO15693_UID_LEN];
  uint8_t tag_version[NFC_TAG_NTAG_VER_REPLY_LEN];
  uint8_t tag_version_len;
  bool t2_cc_from_tag_valid;
  uint8_t t2_cc_page3[NFC_TAG_T2T_PAGE_SIZE_BYTES];
  uint8_t baseline_amp;
  bool tag_written;
  uint32_t last_write_ms;
  uint8_t removed_stable_samples;
  uint32_t last_poll_ms;
  uint32_t last_field_print_ms;
  uint32_t poll_interval_ms;
  bool was_near;
  uint8_t type4_block;
  uint8_t type4_cid;
  bool type4_pcb_has_cid;
  bool type4_need_first_iblock_delay;
} writer_context_t;

#ifdef __cplusplus
extern "C" {
#endif

NERO_NFC_NODISCARD writer_context_t* writer_context_active(void);
void writer_context_reset(writer_context_t* ctx);

#ifdef __cplusplus
}
#endif

/* Transitional aliases: mutable writer state lives in the active app. */
#define WRITER_FRONTEND (writer_context_active()->frontend)
#define WRITER_APP_PAYLOAD (writer_context_active()->payload)
#define WRITER_APP_UID14 (writer_context_active()->uid14)
#define WRITER_APP_UID14_LEN (writer_context_active()->uid14_len)
#define WRITER_APP_ATQA (writer_context_active()->atqa)
#define WRITER_APP_ATQA_VALID (writer_context_active()->atqa_valid)
#define WRITER_APP_SAK (writer_context_active()->sak)
#define WRITER_APP_ATS (writer_context_active()->ats)
#define WRITER_APP_ATS_LEN (writer_context_active()->ats_len)
#define WRITER_APP_UID15 (writer_context_active()->uid15)
#define WRITER_APP_TAG_VERSION (writer_context_active()->tag_version)
#define WRITER_APP_TAG_VERSION_LEN (writer_context_active()->tag_version_len)
#define WRITER_APP_T2_CC_FROM_TAG_VALID \
  (writer_context_active()->t2_cc_from_tag_valid)
#define WRITER_APP_T2_CC_PAGE3 (writer_context_active()->t2_cc_page3)
#define WRITER_APP_BASELINE_AMP (writer_context_active()->baseline_amp)
#define WRITER_APP_TAG_WRITTEN (writer_context_active()->tag_written)
#define WRITER_APP_LAST_WRITE_MS (writer_context_active()->last_write_ms)
#define WRITER_APP_REMOVED_STABLE_SAMPLES \
  (writer_context_active()->removed_stable_samples)
