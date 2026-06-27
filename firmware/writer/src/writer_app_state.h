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

#include "nfc_frontend.h"
#include "nfc_tag_info.h"
#include "writer_payload.h"

#include <stdbool.h>
#include <stdint.h>

extern writer_payload_config_t writer_app_payload;
extern uint8_t writer_app_uid14[NFC_TAG_TYPEA_UID_MAX];
extern uint8_t writer_app_uid14_len;
extern uint8_t writer_app_atqa[NFC_TAG_ATQA_LEN];
extern bool writer_app_atqa_valid;
extern uint8_t writer_app_sak;
extern uint8_t writer_app_ats[NFC_ISO14443_ATS_MAX];
extern uint8_t writer_app_ats_len;
extern uint8_t writer_app_uid15[NFC_FRONTEND_ISO15693_UID_LEN];
extern uint8_t writer_app_tag_version[NFC_TAG_NTAG_VER_REPLY_LEN];
extern uint8_t writer_app_tag_version_len;
extern bool writer_app_t2_cc_from_tag_valid;
extern uint8_t writer_app_t2_cc_page3[NFC_TAG_T2T_PAGE_SIZE_BYTES];
