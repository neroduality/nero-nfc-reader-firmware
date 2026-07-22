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

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* [ISO14443-3] sections 6.5.3.4 and 6.5.4 — Type A UID cascade
 * tag, SAK continuation bit, cascade-level UID CLn width (4 bytes),
 * and assembled UID lengths. SEL_RESP_LEN names the per-level UID CLn
 * buffer, not the SELECT SAK response. */
enum {
  K_S_T25_ISO14443_A_CASCADE_TAG = 0x88u,
  K_S_T25_ISO14443_A_SAK_CASCADE_BIT = 0x04u,
  K_S_T25_ISO14443_A_UID_LEN_SINGLE = 4u,
  K_S_T25_ISO14443_A_UID_LEN_DOUBLE = 7u,
  K_S_T25_ISO14443_A_UID_LEN_TRIPLE = 10u,
  K_S_T25_ISO14443_A_SEL_RESP_LEN = 4u,
  K_S_T25_ISO14443_A_LEVELS_DOUBLE = 2u,
  K_S_T25_ISO14443_A_LEVELS_TRIPLE = 3u,
  K_S_T25_ISO14443_A_ID_X2 = 2u,
  K_S_T25_ISO14443_A_ID_X3 = 3u,
  K_S_T25_ISO14443_A_ID_X4 = 4u,
  K_S_T25_ISO14443_A_ID_X5 = 5u,
  K_S_T25_ISO14443_A_ID_X6 = 6u,
  K_S_T25_ISO14443_A_ID_X7 = 7u,
  K_S_T25_ISO14443_A_ID_X8 = 8u,
  K_S_T25_ISO14443_A_ID_X9 = 9u,
};

NERO_NFC_NODISCARD uint8_t st25_iso14443a_assemble_cascaded_uid(
    uint8_t levels, const uint8_t* cl1_uid, int sak1, const uint8_t* cl2_uid,
    int sak2, const uint8_t* cl3_uid, int sak3, uint8_t* uid_out,
    uint8_t uid_out_capacity, uint8_t* sak_out);

#ifdef __cplusplus
}
#endif
