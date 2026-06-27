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

// Pure ISO/IEC 14443-3 Type A UID assembly from cascade-level SELECT responses.
// Host-testable: depends only on standard headers (no ST25R3916 register stack),
// so the cascade decoding logic can be exercised without RF hardware.

#include "nero_nfc_attrs.h"
#include "nero_nfc_null.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
  /* [ISO14443-3] section 6.5.4 — cascade tag prefixing an incomplete UID level. */
  ST25_ISO14443A_CASCADE_TAG = 0x88u,
  /* [ISO14443-3] section 6.5.3.4 — SAK bit 3 set means the UID is not complete. */
  ST25_ISO14443A_SAK_CASCADE_BIT = 0x04u,
  ST25_ISO14443A_UID_LEN_SINGLE = 4u,
  ST25_ISO14443A_UID_LEN_DOUBLE = 7u,
  ST25_ISO14443A_UID_LEN_TRIPLE = 10u,
  ST25_ISO14443A_SEL_RESP_LEN = 4u,
};

/*
 * Assemble and validate a 4/7/10-byte Type A UID from up to three anticollision
 * cascade levels. `levels` is the number of SELECT levels performed (1, 2 or 3),
 * decided by the caller from each level's SAK cascade bit. Each `clN_uid` holds
 * that level's 4-byte SELECT response (cascade tag + partial UID for non-final
 * levels, or four UID bytes for the final level). Returns the UID length, or 0
 * when the framing is invalid (missing cascade tag, a final level still
 * cascading, or insufficient output capacity). On success `*sak_out` is the
 * final level's SAK.
 */
NERO_NFC_NODISCARD static inline uint8_t st25_iso14443a_assemble_cascaded_uid(
  uint8_t levels, const uint8_t *cl1_uid, int sak1, const uint8_t *cl2_uid, int sak2,
  const uint8_t *cl3_uid, int sak3, uint8_t *uid_out, uint8_t uid_out_capacity, uint8_t *sak_out) {
  if ((uid_out == NERO_NFC_NULL) || (sak_out == NERO_NFC_NULL) || (cl1_uid == NERO_NFC_NULL)) {
    return 0u;
  }

  if (levels == 1u) {
    /* Single cascade level — complete 4-byte UID, no cascade tag. */
    if ((sak1 < 0) || ((sak1 & ST25_ISO14443A_SAK_CASCADE_BIT) != 0) ||
        (uid_out_capacity < ST25_ISO14443A_UID_LEN_SINGLE)) {
      return 0u;
    }
    uid_out[0] = cl1_uid[0];
    uid_out[1] = cl1_uid[1];
    uid_out[2] = cl1_uid[2];
    uid_out[3] = cl1_uid[3];
    *sak_out = (uint8_t)sak1;
    return ST25_ISO14443A_UID_LEN_SINGLE;
  }

  /* Levels >= 2: cascade level 1 must carry the cascade tag and report cascading. */
  if ((sak1 < 0) || ((sak1 & ST25_ISO14443A_SAK_CASCADE_BIT) == 0) ||
      (cl1_uid[0] != ST25_ISO14443A_CASCADE_TAG) || (cl2_uid == NERO_NFC_NULL)) {
    return 0u;
  }

  if (levels == 2u) {
    /* Double cascade — 7-byte UID. */
    if ((sak2 < 0) || ((sak2 & ST25_ISO14443A_SAK_CASCADE_BIT) != 0) ||
        (uid_out_capacity < ST25_ISO14443A_UID_LEN_DOUBLE)) {
      return 0u;
    }
    uid_out[0] = cl1_uid[1];
    uid_out[1] = cl1_uid[2];
    uid_out[2] = cl1_uid[3];
    uid_out[3] = cl2_uid[0];
    uid_out[4] = cl2_uid[1];
    uid_out[5] = cl2_uid[2];
    uid_out[6] = cl2_uid[3];
    *sak_out = (uint8_t)sak2;
    return ST25_ISO14443A_UID_LEN_DOUBLE;
  }

  if (levels == 3u) {
    /* Triple cascade — 10-byte UID. Cascade level 2 must also carry the tag. */
    if ((sak2 < 0) || ((sak2 & ST25_ISO14443A_SAK_CASCADE_BIT) == 0) ||
        (cl2_uid[0] != ST25_ISO14443A_CASCADE_TAG) || (cl3_uid == NERO_NFC_NULL) || (sak3 < 0) ||
        ((sak3 & ST25_ISO14443A_SAK_CASCADE_BIT) != 0) ||
        (uid_out_capacity < ST25_ISO14443A_UID_LEN_TRIPLE)) {
      return 0u;
    }
    uid_out[0] = cl1_uid[1];
    uid_out[1] = cl1_uid[2];
    uid_out[2] = cl1_uid[3];
    uid_out[3] = cl2_uid[1];
    uid_out[4] = cl2_uid[2];
    uid_out[5] = cl2_uid[3];
    uid_out[6] = cl3_uid[0];
    uid_out[7] = cl3_uid[1];
    uid_out[8] = cl3_uid[2];
    uid_out[9] = cl3_uid[3];
    *sak_out = (uint8_t)sak3;
    return ST25_ISO14443A_UID_LEN_TRIPLE;
  }

  return 0u;
}

#ifdef __cplusplus
}
#endif
