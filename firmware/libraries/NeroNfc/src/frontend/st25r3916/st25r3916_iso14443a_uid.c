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

#include "st25r3916_iso14443a_uid.h"

#include "nero_nfc_mem_util.h"
#include "nero_nfc_null.h"

enum {
  K_S_T25_ISO14443_A_ID_X0 = 0u,
  K_S_T25_ISO14443_A_ID_X1 = 1u,
  K_S_T25_ISO14443_A_CASCADE_PARTIAL_UID_LEN = 3u,
  K_S_T25_ISO14443_A_UID_OFFSET_AFTER_TWO_CASCADE_PARTS = 6u,
};

uint8_t st25_iso14443a_assemble_cascaded_uid(
    uint8_t levels, const uint8_t* cl1_uid, int sak1, const uint8_t* cl2_uid,
    int sak2, const uint8_t* cl3_uid, int sak3, uint8_t* uid_out,
    uint8_t uid_out_capacity, uint8_t* sak_out) {
  if ((uid_out == NERO_NFC_NULL) || (sak_out == NERO_NFC_NULL) ||
      (cl1_uid == NERO_NFC_NULL)) {
    return 0u;
  }
  if (levels == 1u) {
    if ((sak1 < 0) || ((sak1 & K_S_T25_ISO14443_A_SAK_CASCADE_BIT) != 0) ||
        (uid_out_capacity < K_S_T25_ISO14443_A_UID_LEN_SINGLE)) {
      return 0u;
    }
    if (!nero_nfc_copy_from(uid_out, uid_out_capacity, 0u, cl1_uid,
                            K_S_T25_ISO14443_A_SEL_RESP_LEN, 0u,
                            K_S_T25_ISO14443_A_UID_LEN_SINGLE)) {
      return 0u;
    }
    *sak_out = (uint8_t)sak1;
    return K_S_T25_ISO14443_A_UID_LEN_SINGLE;
  }
  if ((sak1 < 0) || ((sak1 & K_S_T25_ISO14443_A_SAK_CASCADE_BIT) == 0) ||
      (nero_nfc_u8_at(cl1_uid, K_S_T25_ISO14443_A_SEL_RESP_LEN,
                      K_S_T25_ISO14443_A_ID_X0) !=
       K_S_T25_ISO14443_A_CASCADE_TAG) ||
      (cl2_uid == NERO_NFC_NULL)) {
    return 0u;
  }
  if (levels == K_S_T25_ISO14443_A_LEVELS_DOUBLE) {
    if ((sak2 < 0) || ((sak2 & K_S_T25_ISO14443_A_SAK_CASCADE_BIT) != 0) ||
        (uid_out_capacity < K_S_T25_ISO14443_A_UID_LEN_DOUBLE)) {
      return 0u;
    }
    if (!nero_nfc_copy_from(uid_out, uid_out_capacity, 0u, cl1_uid,
                            K_S_T25_ISO14443_A_SEL_RESP_LEN,
                            K_S_T25_ISO14443_A_ID_X1,
                            K_S_T25_ISO14443_A_CASCADE_PARTIAL_UID_LEN) ||
        !nero_nfc_copy_from(uid_out, uid_out_capacity,
                            K_S_T25_ISO14443_A_CASCADE_PARTIAL_UID_LEN, cl2_uid,
                            K_S_T25_ISO14443_A_SEL_RESP_LEN, 0u,
                            K_S_T25_ISO14443_A_SEL_RESP_LEN)) {
      return 0u;
    }
    *sak_out = (uint8_t)sak2;
    return K_S_T25_ISO14443_A_UID_LEN_DOUBLE;
  }
  if (levels == K_S_T25_ISO14443_A_LEVELS_TRIPLE) {
    if ((sak2 < 0) || ((sak2 & K_S_T25_ISO14443_A_SAK_CASCADE_BIT) == 0) ||
        (nero_nfc_u8_at(cl2_uid, K_S_T25_ISO14443_A_SEL_RESP_LEN,
                        K_S_T25_ISO14443_A_ID_X0) !=
         K_S_T25_ISO14443_A_CASCADE_TAG) ||
        (cl3_uid == NERO_NFC_NULL) || (sak3 < 0) ||
        ((sak3 & K_S_T25_ISO14443_A_SAK_CASCADE_BIT) != 0) ||
        (uid_out_capacity < K_S_T25_ISO14443_A_UID_LEN_TRIPLE)) {
      return 0u;
    }
    if (!nero_nfc_copy_from(uid_out, uid_out_capacity, 0u, cl1_uid,
                            K_S_T25_ISO14443_A_SEL_RESP_LEN,
                            K_S_T25_ISO14443_A_ID_X1,
                            K_S_T25_ISO14443_A_CASCADE_PARTIAL_UID_LEN) ||
        !nero_nfc_copy_from(uid_out, uid_out_capacity,
                            K_S_T25_ISO14443_A_CASCADE_PARTIAL_UID_LEN, cl2_uid,
                            K_S_T25_ISO14443_A_SEL_RESP_LEN,
                            K_S_T25_ISO14443_A_ID_X1,
                            K_S_T25_ISO14443_A_CASCADE_PARTIAL_UID_LEN) ||
        !nero_nfc_copy_from(
            uid_out, uid_out_capacity,
            K_S_T25_ISO14443_A_UID_OFFSET_AFTER_TWO_CASCADE_PARTS, cl3_uid,
            K_S_T25_ISO14443_A_SEL_RESP_LEN, 0u,
            K_S_T25_ISO14443_A_SEL_RESP_LEN)) {
      return 0u;
    }
    *sak_out = (uint8_t)sak3;
    return K_S_T25_ISO14443_A_UID_LEN_TRIPLE;
  }
  return 0u;
}
