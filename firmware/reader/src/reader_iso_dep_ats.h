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
#include "nero_nfc_mem_util.h"
#include "nfc_frontend.h"
#include "reader_iso_dep_timing.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct reader_iso_dep_ats_profile {
  uint8_t fsci;
  uint16_t pic_frame_max;
  uint8_t fwi;
  uint32_t fwt_us;
  bool has_ta;
  uint8_t ta;
  bool has_tb;
  uint8_t tb;
  bool has_tc;
  uint8_t tc;
  bool supports_cid;
  bool supports_nad;
  uint8_t historical_offset;
  uint8_t historical_len;
} reader_iso_dep_ats_profile_t;

enum {
  READER_ISO_DEP_FSCI_TABLE_LEN = 9u,
  READER_ISO_DEP_ATS_MIN_LEN = 2u,
  READER_ISO_DEP_ATS_T0_OFFSET = 1u,
  READER_ISO_DEP_ATS_HEADER_LEN = 2u,
  READER_ISO_DEP_ATS_POS_AFTER_T0 = 2u,
  READER_ISO_DEP_ATS_T0_FSCI_MASK = 0x0Fu,
  READER_ISO_DEP_ATS_T0_TA_MASK = 0x10u,
  READER_ISO_DEP_ATS_T0_TB_MASK = 0x20u,
  READER_ISO_DEP_ATS_T0_TC_MASK = 0x40u,
  READER_ISO_DEP_ATS_TB_FWI_SHIFT = 4u,
  READER_ISO_DEP_ATS_TB_FWI_MASK = 0x0Fu,
  READER_ISO_DEP_ATS_TC_CID_BIT = 0x02u,
  READER_ISO_DEP_ATS_TC_NAD_BIT = 0x01u,
};

static inline void reader_iso_dep_ats_profile_reset(reader_iso_dep_ats_profile_t *profile) {
  if (profile == NERO_NFC_NULL) {
    return;
  }
  profile->fsci = 0u;
  profile->pic_frame_max = (uint16_t)NFC_ISO14443_FSC_MAX;
  profile->fwi = ISO_DEP_FWI_DEFAULT;
  profile->fwt_us = reader_iso_dep_fwt_us_from_fwi(profile->fwi);
  profile->has_ta = false;
  profile->ta = 0u;
  profile->has_tb = false;
  profile->tb = 0u;
  profile->has_tc = false;
  profile->tc = 0u;
  profile->supports_cid = false;
  profile->supports_nad = false;
  profile->historical_offset = 0u;
  profile->historical_len = 0u;
}

static inline uint16_t reader_iso_dep_fsc_from_fsci(uint8_t fsci) {
  /* [ISO14443-4] Table 6 — FSCI 0..8 map to FSC 16..256; FSCI 9..15 are RFU and
   * are treated as the maximum frame size. */
  static const uint16_t fsc_table[] = {16u, 24u, 32u, 40u, 48u, 64u, 96u, 128u, 256u};

  return (fsci < READER_ISO_DEP_FSCI_TABLE_LEN) ? fsc_table[fsci] : (uint16_t)NFC_ISO14443_FSC_MAX;
}

NERO_NFC_NODISCARD static inline bool
reader_iso_dep_parse_ats_profile(const uint8_t *ats, uint8_t ats_len,
                                 reader_iso_dep_ats_profile_t *profile) {
  uint8_t t0;
  uint8_t pos;

  if (profile == NERO_NFC_NULL) {
    return false;
  }
  reader_iso_dep_ats_profile_reset(profile);
  if ((ats == NERO_NFC_NULL) || (ats_len < READER_ISO_DEP_ATS_MIN_LEN)) {
    return false;
  }

  t0 = ats[READER_ISO_DEP_ATS_T0_OFFSET];
  /* [ISO14443-4] section 5.2.5 — ATS T0 low nibble (b4..b1) carries FSCI; the high
   * bits b7/b6/b5 are the TC1/TB1/TA1 presence flags handled below. */
  profile->fsci = (uint8_t)(t0 & READER_ISO_DEP_ATS_T0_FSCI_MASK);
  profile->pic_frame_max = reader_iso_dep_fsc_from_fsci(profile->fsci);

  pos = READER_ISO_DEP_ATS_POS_AFTER_T0;
  if (((t0 & READER_ISO_DEP_ATS_T0_TA_MASK) != 0u) && (pos < ats_len)) {
    profile->has_ta = true;
    profile->ta = ats[pos++];
  }
  if (((t0 & READER_ISO_DEP_ATS_T0_TB_MASK) != 0u) && (pos < ats_len)) {
    profile->has_tb = true;
    profile->tb = ats[pos++];
    profile->fwi =
      (uint8_t)((profile->tb >> READER_ISO_DEP_ATS_TB_FWI_SHIFT) & READER_ISO_DEP_ATS_TB_FWI_MASK);
    if (profile->fwi > ISO_DEP_FWI_MAX) {
      reader_iso_dep_ats_profile_reset(profile);
      return false;
    }
    profile->fwt_us = reader_iso_dep_fwt_us_from_fwi(profile->fwi);
  }
  if (((t0 & READER_ISO_DEP_ATS_T0_TC_MASK) != 0u) && (pos < ats_len)) {
    profile->has_tc = true;
    profile->tc = ats[pos++];
    profile->supports_cid = ((profile->tc & READER_ISO_DEP_ATS_TC_CID_BIT) != 0u);
    profile->supports_nad = ((profile->tc & READER_ISO_DEP_ATS_TC_NAD_BIT) != 0u);
  }
  if (pos < ats_len) {
    profile->historical_offset = pos;
    profile->historical_len = (uint8_t)(ats_len - pos);
  }
  return true;
}
