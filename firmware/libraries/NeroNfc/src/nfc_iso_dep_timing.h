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
#include "nfc_tag_geometry_limits.h"
#include <stdbool.h>
#include <stdint.h>

#define ISO_DEP_PRE_IBLOCK_DELAY_MIN_MS 18u
#define ISO_DEP_PRE_IBLOCK_DELAY_MAX_MS 200u
/* [ISO14443-4] section 7.2 — RATS/ATS exchange timeout (FWT headroom). */
#define SECURITY_KEY_RATS_TIMEOUT_MS NFC_ISO_DEP_RATS_TIMEOUT_MS
#define SECURITY_KEY_SHORT_FRAME_MS 1000u
#define ISO_DEP_US_TO_MS_ROUND_UP 999u
#define ISO_DEP_MS_PER_SECOND 1000u
#define ISO_DEP_LINK_TIMEOUT_MARGIN_MS 30u
#define ISO_DEP_LINK_TIMEOUT_MIN_MS 80u
#define ISO_DEP_WTX_TIMEOUT_MAX_MS 5000u
/*
 * [ISO14443-4] section 7.2 — the PCD must wait at least FWT for the PICC
 * response. FWT reaches ~4949 ms at FWI=14, so the link-response timeout
 * ceiling must cover the full FWT range (aligned with the WTX wait ceiling)
 * instead of truncating a compliant high-FWI token's allowed response window.
 */
#define ISO_DEP_LINK_RESPONSE_TIMEOUT_MAX_MS ISO_DEP_WTX_TIMEOUT_MAX_MS
#define ISO_DEP_APDU_CHUNK_HARD_CAP 48u
#define ISO_DEP_FRAME_EDC_LEN 2u
#define ISO_DEP_FWT_SCALE_NUM 4096u
#define ISO_DEP_FWT_SCALE_DEN 13560000ull
#define ISO_DEP_US_PER_SECOND 1000000ull

#define ISO_DEP_FWI_DEFAULT 4u
#define ISO_DEP_FWI_MAX 14u
#define ISO_DEP_WTXM_MIN 1u
#define ISO_DEP_WTXM_MAX 59u

static inline uint32_t reader_iso_dep_fwt_us_from_fwi(uint8_t fwi) {
  if (fwi > ISO_DEP_FWI_MAX) {
    fwi = ISO_DEP_FWI_DEFAULT;
  }
  return (uint32_t)((((uint64_t)ISO_DEP_FWT_SCALE_NUM) * (1ull << fwi) *
                         ISO_DEP_US_PER_SECOND +
                     ISO_DEP_FWT_SCALE_DEN - 1ull) /
                    ISO_DEP_FWT_SCALE_DEN);
}

static inline uint32_t reader_iso_dep_ms_to_seconds(uint32_t ms) {
  return ms / ISO_DEP_MS_PER_SECOND;
}

static inline uint16_t reader_iso_dep_pre_first_iblock_delay_ms(
    uint32_t fwt_us) {
  uint32_t ms =
      (fwt_us + ISO_DEP_US_TO_MS_ROUND_UP) / (ISO_DEP_US_TO_MS_ROUND_UP + 1u);
  if (ms < ISO_DEP_PRE_IBLOCK_DELAY_MIN_MS) {
    ms = ISO_DEP_PRE_IBLOCK_DELAY_MIN_MS;
  }
  if (ms > ISO_DEP_PRE_IBLOCK_DELAY_MAX_MS) {
    ms = ISO_DEP_PRE_IBLOCK_DELAY_MAX_MS;
  }
  return (uint16_t)ms;
}

static inline uint32_t reader_iso_dep_fwt_us_default(void) {
  return reader_iso_dep_fwt_us_from_fwi((uint8_t)ISO_DEP_FWI_DEFAULT);
}

static inline uint16_t reader_iso_dep_pre_first_iblock_delay_default_ms(void) {
  return reader_iso_dep_pre_first_iblock_delay_ms(
      reader_iso_dep_fwt_us_default());
}

static inline uint8_t reader_iso_dep_fwi_default(void) {
  return (uint8_t)ISO_DEP_FWI_DEFAULT;
}

static inline uint8_t reader_iso_dep_fwi_clamp(uint8_t fwi) {
  if (fwi > ISO_DEP_FWI_MAX) {
    return (uint8_t)ISO_DEP_FWI_DEFAULT;
  }
  return fwi;
}

NERO_NFC_NODISCARD static inline bool reader_iso_dep_wtxm_valid(uint8_t wtxm) {
  return (wtxm >= ISO_DEP_WTXM_MIN) && (wtxm <= ISO_DEP_WTXM_MAX);
}

static inline uint16_t reader_iso_dep_link_response_timeout_ms(
    uint32_t fwt_us) {
  uint32_t ms =
      (fwt_us + ISO_DEP_US_TO_MS_ROUND_UP) / (ISO_DEP_US_TO_MS_ROUND_UP + 1u);
  ms += ISO_DEP_LINK_TIMEOUT_MARGIN_MS;
  if (ms < ISO_DEP_LINK_TIMEOUT_MIN_MS) {
    ms = ISO_DEP_LINK_TIMEOUT_MIN_MS;
  }
  if (ms > ISO_DEP_LINK_RESPONSE_TIMEOUT_MAX_MS) {
    ms = ISO_DEP_LINK_RESPONSE_TIMEOUT_MAX_MS;
  }
  return (uint16_t)ms;
}

static inline uint16_t reader_iso_dep_apdu_chunk_budget(uint16_t pic_frame_max,
                                                        uint8_t tx_hdr_len) {
  uint16_t overhead = (uint16_t)((uint16_t)tx_hdr_len + ISO_DEP_FRAME_EDC_LEN);
  uint16_t cap;

  /* [ISO14443-4] FSC is the complete frame size, including the prologue and
   * two-byte EDC. Never substitute a larger FSC or enforce a minimum INF
   * length: both would create an over-sized on-air frame for small PICCs. */
  if (pic_frame_max <= overhead) {
    return 0u;
  }
  cap = (uint16_t)(pic_frame_max - overhead);
  if (cap > ISO_DEP_APDU_CHUNK_HARD_CAP) {
    cap = ISO_DEP_APDU_CHUNK_HARD_CAP;
  }
  return cap;
}
