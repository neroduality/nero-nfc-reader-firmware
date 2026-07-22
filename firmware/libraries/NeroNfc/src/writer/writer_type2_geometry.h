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

#include "writer_tag_write.h"
#include "nfc_tag_info.h"
#include "nfc_tag_geometry_limits.h"
#include "nero_nfc_attrs.h"
#include "nero_nfc_mem_util.h"

/* Host-testable NTAG21x GET_VERSION fingerprint and CC geometry helpers. */

static inline uint8_t writer_type2_ntag21x_size_id(const uint8_t* rx, int len) {
  nfc_tag_type2_info_t info;

  if ((rx == NERO_NFC_NULL) || (len < (int)NFC_TAG_NTAG_VER_REPLY_LEN) ||
      (len > (int)UINT8_MAX)) {
    return 0u;
  }
  nero_nfc_zero_bytes(&info, sizeof(info));
  nfc_tag_type2_apply_version(&info, rx, (uint8_t)len);
  return (info.family == NFC_TAG_TYPE2_FAMILY_NTAG21X) ? info.size_id : 0u;
}

NERO_NFC_NODISCARD static inline bool writer_type2_is_ntag21x_version_reply(
    const uint8_t* rx, int len) {
  return writer_type2_ntag21x_size_id(rx, len) != 0u;
}

static inline uint16_t writer_type2_cap_last_page_from_mlen(uint8_t mlen) {
  if (mlen <= NFC_TAG_NTAG213_CC_MLEN) {
    return NFC_TAG_NTAG213_LAST_PAGE;
  }
  if (mlen <= NFC_TAG_NTAG215_CC_MLEN) {
    return NFC_TAG_NTAG215_LAST_PAGE;
  }
  return NFC_TAG_NTAG216_LAST_PAGE;
}

static inline uint16_t writer_type2_last_page_from_cc_mlen(uint8_t mlen) {
  uint16_t data_bytes =
      (uint16_t)((uint16_t)mlen * NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES);
  uint16_t pages;

  if (data_bytes == 0u) {
    return 0u;
  }
  pages = (uint16_t)((data_bytes + NFC_TAG_T2T_PAGE_SIZE_BYTES - 1u) /
                     NFC_TAG_T2T_PAGE_SIZE_BYTES);
  return (uint16_t)(NFC_TAG_T2T_CC_PAGE_INDEX + pages);
}

static inline uint16_t writer_type2_physical_cap_last_page(
    bool cc_valid, const uint8_t* cc_page3, uint8_t tag_version_len,
    const uint8_t* tag_version) {
  if (cc_valid && (cc_page3 != NERO_NFC_NULL) &&
      (cc_page3[0] == NFC_FORUM_CC_MAGIC)) {
    if (!nero_nfc_span_ok((size_t)(0), 1u, NFC_TAG_T2T_PAGE_SIZE_BYTES)) {
      return 0u;
    }
    return writer_type2_cap_last_page_from_mlen(
        cc_page3[NFC_TAG_T2T_CC_MLEN_INDEX]);
  }
  if ((tag_version_len < NFC_TAG_NTAG_VER_REPLY_LEN) ||
      (tag_version == NERO_NFC_NULL) ||
      !writer_type2_is_ntag21x_version_reply(tag_version,
                                             (int)tag_version_len)) {
    return 0u;
  }
  switch (writer_type2_ntag21x_size_id(tag_version, (int)tag_version_len)) {
    case NFC_TAG_NTAG213_SIZE_ID:
      return NFC_TAG_NTAG213_LAST_PAGE;
    case NFC_TAG_NTAG215_SIZE_ID:
      return NFC_TAG_NTAG215_LAST_PAGE;
    case NFC_TAG_NTAG216_SIZE_ID:
      return NFC_TAG_NTAG216_LAST_PAGE;
    default:
      return 0u;
  }
}

static inline uint8_t writer_type2_cc_size(writer_type2_family_t fam,
                                           bool cc_valid,
                                           const uint8_t* cc_page3,
                                           uint8_t tag_version_len,
                                           const uint8_t* tag_version) {
  if (fam == WRITER_TYPE2_FAMILY_NTAG21X) {
    if (cc_valid && (cc_page3 != NERO_NFC_NULL) &&
        (cc_page3[0] == NFC_FORUM_CC_MAGIC)) {
      return cc_page3[NFC_TAG_T2T_CC_MLEN_INDEX];
    }
    if ((tag_version_len >= NFC_TAG_NTAG_VER_REPLY_LEN) &&
        (tag_version != NERO_NFC_NULL) &&
        writer_type2_is_ntag21x_version_reply(tag_version,
                                              (int)tag_version_len)) {
      switch (writer_type2_ntag21x_size_id(tag_version, (int)tag_version_len)) {
        case NFC_TAG_NTAG216_SIZE_ID:
          return NFC_TAG_NTAG216_CC_MLEN;
        case NFC_TAG_NTAG215_SIZE_ID:
          return NFC_TAG_NTAG215_CC_MLEN;
        case NFC_TAG_NTAG213_SIZE_ID:
          return NFC_TAG_NTAG213_CC_MLEN;
        default:
          break;
      }
    }
    return NFC_TAG_NTAG213_CC_MLEN;
  }
  if (fam == WRITER_TYPE2_FAMILY_ST25TN) {
    if (cc_valid && (cc_page3 != NERO_NFC_NULL) &&
        (cc_page3[0] == NFC_FORUM_CC_MAGIC)) {
      return cc_page3[NFC_TAG_T2T_CC_MLEN_INDEX];
    }
    return NFC_TAG_ST25TN_CC_MLEN_DEFAULT;
  }
  return NFC_TAG_NTAG213_CC_MLEN;
}

static inline uint16_t writer_type2_max_page(writer_type2_family_t fam,
                                             bool cc_valid,
                                             const uint8_t* cc_page3,
                                             uint8_t tag_version_len,
                                             const uint8_t* tag_version) {
  if (fam == WRITER_TYPE2_FAMILY_NTAG21X) {
    if (cc_valid && (cc_page3 != NERO_NFC_NULL) &&
        (cc_page3[0] == NFC_FORUM_CC_MAGIC)) {
      uint16_t n_def_bytes =
          (uint16_t)((uint16_t)cc_page3[NFC_TAG_T2T_CC_MLEN_INDEX] *
                     NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES);
      uint16_t last_page =
          (uint16_t)((NFC_TAG_T2T_CC_PAGE_INDEX + 1u) +
                     ((n_def_bytes + NFC_TAG_T2T_PAGE_SIZE_BYTES - 1u) /
                      NFC_TAG_T2T_PAGE_SIZE_BYTES) -
                     1u);
      uint16_t cap = writer_type2_physical_cap_last_page(
          cc_valid, cc_page3, tag_version_len, tag_version);
      if ((cap != 0u) && (last_page > cap)) {
        last_page = cap;
      }
      return last_page;
    }
    if ((tag_version_len >= NFC_TAG_NTAG_VER_REPLY_LEN) &&
        (tag_version != NERO_NFC_NULL) &&
        writer_type2_is_ntag21x_version_reply(tag_version,
                                              (int)tag_version_len)) {
      switch (writer_type2_ntag21x_size_id(tag_version, (int)tag_version_len)) {
        case NFC_TAG_NTAG216_SIZE_ID:
          return NFC_TAG_NTAG216_LAST_PAGE;
        case NFC_TAG_NTAG215_SIZE_ID:
          return NFC_TAG_NTAG215_LAST_PAGE;
        case NFC_TAG_NTAG213_SIZE_ID:
          return NFC_TAG_NTAG213_LAST_PAGE;
        default:
          break;
      }
    }
    return NFC_TAG_NTAG213_LAST_PAGE;
  }
  if (fam == WRITER_TYPE2_FAMILY_ST25TN) {
    if (cc_valid && (cc_page3 != NERO_NFC_NULL) &&
        (cc_page3[0] == NFC_FORUM_CC_MAGIC)) {
      uint16_t last_page = writer_type2_last_page_from_cc_mlen(
          cc_page3[NFC_TAG_T2T_CC_MLEN_INDEX]);

      if (last_page == 0u) {
        return NFC_TAG_ST25TN_FALLBACK_LAST_PAGE;
      }
      return (last_page > NFC_TAG_ST25TN_MAX_USER_PAGE)
                 ? NFC_TAG_ST25TN_MAX_USER_PAGE
                 : last_page;
    }
    return NFC_TAG_ST25TN_FALLBACK_LAST_PAGE;
  }
  return NFC_TAG_T2T_FALLBACK_LAST_PAGE;
}
