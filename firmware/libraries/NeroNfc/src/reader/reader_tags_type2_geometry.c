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

#include "reader_tags_type2_geometry.h"

#include "nero_nfc_mem_util.h"
#include "nero_nfc_null.h"
#include "nfc_ndef_tlv.h"
#include "nfc_tag_geometry_limits.h"
#include "nfc_tag_info.h"
#include "reader_tags_internal.h"

uint16_t reader_tags_type2_needed_pages(const uint8_t* data, uint16_t len,
                                        uint16_t max_page) {
  uint16_t pos = READER_TYPE2_CC_PREFIX_BYTES;

  if ((data == NERO_NFC_NULL) || (len <= READER_TYPE2_CC_PREFIX_BYTES) ||
      (nero_nfc_u8_at(data, (size_t)len, 0u) != NFC_FORUM_CC_MAGIC)) {
    return 0u;
  }
  while (pos < len) {
    const uint16_t tlv_start = pos;
    const uint8_t type = data[pos++];
    uint16_t value_len;
    uint32_t need_bytes;

    if (type == NFC_NDEF_TLV_NULL) {
      continue;
    }
    if (type == NFC_NDEF_TLV_TERMINATOR) {
      return (uint16_t)((tlv_start + NFC_TAG_T2T_PAGE_SIZE_BYTES) /
                        NFC_TAG_T2T_PAGE_SIZE_BYTES);
    }
    if (pos >= len) {
      return 0u;
    }
    if (data[pos] == NFC_NDEF_TLV_EXTENDED_LEN) {
      if (!nero_nfc_span_ok(pos, NFC_NDEF_TLV_EXTENDED_LEN_FIELD_BYTES, len)) {
        return 0u;
      }
      value_len =
          (uint16_t)(((uint16_t)data[pos + NFC_NDEF_TLV_EXTENDED_LEN_MSB_OFFSET]
                      << NFC_NDEF_TLV_LEN_SHIFT) |
                     data[pos + NFC_NDEF_TLV_EXTENDED_LEN_LSB_OFFSET]);
      pos = (uint16_t)(pos + NFC_NDEF_TLV_EXTENDED_LEN_FIELD_BYTES);
    } else {
      value_len = data[pos++];
    }
    if (type != NFC_NDEF_TLV_MESSAGE) {
      pos = (uint16_t)(pos + value_len);
      continue;
    }
    need_bytes = (uint32_t)pos + (uint32_t)value_len;
    need_bytes = (need_bytes < (uint32_t)READER_TYPE2_TAG_DUMP_MAX)
                     ? need_bytes
                     : (uint32_t)READER_TYPE2_TAG_DUMP_MAX;
    {
      const uint16_t pages =
          (uint16_t)((need_bytes + NFC_TAG_T2T_PAGE_SIZE_BYTES - 1u) /
                     NFC_TAG_T2T_PAGE_SIZE_BYTES);
      const uint16_t max_pages =
          (uint16_t)(max_page - NFC_TAG_T2T_CC_PAGE_INDEX + 1u);
      return (pages > max_pages) ? max_pages : pages;
    }
  }
  return 0u;
}
