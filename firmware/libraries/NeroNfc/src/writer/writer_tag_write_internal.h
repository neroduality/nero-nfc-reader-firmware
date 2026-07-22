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

#include "nero_nfc_log.h"
#include "writer_app_io.h"
#include "writer_tag_write.h"

#include "nero_nfc_attrs.h"
#include "nero_nfc_mem_util.h"
#include "nero_nfc_null.h"
#include "nfc_storage_ndef.h"
#include "nfc_tag_info.h"

#include "nero_nfc_format.h"
#include "writer_context.h"
#include <stdbool.h>
#include <stdint.h>

#define WRITER_TAG_T4_BLK (writer_context_active()->type4_block)
#define WRITER_TAG_T4_PCB_HAS_CID (writer_context_active()->type4_pcb_has_cid)
#define WRITER_TAG_T4_CID (writer_context_active()->type4_cid)
#define WRITER_TAG_T4_NEED_FIRST_IBLOCK_DELAY \
  (writer_context_active()->type4_need_first_iblock_delay)

NERO_NFC_NODISCARD bool writer_collect_type2_info(
    writer_type2_family_t fam, nfc_tag_type2_info_t* type2_out);
NERO_NFC_NODISCARD bool writer_tag_write_type2_impl(writer_type2_family_t fam);
NERO_NFC_NODISCARD bool writer_tag_write_type4_impl(void);
NERO_NFC_NODISCARD bool writer_tag_write_type5_impl(void);
NERO_NFC_NODISCARD bool writer_tag_write_type5_inventory_step(void);
writer_type2_family_t writer_tag_write_identify_type2_family(void);

typedef bool (*writer_tag_storage_write_unit_fn_t)(uint16_t unit,
                                                   const uint8_t* data,
                                                   uint8_t data_len);

NERO_NFC_NODISCARD static inline bool writer_tag_write_storage_tlv_units(
    const uint8_t* tlv, uint16_t tlv_len, uint16_t first_unit,
    uint8_t unit_size, const char* unit_label,
    writer_tag_storage_write_unit_fn_t write_unit) {
  uint16_t units_needed = 0u;

  if ((tlv == NERO_NFC_NULL) || (unit_size == 0u) ||
      (unit_size > NFC_STORAGE_TYPE5_BLOCK_SIZE) ||
      (write_unit == NERO_NFC_NULL) ||
      !nfc_storage_ceil_units_u16(tlv_len, unit_size, &units_needed) ||
      (units_needed == 0u)) {
    nero_nfc_log_line("  ERROR: invalid storage write geometry");
    return false;
  }
  for (uint16_t unit_index = 0u; unit_index < units_needed; unit_index++) {
    uint8_t unit_data[NFC_STORAGE_TYPE5_BLOCK_SIZE] = {0u, 0u, 0u, 0u};
    const uint16_t off = (uint16_t)(unit_index * unit_size);
    const uint16_t left = (uint16_t)(tlv_len - off);
    const uint16_t chunk = (left > unit_size) ? unit_size : left;
    const uint16_t unit = (uint16_t)(first_unit + unit_index);

    if ((chunk != 0u) && !nero_nfc_copy_bytes(unit_data, sizeof(unit_data), 0u,
                                              tlv + off, chunk)) {
      return false;
    }
    if (!write_unit(unit, unit_data, unit_size)) {
      nero_nfc_log_write("  Write");
      if (unit_label != NERO_NFC_NULL) {
        nero_nfc_log_putc(' ');
        nero_nfc_log_write(unit_label);
      }
      nero_nfc_log_putc(' ');
      {
        char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
        (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                                (unsigned)(uint32_t)(unit));
        nero_nfc_log_write(ndc);
      }
      nero_nfc_log_line(" FAILED");
      return false;
    }
  }
  return true;
}
