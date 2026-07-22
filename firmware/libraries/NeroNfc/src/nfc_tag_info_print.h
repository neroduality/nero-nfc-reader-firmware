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

#include "nfc_tag_info.h"

#include "nero_nfc_attrs.h"
#include "nero_nfc_mem_util.h"
#include "nero_nfc_null.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline void nfc_tag_print_hex_bytes(nero_nfc_emit_fn_t emit,
                                           const uint8_t* data, uint8_t len,
                                           char separator) {
  if ((emit == NERO_NFC_NULL) || (data == NERO_NFC_NULL)) {
    return;
  }
  for (uint8_t i = 0u; i < len; ++i) {
    nero_nfc_emit_hex_u8(emit, data[i]);
    if (i + 1u < len) {
      emit(separator);
    }
  }
}

static inline void nfc_tag_print_line_prefix(nero_nfc_emit_fn_t emit) {
  nero_nfc_emit_write(emit, "  ");
}

static inline void nfc_tag_print_typea_debug(nero_nfc_emit_fn_t emit,
                                             const nfc_tag_typea_info_t* info) {
  const char* vendor_name;

  if ((emit == NERO_NFC_NULL) || (info == NERO_NFC_NULL)) {
    return;
  }
  nfc_tag_print_line_prefix(emit);
  nero_nfc_emit_write(emit, "Serial number / UID (");
  nero_nfc_emit_dec_u32(emit, info->uid_len);
  nero_nfc_emit_write(emit, "B): ");
  nfc_tag_print_hex_bytes(emit, info->uid, info->uid_len, ':');
  nero_nfc_emit_write(emit, "\r\n");

  if (info->atqa_valid) {
    nfc_tag_print_line_prefix(emit);
    nero_nfc_emit_write(emit, "ATQA: ");
    nfc_tag_print_hex_bytes(emit, info->atqa, NFC_TAG_ATQA_LEN, ' ');
    nero_nfc_emit_write(emit, "\r\n");
  }

  nfc_tag_print_line_prefix(emit);
  nero_nfc_emit_write(emit, "SAK: 0x");
  nero_nfc_emit_hex_u8(emit, info->sak);
  nero_nfc_emit_write(emit, "\r\n");

  vendor_name = nfc_tag_iso14443a_manufacturer_name(info->uid, info->uid_len);
  if (vendor_name != NERO_NFC_NULL) {
    nfc_tag_print_line_prefix(emit);
    nero_nfc_emit_write(emit, "Manufacturer: ");
    nero_nfc_emit_write(emit, vendor_name);
    nero_nfc_emit_write(emit, "\r\n");
  }

  if (info->ats_len != 0u) {
    nfc_tag_print_line_prefix(emit);
    nero_nfc_emit_write(emit, "ATS (");
    nero_nfc_emit_dec_u32(emit, info->ats_len);
    nero_nfc_emit_write(emit, "B): ");
    nfc_tag_print_hex_bytes(emit, info->ats, info->ats_len, ' ');
    nero_nfc_emit_write(emit, "\r\n");
  }
}

static inline void nfc_tag_print_type2_debug(
    nero_nfc_emit_fn_t emit, const nfc_tag_typea_info_t* typea,
    const nfc_tag_type2_info_t* type2) {
  if ((emit == NERO_NFC_NULL) || (typea == NERO_NFC_NULL) ||
      (type2 == NERO_NFC_NULL)) {
    return;
  }
  nfc_tag_print_line_prefix(emit);
  nero_nfc_emit_write(emit, "Tag type: ISO 14443-3A");
  if (type2->product_name != NERO_NFC_NULL) {
    nero_nfc_emit_write(emit, ", ");
    if (type2->vendor_name != NERO_NFC_NULL) {
      nero_nfc_emit_write(emit, type2->vendor_name);
      emit(' ');
    }
    nero_nfc_emit_write(emit, type2->product_name);
  } else if (type2->family != NFC_TAG_TYPE2_FAMILY_UNKNOWN) {
    nero_nfc_emit_write(emit, ", ");
    if (type2->vendor_name != NERO_NFC_NULL) {
      nero_nfc_emit_write(emit, type2->vendor_name);
      emit(' ');
    }
    nero_nfc_emit_write(emit, nfc_tag_type2_family_name(type2->family));
  }
  nero_nfc_emit_write(emit, "\r\n");
  nfc_tag_print_line_prefix(emit);
  nero_nfc_emit_write(emit, "Tech list: NfcA, MifareUltralight, Ndef\r\n");
  nfc_tag_print_typea_debug(emit, typea);
  if (type2->version_valid) {
    nfc_tag_print_line_prefix(emit);
    nero_nfc_emit_write(emit, "GET_VERSION: ");
    nfc_tag_print_hex_bytes(emit, type2->version, type2->version_len, ' ');
    nero_nfc_emit_write(emit, "\r\n");
    if (type2->version_len >= NFC_TAG_NTAG_VER_REPLY_LEN) {
      nfc_tag_print_line_prefix(emit);
      nero_nfc_emit_write(emit, "Product code: vendor=0x");
      nero_nfc_emit_hex_u8(emit, type2->vendor_id);
      nero_nfc_emit_write(emit, " product=0x");
      nero_nfc_emit_hex_u8(emit, type2->product_id);
      nero_nfc_emit_write(emit, " subtype=0x");
      nero_nfc_emit_hex_u8(emit, type2->subtype_id);
      nero_nfc_emit_write(emit, " size=0x");
      nero_nfc_emit_hex_u8(emit, type2->size_id);
      nero_nfc_emit_write(emit, "\r\n");
      nfc_tag_print_line_prefix(emit);
      nero_nfc_emit_write(emit, "Product version: ");
      nero_nfc_emit_dec_u32(
          emit, type2->version[NFC_TAG_NTAG_VER_PRODUCT_MAJOR_INDEX]);
      emit('.');
      nero_nfc_emit_dec_u32(
          emit, type2->version[NFC_TAG_NTAG_VER_PRODUCT_MINOR_INDEX]);
      nero_nfc_emit_write(emit, "\r\n");
    }
  }
  if (type2->product_name != NERO_NFC_NULL) {
    nfc_tag_print_line_prefix(emit);
    nero_nfc_emit_write(emit, "Product: ");
    nero_nfc_emit_write(emit, type2->product_name);
    nero_nfc_emit_write(emit, "\r\n");
  } else if (type2->family != NFC_TAG_TYPE2_FAMILY_UNKNOWN) {
    nfc_tag_print_line_prefix(emit);
    nero_nfc_emit_write(emit, "Family: ");
    nero_nfc_emit_write(emit, nfc_tag_type2_family_name(type2->family));
    nero_nfc_emit_write(emit, "\r\n");
  }
  if (type2->cc_valid) {
    if (nero_nfc_span_ok(NFC_TAG_T2T_CC_ACCESS_INDEX, 1u,
                         NFC_TAG_T2T_PAGE_SIZE_BYTES)) {
      nfc_tag_print_line_prefix(emit);
      nero_nfc_emit_write(emit, "CC: ");
      nfc_tag_print_hex_bytes(emit, type2->cc, NFC_TAG_T2T_PAGE_SIZE_BYTES,
                              ' ');
      nero_nfc_emit_write(emit, "\r\n");
      nfc_tag_print_line_prefix(emit);
      nero_nfc_emit_write(emit, "CC file: E1 ");
      nero_nfc_emit_hex_u8(emit, type2->cc[1]);
      emit(' ');
      nero_nfc_emit_hex_u8(emit, type2->cc[NFC_TAG_T2T_CC_MLEN_INDEX]);
      emit(' ');
      nero_nfc_emit_hex_u8(emit, type2->cc[NFC_TAG_T2T_CC_ACCESS_INDEX]);
      nero_nfc_emit_write(emit, "\r\n");
      nfc_tag_print_line_prefix(emit);
      nero_nfc_emit_write(emit,
                          "Data format: NFC Forum Type 2 Tag / NDEF TLV\r\n");
      nfc_tag_print_line_prefix(emit);
      nero_nfc_emit_write(emit, "NDEF mapping: ");
      nero_nfc_emit_dec_u32(emit, type2->mapping_major);
      emit('.');
      nero_nfc_emit_dec_u32(emit, type2->mapping_minor);
      nero_nfc_emit_write(emit, "  Data area: ");
      nero_nfc_emit_dec_u32(emit, type2->data_area_size_bytes);
      nero_nfc_emit_write(emit, " bytes\r\n");
      nfc_tag_print_line_prefix(emit);
      nero_nfc_emit_write(emit, "T2T area size: ");
      nero_nfc_emit_dec_u32(emit, type2->data_area_size_bytes);
      nero_nfc_emit_write(emit, " bytes  TLV area size: ");
      nero_nfc_emit_dec_u32(emit, type2->data_area_size_bytes);
      nero_nfc_emit_write(emit, " bytes\r\n");
      nfc_tag_print_line_prefix(emit);
      nero_nfc_emit_write(emit, "Read access: ");
      nero_nfc_emit_write(emit,
                          type2->read_access_open ? "open" : "restricted");
      nero_nfc_emit_write(emit, "  Write access: ");
      nero_nfc_emit_write(emit,
                          type2->write_access_open ? "open" : "restricted");
      nero_nfc_emit_write(emit, "\r\n");
      nfc_tag_print_line_prefix(emit);
      nero_nfc_emit_write(emit, "Writable: ");
      nero_nfc_emit_write(emit, type2->write_access_open ? "yes" : "no");
      nero_nfc_emit_write(emit, "  Can be made read-only: ");
      nero_nfc_emit_write(emit, type2->write_access_open
                                    ? "yes"
                                    : "already restricted/unknown");
      nero_nfc_emit_write(emit, "\r\n");
    }
  }
  if (type2->auth0_valid) {
    nfc_tag_print_line_prefix(emit);
    nero_nfc_emit_write(emit, "Protected by password: ");
    nero_nfc_emit_write(emit, type2->password_protected ? "yes" : "no");
    nero_nfc_emit_write(emit, " (AUTH0=0x");
    nero_nfc_emit_hex_u8(emit, type2->auth0_page);
    nero_nfc_emit_write(emit, ")\r\n");
  }
  if (type2->signature_valid) {
    nfc_tag_print_line_prefix(emit);
    nero_nfc_emit_write(emit, "Signature: ");
    nfc_tag_print_hex_bytes(emit, type2->signature,
                            (uint8_t)sizeof(type2->signature), ' ');
    nero_nfc_emit_write(emit, "\r\n");
  }
}

static inline void nfc_tag_print_type4_debug(
    nero_nfc_emit_fn_t emit, const nfc_tag_typea_info_t* typea,
    const nfc_tag_type4_info_t* type4) {
  if ((emit == NERO_NFC_NULL) || (typea == NERO_NFC_NULL) ||
      (type4 == NERO_NFC_NULL)) {
    return;
  }
  nfc_tag_print_line_prefix(emit);
  nero_nfc_emit_write(emit, "Tag type: ISO 14443-4, NFC Forum Type 4 Tag\r\n");
  nfc_tag_print_line_prefix(emit);
  nero_nfc_emit_write(emit, "Tech list: NfcA, IsoDep, Ndef\r\n");
  nfc_tag_print_typea_debug(emit, typea);
  if (!type4->cc_valid) {
    return;
  }
  nfc_tag_print_line_prefix(emit);
  nero_nfc_emit_write(emit, "CC: ");
  nfc_tag_print_hex_bytes(emit, type4->cc, type4->cc_len, ' ');
  nero_nfc_emit_write(emit, "\r\n");
  nfc_tag_print_line_prefix(emit);
  nero_nfc_emit_write(emit,
                      "Data format: NFC Forum Type 4 Tag / NDEF file\r\n");
  nfc_tag_print_line_prefix(emit);
  nero_nfc_emit_write(emit, "NDEF mapping: ");
  nero_nfc_emit_dec_u32(emit, type4->mapping_major);
  emit('.');
  nero_nfc_emit_dec_u32(emit, type4->mapping_minor);
  nero_nfc_emit_write(emit, "  MLe=");
  nero_nfc_emit_dec_u32(emit, type4->mle);
  nero_nfc_emit_write(emit, "  MLc=");
  nero_nfc_emit_dec_u32(emit, type4->mlc);
  nero_nfc_emit_write(emit, "\r\n");
  nfc_tag_print_line_prefix(emit);
  nero_nfc_emit_write(emit, "NDEF file ID: 0x");
  nero_nfc_emit_hex_u8(emit, type4->ndef_file_id[0]);
  nero_nfc_emit_hex_u8(emit, type4->ndef_file_id[1]);
  nero_nfc_emit_write(emit, "  Max NDEF file: ");
  nero_nfc_emit_dec_u32(emit, type4->max_ndef_size);
  nero_nfc_emit_write(emit, " bytes\r\n");
  nfc_tag_print_line_prefix(emit);
  nero_nfc_emit_write(emit, "Read access: ");
  nero_nfc_emit_write(emit, type4->read_access_open ? "open" : "restricted");
  nero_nfc_emit_write(emit, "  Write access: ");
  nero_nfc_emit_write(emit, type4->write_access_open ? "open" : "restricted");
  nero_nfc_emit_write(emit, "\r\n");
  nfc_tag_print_line_prefix(emit);
  nero_nfc_emit_write(emit, "Writable: ");
  nero_nfc_emit_write(emit, type4->write_access_open ? "yes" : "no");
  nero_nfc_emit_write(emit, "  Can be made read-only: ");
  nero_nfc_emit_write(
      emit, type4->write_access_open ? "yes (if tag supports locking)" : "no");
  nero_nfc_emit_write(emit, "\r\n");
}

static inline void nfc_tag_print_type5_debug(
    nero_nfc_emit_fn_t emit, const uint8_t* uid, uint8_t uid_len,
    const nfc_tag_type5_info_t* type5) {
  const char* vendor_name;

  if ((emit == NERO_NFC_NULL) || (uid == NERO_NFC_NULL) ||
      (type5 == NERO_NFC_NULL)) {
    return;
  }
  nfc_tag_print_line_prefix(emit);
  nero_nfc_emit_write(emit, "Tag type: ISO 15693 / NFC Forum Type 5 Tag");
  vendor_name = nfc_tag_iso15693_manufacturer_name(uid, uid_len);
  if (vendor_name != NERO_NFC_NULL) {
    nero_nfc_emit_write(emit, ", ");
    nero_nfc_emit_write(emit, vendor_name);
  }
  nero_nfc_emit_write(emit, "\r\n");
  nfc_tag_print_line_prefix(emit);
  nero_nfc_emit_write(emit, "Tech list: NfcV, Ndef\r\n");
  nfc_tag_print_line_prefix(emit);
  nero_nfc_emit_write(emit, "Serial number / UID: ");
  nfc_tag_print_hex_bytes(emit, uid, uid_len, ' ');
  nero_nfc_emit_write(emit, "\r\n");

  if (vendor_name != NERO_NFC_NULL) {
    nfc_tag_print_line_prefix(emit);
    nero_nfc_emit_write(emit, "Manufacturer: ");
    nero_nfc_emit_write(emit, vendor_name);
    nero_nfc_emit_write(emit, "\r\n");
  }
  {
    const char* family_name = nfc_tag_type5_family_name(uid, uid_len, type5);
    if (family_name != NERO_NFC_NULL) {
      nfc_tag_print_line_prefix(emit);
      nero_nfc_emit_write(emit, "Product family: ");
      nero_nfc_emit_write(emit, family_name);
      nero_nfc_emit_write(emit, "\r\n");
    }
  }
  if (type5->raw_len != 0u) {
    nfc_tag_print_line_prefix(emit);
    nero_nfc_emit_write(emit, "System Info: ");
    nfc_tag_print_hex_bytes(emit, type5->raw, type5->raw_len, ' ');
    nero_nfc_emit_write(emit, "\r\n");
  }
  if (type5->dsfid_valid) {
    nfc_tag_print_line_prefix(emit);
    nero_nfc_emit_write(emit, "DSFID: 0x");
    nero_nfc_emit_hex_u8(emit, type5->dsfid);
    if (type5->afi_valid) {
      nero_nfc_emit_write(emit, "  AFI: 0x");
      nero_nfc_emit_hex_u8(emit, type5->afi);
    }
    nero_nfc_emit_write(emit, "\r\n");
  } else if (type5->afi_valid) {
    nfc_tag_print_line_prefix(emit);
    nero_nfc_emit_write(emit, "AFI: 0x");
    nero_nfc_emit_hex_u8(emit, type5->afi);
    nero_nfc_emit_write(emit, "\r\n");
  }
  if (type5->block_count != 0u && type5->block_size != 0u) {
    nfc_tag_print_line_prefix(emit);
    nero_nfc_emit_write(emit, "Geometry: ");
    nero_nfc_emit_dec_u32(emit, type5->block_count);
    nero_nfc_emit_write(emit, " blocks x ");
    nero_nfc_emit_dec_u32(emit, type5->block_size);
    nero_nfc_emit_write(emit, "B\r\n");
  }
  if (type5->ic_ref_valid) {
    nfc_tag_print_line_prefix(emit);
    nero_nfc_emit_write(emit, "IC reference: 0x");
    nero_nfc_emit_hex_u8(emit, type5->ic_ref);
    nero_nfc_emit_write(emit, "\r\n");
  }
  if (type5->cc_valid) {
    nfc_tag_print_line_prefix(emit);
    nero_nfc_emit_write(emit, "CC: ");
    nfc_tag_print_hex_bytes(emit, type5->cc, type5->cc_len, ' ');
    nero_nfc_emit_write(emit, "\r\n");
    nfc_tag_print_line_prefix(emit);
    nero_nfc_emit_write(emit,
                        "Data format: NFC Forum Type 5 Tag / NDEF TLV\r\n");
    nfc_tag_print_line_prefix(emit);
    nero_nfc_emit_write(emit, "NDEF mapping: ");
    nero_nfc_emit_dec_u32(emit, type5->mapping_major);
    emit('.');
    nero_nfc_emit_dec_u32(emit, type5->mapping_minor);
    nero_nfc_emit_write(emit, "  Data area: ");
    nero_nfc_emit_dec_u32(emit, type5->data_area_size_bytes);
    nero_nfc_emit_write(emit, " bytes\r\n");
    nfc_tag_print_line_prefix(emit);
    nero_nfc_emit_write(emit, "Read access: ");
    nero_nfc_emit_write(emit, type5->read_access_open ? "open" : "restricted");
    nero_nfc_emit_write(emit, "  Write access: ");
    nero_nfc_emit_write(emit, type5->write_access_open ? "open" : "restricted");
    nero_nfc_emit_write(emit, "\r\n");
    nfc_tag_print_line_prefix(emit);
    nero_nfc_emit_write(emit, "Writable: ");
    nero_nfc_emit_write(emit, type5->write_access_open ? "yes" : "no");
    nero_nfc_emit_write(emit, "  Can be made read-only: ");
    nero_nfc_emit_write(emit, type5->write_access_open
                                  ? "yes (if tag supports locking)"
                                  : "no");
    nero_nfc_emit_write(emit, "\r\n");
  }
}

#ifdef __cplusplus
}
#endif
