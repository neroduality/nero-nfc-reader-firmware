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

#include "nfc_print_utils.h"
#include "nero_nfc_mem_util.h"
#include "nfc_frontend.h"
#include "nfc_tag_geometry_limits.h"
#include "nero_nfc_attrs.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * NFC Forum capability-container (CC) magic and version bytes.
 *   [T2T-ISO14443-A] section 4.4 (CC layout)
 *   [T2T-ISO14443-A-NTAG21x] GET_VERSION/product metadata and configuration byte indices.
 *   [T5T-ISO15693] section 4.3.1 (CC magic E1h/E2h, byte 1 version/access)
 */
enum {
  NFC_FORUM_CC_MAGIC = 0xE1u,     /* CC present (T2T; T5T 4-byte / 1-byte address CC) */
  NFC_T5T_CC_MAGIC_8BYTE = 0xE2u, /* T5T 8-byte / 2-byte address CC magic */
  NFC_T2T_CC_VERSION = 0x10u,     /* T2T CC mapping version 1.0 */
  NFC_T5T_CC_VERSION = 0x40u,     /* T5T CC version/access byte (1.0) */
};

/* CC nibble / byte masks and field shifts ([T2T-ISO14443-A] section 4.4, [T5T-ISO15693]
 * section 4.3.1). */
#define NFC_TAG_CC_MAPPING_MAJOR_SHIFT 4u
#define NFC_TAG_CC_NIBBLE_MASK NFC_TAG_T2T_ACK_NIBBLE_MASK
#define NFC_TAG_CC_ACCESS_HIGH_NIBBLE_MASK 0xF0u
#define NFC_TAG_T5T_CC_MAPPING_MAJOR_SHIFT 6u
#define NFC_TAG_T5T_CC_MAPPING_MINOR_SHIFT 4u
#define NFC_TAG_T5T_CC_MAPPING_MINOR_MASK 0x03u
#define NFC_TAG_T5T_CC_ACCESS_READ_MASK 0x0Cu
#define NFC_TAG_T5T_CC_ACCESS_WRITE_MASK 0x03u
#define NFC_TAG_T5T_ISO15693_BLOCK_SIZE_MASK 0x1Fu
#define NFC_TAG_CC_CCLEN_MSB_INDEX 0u
#define NFC_TAG_CC_CCLEN_LSB_INDEX 1u
#define NFC_TAG_T4T_CC_MLE_MSB_INDEX 3u
#define NFC_TAG_T4T_CC_MLE_LSB_INDEX 4u
#define NFC_TAG_T4T_CC_MLC_MSB_INDEX 5u
#define NFC_TAG_T4T_CC_MLC_LSB_INDEX 6u
#define NFC_TAG_T4T_CC_NDEF_FILE_ID_MSB_INDEX 9u
#define NFC_TAG_T4T_CC_NDEF_FILE_ID_LSB_INDEX 10u
#define NFC_TAG_T4T_CC_NDEF_SIZE_MSB_INDEX 11u
#define NFC_TAG_T4T_CC_NDEF_SIZE_LSB_INDEX 12u
#define NFC_TAG_T5T_CC_EXT_SIZE_MSB_INDEX 6u
#define NFC_TAG_T5T_CC_EXT_SIZE_LSB_INDEX 7u
#define NFC_TAG_ST25DV_EXT_MEMORY_BLOCK_SIZE_INDEX 2u
#define NFC_TAG_TYPEA_UID_MAX 10u /* [ISO14443-3] cascade level-3 UID field width */
#define NFC_TAG_T2T_CC_MAGIC_INDEX 0u
#define NFC_TAG_T2T_CC_VER_INDEX 1u
#define NFC_TAG_T2T_CC_MLEN_INDEX 2u
#define NFC_TAG_T2T_CC_ACCESS_INDEX 3u
/* [DERIVED] Zero-based aliases for bytes within a 4-byte Type 2 page payload. */
#define NFC_TAG_T2T_PAGE_BYTE2 2u
#define NFC_TAG_T2T_PAGE_BYTE3 3u
#define NFC_TAG_T2T_WRITE_CMD_DATA_OFFSET 2u
#define NFC_TAG_T5T_CC_MLEN_BYTE_INDEX 2u
#define NFC_TAG_T5T_CC_FLAGS_BYTE_INDEX 3u
#define NFC_TAG_T4T_CC_MAPPING_VER_INDEX 2u
#define NFC_TAG_T4T_CC_NDEF_TLV_TAG_INDEX 7u
#define NFC_TAG_T4T_CC_NDEF_TLV_LEN_INDEX 8u
#define NFC_TAG_T4T_CC_READ_ACCESS_INDEX 13u
#define NFC_TAG_T4T_CC_WRITE_ACCESS_INDEX 14u
#define NFC_TAG_NTAG_VER_VENDOR_BYTE_INDEX 1u
#define NFC_TAG_NTAG_VER_PRODUCT_BYTE_INDEX 2u
#define NFC_TAG_NTAG_VER_SUBTYPE_BYTE_INDEX 3u
#define NFC_TAG_NTAG_VER_PRODUCT_MAJOR_INDEX 4u
#define NFC_TAG_NTAG_VER_PRODUCT_MINOR_INDEX 5u
#define NFC_TAG_NTAG_CFG_AUTH0_BYTE_INDEX 3u

#ifdef __cplusplus
enum nfc_tag_kind_t {
#else
typedef enum {
#endif
  NFC_TAG_KIND_NONE = 0,
  NFC_TAG_KIND_TYPE2 = 2,
  NFC_TAG_KIND_TYPE4 = 4,
  NFC_TAG_KIND_TYPE5 = 5,
#ifdef __cplusplus
};
#else
} nfc_tag_kind_t;
#endif

#ifdef __cplusplus
enum nfc_tag_type2_family_t {
#else
typedef enum {
#endif
  NFC_TAG_TYPE2_FAMILY_UNKNOWN = 0,
  NFC_TAG_TYPE2_FAMILY_NTAG21X = 1,
  NFC_TAG_TYPE2_FAMILY_ST25TN = 2,
#ifdef __cplusplus
};
#else
} nfc_tag_type2_family_t;
#endif

#ifdef __cplusplus
struct nfc_tag_typea_info_t {
#else
typedef struct {
#endif
  uint8_t uid[10];
  uint8_t uid_len;
  uint8_t atqa[2];
  bool atqa_valid;
  uint8_t sak;
  uint8_t ats[NFC_ISO14443_ATS_MAX];
  uint8_t ats_len;
#ifdef __cplusplus
};
#else
} nfc_tag_typea_info_t;
#endif

#ifdef __cplusplus
struct nfc_tag_type2_info_t {
#else
typedef struct {
#endif
  uint8_t version[8];
  uint8_t version_len;
  bool version_valid;
  uint8_t vendor_id;
  uint8_t product_id;
  uint8_t subtype_id;
  uint8_t size_id;
  const char *vendor_name;
  const char *product_name;
  nfc_tag_type2_family_t family;
  uint8_t cc[4];
  bool cc_valid;
  uint8_t mapping_major;
  uint8_t mapping_minor;
  uint16_t data_area_size_bytes;
  uint8_t access;
  bool read_access_open;
  bool write_access_open;
  uint16_t max_user_page;
  uint8_t signature[32];
  bool signature_valid;
  uint8_t auth0_page;
  bool auth0_valid;
  bool password_protected;
#ifdef __cplusplus
};
#else
} nfc_tag_type2_info_t;
#endif

#ifdef __cplusplus
struct nfc_tag_type4_info_t {
#else
typedef struct {
#endif
  uint8_t cc[15];
  uint8_t cc_len;
  bool cc_valid;
  uint8_t mapping_major;
  uint8_t mapping_minor;
  uint16_t mle;
  uint16_t mlc;
  uint8_t tlv_type;
  uint8_t tlv_length;
  uint8_t ndef_file_id[2];
  uint16_t max_ndef_size;
  uint8_t read_access;
  uint8_t write_access;
  bool read_access_open;
  bool write_access_open;
#ifdef __cplusplus
};
#else
} nfc_tag_type4_info_t;
#endif

#ifdef __cplusplus
struct nfc_tag_type5_info_t {
#else
typedef struct {
#endif
  uint8_t dsfid;
  bool dsfid_valid;
  uint8_t afi;
  bool afi_valid;
  uint16_t block_count;
  uint8_t block_size;
  uint8_t ic_ref;
  bool ic_ref_valid;
  uint8_t raw[16];
  uint8_t raw_len;
  uint8_t system_info_flags;
  uint8_t cc[8];
  uint8_t cc_len;
  bool cc_valid;
  uint8_t mapping_major;
  uint8_t mapping_minor;
  uint16_t data_area_size_bytes;
  uint8_t access;
  bool read_access_open;
  bool write_access_open;
#ifdef __cplusplus
};
#else
} nfc_tag_type5_info_t;
#endif

#ifdef __cplusplus
struct nfc_tag_info_t {
#else
typedef struct {
#endif
  nfc_tag_kind_t kind;
  union {
    nfc_tag_typea_info_t typea;
    uint8_t type5_uid[8];
  } common;
  union {
    nfc_tag_type2_info_t type2;
    nfc_tag_type4_info_t type4;
    nfc_tag_type5_info_t type5;
  } detail;
#ifdef __cplusplus
};
#else
} nfc_tag_info_t;
#endif

static inline uint16_t nfc_tag_type2_max_user_page_from_size_id(uint8_t size_id) {
  switch (size_id) {
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

static inline const char *nfc_tag_type2_family_name(nfc_tag_type2_family_t family) {
  switch (family) {
  case NFC_TAG_TYPE2_FAMILY_UNKNOWN:
    return NERO_NFC_NULL;
  case NFC_TAG_TYPE2_FAMILY_NTAG21X:
    return "NTAG21x";
  case NFC_TAG_TYPE2_FAMILY_ST25TN:
    return "ST25TN-class";
  default:
    return NERO_NFC_NULL;
  }
}

static inline const char *nfc_tag_iso14443a_manufacturer_name(const uint8_t *uid, uint8_t uid_len) {
  if ((uid == NERO_NFC_NULL) || (uid_len == 0u)) {
    return NERO_NFC_NULL;
  }
  switch (uid[0]) {
  case NFC_TAG_MFR_CODE_ST:
    return "STMicroelectronics";
  case NFC_TAG_MFR_CODE_NXP:
    return "NXP";
  default:
    return NERO_NFC_NULL;
  }
}

static inline const char *nfc_tag_iso15693_manufacturer_name(const uint8_t *uid, uint8_t uid_len) {
  if ((uid == NERO_NFC_NULL) || (uid_len < NFC_TAG_T5T_ISO15693_UID_MFR_MIN_LEN)) {
    return NERO_NFC_NULL;
  }
  switch (uid[1]) {
  case NFC_TAG_MFR_CODE_ST:
    return "STMicroelectronics";
  case NFC_TAG_MFR_CODE_NXP:
    return "NXP";
  default:
    return NERO_NFC_NULL;
  }
}

static inline uint16_t nfc_tag_type2_last_page_from_data_area(uint16_t data_area_size_bytes) {
  uint16_t pages;

  /*
   * [T2T-ISO14443-A] section 4.4 — user pages follow the CC at page
   * NFC_TAG_T2T_CC_PAGE_INDEX; page count derives from the data-area size in
   * bytes (4 bytes per page per [T2T-ISO14443-A] section 5.1).
   */
  if (data_area_size_bytes == 0u) {
    return 0u;
  }
  pages = (uint16_t)((data_area_size_bytes + NFC_TAG_T2T_PAGE_SIZE_BYTES - 1u) /
                     NFC_TAG_T2T_PAGE_SIZE_BYTES);
  return (uint16_t)(NFC_TAG_T2T_CC_PAGE_INDEX + pages);
}

static inline void nfc_tag_type2_clear_cc_info(nfc_tag_type2_info_t *info) {
  if (info == NERO_NFC_NULL) {
    return;
  }
  nero_nfc_zero_bytes(info->cc, sizeof(info->cc));
  info->cc_valid = false;
  info->mapping_major = 0u;
  info->mapping_minor = 0u;
  info->data_area_size_bytes = 0u;
  info->access = 0u;
  info->read_access_open = false;
  info->write_access_open = false;
}

static inline const char *nfc_tag_type5_family_name(const uint8_t *uid, uint8_t uid_len,
                                                    const nfc_tag_type5_info_t *info) {
  const char *vendor = nfc_tag_iso15693_manufacturer_name(uid, uid_len);
  if ((vendor == NERO_NFC_NULL) || (strcmp(vendor, "STMicroelectronics") != 0) ||
      (info == NERO_NFC_NULL)) {
    return NERO_NFC_NULL;
  }
  if (info->ic_ref_valid &&
      ((info->ic_ref == NFC_TAG_ST25DV_IC_REF) || (info->ic_ref == NFC_TAG_ST25DV04KC_IC_REF))) {
    return "ST25DV-class";
  }
  if ((info->block_count != 0u) &&
      (info->block_count <= NFC_TAG_T5T_ISO15693_BLOCK_COUNT_1BYTE_MAX)) {
    return "ST25TV-class";
  }
  if (info->block_count > NFC_TAG_T5T_ISO15693_BLOCK_COUNT_1BYTE_MAX) {
    return "ST25DV-class";
  }
  return "ST25 Type 5-class";
}

static inline void nfc_tag_type2_apply_family_hint(nfc_tag_type2_info_t *info,
                                                   nfc_tag_type2_family_t family) {
  if (info == NERO_NFC_NULL) {
    return;
  }
  info->family = family;
  if (family == NFC_TAG_TYPE2_FAMILY_ST25TN) {
    uint16_t cc_last_page = nfc_tag_type2_last_page_from_data_area(info->data_area_size_bytes);

    info->vendor_name = "STMicroelectronics";
    info->product_name = "ST25TN-class";
    if (info->data_area_size_bytes == NFC_TAG_ST25TN512_DATA_BYTES) {
      info->product_name = "ST25TN512";
    } else if (info->data_area_size_bytes == NFC_TAG_ST25TN01K_DATA_BYTES) {
      info->product_name = "ST25TN01K";
    }
    if (cc_last_page != 0u) {
      info->max_user_page =
        (cc_last_page > NFC_TAG_ST25TN_MAX_USER_PAGE) ? NFC_TAG_ST25TN_MAX_USER_PAGE : cc_last_page;
    } else if (info->max_user_page == 0u) {
      info->max_user_page = NFC_TAG_ST25TN_FALLBACK_LAST_PAGE;
    }
  }
}

static inline void nfc_tag_type2_apply_version(nfc_tag_type2_info_t *info, const uint8_t *version,
                                               uint8_t version_len) {
  if ((info == NERO_NFC_NULL) || (version == NERO_NFC_NULL) || (version_len == 0u)) {
    return;
  }
  info->version_valid = nero_nfc_copy_bytes(info->version, sizeof(info->version), 0u, version,
                                            (uint8_t)((version_len > (uint8_t)sizeof(info->version))
                                                        ? sizeof(info->version)
                                                        : version_len));
  info->version_len =
    (uint8_t)((version_len > (uint8_t)sizeof(info->version)) ? sizeof(info->version) : version_len);
  if (info->version_len < NFC_TAG_NTAG_VER_REPLY_LEN) {
    return;
  }
  info->vendor_id = info->version[1];
  info->product_id = info->version[2];
  info->subtype_id = info->version[3];
  info->size_id = info->version[6];

  if (info->vendor_id == NFC_TAG_NTAG_VER_VENDOR_NXP) {
    info->vendor_name = "NXP";
  }
  if ((info->version[0] == NFC_TAG_NTAG_VER_FIXED_HEADER) &&
      (info->product_id == NFC_TAG_NTAG_VER_PRODUCT_NTAG) &&
      (info->subtype_id == NFC_TAG_NTAG_VER_SUBTYPE) &&
      (info->version[7] == NFC_TAG_NTAG_VER_PROTO_14443)) {
    info->family = NFC_TAG_TYPE2_FAMILY_NTAG21X;
    info->product_name = "NTAG21x";
    switch (info->size_id) {
    case NFC_TAG_NTAG216_SIZE_ID:
      info->product_name = "NTAG216";
      break;
    case NFC_TAG_NTAG215_SIZE_ID:
      info->product_name = "NTAG215";
      break;
    case NFC_TAG_NTAG213_SIZE_ID:
      info->product_name = "NTAG213";
      break;
    default:
      break;
    }
    info->max_user_page = nfc_tag_type2_max_user_page_from_size_id(info->size_id);
  }
}

static inline void nfc_tag_type2_apply_cc(nfc_tag_type2_info_t *info, const uint8_t *cc,
                                          uint8_t cc_len) {
  if (info == NERO_NFC_NULL) {
    return;
  }
  nfc_tag_type2_clear_cc_info(info);
  if ((cc == NERO_NFC_NULL) || (cc_len < NFC_TAG_T2T_PAGE_SIZE_BYTES)) {
    return;
  }
  if (cc[0] != NFC_FORUM_CC_MAGIC) {
    return;
  }
  if (!nero_nfc_copy_bytes(info->cc, sizeof(info->cc), 0u, cc, NFC_TAG_T2T_PAGE_SIZE_BYTES)) {
    return;
  }
  info->cc_valid = true;
  info->mapping_major = (uint8_t)(cc[1] >> NFC_TAG_CC_MAPPING_MAJOR_SHIFT);
  info->mapping_minor = (uint8_t)(cc[1] & NFC_TAG_CC_NIBBLE_MASK);
  info->data_area_size_bytes = (uint16_t)((uint16_t)cc[2] * NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES);
  info->access = cc[3];
  info->read_access_open = (cc[3] & NFC_TAG_CC_ACCESS_HIGH_NIBBLE_MASK) == 0u;
  info->write_access_open = (cc[3] & NFC_TAG_CC_NIBBLE_MASK) == 0u;
}

static inline void nfc_tag_type2_apply_signature(nfc_tag_type2_info_t *info, const uint8_t *sig,
                                                 uint8_t sig_len) {
  if ((info == NERO_NFC_NULL) || (sig == NERO_NFC_NULL) ||
      (sig_len < (uint8_t)sizeof(info->signature))) {
    return;
  }
  if (!nero_nfc_copy_bytes(info->signature, sizeof(info->signature), 0u, sig,
                           sizeof(info->signature))) {
    return;
  }
  info->signature_valid = true;
}

static inline void nfc_tag_type2_apply_auth0(nfc_tag_type2_info_t *info, uint8_t auth0_page) {
  if (info == NERO_NFC_NULL) {
    return;
  }
  info->auth0_page = auth0_page;
  info->auth0_valid = true;
  info->password_protected = (auth0_page != NFC_TAG_NTAG_AUTH0_DISABLED) &&
                             (info->max_user_page == 0u || auth0_page <= info->max_user_page);
}

NERO_NFC_NODISCARD static inline bool nfc_tag_type4_apply_cc(nfc_tag_type4_info_t *info,
                                                             const uint8_t *cc, uint8_t cc_len) {
  if (info == NERO_NFC_NULL) {
    return false;
  }
  nero_nfc_zero_bytes(info, sizeof(*info));
  if ((cc == NERO_NFC_NULL) || (cc_len < NFC_TAG_T4T_CC_MIN_LEN)) {
    return false;
  }
  {
    uint16_t declared_len = cc[NFC_TAG_CC_CCLEN_MSB_INDEX];
    uint16_t mle;
    uint16_t mlc;
    declared_len = (uint16_t)((declared_len << NFC_BYTE_SHIFT_8) | cc[NFC_TAG_CC_CCLEN_LSB_INDEX]);
    mle = (uint16_t)(((uint16_t)cc[NFC_TAG_T4T_CC_MLE_MSB_INDEX] << NFC_BYTE_SHIFT_8) |
                     cc[NFC_TAG_T4T_CC_MLE_LSB_INDEX]);
    mlc = (uint16_t)(((uint16_t)cc[NFC_TAG_T4T_CC_MLC_MSB_INDEX] << NFC_BYTE_SHIFT_8) |
                     cc[NFC_TAG_T4T_CC_MLC_LSB_INDEX]);
    /*
     * [T4T-ISO14443-4] section 7.2.1.7 — NDEF File Control TLV is T=04h, L=06h;
     * MLe is valid in 000Fh..FFFFh and MLc in 000Dh..FFFFh. Reject a CC whose
     * declared length, TLV header, or MLe/MLc fall outside the spec ranges.
     */
    if (declared_len < NFC_TAG_T4T_CC_MIN_LEN || declared_len > cc_len ||
        cc[7] != NFC_TAG_T4T_NDEF_TLV_TYPE || cc[8] != NFC_TAG_T4T_NDEF_TLV_LEN ||
        mle < NFC_TAG_T4T_MLE_MIN || mlc < NFC_TAG_T4T_MLC_MIN) {
      return false;
    }
  }
  if (!nero_nfc_copy_bytes(info->cc, sizeof(info->cc), 0u, cc, NFC_TAG_T4T_CC_MIN_LEN)) {
    return false;
  }
  info->cc_len = NFC_TAG_T4T_CC_MIN_LEN;
  info->cc_valid = true;
  info->mapping_major = (uint8_t)(cc[2] >> NFC_TAG_CC_MAPPING_MAJOR_SHIFT);
  info->mapping_minor = (uint8_t)(cc[2] & NFC_TAG_CC_NIBBLE_MASK);
  info->mle = (uint16_t)(((uint16_t)cc[NFC_TAG_T4T_CC_MLE_MSB_INDEX] << NFC_BYTE_SHIFT_8) |
                         cc[NFC_TAG_T4T_CC_MLE_LSB_INDEX]);
  info->mlc = (uint16_t)(((uint16_t)cc[NFC_TAG_T4T_CC_MLC_MSB_INDEX] << NFC_BYTE_SHIFT_8) |
                         cc[NFC_TAG_T4T_CC_MLC_LSB_INDEX]);
  info->tlv_type = cc[7];
  info->tlv_length = cc[8];
  info->ndef_file_id[0] = cc[NFC_TAG_T4T_CC_NDEF_FILE_ID_MSB_INDEX];
  info->ndef_file_id[1] = cc[NFC_TAG_T4T_CC_NDEF_FILE_ID_LSB_INDEX];
  info->max_ndef_size =
    (uint16_t)(((uint16_t)cc[NFC_TAG_T4T_CC_NDEF_SIZE_MSB_INDEX] << NFC_BYTE_SHIFT_8) |
               cc[NFC_TAG_T4T_CC_NDEF_SIZE_LSB_INDEX]);
  info->read_access = cc[13];
  info->write_access = cc[14];
  info->read_access_open = cc[13] == 0x00u;
  info->write_access_open = cc[14] == 0x00u;
  return true;
}

static inline void nfc_tag_type5_clear_cc_info(nfc_tag_type5_info_t *info) {
  if (info == NERO_NFC_NULL) {
    return;
  }
  nero_nfc_zero_bytes(info->cc, sizeof(info->cc));
  info->cc_len = 0u;
  info->cc_valid = false;
  info->mapping_major = 0u;
  info->mapping_minor = 0u;
  info->data_area_size_bytes = 0u;
  info->access = 0u;
  info->read_access_open = false;
  info->write_access_open = false;
}

static inline void nfc_tag_type5_clear_system_info(nfc_tag_type5_info_t *info) {
  if (info == NERO_NFC_NULL) {
    return;
  }
  info->dsfid = 0u;
  info->dsfid_valid = false;
  info->afi = 0u;
  info->afi_valid = false;
  info->block_count = 0u;
  info->block_size = 0u;
  info->ic_ref = 0u;
  info->ic_ref_valid = false;
  nero_nfc_zero_bytes(info->raw, sizeof(info->raw));
  info->raw_len = 0u;
  info->system_info_flags = 0u;
}

static inline void nfc_tag_type5_apply_cc(nfc_tag_type5_info_t *info, const uint8_t *cc,
                                          uint8_t cc_len) {
  uint16_t size_units = 0u;
  uint8_t cc_bytes;

  if (info == NERO_NFC_NULL) {
    return;
  }
  nfc_tag_type5_clear_cc_info(info);
  if ((cc == NERO_NFC_NULL) || (cc_len < NFC_TAG_T5T_CC_LEN_SHORT)) {
    return;
  }
  /*
   * [T5T-ISO15693] section 4.3.1: CC byte 0 magic is E1h (1-byte block address
   * mode) or E2h (2-byte block address mode). Both are valid magic numbers.
   */
  if ((cc[0] != NFC_FORUM_CC_MAGIC) && (cc[0] != NFC_T5T_CC_MAGIC_8BYTE)) {
    return;
  }
  /*
   * [T5T-ISO15693] section 4.3.1.17: byte 2 (MLEN) selects CC length. Non-zero MLEN →
   * NFC_TAG_T5T_CC_LEN_SHORT CC whose T5T_Area size is MLEN (in 8-byte units).
   * Zero MLEN → NFC_TAG_T5T_CC_LEN_EXTENDED CC; area size is in bytes 6..7.
   */
  if (cc[2] != 0u) {
    cc_bytes = NFC_TAG_T5T_CC_LEN_SHORT;
    size_units = cc[2];
  } else {
    if (cc_len < NFC_TAG_T5T_CC_LEN_EXTENDED) {
      return;
    }
    cc_bytes = NFC_TAG_T5T_CC_LEN_EXTENDED;
    size_units = (uint16_t)(((uint16_t)cc[NFC_TAG_T5T_CC_EXT_SIZE_MSB_INDEX] << NFC_BYTE_SHIFT_8) |
                            cc[NFC_TAG_T5T_CC_EXT_SIZE_LSB_INDEX]);
  }
  if ((size_units == 0u) ||
      (size_units > (uint16_t)(UINT16_MAX / NFC_TAG_T5T_AREA_SIZE_UNIT_BYTES))) {
    nfc_tag_type5_clear_cc_info(info);
    return;
  }
  nero_nfc_zero_bytes(info->cc, sizeof(info->cc));
  if (!nero_nfc_copy_bytes(info->cc, sizeof(info->cc), 0u, cc, cc_bytes)) {
    return;
  }
  info->cc_len = cc_bytes;
  info->mapping_major = (uint8_t)(cc[1] >> NFC_TAG_T5T_CC_MAPPING_MAJOR_SHIFT);
  info->mapping_minor =
    (uint8_t)((cc[1] >> NFC_TAG_T5T_CC_MAPPING_MINOR_SHIFT) & NFC_TAG_T5T_CC_MAPPING_MINOR_MASK);
  info->access = (uint8_t)(cc[1] & NFC_TAG_CC_NIBBLE_MASK);
  info->read_access_open = (cc[1] & NFC_TAG_T5T_CC_ACCESS_READ_MASK) == 0u;
  info->write_access_open = (cc[1] & NFC_TAG_T5T_CC_ACCESS_WRITE_MASK) == 0u;
  info->cc_valid = true;
  info->data_area_size_bytes = (uint16_t)(size_units * NFC_TAG_T5T_AREA_SIZE_UNIT_BYTES);
}

static inline void nfc_tag_type5_apply_system_info(nfc_tag_type5_info_t *info, const uint8_t *raw,
                                                   uint8_t raw_len) {
  uint8_t pos = 0u;

  if (info == NERO_NFC_NULL) {
    return;
  }
  nfc_tag_type5_clear_system_info(info);
  if ((raw == NERO_NFC_NULL) || (raw_len < NFC_TAG_T5T_ISO15693_SYS_INFO_PREAMBLE_LEN)) {
    return;
  }
  if (!nero_nfc_copy_bytes(
        info->raw, sizeof(info->raw), 0u, raw,
        (uint8_t)((raw_len > (uint8_t)sizeof(info->raw)) ? sizeof(info->raw) : raw_len))) {
    return;
  }
  info->raw_len = (uint8_t)((raw_len > (uint8_t)sizeof(info->raw)) ? sizeof(info->raw) : raw_len);
  info->system_info_flags = raw[1];
  pos = (uint8_t)(NFC_TAG_T5T_ISO15693_SYS_INFO_PREAMBLE_LEN +
                  NFC_TAG_T5T_ISO15693_SYS_INFO_UID_FIELD_LEN);
  if ((raw[1] & NFC_TAG_T5T_ISO15693_INFO_FLAG_DSFID) != 0u && pos < raw_len) {
    info->dsfid = raw[pos++];
    info->dsfid_valid = true;
  }
  if ((raw[1] & NFC_TAG_T5T_ISO15693_INFO_FLAG_AFI) != 0u && pos < raw_len) {
    info->afi = raw[pos++];
    info->afi_valid = true;
  }
  if ((raw[1] & NFC_TAG_T5T_ISO15693_INFO_FLAG_MEMORY_SIZE) != 0u &&
      (uint16_t)(pos + NFC_TAG_T5T_ISO15693_MEMORY_SIZE_FIELD_LEN) <= raw_len) {
    info->block_count = (uint16_t)((uint16_t)raw[pos] + 1u);
    info->block_size = (uint8_t)((raw[pos + 1u] & NFC_TAG_T5T_ISO15693_BLOCK_SIZE_MASK) + 1u);
    pos = (uint8_t)(pos + NFC_TAG_T5T_ISO15693_MEMORY_SIZE_FIELD_LEN);
  }
  if ((raw[1] & NFC_TAG_T5T_ISO15693_INFO_FLAG_IC_REF) != 0u && pos < raw_len) {
    info->ic_ref = raw[pos];
    info->ic_ref_valid = true;
  }
}

/*
 * [T5T-ISO15693] section 10.3.4 / [T5T-ISO15693-ST25DV] section 7.6.23 — Extended Get System Info
 * response parser. The extended memory-size field is two block-count bytes plus
 * one block-size byte, so tags above 256 blocks (ST25DV16KC / ST25DV64KC) are
 * reachable. Frame: resp_flags, info_flags, UID (8 B), [DSFID], [AFI],
 * [NB_lsb NB_msb block_size], [IC ref].
 */
static inline void nfc_tag_type5_apply_system_info_ext(nfc_tag_type5_info_t *info,
                                                       const uint8_t *raw, uint8_t raw_len) {
  uint8_t pos;

  if (info == NERO_NFC_NULL) {
    return;
  }
  nfc_tag_type5_clear_system_info(info);
  if ((raw == NERO_NFC_NULL) || (raw_len < NFC_TAG_T5T_ISO15693_SYS_INFO_EXT_MIN_REPLY_LEN)) {
    return;
  }
  if (!nero_nfc_copy_bytes(
        info->raw, sizeof(info->raw), 0u, raw,
        (uint8_t)((raw_len > (uint8_t)sizeof(info->raw)) ? sizeof(info->raw) : raw_len))) {
    return;
  }
  info->raw_len = (uint8_t)((raw_len > (uint8_t)sizeof(info->raw)) ? sizeof(info->raw) : raw_len);
  info->system_info_flags = raw[1];
  pos = (uint8_t)(NFC_TAG_T5T_ISO15693_SYS_INFO_PREAMBLE_LEN +
                  NFC_TAG_T5T_ISO15693_SYS_INFO_UID_FIELD_LEN);
  if ((raw[1] & NFC_TAG_T5T_ISO15693_INFO_FLAG_DSFID) != 0u && pos < raw_len) {
    info->dsfid = raw[pos++];
    info->dsfid_valid = true;
  }
  if ((raw[1] & NFC_TAG_T5T_ISO15693_INFO_FLAG_AFI) != 0u && pos < raw_len) {
    info->afi = raw[pos++];
    info->afi_valid = true;
  }
  if ((raw[1] & NFC_TAG_T5T_ISO15693_INFO_FLAG_MEMORY_SIZE) != 0u &&
      (uint16_t)(pos + NFC_TAG_ST25DV_EXT_MEMORY_SIZE_FIELD_LEN) <= raw_len) {
    uint32_t nb = (uint32_t)raw[pos] | ((uint32_t)raw[pos + 1u] << NFC_BYTE_SHIFT_8);
    nb += 1u;
    info->block_count = (nb > (uint32_t)UINT16_MAX) ? UINT16_MAX : (uint16_t)nb;
    info->block_size = (uint8_t)((raw[pos + NFC_TAG_ST25DV_EXT_MEMORY_BLOCK_SIZE_INDEX] &
                                  NFC_TAG_T5T_ISO15693_BLOCK_SIZE_MASK) +
                                 1u);
    pos = (uint8_t)(pos + NFC_TAG_ST25DV_EXT_MEMORY_SIZE_FIELD_LEN);
  }
  if ((raw[1] & NFC_TAG_T5T_ISO15693_INFO_FLAG_IC_REF) != 0u && pos < raw_len) {
    info->ic_ref = raw[pos];
    info->ic_ref_valid = true;
  }
}

NERO_NFC_NODISCARD static inline bool
nfc_tag_type5_cc_signals_mlen_overflow(const nfc_tag_type5_info_t *info) {
  return (info != NERO_NFC_NULL) && info->cc_valid && (info->cc_len == NFC_TAG_T5T_CC_LEN_SHORT) &&
         (info->cc[NFC_TAG_T5T_CC_MLEN_BYTE_INDEX] == NFC_TAG_T5T_CC_MLEN_OVERFLOW) &&
         ((info->cc[NFC_TAG_T5T_CC_FLAGS_BYTE_INDEX] & NFC_TAG_T5T_CC_MLEN_OVERFLOW_CC3_FLAG) !=
          0u);
}

/*
 * [T5T-ISO15693] section 4.3.1.17 "MLEN overflow": a NFC_TAG_T5T_CC_LEN_SHORT CC cannot
 * encode areas larger than 2040 bytes (MLEN would exceed 0xFF). Such tags set
 * CC byte 2 to NFC_TAG_T5T_CC_MLEN_OVERFLOW and CC byte 3 bit 2
 * (NFC_TAG_T5T_CC_MLEN_OVERFLOW_CC3_FLAG), deferring the real T5T_Area size to
 * Get System Info. Call after nfc_tag_type5_apply_cc() and
 * nfc_tag_type5_apply_system_info().
 */
static inline void nfc_tag_type5_resolve_mlen_overflow(nfc_tag_type5_info_t *info) {
  uint32_t total_bytes;

  if ((info == NERO_NFC_NULL) || !info->cc_valid) {
    return;
  }
  if (!nfc_tag_type5_cc_signals_mlen_overflow(info)) {
    return;
  }
  if ((info->block_count == 0u) || (info->block_size == 0u)) {
    return;
  }
  total_bytes = (uint32_t)info->block_count * (uint32_t)info->block_size;
  if (total_bytes <= (uint32_t)info->cc_len) {
    return;
  }
  /* The T5T_Area excludes the CC bytes that live at the start of memory. */
  total_bytes -= (uint32_t)info->cc_len;
  info->data_area_size_bytes =
    (total_bytes > (uint32_t)UINT16_MAX) ? UINT16_MAX : (uint16_t)total_bytes;
}

#ifdef __cplusplus
}
#endif
