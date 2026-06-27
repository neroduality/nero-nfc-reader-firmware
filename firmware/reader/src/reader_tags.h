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

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
using reader_tag_kind_t = nfc_tag_kind_t;
using reader_tag_typea_info_t = nfc_tag_typea_info_t;
using reader_tag_type2_info_t = nfc_tag_type2_info_t;
using reader_tag_type4_info_t = nfc_tag_type4_info_t;
using reader_tag_type5_info_t = nfc_tag_type5_info_t;
using reader_tag_info_t = nfc_tag_info_t;
#else
typedef nfc_tag_kind_t reader_tag_kind_t;
typedef nfc_tag_typea_info_t reader_tag_typea_info_t;
typedef nfc_tag_type2_info_t reader_tag_type2_info_t;
typedef nfc_tag_type4_info_t reader_tag_type4_info_t;
typedef nfc_tag_type5_info_t reader_tag_type5_info_t;
typedef nfc_tag_info_t reader_tag_info_t;
#endif

#define READER_TAG_KIND_NONE NFC_TAG_KIND_NONE
#define READER_TAG_KIND_TYPE2 NFC_TAG_KIND_TYPE2
#define READER_TAG_KIND_TYPE4 NFC_TAG_KIND_TYPE4
#define READER_TAG_KIND_TYPE5 NFC_TAG_KIND_TYPE5

void reader_tags_read_ntag_tag(void);
void reader_tags_read_type4_tag(void);
NERO_NFC_NODISCARD bool reader_tags_read_type4_ndef(void);
NERO_NFC_NODISCARD bool reader_tags_iso15693_inventory_step(void);
void reader_tags_read_dynamic_or_static_type5(void);

NERO_NFC_NODISCARD bool reader_tags_get_typea_info(reader_tag_typea_info_t *info);
NERO_NFC_NODISCARD bool reader_tags_get_type2_info(reader_tag_type2_info_t *info);
/* CC/page-3 only — for PC/SC storage READ BINARY (matches type5 CC probe weight). */
NERO_NFC_NODISCARD bool reader_tags_get_type2_storage_info(reader_tag_type2_info_t *info);
NERO_NFC_NODISCARD bool reader_tags_get_type4_info(reader_tag_type4_info_t *info);
NERO_NFC_NODISCARD bool reader_tags_get_type5_info(reader_tag_type5_info_t *info);
NERO_NFC_NODISCARD bool reader_tags_get_tag_info(reader_tag_info_t *info);
int reader_tags_load_type2_ndef_message(uint8_t *dst, uint16_t dst_cap);
int reader_tags_load_type5_ndef_message(uint8_t *dst, uint16_t dst_cap);
NERO_NFC_NODISCARD bool reader_tags_write_type2_ndef_message(const uint8_t *ndef,
                                                             uint16_t ndef_len);
NERO_NFC_NODISCARD bool reader_tags_write_type5_ndef_message(const uint8_t *ndef,
                                                             uint16_t ndef_len);
int reader_tags_type2_transceive(const uint8_t *tx, uint16_t tx_len, uint8_t *rx, uint16_t rx_max);
NERO_NFC_NODISCARD bool reader_tags_type2_write_page(uint8_t page, const uint8_t *data);
int reader_tags_type2_read_binary(uint16_t page, uint8_t *buf, uint16_t len);
int reader_tags_type5_transceive(const uint8_t *tx, uint16_t tx_len, uint8_t *rx, uint16_t rx_max);
NERO_NFC_NODISCARD bool reader_tags_type5_write_block(uint16_t block, const uint8_t *data,
                                                      uint8_t data_len);
int reader_tags_type5_read_binary(uint16_t block, uint8_t *buf, uint16_t len);

#ifdef __cplusplus
}
#endif
