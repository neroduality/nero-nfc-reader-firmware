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

#include <stdbool.h>
#include <stdint.h>

typedef enum {
  WRITER_TYPE2_FAMILY_UNKNOWN = 0,
  WRITER_TYPE2_FAMILY_NTAG21X,
  WRITER_TYPE2_FAMILY_ST25TN,
} writer_type2_family_t;

#ifdef __cplusplus
extern "C" {
#endif

void writer_tag_write_reset_type4_session(void);
NERO_NFC_NODISCARD writer_type2_family_t writer_tag_identify_type2(void);
NERO_NFC_NODISCARD bool writer_tag_write_type2_ndef(writer_type2_family_t fam);
NERO_NFC_NODISCARD bool writer_tag_write_type4_ndef(void);
NERO_NFC_NODISCARD bool writer_tag_write_type5_ndef(void);
NERO_NFC_NODISCARD bool writer_tag_type5_inventory(void);

#ifdef __cplusplus
}
#endif
