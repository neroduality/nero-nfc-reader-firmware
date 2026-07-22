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

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum nero_nfc_product {
  NERO_NFC_PRODUCT_INVALID = 0,
  NERO_NFC_PRODUCT_READER = 1,
  NERO_NFC_PRODUCT_WRITER = 2,
  NERO_NFC_PRODUCT_COMBINED = 3,
} nero_nfc_product_t;

#ifdef __cplusplus
}
#endif
