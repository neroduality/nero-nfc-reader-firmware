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

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
  NERO_NFC_FORMAT_SNPRINTF_DEC_CAP = 16u,
  NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP = 8u,
};

int nero_nfc_snprintf(char *buf, size_t cap, const char *fmt, ...);
int nero_nfc_vsnprintf(char *buf, size_t cap, const char *fmt, va_list args);

#ifdef __cplusplus
}
#endif
