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

/* Combined-mode serial and USB bring-up (runtime/nfc_hal_board.c). */
void nfc_hal_usb_begin(void);
void nfc_hal_preload_serial(void);
int nfc_hal_pushback_available(void);
int nfc_hal_pushback_read(void);
void nfc_hal_pushback_return(const uint8_t* bytes, uint16_t len);

#ifdef __cplusplus
}
#endif
