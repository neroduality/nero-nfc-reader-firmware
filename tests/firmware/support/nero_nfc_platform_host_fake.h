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

#include "nero_nfc_platform.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void nero_nfc_platform_host_fake_reset(void);
nero_nfc_platform_ops_t nero_nfc_platform_host_fake_ops(void);
void nero_nfc_platform_host_fake_set_millis(uint32_t ms);
void nero_nfc_platform_host_fake_set_serial_available(int count);
void nero_nfc_platform_host_fake_set_serial_read_byte(int value);
char nero_nfc_platform_host_fake_last_serial_char(void);
uint8_t nero_nfc_platform_host_fake_last_spi(void);

#ifdef __cplusplus
}
#endif
