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

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*reader_security_key_utest_iso_dep_transceive_fn)(const uint8_t *tx, uint16_t tx_len,
                                                         uint8_t *rx, uint16_t rx_max,
                                                         bool with_crc, uint16_t timeout_ms);

void reader_security_key_utest_reset_iso_dep(void);
void reader_security_key_utest_set_iso_dep_transceive(reader_security_key_utest_iso_dep_transceive_fn fn);

#ifdef __cplusplus
}
#endif
