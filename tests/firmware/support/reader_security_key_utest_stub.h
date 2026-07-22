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

void reader_security_key_utest_reset(void);
void reader_security_key_utest_set_open_session_ok(bool ok);
void reader_security_key_utest_set_copy_atr_ok(bool ok);
void reader_security_key_utest_set_apdu_response(const uint8_t* rsp,
                                                 uint16_t len);
uint16_t reader_security_key_utest_last_apdu_rsp_cap(void);
void reader_security_key_utest_set_select_fido_probe_ok(bool ok);
uint16_t reader_security_key_utest_select_fido_probe_count(void);
void reader_security_key_utest_set_abort_during_exchange(bool enabled);
uint16_t reader_security_key_utest_time_extension_binding_count(void);

#ifdef __cplusplus
}
#endif
