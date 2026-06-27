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

#ifdef __cplusplus
extern "C" {
#endif

#if defined(NERO_HOST_UNIT_TEST_HOOKS)

void reader_hal_utest_reset(void);

void reader_hal_utest_set_millis(uint32_t ms);

void reader_hal_utest_advance_millis(uint32_t delta);

const uint8_t *reader_hal_utest_ccid_last_send(void);

uint16_t reader_hal_utest_ccid_last_send_len(void);

const uint8_t *reader_hal_utest_ccid_first_send(void);

uint16_t reader_hal_utest_ccid_first_send_len(void);

uint16_t reader_hal_utest_ccid_send_count(void);

uint16_t reader_hal_utest_ccid_time_extension_send_count(void);

uint16_t reader_hal_utest_ccid_notify_count(void);

NERO_NFC_NODISCARD bool reader_hal_utest_ccid_last_notify_present(void);

void reader_hal_utest_ccid_set_abort_pending(bool pending, uint8_t slot, uint8_t seq);

void reader_hal_utest_serial_feed(const char *text);

uint16_t reader_hal_utest_serial_available(void);

#endif

#ifdef __cplusplus
}
#endif
