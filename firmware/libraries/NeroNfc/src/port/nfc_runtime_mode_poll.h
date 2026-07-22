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

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Combined firmware (nfc.ino): nfc_app.c implements these so UART "mode
 * reader/writer" still works while reader_loop blocks in its tag-removal wait.
 * Standalone reader/writer sketches link the
 * small *_runtime_mode_poll.c stubs in this repo.
 */

NERO_NFC_NODISCARD bool nfc_app_poll_mode_switch(void);
NERO_NFC_NODISCARD bool nfc_app_runtime_is_reader(void);

/* Caller must nfc_hal_preload_serial() first: scan ring for mode lines. True if
 * mode changed. */
NERO_NFC_NODISCARD bool nfc_app_scan_mode_uart(void);

#ifdef __cplusplus
}
#endif
