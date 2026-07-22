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

typedef enum {
  NFC_SESSION_OWNER_NONE = 0,
  NFC_SESSION_OWNER_CCID = 1,
} nfc_session_owner_t;

nfc_session_owner_t nfc_session_owner_get(void);

void nfc_session_owner_set(nfc_session_owner_t o);

#ifdef __cplusplus
}
#endif
