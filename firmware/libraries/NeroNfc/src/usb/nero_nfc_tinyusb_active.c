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

#include "nero_nfc_tinyusb_active.h"

#include "nero_nfc_null.h"

/*
 * TinyUSB's device callbacks have no caller-provided context. Keep the sole
 * process-wide binding here and make a second live application fail to bind.
 * All mutable NFC state remains in the referenced caller-owned application.
 */
static nero_nfc_app_t* g_tinyusb_active_instance = NERO_NFC_NULL;

bool nero_nfc_tinyusb_active_bind(nero_nfc_app_t* app) {
  if ((app == NERO_NFC_NULL) || ((g_tinyusb_active_instance != NERO_NFC_NULL) &&
                                 (g_tinyusb_active_instance != app))) {
    return false;
  }
  g_tinyusb_active_instance = app;
  return true;
}

void nero_nfc_tinyusb_active_unbind(void) {
  g_tinyusb_active_instance = NERO_NFC_NULL;
}

nero_nfc_app_t* nero_nfc_tinyusb_active_get(void) {
  return g_tinyusb_active_instance;
}
