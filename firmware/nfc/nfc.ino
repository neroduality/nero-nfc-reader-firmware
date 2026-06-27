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

/*
 * Combined NFC firmware — reader + writer in one flash image.
 *
 * Default mode: reader (override at build time with NFC_MODE=writer, or at
 * runtime by sending "mode writer\n" over the serial console).
 *
 * Build:  make            (or: make nfc)
 * Flash:  make flash  |  make flash-cdc
 * Mode:   NFC_MODE=writer make flash-cdc
 */

#include "src/nfc_app.h"

void setup() {
  nfc_app_setup();
}

void loop() {
  nfc_app_loop();
}
