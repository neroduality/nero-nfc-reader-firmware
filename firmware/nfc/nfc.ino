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

#include <NeroNfc.h>
#include <NeroNfcArduino.hpp>

static NfcArduinoPort g_port;
static nero_nfc_app_storage_t g_storage;
static nero_nfc_app_t *g_app = nullptr;

void setup() {
  nero_nfc_board_config_t board;
  nero_nfc_platform_ops_t ops;

  nero_nfc_board_config_defaults(&board);
  g_port.SetSpiClockHz(board.spi_clock_hz);
  ops = g_port.MakeOps();
#if defined(NERO_CCID_ONLY_BUILD)
  g_app = nero_nfc_app_init(&g_storage, &ops, &board,
                            NERO_NFC_PRODUCT_READER);
#else
  g_app =
      nero_nfc_app_init(&g_storage, &ops, &board, NERO_NFC_PRODUCT_COMBINED);
#endif
  if (g_app == nullptr) {
    return;
  }
  nero_nfc_app_begin(g_app);
}

void loop() { nero_nfc_app_step(g_app); }
