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

#include "writer_hal_utest_stub.hpp"
#include "nero_nfc_null.h"

namespace {
enum {
  kTestLit1000u = 1000u,
};
}  // namespace

#include "writer_hal.h"

#include "nero_nfc_app.h"
#include "nero_nfc_board.h"
#include "nero_nfc_log.h"
#include "nero_nfc_platform_host_fake.h"
#include "writer_context.h"

#include <cstdint>
#include <string>

namespace {

std::string g_input;
std::string g_output;
uint32_t g_millis;
nero_nfc_app_storage_t g_app_storage;

}  // namespace

void WriterHalUtestReset() {
  nero_nfc_app_t* active = nero_nfc_app_active();
  if (active != NERO_NFC_NULL) {
    (void)nero_nfc_app_unbind_active(active);
  }
  nero_nfc_board_config_t board{};
  nero_nfc_board_config_defaults(&board);
  const nero_nfc_platform_ops_t kOps = nero_nfc_platform_host_fake_ops();
  (void)nero_nfc_app_init(&g_app_storage, &kOps, &board,
                          NERO_NFC_PRODUCT_COMBINED);
  writer_context_reset(writer_context_active());
  g_input.clear();
  g_output.clear();
  g_millis = 0u;
  nero_nfc_log_set_sink(&writer_hal_serial_write_char);
}

void WriterHalUtestFeed(const char* text) {
  if (text != NERO_NFC_NULL) {
    g_input.append(text);
  }
}

bool WriterHalUtestInputAvailable() { return !g_input.empty(); }

std::string WriterHalUtestOutput() { return g_output; }

void writer_hal_serial_begin(unsigned long baud) { (void)baud; }

bool writer_hal_serial_ready() { return true; }

void writer_hal_serial_write_char(char c) { g_output.push_back(c); }

bool writer_hal_serial_available() { return !g_input.empty(); }

int writer_hal_serial_read_byte() {
  if (g_input.empty()) {
    return -1;
  }
  const auto kCh = static_cast<unsigned char>(g_input.front());
  g_input.erase(0u, 1u);
  return static_cast<int>(kCh);
}

void writer_hal_delay_ms(uint32_t ms) { g_millis += ms; }

void writer_hal_delay_us(uint32_t us) { g_millis += us / kTestLit1000u; }

uint32_t writer_hal_millis() { return g_millis; }

uint32_t writer_hal_micros() { return g_millis * kTestLit1000u; }

void writer_hal_pin_mode(uint8_t pin, uint8_t mode) {
  (void)pin;
  (void)mode;
}

void writer_hal_digital_write(uint8_t pin, uint8_t value) {
  (void)pin;
  (void)value;
}

int writer_hal_digital_read(uint8_t pin) {
  (void)pin;
  return 0;
}

void writer_hal_spi_begin() {}

void writer_hal_spi_begin_transaction() {}

void writer_hal_spi_end_transaction() {}

uint8_t writer_hal_spi_transfer(uint8_t data) { return data; }
