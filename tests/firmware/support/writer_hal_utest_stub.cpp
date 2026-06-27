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


#include "nero_nfc_null.h"
#include "writer_hal_utest_stub.h"

#include "writer_hal.h"

#include "nero_nfc_log.h"

#include <cstdint>
#include <string>

namespace {

std::string g_input;
std::string g_output;
uint32_t g_millis;

} // namespace

void writer_hal_utest_reset(void) {
  g_input.clear();
  g_output.clear();
  g_millis = 0u;
}

void writer_hal_utest_feed(const char *text) {
  if (text != NERO_NFC_NULL) {
    g_input.append(text);
  }
}

bool writer_hal_utest_input_available(void) { return !g_input.empty(); }

std::string writer_hal_utest_output(void) { return g_output; }

void writer_hal_serial_begin(unsigned long baud) { (void)baud; }

bool writer_hal_serial_ready(void) { return true; }

void writer_hal_serial_write_char(char c) { g_output.push_back(c); }

extern "C" void nero_nfc_log_putc(char c) { writer_hal_serial_write_char(c); }

bool writer_hal_serial_available(void) { return !g_input.empty(); }

int writer_hal_serial_read_byte(void) {
  if (g_input.empty()) {
    return -1;
  }
  const unsigned char ch = static_cast<unsigned char>(g_input.front());
  g_input.erase(0u, 1u);
  return static_cast<int>(ch);
}

void writer_hal_delay_ms(uint32_t ms) { g_millis += ms; }

void writer_hal_delay_us(uint32_t us) { g_millis += us / 1000u; }

uint32_t writer_hal_millis(void) { return g_millis; }

uint32_t writer_hal_micros(void) { return g_millis * 1000u; }

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

void writer_hal_spi_begin(void) {}

void writer_hal_spi_begin_transaction(void) {}

void writer_hal_spi_end_transaction(void) {}

uint8_t writer_hal_spi_transfer(uint8_t data) { return data; }
