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

#include <Arduino.h>
#include <SPI.h>

#if defined(NERO_CCID_USB_BUILD)
#include "tusb.h"
#endif
#include "nfc_board_defaults.h"
#include "reader_hal.h"

static SPISettings g_reader_spi_settings(NFC_BOARD_SPI_CLOCK_HZ, MSBFIRST, SPI_MODE1);

void reader_hal_serial_begin(unsigned long baud) {
  Serial.begin(baud);
}

bool reader_hal_serial_ready(void) {
  return (bool)Serial;
}

void reader_hal_serial_write_char(char c) {
  Serial.write(static_cast<uint8_t>(c));
}

extern "C" void nero_nfc_log_putc(char c) {
  reader_hal_serial_write_char(c);
}

int reader_hal_serial_available(void) {
  return static_cast<int>(Serial.available());
}

int reader_hal_serial_read_byte(void) {
  return Serial.read();
}

void reader_hal_delay_ms(uint32_t ms) {
#if defined(NERO_CCID_USB_BUILD)
  while (ms-- > 0u) {
    reader_hal_service();
    delay(1u);
  }
#else
  delay(ms);
#endif
}

void reader_hal_service(void) {
#if defined(NERO_CCID_USB_BUILD)
  tud_task();
#endif
}

void reader_hal_delay_us(uint32_t us) {
  delayMicroseconds(us);
}

uint32_t reader_hal_millis(void) {
  return millis();
}

uint32_t reader_hal_micros(void) {
  return micros();
}

void reader_hal_pin_mode(uint8_t pin, uint8_t mode) {
  pinMode(pin, mode == READER_HAL_PIN_OUTPUT ? OUTPUT : INPUT);
}

void reader_hal_digital_write(uint8_t pin, uint8_t value) {
  digitalWrite(pin, value ? HIGH : LOW);
}

int reader_hal_digital_read(uint8_t pin) {
  return digitalRead(pin);
}

void reader_hal_spi_begin(void) {
  SPI.begin();
}

void reader_hal_spi_begin_transaction(void) {
  SPI.beginTransaction(g_reader_spi_settings);
}

void reader_hal_spi_end_transaction(void) {
  SPI.endTransaction();
}

uint8_t reader_hal_spi_transfer(uint8_t data) {
  return SPI.transfer(data);
}
