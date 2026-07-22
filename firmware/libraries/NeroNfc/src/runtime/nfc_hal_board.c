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
 * Combined reader+writer HAL for firmware/nfc (single SPI / UART stack).
 * Arduino I/O is owned by NfcArduinoPort; this unit keeps combined-mode
 * buffering and mode-scan behavior.
 */

#include "nero_nfc_log.h"
#include "nero_nfc_null.h"

#if defined(NERO_CCID_USB_BUILD)
#include "tusb.h"
#endif

#include <stdint.h>

#include "nero_nfc_app.h"
#include "nero_nfc_platform.h"
#include "nfc_combined_shell.h"
#include "nfc_runtime_mode_poll.h"
#include "reader_hal.h"
#include "writer_hal.h"

#if defined(NERO_CCID_USB_BUILD) && defined(NERO_CCID_STM32_USB_BUILD)
#include "reader_hal_ccid_usb.h"
#endif

void nfc_hal_usb_begin(void) {
#if defined(NERO_CCID_USB_BUILD) && defined(NERO_CCID_STM32_USB_BUILD)
  reader_hal_ccid_usb_begin();
#endif
}

#if !defined(NERO_CCID_ONLY_BUILD)
#ifndef NFC_HAL_RXBUF_CAP
#define NFC_HAL_RXBUF_CAP 128u
#endif

void nfc_hal_preload_serial(void) {
  nero_nfc_app_t* app = nero_nfc_app_active();
  if (app == NERO_NFC_NULL) {
    return;
  }
  nero_nfc_app_serial_preload(app);
}

int nfc_hal_pushback_available(void) {
  nero_nfc_app_t* app = nero_nfc_app_active();
  if (app == NERO_NFC_NULL) {
    return 0;
  }
  return nero_nfc_app_serial_pushback_available(app);
}

int nfc_hal_pushback_read(void) {
  nero_nfc_app_t* app = nero_nfc_app_active();
  if (app == NERO_NFC_NULL) {
    return -1;
  }
  return nero_nfc_app_serial_pushback_read(app);
}

void nfc_hal_pushback_return(const uint8_t* bytes, uint16_t len) {
  nero_nfc_app_t* app = nero_nfc_app_active();
  if (app == NERO_NFC_NULL) {
    return;
  }
  nero_nfc_app_serial_pushback_return(app, bytes, len);
}
#else
void nfc_hal_preload_serial(void) {}

int nfc_hal_pushback_available(void) { return 0; }

int nfc_hal_pushback_read(void) { return -1; }

void nfc_hal_pushback_return(const uint8_t* bytes, uint16_t len) {
  (void)bytes;
  (void)len;
}
#endif

void reader_hal_serial_begin(unsigned long baud) {
#if !defined(NERO_CCID_ONLY_BUILD)
  nero_nfc_platform_serial_begin((uint32_t)(baud));
#else
  (void)baud;
#endif
  nero_nfc_log_set_sink(&reader_hal_serial_write_char);
}

bool reader_hal_serial_ready(void) {
#if !defined(NERO_CCID_ONLY_BUILD)
  return nero_nfc_platform_serial_ready();
#else
  return false;
#endif
}

void reader_hal_serial_write_char(char c) {
#if !defined(NERO_CCID_ONLY_BUILD)
  nero_nfc_platform_serial_write_char(c);
#else
  (void)c;
#endif
}

int reader_hal_serial_available(void) {
#if !defined(NERO_CCID_ONLY_BUILD)
  nfc_hal_preload_serial();
  return nfc_hal_pushback_available() + nero_nfc_platform_serial_available();
#else
  return 0;
#endif
}

int reader_hal_serial_read_byte(void) {
#if !defined(NERO_CCID_ONLY_BUILD)
  nfc_hal_preload_serial();
  if (nfc_app_scan_mode_uart()) {
    return -1;
  }
  if (nfc_hal_pushback_available() > 0) {
    return nfc_hal_pushback_read();
  }
  return nero_nfc_platform_serial_read_byte();
#else
  return -1;
#endif
}

void reader_hal_delay_ms(uint32_t ms) {
#if defined(NERO_CCID_USB_BUILD)
  while (ms-- > 0u) {
    reader_hal_service();
    nero_nfc_platform_delay_ms(1u);
  }
#else
  nero_nfc_platform_delay_ms(ms);
#endif
}

void reader_hal_service(void) {
#if defined(NERO_CCID_USB_BUILD)
  tud_task();
#else
  nero_nfc_platform_service();
#endif
}

void reader_hal_delay_us(uint32_t us) { nero_nfc_platform_delay_us(us); }

uint32_t reader_hal_millis(void) { return nero_nfc_platform_millis(); }

uint32_t reader_hal_micros(void) { return nero_nfc_platform_micros(); }

void reader_hal_pin_mode(uint8_t pin, uint8_t mode) {
  nero_nfc_platform_pin_mode(pin, mode == READER_HAL_PIN_OUTPUT
                                      ? NERO_NFC_PIN_OUTPUT
                                      : NERO_NFC_PIN_INPUT);
}

void reader_hal_digital_write(uint8_t pin, uint8_t value) {
  nero_nfc_platform_digital_write(pin, value);
}

int reader_hal_digital_read(uint8_t pin) {
  return nero_nfc_platform_digital_read(pin);
}

void reader_hal_spi_begin(void) { nero_nfc_platform_spi_begin(); }

void reader_hal_spi_begin_transaction(void) {
  nero_nfc_platform_spi_begin_transaction();
}

void reader_hal_spi_end_transaction(void) {
  nero_nfc_platform_spi_end_transaction();
}

uint8_t reader_hal_spi_transfer(uint8_t data) {
  return nero_nfc_platform_spi_transfer(data);
}

void writer_hal_serial_begin(unsigned long baud) {
#if !defined(NERO_CCID_ONLY_BUILD)
  const nero_nfc_app_t* app = nero_nfc_app_active();
  if ((app != NERO_NFC_NULL) &&
      ((nero_nfc_app_product(app) == NERO_NFC_PRODUCT_WRITER) ||
       !nero_nfc_platform_serial_ready())) {
    nero_nfc_platform_serial_begin((uint32_t)(baud));
  }
#else
  (void)baud;
#endif
  nero_nfc_log_set_sink(&writer_hal_serial_write_char);
}

bool writer_hal_serial_ready(void) {
#if !defined(NERO_CCID_ONLY_BUILD)
  return nero_nfc_platform_serial_ready();
#else
  return false;
#endif
}

void writer_hal_serial_write_char(char c) {
#if !defined(NERO_CCID_ONLY_BUILD)
  nero_nfc_platform_serial_write_char(c);
#else
  (void)c;
#endif
}

bool writer_hal_serial_available(void) {
#if !defined(NERO_CCID_ONLY_BUILD)
  nfc_hal_preload_serial();
  return (nfc_hal_pushback_available() > 0) ||
         (nero_nfc_platform_serial_available() > 0);
#else
  return false;
#endif
}

int writer_hal_serial_read_byte(void) {
#if !defined(NERO_CCID_ONLY_BUILD)
  nfc_hal_preload_serial();
  if (nfc_app_scan_mode_uart()) {
    return -1;
  }
  if (nfc_hal_pushback_available() > 0) {
    return nfc_hal_pushback_read();
  }
  if (nero_nfc_platform_serial_available() <= 0) {
    return -1;
  }
  return nero_nfc_platform_serial_read_byte();
#else
  return -1;
#endif
}

void writer_hal_delay_ms(uint32_t ms) { nero_nfc_platform_delay_ms(ms); }

void writer_hal_delay_us(uint32_t us) { nero_nfc_platform_delay_us(us); }

uint32_t writer_hal_millis(void) { return nero_nfc_platform_millis(); }

uint32_t writer_hal_micros(void) { return nero_nfc_platform_micros(); }

void writer_hal_pin_mode(uint8_t pin, uint8_t mode) {
  nero_nfc_platform_pin_mode(pin, mode == WRITER_HAL_PIN_OUTPUT
                                      ? NERO_NFC_PIN_OUTPUT
                                      : NERO_NFC_PIN_INPUT);
}

void writer_hal_digital_write(uint8_t pin, uint8_t value) {
  nero_nfc_platform_digital_write(pin, value);
}

int writer_hal_digital_read(uint8_t pin) {
  return nero_nfc_platform_digital_read(pin);
}

void writer_hal_spi_begin(void) { nero_nfc_platform_spi_begin(); }

void writer_hal_spi_begin_transaction(void) {
  nero_nfc_platform_spi_begin_transaction();
}

void writer_hal_spi_end_transaction(void) {
  nero_nfc_platform_spi_end_transaction();
}

uint8_t writer_hal_spi_transfer(uint8_t data) {
  return nero_nfc_platform_spi_transfer(data);
}

void nfc_combined_shell_serial_begin(unsigned long baud) {
#if !defined(NERO_CCID_ONLY_BUILD)
  nero_nfc_platform_serial_begin((uint32_t)(baud));
#else
  (void)baud;
#endif
}

bool nfc_combined_shell_serial_ready(void) {
#if !defined(NERO_CCID_ONLY_BUILD)
  return nero_nfc_platform_serial_ready();
#else
  return false;
#endif
}

void nfc_combined_shell_serial_write_byte(uint8_t value) {
#if !defined(NERO_CCID_ONLY_BUILD)
  nero_nfc_platform_serial_write_char((char)(value));
#else
  (void)value;
#endif
}

uint32_t nfc_combined_shell_millis(void) { return nero_nfc_platform_millis(); }
