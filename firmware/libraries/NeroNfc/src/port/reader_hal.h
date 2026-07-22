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

enum {
  READER_HAL_PIN_INPUT = 0,
  READER_HAL_PIN_OUTPUT = 1,
};

void reader_hal_serial_begin(unsigned long baud);
NERO_NFC_NODISCARD bool reader_hal_serial_ready(void);
void reader_hal_serial_write_char(char c);
int reader_hal_serial_available(void);
/* Returns byte 0–255 from USB serial, or -1 if none. */
int reader_hal_serial_read_byte(void);
void reader_hal_delay_us(uint32_t us);
void reader_hal_delay_ms(uint32_t ms);
void reader_hal_service(void);
uint32_t reader_hal_millis(void);
uint32_t reader_hal_micros(void);

void reader_hal_pin_mode(uint8_t pin, uint8_t mode);
void reader_hal_digital_write(uint8_t pin, uint8_t value);
int reader_hal_digital_read(uint8_t pin);

void reader_hal_spi_begin(void);
void reader_hal_spi_begin_transaction(void);
void reader_hal_spi_end_transaction(void);
uint8_t reader_hal_spi_transfer(uint8_t data);

#if defined(NERO_CCID_USB_BUILD)

NERO_NFC_NODISCARD bool reader_hal_ccid_recv(uint8_t* buf, uint16_t* len_io);

NERO_NFC_NODISCARD bool reader_hal_ccid_peek(const uint8_t** buf_out,
                                             uint16_t* len_out);

void reader_hal_ccid_release(void);

NERO_NFC_NODISCARD bool reader_hal_ccid_send(const uint8_t* buf, uint16_t len,
                                             uint32_t deadline_ms);

void reader_hal_ccid_notify_slot_change(bool card_present);

NERO_NFC_NODISCARD bool reader_hal_ccid_abort_request_pending(uint8_t* slot_out,
                                                              uint8_t* seq_out);

void reader_hal_ccid_clear_abort_request(uint8_t slot, uint8_t seq);

#endif /* NERO_CCID_USB_BUILD */

#ifdef __cplusplus
}
#endif
