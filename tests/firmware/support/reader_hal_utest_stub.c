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

#include "reader_hal.h"
#include "reader_hal_utest.h"
#include "nero_nfc_mem_util.h"
#include "nfc_ccid_frame.h"

#include <string.h>

enum {
  READER_HAL_UTEST_SEND_BUF_CAP = 4096u,
  READER_HAL_UTEST_SERIAL_INPUT_CAP = 10000u,
  READER_HAL_UTEST_US_PER_MS = 1000u,
};

static uint32_t g_millis;
static uint8_t g_first_send[READER_HAL_UTEST_SEND_BUF_CAP];
static uint16_t g_first_send_len;
static uint8_t g_last_send[READER_HAL_UTEST_SEND_BUF_CAP];
static uint16_t g_last_send_len;
static uint16_t g_send_count;
static uint16_t g_time_extension_send_count;
static bool g_send_ok;
static uint16_t g_notify_count;
static bool g_last_notify_present;
static bool g_abort_pending;
static uint8_t g_abort_slot;
static uint8_t g_abort_seq;
static char g_serial_input[READER_HAL_UTEST_SERIAL_INPUT_CAP];
static uint16_t g_serial_input_len;
static uint16_t g_serial_input_off;

void reader_hal_utest_reset(void) {
  g_millis = 0u;
  g_first_send_len = 0u;
  g_last_send_len = 0u;
  g_send_count = 0u;
  g_time_extension_send_count = 0u;
  g_send_ok = true;
  g_notify_count = 0u;
  g_last_notify_present = false;
  g_abort_pending = false;
  g_abort_slot = 0u;
  g_abort_seq = 0u;
  g_serial_input_len = 0u;
  g_serial_input_off = 0u;
}

void reader_hal_utest_set_millis(uint32_t ms) { g_millis = ms; }

void reader_hal_utest_advance_millis(uint32_t delta) { g_millis += delta; }

const uint8_t* reader_hal_utest_ccid_last_send(void) { return g_last_send; }

uint16_t reader_hal_utest_ccid_last_send_len(void) { return g_last_send_len; }

const uint8_t* reader_hal_utest_ccid_first_send(void) { return g_first_send; }

uint16_t reader_hal_utest_ccid_first_send_len(void) { return g_first_send_len; }

uint16_t reader_hal_utest_ccid_send_count(void) { return g_send_count; }

uint16_t reader_hal_utest_ccid_time_extension_send_count(void) {
  return g_time_extension_send_count;
}

void reader_hal_utest_ccid_set_send_ok(bool ok) { g_send_ok = ok; }

uint16_t reader_hal_utest_ccid_notify_count(void) { return g_notify_count; }

bool reader_hal_utest_ccid_last_notify_present(void) {
  return g_last_notify_present;
}

void reader_hal_utest_ccid_set_abort_pending(bool pending, uint8_t slot,
                                             uint8_t seq) {
  g_abort_pending = pending;
  g_abort_slot = slot;
  g_abort_seq = seq;
}

void reader_hal_utest_serial_feed(const char* text) {
  size_t len = 0u;

  if ((text == NERO_NFC_NULL) ||
      !nero_nfc_bounded_strlen(text, sizeof(g_serial_input), &len)) {
    return;
  }
  if (len > sizeof(g_serial_input)) {
    len = sizeof(g_serial_input);
  }
  if (!nero_nfc_copy_bytes(g_serial_input, sizeof(g_serial_input), 0u, text,
                           len)) {
    return;
  }
  g_serial_input_len = (uint16_t)len;
  g_serial_input_off = 0u;
}

uint16_t reader_hal_utest_serial_available(void) {
  return (uint16_t)(g_serial_input_len - g_serial_input_off);
}

void reader_hal_serial_begin(unsigned long baud) { (void)baud; }

bool reader_hal_serial_ready(void) { return false; }

void reader_hal_serial_write_char(char c) { (void)c; }

int reader_hal_serial_available(void) {
  return (int)reader_hal_utest_serial_available();
}

int reader_hal_serial_read_byte(void) {
  if (g_serial_input_off >= g_serial_input_len) {
    return -1;
  }
  return (int)(uint8_t)g_serial_input[g_serial_input_off++];
}

void reader_hal_delay_us(uint32_t us) { (void)us; }

void reader_hal_delay_ms(uint32_t ms) { (void)ms; }

void reader_hal_service(void) {}

uint32_t reader_hal_millis(void) { return g_millis; }

uint32_t reader_hal_micros(void) {
  return g_millis * READER_HAL_UTEST_US_PER_MS;
}

void reader_hal_pin_mode(uint8_t pin, uint8_t mode) {
  (void)pin;
  (void)mode;
}

void reader_hal_digital_write(uint8_t pin, uint8_t value) {
  (void)pin;
  (void)value;
}

int reader_hal_digital_read(uint8_t pin) {
  (void)pin;
  return 0;
}

void reader_hal_spi_begin(void) {}

void reader_hal_spi_begin_transaction(void) {}

void reader_hal_spi_end_transaction(void) {}

uint8_t reader_hal_spi_transfer(uint8_t data) { return data; }

bool reader_hal_ccid_recv(uint8_t* buf, uint16_t* len_io) {
  if (len_io != NERO_NFC_NULL) {
    if ((buf != NERO_NFC_NULL) && (*len_io > 0u)) {
      if (!nero_nfc_store_u8(buf, (size_t)(*len_io), (size_t)(0),
                             (uint8_t)(0u))) {
        return false;
      }
    }
    *len_io = 0u;
  }
  return false;
}

bool reader_hal_ccid_peek(const uint8_t** buf_out, uint16_t* len_out) {
  (void)buf_out;
  if (len_out != NERO_NFC_NULL) {
    *len_out = 0u;
  }
  return false;
}

void reader_hal_ccid_release(void) {}

bool reader_hal_ccid_send(const uint8_t* buf, uint16_t len,
                          uint32_t deadline_ms) {
  (void)deadline_ms;
  if ((buf == NERO_NFC_NULL) || (len == 0u)) {
    return false;
  }
  if (len > sizeof(g_last_send)) {
    len = (uint16_t)sizeof(g_last_send);
  }
  if (g_send_count == 0u) {
    (void)nero_nfc_copy_bytes(g_first_send, (uint16_t)sizeof(g_first_send), 0u,
                              buf, len);
    g_first_send_len = len;
  }
  (void)nero_nfc_copy_bytes(g_last_send, (uint16_t)sizeof(g_last_send), 0u, buf,
                            len);
  g_last_send_len = len;
  if ((len >= NFC_CCID_BULK_HEADER_LEN) &&
      ((nero_nfc_u8_at(buf, (size_t)len,
                       (size_t)(NFC_CCID_BULK_LEVEL_PARAM_OFFSET)) &
        NFC_CCID_ICC_CMD_TIME_EXTENSION) != 0u)) {
    g_time_extension_send_count++;
  }
  g_send_count++;
  return g_send_ok;
}

void reader_hal_ccid_notify_slot_change(bool card_present) {
  g_last_notify_present = card_present;
  g_notify_count++;
}

bool reader_hal_ccid_abort_request_pending(uint8_t* slot_out,
                                           uint8_t* seq_out) {
  if (!g_abort_pending) {
    return false;
  }
  if (slot_out != NERO_NFC_NULL) {
    *slot_out = g_abort_slot;
  }
  if (seq_out != NERO_NFC_NULL) {
    *seq_out = g_abort_seq;
  }
  return true;
}

void reader_hal_ccid_clear_abort_request(uint8_t slot, uint8_t seq) {
  (void)slot;
  (void)seq;
  g_abort_pending = false;
}
