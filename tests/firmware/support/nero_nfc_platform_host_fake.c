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

#include "nero_nfc_platform.h"

#include "nero_nfc_app.h"
#include "nero_nfc_null.h"

#include <stdint.h>

enum {
  HOST_FAKE_US_PER_MS = 1000u,
};

static uint32_t g_millis;
static uint32_t g_micros;
static char g_last_serial_char;
static int g_serial_available;
static int g_serial_read_byte = -1;
static uint8_t g_last_spi;
static uint8_t g_last_pin;
static uint8_t g_last_pin_mode;
static uint8_t g_last_pin_value;

void nero_nfc_platform_host_fake_reset(void) {
  g_millis = 0u;
  g_micros = 0u;
  g_last_serial_char = '\0';
  g_serial_available = 0;
  g_serial_read_byte = -1;
  g_last_spi = 0u;
  g_last_pin = 0u;
  g_last_pin_mode = 0u;
  g_last_pin_value = 0u;
  nero_nfc_app_t* active = nero_nfc_app_active();
  if (active != NERO_NFC_NULL) {
    (void)nero_nfc_app_unbind_active(active);
  }
}

void nero_nfc_platform_host_fake_set_millis(uint32_t ms) { g_millis = ms; }

void nero_nfc_platform_host_fake_set_serial_available(int count) {
  g_serial_available = count;
}

void nero_nfc_platform_host_fake_set_serial_read_byte(int value) {
  g_serial_read_byte = value;
}

char nero_nfc_platform_host_fake_last_serial_char(void) {
  return g_last_serial_char;
}

uint8_t nero_nfc_platform_host_fake_last_spi(void) { return g_last_spi; }

static uint32_t fake_millis(void* context) {
  (void)context;
  return g_millis;
}

static uint32_t fake_micros(void* context) {
  (void)context;
  return g_micros;
}

static void fake_delay_ms(void* context, uint32_t ms) {
  (void)context;
  g_millis += ms;
  g_micros += ms * (uint32_t)HOST_FAKE_US_PER_MS;
}

static void fake_delay_us(void* context, uint32_t us) {
  (void)context;
  g_micros += us;
  g_millis += us / (uint32_t)HOST_FAKE_US_PER_MS;
}

static void fake_serial_begin(void* context, uint32_t baud) {
  (void)context;
  (void)baud;
}

static bool fake_serial_ready(void* context) {
  (void)context;
  return true;
}

static void fake_serial_write_char(void* context, char c) {
  (void)context;
  g_last_serial_char = c;
}

static int fake_serial_available(void* context) {
  (void)context;
  return g_serial_available;
}

static int fake_serial_read_byte(void* context) {
  (void)context;
  return g_serial_read_byte;
}

static void fake_pin_mode(void* context, uint8_t pin, uint8_t mode) {
  (void)context;
  g_last_pin = pin;
  g_last_pin_mode = mode;
}

static void fake_digital_write(void* context, uint8_t pin, uint8_t value) {
  (void)context;
  g_last_pin = pin;
  g_last_pin_value = value;
}

static int fake_digital_read(void* context, uint8_t pin) {
  (void)context;
  (void)pin;
  return (int)g_last_pin_value;
}

static void fake_spi_begin(void* context) { (void)context; }

static void fake_spi_begin_transaction(void* context) { (void)context; }

static void fake_spi_end_transaction(void* context) { (void)context; }

static uint8_t fake_spi_transfer(void* context, uint8_t data) {
  (void)context;
  g_last_spi = data;
  return data;
}

nero_nfc_platform_ops_t nero_nfc_platform_host_fake_ops(void) {
  nero_nfc_platform_ops_t ops;
  ops.abi_version = NERO_NFC_PLATFORM_OPS_ABI_VERSION;
  ops.struct_size = sizeof(ops);
  ops.context = NERO_NFC_NULL;
  ops.millis = &fake_millis;
  ops.micros = &fake_micros;
  ops.delay_ms = &fake_delay_ms;
  ops.delay_us = &fake_delay_us;
  ops.service = NERO_NFC_NULL;
  ops.serial_begin = &fake_serial_begin;
  ops.serial_ready = &fake_serial_ready;
  ops.serial_write_char = &fake_serial_write_char;
  ops.serial_available = &fake_serial_available;
  ops.serial_read_byte = &fake_serial_read_byte;
  ops.pin_mode = &fake_pin_mode;
  ops.digital_write = &fake_digital_write;
  ops.digital_read = &fake_digital_read;
  ops.spi_begin = &fake_spi_begin;
  ops.spi_begin_transaction = &fake_spi_begin_transaction;
  ops.spi_end_transaction = &fake_spi_end_transaction;
  ops.spi_transfer = &fake_spi_transfer;
  return ops;
}
