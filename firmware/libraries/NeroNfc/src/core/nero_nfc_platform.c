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
#include "nero_nfc_mem_util.h"
#include "nero_nfc_null.h"

static const nero_nfc_platform_ops_t* active_ops(void) {
  nero_nfc_app_t* app = nero_nfc_app_active();
  if (app == NERO_NFC_NULL) {
    return NERO_NFC_NULL;
  }
  return nero_nfc_app_platform_ops(app);
}

#define G_OPS (*active_ops())
#define G_BOUND (active_ops() != NERO_NFC_NULL)

bool nero_nfc_platform_ops_validate(const nero_nfc_platform_ops_t* ops) {
  if (ops == NERO_NFC_NULL) {
    return false;
  }
  if (ops->abi_version != NERO_NFC_PLATFORM_OPS_ABI_VERSION) {
    return false;
  }
  if (ops->struct_size < sizeof(nero_nfc_platform_ops_t)) {
    return false;
  }
  if ((ops->millis == NERO_NFC_NULL) || (ops->micros == NERO_NFC_NULL) ||
      (ops->delay_ms == NERO_NFC_NULL) || (ops->delay_us == NERO_NFC_NULL) ||
      (ops->serial_begin == NERO_NFC_NULL) ||
      (ops->serial_ready == NERO_NFC_NULL) ||
      (ops->serial_write_char == NERO_NFC_NULL) ||
      (ops->serial_available == NERO_NFC_NULL) ||
      (ops->serial_read_byte == NERO_NFC_NULL) ||
      (ops->pin_mode == NERO_NFC_NULL) ||
      (ops->digital_write == NERO_NFC_NULL) ||
      (ops->digital_read == NERO_NFC_NULL) ||
      (ops->spi_begin == NERO_NFC_NULL) ||
      (ops->spi_begin_transaction == NERO_NFC_NULL) ||
      (ops->spi_end_transaction == NERO_NFC_NULL) ||
      (ops->spi_transfer == NERO_NFC_NULL)) {
    return false;
  }
  return true;
}

void nero_nfc_platform_ops_copy(nero_nfc_platform_ops_t* dst,
                                const nero_nfc_platform_ops_t* src) {
  if ((dst == NERO_NFC_NULL) || (src == NERO_NFC_NULL)) {
    return;
  }
  (void)nero_nfc_copy_bytes(dst, sizeof(*dst), 0u, src, sizeof(*src));
  dst->struct_size = sizeof(nero_nfc_platform_ops_t);
}

uint32_t nero_nfc_platform_millis(void) {
  if (!G_BOUND) {
    return 0u;
  }
  return G_OPS.millis(G_OPS.context);
}

uint32_t nero_nfc_platform_micros(void) {
  if (!G_BOUND) {
    return 0u;
  }
  return G_OPS.micros(G_OPS.context);
}

void nero_nfc_platform_delay_ms(uint32_t ms) {
  if (!G_BOUND) {
    return;
  }
  G_OPS.delay_ms(G_OPS.context, ms);
}

void nero_nfc_platform_delay_us(uint32_t us) {
  if (!G_BOUND) {
    return;
  }
  G_OPS.delay_us(G_OPS.context, us);
}

void nero_nfc_platform_service(void) {
  if (!G_BOUND || (G_OPS.service == NERO_NFC_NULL)) {
    return;
  }
  G_OPS.service(G_OPS.context);
}

void nero_nfc_platform_serial_begin(uint32_t baud) {
  if (!G_BOUND) {
    return;
  }
  G_OPS.serial_begin(G_OPS.context, baud);
}

bool nero_nfc_platform_serial_ready(void) {
  if (!G_BOUND) {
    return false;
  }
  return G_OPS.serial_ready(G_OPS.context);
}

void nero_nfc_platform_serial_write_char(char c) {
  if (!G_BOUND) {
    return;
  }
  G_OPS.serial_write_char(G_OPS.context, c);
}

int nero_nfc_platform_serial_available(void) {
  if (!G_BOUND) {
    return 0;
  }
  return G_OPS.serial_available(G_OPS.context);
}

int nero_nfc_platform_serial_read_byte(void) {
  if (!G_BOUND) {
    return -1;
  }
  return G_OPS.serial_read_byte(G_OPS.context);
}

void nero_nfc_platform_pin_mode(uint8_t pin, uint8_t mode) {
  if (!G_BOUND) {
    return;
  }
  G_OPS.pin_mode(G_OPS.context, pin, mode);
}

void nero_nfc_platform_digital_write(uint8_t pin, uint8_t value) {
  if (!G_BOUND) {
    return;
  }
  G_OPS.digital_write(G_OPS.context, pin, value);
}

int nero_nfc_platform_digital_read(uint8_t pin) {
  if (!G_BOUND) {
    return 0;
  }
  return G_OPS.digital_read(G_OPS.context, pin);
}

void nero_nfc_platform_spi_begin(void) {
  if (!G_BOUND) {
    return;
  }
  G_OPS.spi_begin(G_OPS.context);
}

void nero_nfc_platform_spi_begin_transaction(void) {
  if (!G_BOUND) {
    return;
  }
  G_OPS.spi_begin_transaction(G_OPS.context);
}

void nero_nfc_platform_spi_end_transaction(void) {
  if (!G_BOUND) {
    return;
  }
  G_OPS.spi_end_transaction(G_OPS.context);
}

uint8_t nero_nfc_platform_spi_transfer(uint8_t data) {
  if (!G_BOUND) {
    return 0u;
  }
  return G_OPS.spi_transfer(G_OPS.context, data);
}
