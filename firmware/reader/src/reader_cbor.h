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

struct cbor_reader_t {
  const uint8_t *data;
  uint16_t len;
  uint16_t pos;
};

NERO_NFC_NODISCARD bool cbor_has_remaining(const cbor_reader_t *c, uint32_t count);
NERO_NFC_NODISCARD bool cbor_at_end(const cbor_reader_t *c);
uint8_t cbor_next(cbor_reader_t *c);
NERO_NFC_NODISCARD bool cbor_read_head(cbor_reader_t *c, uint8_t *major, uint32_t *value);
NERO_NFC_NODISCARD bool cbor_read_uint(cbor_reader_t *c, uint32_t *value);
NERO_NFC_NODISCARD bool cbor_read_text(cbor_reader_t *c, char *buffer, uint16_t buffer_len);
NERO_NFC_NODISCARD bool cbor_read_bytes(cbor_reader_t *c, uint8_t *buffer, uint16_t buffer_len,
                                        uint16_t *out_len);
NERO_NFC_NODISCARD bool cbor_read_bytes_indefinite(cbor_reader_t *c, uint8_t *buffer,
                                                   uint16_t buffer_len, uint16_t *out_len);
NERO_NFC_NODISCARD bool cbor_read_bytes_flexible(cbor_reader_t *c, uint8_t *buffer,
                                                 uint16_t buffer_len, uint16_t *out_len);
NERO_NFC_NODISCARD bool cbor_read_bytes_maybe_tagged(cbor_reader_t *c, uint8_t *buffer,
                                                     uint16_t buffer_len, uint16_t *out_len);
NERO_NFC_NODISCARD bool cbor_read_legacy_signature_tail(cbor_reader_t *c, uint8_t *buffer,
                                                        uint16_t buffer_len, uint16_t *out_len);
NERO_NFC_NODISCARD bool cbor_skip(cbor_reader_t *c);
