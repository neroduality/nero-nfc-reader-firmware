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

NERO_NFC_NODISCARD bool reader_security_key_select_fido_probe(bool verbose,
                                                              bool follow_get_response,
                                                              uint8_t *rsp_out, uint16_t rsp_cap,
                                                              uint16_t *rsp_len_out);

#if defined(NERO_CCID_USB_BUILD)

void reader_security_key_ccid_release_iso_session();

NERO_NFC_NODISCARD bool reader_security_key_ccid_open_iso_session();

NERO_NFC_NODISCARD bool
reader_security_key_pcsc_contactless_copy_atr(uint8_t *dst, uint16_t dst_cap, uint16_t *alen_io);

using reader_security_key_ccid_time_extension_cb_t = void (*)(const void *ctx);

void reader_security_key_set_ccid_time_extension_callback(
  reader_security_key_ccid_time_extension_cb_t cb, void *ctx);

NERO_NFC_NODISCARD bool reader_security_key_apdu_needs_ccid_time_extension(const uint8_t *apdu,
                                                                           uint16_t apdu_len);

uint16_t reader_security_key_apdu_exchange(const uint8_t *apdu, uint16_t apdu_len, uint8_t *rsp,
                                           uint16_t rsp_cap);

#endif /* NERO_CCID_USB_BUILD */
