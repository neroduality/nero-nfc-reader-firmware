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

void reader_protocol_configure_iso14443a(void);
void reader_protocol_configure_iso15693(void);
NERO_NFC_NODISCARD bool reader_protocol_field_on(void);
NERO_NFC_NODISCARD bool reader_protocol_activate_iso14443a(void);
NERO_NFC_NODISCARD bool reader_protocol_send_wupa(uint8_t* atqa);
int reader_protocol_transceive14(const uint8_t* tx_data, uint16_t tx_len,
                                 uint8_t* rx, uint16_t rx_max, bool with_crc,
                                 uint16_t timeout_ms, bool anticol,
                                 bool no_rx_par);
int reader_protocol_iso15693_transceive(const uint8_t* tx, uint16_t tx_len,
                                        uint8_t* rx, uint16_t rx_max,
                                        uint16_t timeout_ms);
int reader_iso_dep_send_apdu(const uint8_t* apdu, uint16_t apdu_len,
                             uint8_t* resp, uint16_t resp_buf_len);
NERO_NFC_NODISCARD bool reader_iso_dep_select_app(const uint8_t* aid,
                                                  uint8_t aid_len,
                                                  const char* name);
NERO_NFC_NODISCARD bool reader_iso_dep_select_ndef_app(void);

#ifdef __cplusplus
}
#endif
