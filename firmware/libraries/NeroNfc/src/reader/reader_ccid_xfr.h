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

#ifdef __cplusplus
extern "C" {
#endif

#include "nero_nfc_attrs.h"
#include "reader_tags.h"

#include <stdint.h>

#if defined(NERO_CCID_USB_BUILD)

NERO_NFC_NODISCARD bool reader_ccid_deadline_elapsed(uint32_t deadline_ms);
void reader_ccid_clear_xfr_response_chain(void);
void reader_ccid_clear_xfr_command_chain(void);
NERO_NFC_NODISCARD bool reader_ccid_append_xfr_command_chain(
    const uint8_t* data, uint16_t len, bool begin_chain);
void reader_ccid_send_xfr_command_continue(uint8_t* work, uint8_t seq);
void reader_ccid_send_xfr_chain_chunk(uint8_t* work, uint8_t seq);
void reader_ccid_send_xfr_data_response(uint8_t* work, uint8_t seq,
                                        const uint8_t* data, uint16_t len);
uint8_t reader_ccid_current_icc_level(void);
uint8_t reader_ccid_reply_param_status(void);
void reader_ccid_teardown_session(void);
void reader_ccid_complete_card_removal(void);
void reader_ccid_reply_slot_stat(uint8_t* buf10, uint8_t seq8, uint8_t icclvl,
                                 uint8_t err_code);
void reader_ccid_reply_data_block_error(uint8_t* buf10, uint8_t seq8,
                                        uint8_t icclvl, uint8_t err_code);
void reader_ccid_reply_command_not_supported(uint8_t* buf10, uint8_t msg_type,
                                             uint8_t seq8);
void reader_ccid_reply_data_preface(uint8_t* buf10, uint8_t seq8,
                                    uint32_t databytes, uint8_t chain);

NERO_NFC_NODISCARD bool reader_ccid_prepare_tag_for_power_on(
    reader_tag_kind_t tag_kind);

void reader_ccid_begin_time_extension(uint8_t seq8, bool send_initial);
void reader_ccid_end_time_extension(void);

void reader_ccid_handle_bulk(const uint8_t* frame, uint16_t nbytes);

#endif /* NERO_CCID_USB_BUILD */

#ifdef __cplusplus
}
#endif
