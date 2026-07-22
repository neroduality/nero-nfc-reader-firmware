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

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void reader_tags_utest_reset(void);
void reader_tags_utest_set_typea_info(const uint8_t* uid, uint8_t uid_len,
                                      const uint8_t* atqa, uint8_t sak,
                                      const uint8_t* ats, uint8_t ats_len);
void reader_tags_utest_set_type2_storage_info(uint16_t data_area_size,
                                              bool read_open, bool write_open);
void reader_tags_utest_set_type5_info(uint16_t cc_len, uint16_t data_area_size,
                                      uint16_t block_count, bool read_open,
                                      bool write_open);
void reader_tags_utest_set_type2_write_ok(bool ok);
void reader_tags_utest_abort_after_type2_writes(uint16_t count);
void reader_tags_utest_set_type5_write_ok(bool ok);
void reader_tags_utest_abort_after_type5_writes(uint16_t count);
void reader_tags_utest_set_type2_transceive_response(const uint8_t* rsp,
                                                     uint16_t len);
uint16_t reader_tags_utest_type2_write_count(void);
uint16_t reader_tags_utest_type5_write_count(void);
uint16_t reader_tags_utest_type5_read_count(void);
uint16_t reader_tags_utest_type5_last_read_block(void);
uint16_t reader_tags_utest_type5_last_read_len(void);
uint16_t reader_tags_utest_type2_transceive_count(void);
uint16_t reader_tags_utest_type5_transceive_count(void);

#ifdef __cplusplus
}
#endif
