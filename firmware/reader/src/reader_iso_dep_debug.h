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

#include <stdint.h>

void reader_iso_dep_debug_dump(const char *label, const uint8_t *buf, uint16_t len,
                               uint16_t max_show);
void reader_iso_dep_debug_dump_irq_u32(const char *label, uint32_t irqs);
void reader_iso_dep_debug_dump_xcvr_diag(uint16_t tx_len, uint16_t timeout_ms, int rlen);
