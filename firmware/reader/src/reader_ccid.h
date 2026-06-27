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

#include "reader_tags.h"

#include <stdint.h>

void reader_ccid_poll();

/** Called by the NFC detection loop when a CCID-exposed tag enters the field. */
void reader_ccid_on_tag_detected(reader_tag_kind_t tag_kind);

/** Invoked once the analogue tag-presence fence fires (UART reader debounce path). */
void reader_ccid_on_tag_removed_from_field();

/** Returns the current CCID bICCStatus value (CCID spec table 6-2 bits [1:0]). */
uint8_t reader_ccid_icc_status();

/** Returns the tag kind currently exposed through the CCID slot. */
reader_tag_kind_t reader_ccid_tag_kind();
