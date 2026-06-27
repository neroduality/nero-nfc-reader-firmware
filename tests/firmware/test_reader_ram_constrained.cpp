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

#ifndef NERO_RAM_CONSTRAINED
#error "compile this TU with NERO_RAM_CONSTRAINED=1"
#endif

#include "nero_nfc_limits.h"
#include "reader_context.h"

#include <gtest/gtest.h>

TEST(ReaderRamConstrained, UnoR4GlobalRamBudgetIsBelowSram) {
  EXPECT_LT(NERO_NFC_UNO_R4_GLOBAL_RAM_MAX, NERO_NFC_UNO_R4_SRAM_BYTES);
}
