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


#include "nero_nfc_null.h"
#include <cstdint>
#include <string>

#include <gtest/gtest.h>

extern "C" {
#include "nfc_print_utils.h"
void nero_nfc_print_utils_compile_touch_c(void);
}

static std::string *g_emit_target = NERO_NFC_NULL;

extern "C" void test_nfc_emit_char(char c) {
  if (g_emit_target != NERO_NFC_NULL) {
    g_emit_target->push_back(static_cast<char>(c));
  }
}

namespace {

class EmitGuard {
public:
  explicit EmitGuard(std::string *target) { g_emit_target = target; }
  ~EmitGuard() { g_emit_target = NERO_NFC_NULL; }
};

} // namespace

TEST(NfcPrintUtils, WriteCstrNullEmitOrStringNoop) {
  std::string captured;
  EmitGuard guard(&captured);
  nero_nfc_emit_write(reinterpret_cast<nero_nfc_emit_fn_t>(0), "hi");
  EXPECT_TRUE(captured.empty());

  nero_nfc_emit_write(test_nfc_emit_char, reinterpret_cast<const char *>(0));
  EXPECT_TRUE(captured.empty());
}

TEST(NfcPrintUtils, WriteCstrCopiesChars) {
  std::string captured;
  EmitGuard guard(&captured);
  nero_nfc_emit_write(test_nfc_emit_char, "NFC");
  EXPECT_EQ(captured, "NFC");
}

TEST(NfcPrintUtils, PrintHexU8NullEmit) {
  std::string captured;
  EmitGuard guard(&captured);
  nero_nfc_emit_hex_u8(reinterpret_cast<nero_nfc_emit_fn_t>(0), 0xABU);
  EXPECT_TRUE(captured.empty());
}

TEST(NfcPrintUtils, PrintHexU8Formats) {
  std::string captured;
  EmitGuard guard(&captured);
  nero_nfc_emit_hex_u8(test_nfc_emit_char, 0x00U);
  EXPECT_EQ(captured, "00");
  captured.clear();

  nero_nfc_emit_hex_u8(test_nfc_emit_char, 0xFFU);
  EXPECT_EQ(captured, "FF");
  captured.clear();

  nero_nfc_emit_hex_u8(test_nfc_emit_char, 0x5AU);
  EXPECT_EQ(captured, "5A");
}

TEST(NfcPrintUtils, PrintDecU32NullEmit) {
  std::string captured;
  EmitGuard guard(&captured);
  nero_nfc_emit_dec_u32(reinterpret_cast<nero_nfc_emit_fn_t>(0), 42U);
  EXPECT_TRUE(captured.empty());
}

TEST(NfcPrintUtils, PrintDecU32ZeroAndMultiDigit) {
  std::string captured;
  EmitGuard guard(&captured);
  nero_nfc_emit_dec_u32(test_nfc_emit_char, 0U);
  EXPECT_EQ(captured, "0");

  captured.clear();
  nero_nfc_emit_dec_u32(test_nfc_emit_char, 9U);
  EXPECT_EQ(captured, "9");

  captured.clear();
  nero_nfc_emit_dec_u32(test_nfc_emit_char, 10U);
  EXPECT_EQ(captured, "10");

  captured.clear();
  nero_nfc_emit_dec_u32(test_nfc_emit_char, 1000U);
  EXPECT_EQ(captured, "1000");

  captured.clear();
  nero_nfc_emit_dec_u32(test_nfc_emit_char, 4294967295U);
  EXPECT_EQ(captured, "4294967295");
}

TEST(NfcPrintUtils, PrintDecI32SignAndZero) {
  std::string captured;
  EmitGuard guard(&captured);
  nero_nfc_emit_dec_i32(reinterpret_cast<nero_nfc_emit_fn_t>(0), -1);
  EXPECT_TRUE(captured.empty());

  nero_nfc_emit_dec_i32(test_nfc_emit_char, 0);
  EXPECT_EQ(captured, "0");

  captured.clear();
  nero_nfc_emit_dec_i32(test_nfc_emit_char, -42);
  EXPECT_EQ(captured, "-42");

  captured.clear();
  nero_nfc_emit_dec_i32(test_nfc_emit_char, 12345);
  EXPECT_EQ(captured, "12345");
}

TEST(NfcPrintUtils, PureCTranslationUnitTouchesHeader) {
  /* Side effect is the pure-C TU linking + exercising every inline in a C
   * compiler. */
  nero_nfc_print_utils_compile_touch_c();
  SUCCEED();
}
