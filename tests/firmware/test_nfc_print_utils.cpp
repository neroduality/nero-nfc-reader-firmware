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

namespace {
enum {
  kTestLit0x5Au = 0x5AU,
  kTestLit0xAbu = 0xABU,
  kTestLit0xFfu = 0xFFU,
  kTestLit1000U = 1000U,
  kTestLit10U = 10U,
  kTestLit12345 = 12345,
  kTestLit42 = 42,
  kTestLit4294967295U = 4294967295U,
  kTestLit42U = 42U,
  kTestLit9U = 9U,
};
}  // namespace

#include <gtest/gtest.h>

#include "nfc_print_utils.h"
#include "test_nfc_print_utils_compile.h"

static std::string* g_emit_target = NERO_NFC_NULL;

extern "C" void TestNfcEmitChar(char c) {
  if (g_emit_target != NERO_NFC_NULL) {
    g_emit_target->push_back(c);
  }
}

namespace {

class EmitGuard {
 public:
  explicit EmitGuard(std::string* target) { g_emit_target = target; }
  EmitGuard(const EmitGuard&) = delete;
  EmitGuard& operator=(const EmitGuard&) = delete;
  EmitGuard(EmitGuard&&) = delete;
  EmitGuard& operator=(EmitGuard&&) = delete;
  ~EmitGuard() { g_emit_target = NERO_NFC_NULL; }
};

}  // namespace

TEST(NfcPrintUtils, WriteCstrNullEmitOrStringNoop) {
  std::string captured;
  EmitGuard guard(&captured);
  nero_nfc_emit_write(reinterpret_cast<nero_nfc_emit_fn_t>(0), "hi");
  EXPECT_TRUE(captured.empty());

  nero_nfc_emit_write(TestNfcEmitChar, reinterpret_cast<const char*>(0));
  EXPECT_TRUE(captured.empty());
}

TEST(NfcPrintUtils, WriteCstrCopiesChars) {
  std::string captured;
  EmitGuard guard(&captured);
  nero_nfc_emit_write(TestNfcEmitChar, "NFC");
  EXPECT_EQ(captured, "NFC");
}

TEST(NfcPrintUtils, PrintHexU8NullEmit) {
  std::string captured;
  EmitGuard guard(&captured);
  nero_nfc_emit_hex_u8(reinterpret_cast<nero_nfc_emit_fn_t>(0), kTestLit0xAbu);
  EXPECT_TRUE(captured.empty());
}

TEST(NfcPrintUtils, PrintHexU8Formats) {
  std::string captured;
  EmitGuard guard(&captured);
  nero_nfc_emit_hex_u8(TestNfcEmitChar, 0x00U);
  EXPECT_EQ(captured, "00");
  captured.clear();

  nero_nfc_emit_hex_u8(TestNfcEmitChar, kTestLit0xFfu);
  EXPECT_EQ(captured, "FF");
  captured.clear();

  nero_nfc_emit_hex_u8(TestNfcEmitChar, kTestLit0x5Au);
  EXPECT_EQ(captured, "5A");
}

TEST(NfcPrintUtils, PrintDecU32NullEmit) {
  std::string captured;
  EmitGuard guard(&captured);
  nero_nfc_emit_dec_u32(reinterpret_cast<nero_nfc_emit_fn_t>(0), kTestLit42U);
  EXPECT_TRUE(captured.empty());
}

TEST(NfcPrintUtils, PrintDecU32ZeroAndMultiDigit) {
  std::string captured;
  EmitGuard guard(&captured);
  nero_nfc_emit_dec_u32(TestNfcEmitChar, 0U);
  EXPECT_EQ(captured, "0");

  captured.clear();
  nero_nfc_emit_dec_u32(TestNfcEmitChar, kTestLit9U);
  EXPECT_EQ(captured, "9");

  captured.clear();
  nero_nfc_emit_dec_u32(TestNfcEmitChar, kTestLit10U);
  EXPECT_EQ(captured, "10");

  captured.clear();
  nero_nfc_emit_dec_u32(TestNfcEmitChar, kTestLit1000U);
  EXPECT_EQ(captured, "1000");

  captured.clear();
  nero_nfc_emit_dec_u32(TestNfcEmitChar, kTestLit4294967295U);
  EXPECT_EQ(captured, "4294967295");
}

TEST(NfcPrintUtils, PrintDecI32SignAndZero) {
  std::string captured;
  EmitGuard guard(&captured);
  nero_nfc_emit_dec_i32(reinterpret_cast<nero_nfc_emit_fn_t>(0), -1);
  EXPECT_TRUE(captured.empty());

  nero_nfc_emit_dec_i32(TestNfcEmitChar, 0);
  EXPECT_EQ(captured, "0");

  captured.clear();
  nero_nfc_emit_dec_i32(TestNfcEmitChar, -static_cast<int32_t>(kTestLit42));
  EXPECT_EQ(captured, "-42");

  captured.clear();
  nero_nfc_emit_dec_i32(TestNfcEmitChar, kTestLit12345);
  EXPECT_EQ(captured, "12345");
}

TEST(NfcPrintUtils, PureCTranslationUnitTouchesHeader) {
  /* Side effect is the pure-C TU linking + exercising every inline in a C
   * compiler. */
  nero_nfc_print_utils_compile_touch_c();
  SUCCEED();
}
