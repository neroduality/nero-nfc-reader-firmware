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

// Unit tests for nero_nfc_browser fork/exec path (no real browser; uses
// /bin/true).
//
#include "nero_nfc_browser.hpp"

#include <cstdlib>

#include <gtest/gtest.h>

class UserspaceBrowserTest : public ::testing::Test {
 protected:
  void TearDown() override {
    nero_nfc::NeroNfcUtestClearOpenUrlHook();
    unsetenv("NERO_NFC_UTEST_BROWSER_EXEC");
  }
};

TEST_F(UserspaceBrowserTest, OpenUrlForkPathWithTestHelper) {
  nero_nfc::NeroNfcUtestClearOpenUrlHook();
  setenv("NERO_NFC_UTEST_BROWSER_EXEC", "/bin/true", 1);
  nero_nfc::OpenUrlNonblocking("https://coverage.example.test/");
}

TEST_F(UserspaceBrowserTest, AllowsPrintableUriCharactersWithoutShellParsing) {
  EXPECT_TRUE(nero_nfc::NeroNfcUtestUrlSafeForOpener(
      "https://example.test/?price=$5&name='tag'"));
}

TEST_F(UserspaceBrowserTest, RejectsControlCharacters) {
  EXPECT_FALSE(nero_nfc::NeroNfcUtestUrlSafeForOpener(
      "https://example.test/line\nbreak"));
}
