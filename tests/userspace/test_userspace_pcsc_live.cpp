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

#include "nero_nfc_pcsc.hpp"

#include <gtest/gtest.h>

#include <vector>

#if defined(NERO_USERSPACE_HAVE_PCSC)

TEST(UserspacePcscLive, ListReadersOverrideStillWorksWithPcscLinked) {
  const std::vector<std::string> kReadersIn = {"Nero NFC Test Reader"};
  nero_nfc::NeroNfcUtestSetListPcscReadersOverride(&kReadersIn);
  std::vector<std::string> readers_out;
  std::string err;
  ASSERT_TRUE(nero_nfc::ListPcscReaders(readers_out, err)) << err;
  nero_nfc::NeroNfcUtestClearListPcscReadersOverride();
  ASSERT_EQ(readers_out.size(), 1u);
  EXPECT_EQ(readers_out[0], "Nero NFC Test Reader");
}

#else

TEST(UserspacePcscLive, SkippedWithoutLibpcsclite) {
  GTEST_SKIP()
      << "Rebuild with NERO_TESTS_ENABLE_PCSC=1 and libpcsclite dev headers";
}

#endif
