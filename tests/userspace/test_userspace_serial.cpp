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

// Unit tests for nero_nfc_serial.
//
#include "nero_nfc_serial.hpp"

namespace {
enum {
  kTestLit42 = 42,
};
}  // namespace

#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>

#include <cstdio>

#include <gtest/gtest.h>

namespace {
enum {
  kPtsPathScratchCap = 256u,
};
}  // namespace

class UserspaceSerialTest : public ::testing::Test {
 protected:
  void TearDown() override {
    nero_nfc::NeroNfcUtestClearSerialOpenHook();
    nero_nfc::NeroNfcUtestSetSerialResetNoop(false);
    nero_nfc::NeroNfcUtestSetSerialResetSkipDelays(false);
  }
};

TEST_F(UserspaceSerialTest, OpenHookShortCircuitsKernelOpen) {
  bool called = false;
  nero_nfc::NeroNfcUtestSetSerialOpenHook([&](const std::string& path) {
    called = true;
    EXPECT_EQ(path, "/dev/fictional");
    return kTestLit42;
  });
  EXPECT_EQ(nero_nfc::SerialOpen("/dev/fictional"), 42);
  EXPECT_TRUE(called);
}

TEST_F(UserspaceSerialTest, ResetNoopDoesNotTouchFd) {
  nero_nfc::NeroNfcUtestSetSerialResetNoop(true);
  EXPECT_TRUE(nero_nfc::SerialReset(-1));
}

TEST(SerialClose, NegativeFdIsNoOp) { EXPECT_FALSE(nero_nfc::SerialClose(-1)); }

TEST(SerialOpen, OpenFailsForMissingPath) {
  EXPECT_EQ(nero_nfc::SerialOpen("/nonexistent/nero_nfc_serial_utest_path"),
            -1);
}

TEST(SerialOpen, OpenFailsWhenPathIsRegularFile) {
  char tmpl[] = "/tmp/nero_serial_utestXXXXXX";
  int tfd = mkstemp(&tmpl[0]);
  ASSERT_GE(tfd, 0);
  ASSERT_EQ(write(tfd, "x", 1), 1);
  close(tfd);
  EXPECT_EQ(nero_nfc::SerialOpen(std::string(&tmpl[0])), -1);
  EXPECT_EQ(std::remove(&tmpl[0]), 0);
}

TEST_F(UserspaceSerialTest, ResetWithSkipDelaysTouchesIoctlOnPty) {
  int master = posix_openpt(O_RDWR | O_NOCTTY);
  if (master < 0) {
    GTEST_SKIP() << "posix_openpt not available";
  }
  ASSERT_EQ(grantpt(master), 0);
  ASSERT_EQ(unlockpt(master), 0);
  char pts[kPtsPathScratchCap]{};
  ASSERT_EQ(ptsname_r(master, &pts[0], sizeof(pts)), 0);
  int fd = open(&pts[0], O_RDWR | O_NOCTTY);
  ASSERT_GE(fd, 0);

  nero_nfc::NeroNfcUtestSetSerialResetSkipDelays(true);
  (void)nero_nfc::SerialReset(fd);
  EXPECT_TRUE(nero_nfc::SerialClose(fd));
  close(master);
}

TEST(SerialOpen, OpensPtySlaveWhenAvailable) {
  int master = posix_openpt(O_RDWR | O_NOCTTY);
  if (master < 0) {
    GTEST_SKIP() << "posix_openpt not available";
  }
  ASSERT_EQ(grantpt(master), 0);
  ASSERT_EQ(unlockpt(master), 0);
  char pts[kPtsPathScratchCap]{};
  ASSERT_EQ(ptsname_r(master, &pts[0], sizeof(pts)), 0);
  int fd = nero_nfc::SerialOpen(std::string(&pts[0]));
  ASSERT_GE(fd, 0);
  EXPECT_TRUE(nero_nfc::SerialClose(fd));
  close(master);
}
