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
#include "nero_nfc_serial.h"

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <cstdio>

#include <gtest/gtest.h>

class UserspaceSerialTest : public ::testing::Test {
protected:
  void TearDown() override {
    nero_nfc::nero_nfc_utest_clear_serial_open_hook();
    nero_nfc::nero_nfc_utest_set_serial_reset_noop(false);
    nero_nfc::nero_nfc_utest_set_serial_reset_skip_delays(false);
  }
};

TEST_F(UserspaceSerialTest, OpenHookShortCircuitsKernelOpen) {
  bool called = false;
  nero_nfc::nero_nfc_utest_set_serial_open_hook([&](const std::string &path) {
    called = true;
    EXPECT_EQ(path, "/dev/fictional");
    return 42;
  });
  EXPECT_EQ(nero_nfc::serial_open("/dev/fictional"), 42);
  EXPECT_TRUE(called);
}

TEST_F(UserspaceSerialTest, ResetNoopDoesNotTouchFd) {
  nero_nfc::nero_nfc_utest_set_serial_reset_noop(true);
  nero_nfc::serial_reset(-1);
}

TEST(SerialClose, NegativeFdIsNoOp) { nero_nfc::serial_close(-1); }

TEST(SerialOpen, OpenFailsForMissingPath) {
  EXPECT_EQ(nero_nfc::serial_open("/nonexistent/nero_nfc_serial_utest_path"),
            -1);
}

TEST(SerialOpen, OpenFailsWhenPathIsRegularFile) {
  char tmpl[] = "/tmp/nero_serial_utestXXXXXX";
  int tfd = mkstemp(tmpl);
  ASSERT_GE(tfd, 0);
  ASSERT_EQ(write(tfd, "x", 1), 1);
  close(tfd);
  EXPECT_EQ(nero_nfc::serial_open(std::string(tmpl)), -1);
  std::remove(tmpl);
}

TEST_F(UserspaceSerialTest, ResetWithSkipDelaysTouchesIoctlOnPty) {
  int master = posix_openpt(O_RDWR | O_NOCTTY);
  if (master < 0) {
    GTEST_SKIP() << "posix_openpt not available";
  }
  ASSERT_EQ(grantpt(master), 0);
  ASSERT_EQ(unlockpt(master), 0);
  char pts[256]{};
  ASSERT_EQ(ptsname_r(master, pts, sizeof(pts)), 0);
  int fd = open(pts, O_RDWR | O_NOCTTY);
  ASSERT_GE(fd, 0);

  nero_nfc::nero_nfc_utest_set_serial_reset_skip_delays(true);
  nero_nfc::serial_reset(fd);
  nero_nfc::serial_close(fd);
  close(master);
}

TEST(SerialOpen, OpensPtySlaveWhenAvailable) {
  int master = posix_openpt(O_RDWR | O_NOCTTY);
  if (master < 0) {
    GTEST_SKIP() << "posix_openpt not available";
  }
  ASSERT_EQ(grantpt(master), 0);
  ASSERT_EQ(unlockpt(master), 0);
  char pts[256]{};
  ASSERT_EQ(ptsname_r(master, pts, sizeof(pts)), 0);
  int fd = nero_nfc::serial_open(std::string(pts));
  ASSERT_GE(fd, 0);
  nero_nfc::serial_close(fd);
  close(master);
}
