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

// Unit tests for nero_nfc_driver, nero_nfc_browser integration seams.
//
#include "nero_nfc_browser.hpp"
#include "nero_nfc_detect.hpp"
#include "nero_nfc_driver.hpp"
#include "nero_nfc_io.hpp"
#include "nero_nfc_serial.hpp"
#include "nero_nfc_bounds.hpp"

namespace {
enum {
  kTestLit100 = 100,
  kTestLit2 = 2,
  kTestLit20 = 20,
  kTestLit200 = 200,
  kTestLit30 = 30,
  kTestLit40000 = 40000,
  kTestLit50 = 50,
  kTestLit64 = 64,
  kTestLit7 = 7,
};
}  // namespace

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <string>
#include <thread>

namespace {
enum {
  kSerialReadScratchCap = 256u,
};
}  // namespace

class UserspaceDriverTest : public ::testing::Test {
 protected:
  void TearDown() override {
    nero_nfc::NeroNfcUtestClearFindSerialPortsOverride();
    nero_nfc::NeroNfcUtestClearSerialOpenHook();
    nero_nfc::NeroNfcUtestClearOpenUrlHook();
  }
};

TEST_F(UserspaceDriverTest, FormattedStdoutLineUsesPublicOverload) {
  testing::internal::CaptureStdout();
  nero_nfc::NeroNfcStdoutLine("value {}", static_cast<int>(kTestLit7));
  EXPECT_EQ(testing::internal::GetCapturedStdout(), "value 7\n");
}

static bool WaitFdReadable(int fd, int timeout_ms) {
  for (int elapsed = 0; elapsed < timeout_ms; elapsed += kTestLit20) {
    pollfd p{.fd = fd, .events = POLLIN, .revents = 0};
    int r = poll(&p, 1, kTestLit20);
    if (r > 0 && (p.revents & POLLIN) != 0) {
      return true;
    }
  }
  return false;
}

TEST_F(UserspaceDriverTest, DispatchLinePrintsAndOpensBrowserWhenEnabled) {
  std::string last_url;
  nero_nfc::NeroNfcUtestSetOpenUrlHook(
      [&](const std::string& u) { last_url = u; });

  int pipefd[kTestLit2];
  ASSERT_EQ(pipe(&pipefd[0]), 0);
  int saved_out = dup(STDOUT_FILENO);
  ASSERT_GE(saved_out, 0);
  ASSERT_EQ(nero_nfc::NeroNfcStdoutFlush(), 0);
  dup2(pipefd[1], STDOUT_FILENO);
  close(pipefd[1]);

  nero_nfc::DriverOptions opts;
  opts.open_urls_ = true;
  nero_nfc::DriverDispatchLineForTest("BROWSER_OPEN:https://example.test/x",
                                      opts);

  ASSERT_EQ(nero_nfc::NeroNfcStdoutFlush(), 0);
  dup2(saved_out, STDOUT_FILENO);
  close(saved_out);

  char buf[kSerialReadScratchCap]{};
  ASSERT_TRUE(WaitFdReadable(pipefd[0], 500));
  ssize_t n = read(pipefd[0], &buf[0], sizeof(buf) - 1);
  close(pipefd[0]);
  ASSERT_GT(n, 0);
  nero_nfc::At(buf, static_cast<std::size_t>(n)) = '\0';
  EXPECT_STREQ(&buf[0], "BROWSER_OPEN:https://example.test/x\n");
  EXPECT_EQ(last_url, "https://example.test/x");
}

TEST_F(UserspaceDriverTest, DispatchLineSkipsBrowserWhenDisabled) {
  int pipefd[kTestLit2];
  ASSERT_EQ(pipe(&pipefd[0]), 0);
  int saved_out = dup(STDOUT_FILENO);
  ASSERT_EQ(nero_nfc::NeroNfcStdoutFlush(), 0);
  dup2(pipefd[1], STDOUT_FILENO);
  close(pipefd[1]);

  nero_nfc::DriverOptions opts;
  opts.open_urls_ = false;
  nero_nfc::DriverDispatchLineForTest("BROWSER_OPEN:https://example.test/x",
                                      opts);

  ASSERT_EQ(nero_nfc::NeroNfcStdoutFlush(), 0);
  dup2(saved_out, STDOUT_FILENO);
  close(saved_out);

  EXPECT_FALSE(WaitFdReadable(pipefd[0], 100));
  close(pipefd[0]);
}

TEST_F(UserspaceDriverTest, ReaderThreadFeedsLinesToDispatch) {
  int sp[kTestLit2];
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, &sp[0]), 0);

  int pipefd[kTestLit2];
  ASSERT_EQ(pipe(&pipefd[0]), 0);
  int saved_out = dup(STDOUT_FILENO);
  ASSERT_EQ(nero_nfc::NeroNfcStdoutFlush(), 0);
  dup2(pipefd[1], STDOUT_FILENO);
  close(pipefd[1]);

  std::atomic<bool> stop{false};
  nero_nfc::DriverOptions opts;
  opts.open_urls_ = false;
  std::thread worker(
      [&] { nero_nfc::ReaderThreadForTest(sp[0], opts, &stop); });

  const char* payload = "neroline\n";
  ASSERT_EQ(write(sp[1], payload, std::strlen(payload)),
            static_cast<ssize_t>(std::strlen(payload)));

  char buf[kSerialReadScratchCap]{};
  bool got = false;
  for (int i = 0; i < kTestLit100 && !got; ++i) {
    if (WaitFdReadable(pipefd[0], kTestLit50)) {
      ssize_t n = read(pipefd[0], &buf[0], sizeof(buf) - 1);
      if (n > 0) {
        nero_nfc::At(buf, static_cast<std::size_t>(n)) = '\0';
        got = true;
      }
    }
  }

  stop.store(true);
  shutdown(sp[1], SHUT_RDWR);
  worker.join();

  ASSERT_EQ(nero_nfc::NeroNfcStdoutFlush(), 0);
  dup2(saved_out, STDOUT_FILENO);
  close(saved_out);
  close(pipefd[0]);
  close(sp[0]);
  close(sp[1]);

  ASSERT_TRUE(got);
  EXPECT_STREQ(&buf[0], "neroline\n");
}

TEST_F(UserspaceDriverTest, RunSendWritesNewlineTerminatedCommand) {
  int sp[kTestLit2];
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, &sp[0]), 0);

  nero_nfc::NeroNfcUtestSetSerialOpenHook(
      [&](const std::string&) { return sp[0]; });

  std::vector<std::string> ports = {"/dev/ttyUSB0"};
  nero_nfc::NeroNfcUtestSetFindSerialPortsOverride(&ports);

  nero_nfc::DriverOptions opts;
  int rc = nero_nfc::RunSend(opts, "HELLO");
  EXPECT_EQ(rc, 0);

  char buf[kTestLit64]{};
  ASSERT_TRUE(WaitFdReadable(sp[1], 1000));
  ssize_t n = read(sp[1], &buf[0], sizeof(buf) - 1);
  close(sp[1]);
  ASSERT_GT(n, 0);
  nero_nfc::At(buf, static_cast<std::size_t>(n)) = '\0';
  EXPECT_STREQ(&buf[0], "HELLO\n");
}

TEST_F(UserspaceDriverTest, RunSendFailsWhenSerialOpenFails) {
  nero_nfc::NeroNfcUtestSetSerialOpenHook(
      [&](const std::string&) { return -1; });
  std::vector<std::string> ports = {"/dev/ttyACM9"};
  nero_nfc::NeroNfcUtestSetFindSerialPortsOverride(&ports);
  nero_nfc::DriverOptions opts;
  EXPECT_EQ(nero_nfc::RunSend(opts, "X"), 1);
}

TEST_F(UserspaceDriverTest, RunSendFailsWhenWriteFails) {
  nero_nfc::NeroNfcUtestSetSerialOpenHook([&](const std::string&) {
    int fd = open("/dev/null", O_RDONLY);
    EXPECT_GE(fd, 0);
    return fd;
  });
  std::vector<std::string> ports = {"/dev/ttyACM0"};
  nero_nfc::NeroNfcUtestSetFindSerialPortsOverride(&ports);
  nero_nfc::DriverOptions opts;
  EXPECT_EQ(nero_nfc::RunSend(opts, "CMD"), 1);
}

TEST_F(UserspaceDriverTest, RunFnsReturnEarlyWhenNoPortDetected) {
  std::vector<std::string> empty;
  nero_nfc::NeroNfcUtestSetFindSerialPortsOverride(&empty);
  nero_nfc::DriverOptions opts;
  EXPECT_EQ(nero_nfc::RunListenOnly(opts), 1);
  EXPECT_EQ(nero_nfc::RunInteractive(opts), 1);
  EXPECT_EQ(nero_nfc::RunSend(opts, "X"), 1);
  EXPECT_EQ(nero_nfc::RunSendThenMonitor(opts, "Y"), 1);
  EXPECT_EQ(nero_nfc::RunSendThenInteractive(opts, "Z", {"a"}), 1);
}

TEST_F(UserspaceDriverTest, RunListenOnlyReturnsEarlyWhenSerialOpenFails) {
  nero_nfc::NeroNfcUtestSetSerialOpenHook(
      [&](const std::string&) { return -1; });
  std::vector<std::string> ports = {"/dev/ttyACM0"};
  nero_nfc::NeroNfcUtestSetFindSerialPortsOverride(&ports);
  nero_nfc::DriverOptions opts;
  EXPECT_EQ(nero_nfc::RunListenOnly(opts), 1);
}

TEST_F(UserspaceDriverTest, RunInteractiveReturnsEarlyWhenSerialOpenFails) {
  nero_nfc::NeroNfcUtestSetSerialOpenHook(
      [&](const std::string&) { return -1; });
  std::vector<std::string> ports = {"/dev/ttyACM0"};
  nero_nfc::NeroNfcUtestSetFindSerialPortsOverride(&ports);
  nero_nfc::DriverOptions opts;
  EXPECT_EQ(nero_nfc::RunInteractive(opts), 1);
}

TEST_F(UserspaceDriverTest, RunSendThenMonitorReturnsEarlyWhenSerialOpenFails) {
  nero_nfc::NeroNfcUtestSetSerialOpenHook(
      [&](const std::string&) { return -1; });
  std::vector<std::string> ports = {"/dev/ttyACM0"};
  nero_nfc::NeroNfcUtestSetFindSerialPortsOverride(&ports);
  nero_nfc::DriverOptions opts;
  EXPECT_EQ(nero_nfc::RunSendThenMonitor(opts, "X"), 1);
}

TEST_F(UserspaceDriverTest,
       RunSendThenInteractiveReturnsEarlyWhenSerialOpenFails) {
  nero_nfc::NeroNfcUtestSetSerialOpenHook(
      [&](const std::string&) { return -1; });
  std::vector<std::string> ports = {"/dev/ttyACM0"};
  nero_nfc::NeroNfcUtestSetFindSerialPortsOverride(&ports);
  nero_nfc::DriverOptions opts;
  EXPECT_EQ(nero_nfc::RunSendThenInteractive(opts, "X", {}), 1);
}

TEST_F(UserspaceDriverTest, RunListenOnlyUntilStdinEof) {
  int inpipe[kTestLit2];
  ASSERT_EQ(pipe(&inpipe[0]), 0);
  int saved_in = dup(STDIN_FILENO);
  ASSERT_GE(saved_in, 0);
  dup2(inpipe[0], STDIN_FILENO);
  close(inpipe[0]);

  int sp[kTestLit2];
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, &sp[0]), 0);
  nero_nfc::NeroNfcUtestSetSerialOpenHook(
      [&](const std::string&) { return sp[0]; });
  std::vector<std::string> ports = {"/dev/ttyACM0"};
  nero_nfc::NeroNfcUtestSetFindSerialPortsOverride(&ports);
  nero_nfc::DriverOptions opts;
  opts.open_urls_ = false;

  std::thread closer([&] {
    usleep(kTestLit40000);
    close(inpipe[1]);
  });

  EXPECT_EQ(nero_nfc::RunListenOnly(opts), 0);
  closer.join();

  dup2(saved_in, STDIN_FILENO);
  close(saved_in);
  close(sp[1]);
}

TEST_F(UserspaceDriverTest, RunInteractiveForwardsLineToSerial) {
  int inpipe[kTestLit2];
  ASSERT_EQ(pipe(&inpipe[0]), 0);
  int saved_in = dup(STDIN_FILENO);
  ASSERT_GE(saved_in, 0);
  dup2(inpipe[0], STDIN_FILENO);
  close(inpipe[0]);

  int sp[kTestLit2];
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, &sp[0]), 0);
  nero_nfc::NeroNfcUtestSetSerialOpenHook(
      [&](const std::string&) { return sp[0]; });
  std::vector<std::string> ports = {"/dev/ttyACM0"};
  nero_nfc::NeroNfcUtestSetFindSerialPortsOverride(&ports);
  nero_nfc::DriverOptions opts;
  opts.open_urls_ = false;

  std::thread feeder([&] {
    usleep(kTestLit40000);
    const char kCmd[] = "FROM_STDIN\n";
    EXPECT_EQ(write(inpipe[1], &kCmd[0], sizeof(kCmd) - 1),
              static_cast<ssize_t>(sizeof(kCmd) - 1));
    usleep(kTestLit40000);
    close(inpipe[1]);
  });

  EXPECT_EQ(nero_nfc::RunInteractive(opts), 0);
  feeder.join();

  dup2(saved_in, STDIN_FILENO);
  close(saved_in);

  char buf[kTestLit64]{};
  ASSERT_TRUE(WaitFdReadable(sp[1], 1000));
  ssize_t n = read(sp[1], &buf[0], sizeof(buf) - 1);
  close(sp[1]);
  ASSERT_GT(n, 0);
  nero_nfc::At(buf, static_cast<std::size_t>(n)) = '\0';
  EXPECT_STREQ(&buf[0], "FROM_STDIN\n");
}

TEST_F(UserspaceDriverTest, RunSendThenMonitorSendsThenReadsUntilStdinEof) {
  int inpipe[kTestLit2];
  ASSERT_EQ(pipe(&inpipe[0]), 0);
  int saved_in = dup(STDIN_FILENO);
  ASSERT_GE(saved_in, 0);
  dup2(inpipe[0], STDIN_FILENO);
  close(inpipe[0]);

  int sp[kTestLit2];
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, &sp[0]), 0);
  nero_nfc::NeroNfcUtestSetSerialOpenHook(
      [&](const std::string&) { return sp[0]; });
  std::vector<std::string> ports = {"/dev/ttyACM0"};
  nero_nfc::NeroNfcUtestSetFindSerialPortsOverride(&ports);
  nero_nfc::DriverOptions opts;
  opts.open_urls_ = false;

  std::thread closer([&] {
    usleep(kTestLit40000);
    close(inpipe[1]);
  });

  EXPECT_EQ(nero_nfc::RunSendThenMonitor(opts, "FIRST"), 0);
  closer.join();

  dup2(saved_in, STDIN_FILENO);
  close(saved_in);

  char buf[kTestLit64]{};
  ASSERT_TRUE(WaitFdReadable(sp[1], 1000));
  ssize_t n = read(sp[1], &buf[0], sizeof(buf) - 1);
  ASSERT_GT(n, 0);
  nero_nfc::At(buf, static_cast<std::size_t>(n)) = '\0';
  EXPECT_STREQ(&buf[0], "FIRST\n");
  close(sp[1]);
}

TEST_F(UserspaceDriverTest, RunSendThenMonitorFailsWhenInitialSendFails) {
  nero_nfc::NeroNfcUtestSetSerialOpenHook([&](const std::string&) {
    int fd = open("/dev/null", O_RDONLY);
    EXPECT_GE(fd, 0);
    return fd;
  });
  std::vector<std::string> ports = {"/dev/ttyACM0"};
  nero_nfc::NeroNfcUtestSetFindSerialPortsOverride(&ports);
  nero_nfc::DriverOptions opts;
  EXPECT_EQ(nero_nfc::RunSendThenMonitor(opts, "N"), 1);
}

TEST_F(UserspaceDriverTest,
       RunSendThenInteractiveSendsCombinedCommandThenStdin) {
  int inpipe[kTestLit2];
  ASSERT_EQ(pipe(&inpipe[0]), 0);
  int saved_in = dup(STDIN_FILENO);
  ASSERT_GE(saved_in, 0);
  dup2(inpipe[0], STDIN_FILENO);
  close(inpipe[0]);

  int sp[kTestLit2];
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, &sp[0]), 0);
  nero_nfc::NeroNfcUtestSetSerialOpenHook(
      [&](const std::string&) { return sp[0]; });
  std::vector<std::string> ports = {"/dev/ttyACM0"};
  nero_nfc::NeroNfcUtestSetFindSerialPortsOverride(&ports);
  nero_nfc::DriverOptions opts;
  opts.open_urls_ = false;

  std::thread feeder([&] {
    usleep(kTestLit40000);
    const char kLine2[] = "SECOND\n";
    EXPECT_EQ(write(inpipe[1], &kLine2[0], sizeof(kLine2) - 1),
              static_cast<ssize_t>(sizeof(kLine2) - 1));
    usleep(kTestLit40000);
    close(inpipe[1]);
  });

  EXPECT_EQ(nero_nfc::RunSendThenInteractive(opts, "FIRST", {"extra"}), 0);
  feeder.join();

  dup2(saved_in, STDIN_FILENO);
  close(saved_in);

  std::string acc;
  char chunk[kTestLit64];
  for (int attempt = 0; attempt < kTestLit30 &&
                        (acc.find("FIRST extra\n") == std::string::npos ||
                         acc.find("SECOND\n") == std::string::npos);
       ++attempt) {
    if (!WaitFdReadable(sp[1], kTestLit200)) {
      continue;
    }
    ssize_t n = read(sp[1], &chunk[0], sizeof(chunk));
    if (n > 0) {
      acc.append(&chunk[0], static_cast<size_t>(n));
    }
  }
  close(sp[1]);
  EXPECT_NE(acc.find("FIRST extra\n"), std::string::npos);
  EXPECT_NE(acc.find("SECOND\n"), std::string::npos);
}

TEST_F(UserspaceDriverTest, RunSendThenInteractiveFailsWhenInitialSendFails) {
  nero_nfc::NeroNfcUtestSetSerialOpenHook([&](const std::string&) {
    int fd = open("/dev/null", O_RDONLY);
    EXPECT_GE(fd, 0);
    return fd;
  });
  std::vector<std::string> ports = {"/dev/ttyACM0"};
  nero_nfc::NeroNfcUtestSetFindSerialPortsOverride(&ports);
  nero_nfc::DriverOptions opts;
  EXPECT_EQ(nero_nfc::RunSendThenInteractive(opts, "Q", {"z"}), 1);
}
