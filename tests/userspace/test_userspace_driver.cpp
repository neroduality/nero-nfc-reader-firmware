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
#include "nero_nfc_browser.h"
#include "nero_nfc_detect.h"
#include "nero_nfc_driver.h"
#include "nero_nfc_serial.h"

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <string>
#include <thread>

class UserspaceDriverTest : public ::testing::Test {
protected:
  void TearDown() override {
    nero_nfc::nero_nfc_utest_clear_find_serial_ports_override();
    nero_nfc::nero_nfc_utest_clear_serial_open_hook();
    nero_nfc::nero_nfc_utest_clear_open_url_hook();
  }
};

static bool wait_fd_readable(int fd, int timeout_ms) {
  for (int elapsed = 0; elapsed < timeout_ms; elapsed += 20) {
    pollfd p{fd, POLLIN, 0};
    int r = poll(&p, 1, 20);
    if (r > 0 && (p.revents & POLLIN) != 0) {
      return true;
    }
  }
  return false;
}

TEST_F(UserspaceDriverTest, DispatchLinePrintsAndOpensBrowserWhenEnabled) {
  std::string last_url;
  nero_nfc::nero_nfc_utest_set_open_url_hook(
      [&](const std::string &u) { last_url = u; });

  int pipefd[2];
  ASSERT_EQ(pipe(pipefd), 0);
  int saved_out = dup(STDOUT_FILENO);
  ASSERT_GE(saved_out, 0);
  fflush(stdout);
  dup2(pipefd[1], STDOUT_FILENO);
  close(pipefd[1]);

  nero_nfc::DriverOptions opts;
  opts.open_urls = true;
  nero_nfc::driver_dispatch_line_for_test("BROWSER_OPEN:https://example.test/x",
                                          opts);

  fflush(stdout);
  dup2(saved_out, STDOUT_FILENO);
  close(saved_out);

  char buf[256]{};
  ASSERT_TRUE(wait_fd_readable(pipefd[0], 500));
  ssize_t n = read(pipefd[0], buf, sizeof(buf) - 1);
  close(pipefd[0]);
  ASSERT_GT(n, 0);
  buf[static_cast<size_t>(n)] = '\0';
  EXPECT_STREQ(buf, "BROWSER_OPEN:https://example.test/x\n");
  EXPECT_EQ(last_url, "https://example.test/x");
}

TEST_F(UserspaceDriverTest, DispatchLineSkipsBrowserWhenDisabled) {
  int pipefd[2];
  ASSERT_EQ(pipe(pipefd), 0);
  int saved_out = dup(STDOUT_FILENO);
  fflush(stdout);
  dup2(pipefd[1], STDOUT_FILENO);
  close(pipefd[1]);

  nero_nfc::DriverOptions opts;
  opts.open_urls = false;
  nero_nfc::driver_dispatch_line_for_test("BROWSER_OPEN:https://example.test/x",
                                          opts);

  fflush(stdout);
  dup2(saved_out, STDOUT_FILENO);
  close(saved_out);

  EXPECT_FALSE(wait_fd_readable(pipefd[0], 100));
  close(pipefd[0]);
}

TEST_F(UserspaceDriverTest, ReaderThreadFeedsLinesToDispatch) {
  int sp[2];
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp), 0);

  int pipefd[2];
  ASSERT_EQ(pipe(pipefd), 0);
  int saved_out = dup(STDOUT_FILENO);
  fflush(stdout);
  dup2(pipefd[1], STDOUT_FILENO);
  close(pipefd[1]);

  std::atomic<bool> stop{false};
  nero_nfc::DriverOptions opts;
  opts.open_urls = false;
  std::thread worker(
      [&] { nero_nfc::reader_thread_for_test(sp[0], opts, &stop); });

  const char *payload = "neroline\n";
  ASSERT_EQ(write(sp[1], payload, std::strlen(payload)),
            static_cast<ssize_t>(std::strlen(payload)));

  char buf[256]{};
  bool got = false;
  for (int i = 0; i < 100 && !got; ++i) {
    if (wait_fd_readable(pipefd[0], 50)) {
      ssize_t n = read(pipefd[0], buf, sizeof(buf) - 1);
      if (n > 0) {
        buf[static_cast<size_t>(n)] = '\0';
        got = true;
      }
    }
  }

  stop.store(true);
  shutdown(sp[1], SHUT_RDWR);
  worker.join();

  fflush(stdout);
  dup2(saved_out, STDOUT_FILENO);
  close(saved_out);
  close(pipefd[0]);
  close(sp[0]);
  close(sp[1]);

  ASSERT_TRUE(got);
  EXPECT_STREQ(buf, "neroline\n");
}

TEST_F(UserspaceDriverTest, RunSendWritesNewlineTerminatedCommand) {
  int sp[2];
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp), 0);

  nero_nfc::nero_nfc_utest_set_serial_open_hook(
      [&](const std::string &) { return sp[0]; });

  std::vector<std::string> ports = {"/dev/ttyUSB0"};
  nero_nfc::nero_nfc_utest_set_find_serial_ports_override(&ports);

  nero_nfc::DriverOptions opts;
  int rc = nero_nfc::run_send(opts, "HELLO");
  EXPECT_EQ(rc, 0);

  char buf[64]{};
  ASSERT_TRUE(wait_fd_readable(sp[1], 1000));
  ssize_t n = read(sp[1], buf, sizeof(buf) - 1);
  close(sp[1]);
  ASSERT_GT(n, 0);
  buf[static_cast<size_t>(n)] = '\0';
  EXPECT_STREQ(buf, "HELLO\n");
}

TEST_F(UserspaceDriverTest, RunSendFailsWhenSerialOpenFails) {
  nero_nfc::nero_nfc_utest_set_serial_open_hook(
      [&](const std::string &) { return -1; });
  std::vector<std::string> ports = {"/dev/ttyACM9"};
  nero_nfc::nero_nfc_utest_set_find_serial_ports_override(&ports);
  nero_nfc::DriverOptions opts;
  EXPECT_EQ(nero_nfc::run_send(opts, "X"), 1);
}

TEST_F(UserspaceDriverTest, RunSendFailsWhenWriteFails) {
  nero_nfc::nero_nfc_utest_set_serial_open_hook([&](const std::string &) {
    int fd = open("/dev/null", O_RDONLY);
    EXPECT_GE(fd, 0);
    return fd;
  });
  std::vector<std::string> ports = {"/dev/ttyACM0"};
  nero_nfc::nero_nfc_utest_set_find_serial_ports_override(&ports);
  nero_nfc::DriverOptions opts;
  EXPECT_EQ(nero_nfc::run_send(opts, "CMD"), 1);
}

TEST_F(UserspaceDriverTest, RunFnsReturnEarlyWhenNoPortDetected) {
  std::vector<std::string> empty;
  nero_nfc::nero_nfc_utest_set_find_serial_ports_override(&empty);
  nero_nfc::DriverOptions opts;
  EXPECT_EQ(nero_nfc::run_listen_only(opts), 1);
  EXPECT_EQ(nero_nfc::run_interactive(opts), 1);
  EXPECT_EQ(nero_nfc::run_send(opts, "X"), 1);
  EXPECT_EQ(nero_nfc::run_send_then_monitor(opts, "Y"), 1);
  EXPECT_EQ(nero_nfc::run_send_then_interactive(opts, "Z", {"a"}), 1);
}

TEST_F(UserspaceDriverTest, RunListenOnlyReturnsEarlyWhenSerialOpenFails) {
  nero_nfc::nero_nfc_utest_set_serial_open_hook(
      [&](const std::string &) { return -1; });
  std::vector<std::string> ports = {"/dev/ttyACM0"};
  nero_nfc::nero_nfc_utest_set_find_serial_ports_override(&ports);
  nero_nfc::DriverOptions opts;
  EXPECT_EQ(nero_nfc::run_listen_only(opts), 1);
}

TEST_F(UserspaceDriverTest, RunInteractiveReturnsEarlyWhenSerialOpenFails) {
  nero_nfc::nero_nfc_utest_set_serial_open_hook(
      [&](const std::string &) { return -1; });
  std::vector<std::string> ports = {"/dev/ttyACM0"};
  nero_nfc::nero_nfc_utest_set_find_serial_ports_override(&ports);
  nero_nfc::DriverOptions opts;
  EXPECT_EQ(nero_nfc::run_interactive(opts), 1);
}

TEST_F(UserspaceDriverTest, RunSendThenMonitorReturnsEarlyWhenSerialOpenFails) {
  nero_nfc::nero_nfc_utest_set_serial_open_hook(
      [&](const std::string &) { return -1; });
  std::vector<std::string> ports = {"/dev/ttyACM0"};
  nero_nfc::nero_nfc_utest_set_find_serial_ports_override(&ports);
  nero_nfc::DriverOptions opts;
  EXPECT_EQ(nero_nfc::run_send_then_monitor(opts, "X"), 1);
}

TEST_F(UserspaceDriverTest,
       RunSendThenInteractiveReturnsEarlyWhenSerialOpenFails) {
  nero_nfc::nero_nfc_utest_set_serial_open_hook(
      [&](const std::string &) { return -1; });
  std::vector<std::string> ports = {"/dev/ttyACM0"};
  nero_nfc::nero_nfc_utest_set_find_serial_ports_override(&ports);
  nero_nfc::DriverOptions opts;
  EXPECT_EQ(nero_nfc::run_send_then_interactive(opts, "X", {}), 1);
}

TEST_F(UserspaceDriverTest, RunListenOnlyUntilStdinEof) {
  int inpipe[2];
  ASSERT_EQ(pipe(inpipe), 0);
  int saved_in = dup(STDIN_FILENO);
  ASSERT_GE(saved_in, 0);
  dup2(inpipe[0], STDIN_FILENO);
  close(inpipe[0]);

  int sp[2];
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp), 0);
  nero_nfc::nero_nfc_utest_set_serial_open_hook(
      [&](const std::string &) { return sp[0]; });
  std::vector<std::string> ports = {"/dev/ttyACM0"};
  nero_nfc::nero_nfc_utest_set_find_serial_ports_override(&ports);
  nero_nfc::DriverOptions opts;
  opts.open_urls = false;

  std::thread closer([&] {
    usleep(40000);
    close(inpipe[1]);
  });

  EXPECT_EQ(nero_nfc::run_listen_only(opts), 0);
  closer.join();

  dup2(saved_in, STDIN_FILENO);
  close(saved_in);
  close(sp[1]);
}

TEST_F(UserspaceDriverTest, RunInteractiveForwardsLineToSerial) {
  int inpipe[2];
  ASSERT_EQ(pipe(inpipe), 0);
  int saved_in = dup(STDIN_FILENO);
  ASSERT_GE(saved_in, 0);
  dup2(inpipe[0], STDIN_FILENO);
  close(inpipe[0]);

  int sp[2];
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp), 0);
  nero_nfc::nero_nfc_utest_set_serial_open_hook(
      [&](const std::string &) { return sp[0]; });
  std::vector<std::string> ports = {"/dev/ttyACM0"};
  nero_nfc::nero_nfc_utest_set_find_serial_ports_override(&ports);
  nero_nfc::DriverOptions opts;
  opts.open_urls = false;

  std::thread feeder([&] {
    usleep(40000);
    const char cmd[] = "FROM_STDIN\n";
    EXPECT_EQ(write(inpipe[1], cmd, sizeof(cmd) - 1),
              static_cast<ssize_t>(sizeof(cmd) - 1));
    usleep(40000);
    close(inpipe[1]);
  });

  EXPECT_EQ(nero_nfc::run_interactive(opts), 0);
  feeder.join();

  dup2(saved_in, STDIN_FILENO);
  close(saved_in);

  char buf[64]{};
  ASSERT_TRUE(wait_fd_readable(sp[1], 1000));
  ssize_t n = read(sp[1], buf, sizeof(buf) - 1);
  close(sp[1]);
  ASSERT_GT(n, 0);
  buf[static_cast<size_t>(n)] = '\0';
  EXPECT_STREQ(buf, "FROM_STDIN\n");
}

TEST_F(UserspaceDriverTest, RunSendThenMonitorSendsThenReadsUntilStdinEof) {
  int inpipe[2];
  ASSERT_EQ(pipe(inpipe), 0);
  int saved_in = dup(STDIN_FILENO);
  ASSERT_GE(saved_in, 0);
  dup2(inpipe[0], STDIN_FILENO);
  close(inpipe[0]);

  int sp[2];
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp), 0);
  nero_nfc::nero_nfc_utest_set_serial_open_hook(
      [&](const std::string &) { return sp[0]; });
  std::vector<std::string> ports = {"/dev/ttyACM0"};
  nero_nfc::nero_nfc_utest_set_find_serial_ports_override(&ports);
  nero_nfc::DriverOptions opts;
  opts.open_urls = false;

  std::thread closer([&] {
    usleep(40000);
    close(inpipe[1]);
  });

  EXPECT_EQ(nero_nfc::run_send_then_monitor(opts, "FIRST"), 0);
  closer.join();

  dup2(saved_in, STDIN_FILENO);
  close(saved_in);

  char buf[64]{};
  ASSERT_TRUE(wait_fd_readable(sp[1], 1000));
  ssize_t n = read(sp[1], buf, sizeof(buf) - 1);
  ASSERT_GT(n, 0);
  buf[static_cast<size_t>(n)] = '\0';
  EXPECT_STREQ(buf, "FIRST\n");
  close(sp[1]);
}

TEST_F(UserspaceDriverTest, RunSendThenMonitorFailsWhenInitialSendFails) {
  nero_nfc::nero_nfc_utest_set_serial_open_hook([&](const std::string &) {
    int fd = open("/dev/null", O_RDONLY);
    EXPECT_GE(fd, 0);
    return fd;
  });
  std::vector<std::string> ports = {"/dev/ttyACM0"};
  nero_nfc::nero_nfc_utest_set_find_serial_ports_override(&ports);
  nero_nfc::DriverOptions opts;
  EXPECT_EQ(nero_nfc::run_send_then_monitor(opts, "N"), 1);
}

TEST_F(UserspaceDriverTest,
       RunSendThenInteractiveSendsCombinedCommandThenStdin) {
  int inpipe[2];
  ASSERT_EQ(pipe(inpipe), 0);
  int saved_in = dup(STDIN_FILENO);
  ASSERT_GE(saved_in, 0);
  dup2(inpipe[0], STDIN_FILENO);
  close(inpipe[0]);

  int sp[2];
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp), 0);
  nero_nfc::nero_nfc_utest_set_serial_open_hook(
      [&](const std::string &) { return sp[0]; });
  std::vector<std::string> ports = {"/dev/ttyACM0"};
  nero_nfc::nero_nfc_utest_set_find_serial_ports_override(&ports);
  nero_nfc::DriverOptions opts;
  opts.open_urls = false;

  std::thread feeder([&] {
    usleep(40000);
    const char line2[] = "SECOND\n";
    EXPECT_EQ(write(inpipe[1], line2, sizeof(line2) - 1),
              static_cast<ssize_t>(sizeof(line2) - 1));
    usleep(40000);
    close(inpipe[1]);
  });

  EXPECT_EQ(nero_nfc::run_send_then_interactive(opts, "FIRST", {"extra"}), 0);
  feeder.join();

  dup2(saved_in, STDIN_FILENO);
  close(saved_in);

  std::string acc;
  char chunk[64];
  for (int attempt = 0;
       attempt < 30 && (acc.find("FIRST extra\n") == std::string::npos ||
                        acc.find("SECOND\n") == std::string::npos);
       ++attempt) {
    if (!wait_fd_readable(sp[1], 200)) {
      continue;
    }
    ssize_t n = read(sp[1], chunk, sizeof(chunk));
    if (n > 0) {
      acc.append(chunk, static_cast<size_t>(n));
    }
  }
  close(sp[1]);
  EXPECT_NE(acc.find("FIRST extra\n"), std::string::npos);
  EXPECT_NE(acc.find("SECOND\n"), std::string::npos);
}

TEST_F(UserspaceDriverTest, RunSendThenInteractiveFailsWhenInitialSendFails) {
  nero_nfc::nero_nfc_utest_set_serial_open_hook([&](const std::string &) {
    int fd = open("/dev/null", O_RDONLY);
    EXPECT_GE(fd, 0);
    return fd;
  });
  std::vector<std::string> ports = {"/dev/ttyACM0"};
  nero_nfc::nero_nfc_utest_set_find_serial_ports_override(&ports);
  nero_nfc::DriverOptions opts;
  EXPECT_EQ(nero_nfc::run_send_then_interactive(opts, "Q", {"z"}), 1);
}
