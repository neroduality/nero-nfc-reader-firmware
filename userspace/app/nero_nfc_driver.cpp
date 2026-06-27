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

#include "nero_nfc_driver.h"

#include <poll.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "nero_nfc_browser.h"
#include "nero_nfc_detect.h"
#include "nero_nfc_io.h"
#include "nero_nfc_line_pump.h"
#include "nero_nfc_serial.h"

namespace {

static constexpr std::size_t kReadBufBytes = 512u;
static constexpr int kPollTimeoutMs = 200;

void dispatch_serial_line(const std::string &line, const nero_nfc::DriverOptions &opts) {
  if (!opts.open_urls && nero_nfc::is_browser_line(line)) {
    return;
  }
  nero_nfc::nero_nfc_stdout_line(line.c_str());
  if (opts.open_urls && nero_nfc::is_browser_line(line)) {
    nero_nfc::open_url_nonblocking(nero_nfc::extract_browser_url(line));
  }
}

void run_reader_loop(int fd, const nero_nfc::DriverOptions &opts, std::atomic<bool> *stop) {
  nero_nfc::LinePump pump([&](const std::string &line) { dispatch_serial_line(line, opts); });
  std::array<char, kReadBufBytes> buf{};
  while (!stop->load()) {
    struct pollfd pfd{.fd = fd, .events = POLLIN, .revents = 0};
    int r = poll(&pfd, 1, kPollTimeoutMs);
    if (r <= 0) {
      continue;
    }
    ssize_t n = read(fd, buf.data(), buf.size());
    if (n <= 0) {
      break;
    }
    pump.feed(buf.data(), static_cast<size_t>(n));
  }
}

std::string resolve_port(const nero_nfc::DriverOptions &opts) {
  auto port = nero_nfc::detect_serial_port_candidate(opts.port);
  if (port.empty()) {
    nero_nfc::nero_nfc_stderr_line(
      "error: no serial port detected (set PORT=/dev/ttyACM0 or use --port)");
  }
  return port;
}

int send_line(int fd, const std::string &command) {
  if (command.size() > nero_nfc::LinePump::kMaxBufBytes) {
    nero_nfc::nero_nfc_stderr_line("error: command exceeds {} byte cap",
                                   nero_nfc::LinePump::kMaxBufBytes);
    return -1;
  }
  std::string line = command + "\n";
  size_t off = 0u;
  while (off < line.size()) {
    const ssize_t n = write(fd, line.data() + off, line.size() - off);
    if (n < 0) {
      nero_nfc::nero_nfc_stderr_line("write: {}", std::strerror(errno));
      return -1;
    }
    if (n == 0) {
      return -1;
    }
    off += static_cast<size_t>(n);
  }
  return 0;
}

} // namespace

namespace nero_nfc {

#ifdef NERO_HOST_UNIT_TEST_HOOKS
void driver_dispatch_line_for_test(const std::string &line, const DriverOptions &opts) {
  dispatch_serial_line(line, opts);
}

void reader_thread_for_test(int fd, const DriverOptions &opts, std::atomic<bool> *stop) {
  run_reader_loop(fd, opts, stop);
}
#endif

int run_listen_only(const DriverOptions &opts) {
  std::string port = resolve_port(opts);
  if (port.empty()) {
    return 1;
  }
  int fd = serial_open(port);
  if (fd < 0) {
    nero_nfc::nero_nfc_stderr_line("error: cannot open {}: {}", port, std::strerror(errno));
    return 1;
  }
  nero_nfc::nero_nfc_stderr_line("reader: CDC bridge on {}; ready to tap NFC tags (Ctrl+D to stop)",
                                 port);
  std::atomic<bool> stop{false};
  std::thread rt(run_reader_loop, fd, std::cref(opts), &stop);
  // Block until stdin is closed (Ctrl D) or a signal arrives.
  char c;
  while (read(STDIN_FILENO, &c, 1) > 0) {}
  stop.store(true);
  rt.join();
  serial_close(fd);
  return 0;
}

int run_interactive(const DriverOptions &opts) {
  std::string port = resolve_port(opts);
  if (port.empty()) {
    return 1;
  }
  int fd = serial_open(port);
  if (fd < 0) {
    nero_nfc::nero_nfc_stderr_line("error: cannot open {}: {}", port, std::strerror(errno));
    return 1;
  }
  std::atomic<bool> stop{false};
  std::thread rt(run_reader_loop, fd, std::cref(opts), &stop);
  // Forward stdin lines to the device.
  std::string line;
  char c;
  while (read(STDIN_FILENO, &c, 1) > 0) {
    if (c == '\n') {
      send_line(fd, line);
      line.clear();
    } else if (line.size() < nero_nfc::LinePump::kMaxBufBytes) {
      line.push_back(c);
    }
  }
  stop.store(true);
  rt.join();
  serial_close(fd);
  return 0;
}

int run_send(const DriverOptions &opts, const std::string &command) {
  std::string port = resolve_port(opts);
  if (port.empty()) {
    return 1;
  }
  int fd = serial_open(port);
  if (fd < 0) {
    nero_nfc::nero_nfc_stderr_line("error: cannot open {}: {}", port, std::strerror(errno));
    return 1;
  }
  int rc = send_line(fd, command);
  serial_close(fd);
  return (rc == 0) ? 0 : 1;
}

int run_send_then_monitor(const DriverOptions &opts, const std::string &command) {
  std::string port = resolve_port(opts);
  if (port.empty()) {
    return 1;
  }
  int fd = serial_open(port);
  if (fd < 0) {
    nero_nfc::nero_nfc_stderr_line("error: cannot open {}: {}", port, std::strerror(errno));
    return 1;
  }
  if (send_line(fd, command) != 0) {
    serial_close(fd);
    return 1;
  }
  nero_nfc::nero_nfc_stderr_line("reader: CDC bridge on {}; ready to tap NFC tags (Ctrl+D to stop)",
                                 port);
  std::atomic<bool> stop{false};
  std::thread rt(run_reader_loop, fd, std::cref(opts), &stop);
  char c;
  while (read(STDIN_FILENO, &c, 1) > 0) {}
  stop.store(true);
  rt.join();
  serial_close(fd);
  return 0;
}

int run_send_then_interactive(const DriverOptions &opts, const std::string &command,
                              const std::vector<std::string> &extra_args) {
  std::string port = resolve_port(opts);
  if (port.empty()) {
    return 1;
  }
  int fd = serial_open(port);
  if (fd < 0) {
    nero_nfc::nero_nfc_stderr_line("error: cannot open {}: {}", port, std::strerror(errno));
    return 1;
  }
  std::string full_cmd = command;
  for (const auto &arg : extra_args) {
    full_cmd += " ";
    full_cmd += arg;
  }
  if (send_line(fd, full_cmd) != 0) {
    serial_close(fd);
    return 1;
  }
  nero_nfc::nero_nfc_stderr_line("writer: CDC bridge on {}; ready to tap a writable NFC tag", port);
  std::atomic<bool> stop{false};
  std::thread rt(run_reader_loop, fd, std::cref(opts), &stop);
  std::string line;
  char c;
  while (read(STDIN_FILENO, &c, 1) > 0) {
    if (c == '\n') {
      send_line(fd, line);
      line.clear();
    } else if (line.size() < nero_nfc::LinePump::kMaxBufBytes) {
      line.push_back(c);
    }
  }
  stop.store(true);
  rt.join();
  serial_close(fd);
  return 0;
}

} // namespace nero_nfc
