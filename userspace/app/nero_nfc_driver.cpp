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

#include "nero_nfc_driver.hpp"

#include <poll.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <string_view>
#include <string>
#include <thread>
#include <vector>

#include "nero_nfc_browser.hpp"
#include "nero_nfc_detect.hpp"
#include "nero_nfc_io.hpp"
#include "nero_nfc_line_pump.hpp"
#include "nero_nfc_serial.hpp"

namespace {

constexpr std::size_t kReadBufBytes = 512u;
constexpr int kPollTimeoutMs = 200;

void DispatchSerialLine(const std::string& line,
                        const nero_nfc::DriverOptions& opts) {
  if (!opts.open_urls_ && nero_nfc::IsBrowserLine(line)) {
    return;
  }
  nero_nfc::NeroNfcStdoutLine(line.c_str());
  if (opts.open_urls_ && nero_nfc::IsBrowserLine(line)) {
    nero_nfc::OpenUrlNonblocking(nero_nfc::ExtractBrowserUrl(line));
  }
}

void RunReaderLoop(int fd, const nero_nfc::DriverOptions& opts,
                   std::atomic<bool>* stop) {
  nero_nfc::LinePump pump(
      [&](const std::string& line) { DispatchSerialLine(line, opts); });
  std::array<char, kReadBufBytes> buf{};
  while (!stop->load()) {
    struct pollfd pfd{.fd = fd, .events = POLLIN, .revents = 0};
    int r = poll(&pfd, 1, kPollTimeoutMs);
    if (r < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }
    if (r == 0) {
      continue;
    }
    if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
      break;
    }
    ssize_t n = read(fd, buf.data(), buf.size());
    if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
      continue;
    }
    if (n <= 0) {
      break;
    }
    pump.Feed(buf.data(), static_cast<size_t>(n));
  }
}

std::string ResolvePort(const nero_nfc::DriverOptions& opts) {
  auto port = nero_nfc::DetectSerialPortCandidate(opts.port_);
  if (port.empty()) {
    nero_nfc::NeroNfcStderrLine(
        "error: no serial port detected (set PORT=/dev/ttyACM0 or use --port)");
  }
  return port;
}

int SendLine(int fd, const std::string& command) {
  if (fd < 0 || command.size() > nero_nfc::LinePump::kMaxBufBytes ||
      command.find('\0') != std::string::npos ||
      command.find('\r') != std::string::npos ||
      command.find('\n') != std::string::npos) {
    nero_nfc::NeroNfcStderrLine(
        "error: command is invalid or exceeds {} byte cap",
        nero_nfc::LinePump::kMaxBufBytes);
    return -1;
  }
  std::string line = command + "\n";
  size_t off = 0u;
  while (off < line.size()) {
    const std::string_view kChunk = std::string_view{line}.substr(off);
    const ssize_t kN = write(fd, kChunk.data(), kChunk.size());
    if (kN < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        struct pollfd pfd{.fd = fd, .events = POLLOUT, .revents = 0};
        const int kPollRc = poll(&pfd, 1, kPollTimeoutMs);
        if (kPollRc > 0 && (pfd.revents & POLLOUT) != 0) {
          continue;
        }
      }
      nero_nfc::NeroNfcStderrLine("write: {}", std::strerror(errno));
      return -1;
    }
    if (kN == 0) {
      return -1;
    }
    off += static_cast<size_t>(kN);
  }
  return 0;
}

}  // namespace

namespace nero_nfc {

#ifdef NERO_HOST_UNIT_TEST_HOOKS
void DriverDispatchLineForTest(const std::string& line,
                               const DriverOptions& opts) {
  DispatchSerialLine(line, opts);
}

void ReaderThreadForTest(int fd, const DriverOptions& opts,
                         std::atomic<bool>* stop) {
  RunReaderLoop(fd, opts, stop);
}
#endif

int RunListenOnly(const DriverOptions& opts) {
  std::string port = ResolvePort(opts);
  if (port.empty()) {
    return 1;
  }
  int fd = SerialOpen(port);
  if (fd < 0) {
    nero_nfc::NeroNfcStderrLine("error: cannot open {}: {}", port,
                                std::strerror(errno));
    return 1;
  }
  nero_nfc::NeroNfcStderrLine(
      "reader: CDC bridge on {}; ready to tap NFC tags (Ctrl+D to stop)", port);
  std::atomic<bool> stop{false};
  std::thread rt(RunReaderLoop, fd, std::cref(opts), &stop);
  // Block until stdin is closed (Ctrl D) or a signal arrives.
  char c;
  while (read(STDIN_FILENO, &c, 1) > 0) {
  }
  stop.store(true);
  rt.join();
  (void)SerialClose(fd);
  return 0;
}

int RunInteractive(const DriverOptions& opts) {
  std::string port = ResolvePort(opts);
  if (port.empty()) {
    return 1;
  }
  int fd = SerialOpen(port);
  if (fd < 0) {
    nero_nfc::NeroNfcStderrLine("error: cannot open {}: {}", port,
                                std::strerror(errno));
    return 1;
  }
  std::atomic<bool> stop{false};
  std::thread rt(RunReaderLoop, fd, std::cref(opts), &stop);
  // Forward stdin lines to the device.
  std::string line;
  bool oversized_line = false;
  char c;
  while (read(STDIN_FILENO, &c, 1) > 0) {
    if (c == '\n') {
      if (oversized_line) {
        nero_nfc::NeroNfcStderrLine("error: oversized command discarded");
      } else if (SendLine(fd, line) != 0) {
        break;
      }
      line.clear();
      oversized_line = false;
    } else if (line.size() < nero_nfc::LinePump::kMaxBufBytes) {
      if (!oversized_line) {
        line.push_back(c);
      }
    } else {
      line.clear();
      oversized_line = true;
    }
  }
  stop.store(true);
  rt.join();
  (void)SerialClose(fd);
  return 0;
}

int RunSend(const DriverOptions& opts, const std::string& command) {
  std::string port = ResolvePort(opts);
  if (port.empty()) {
    return 1;
  }
  int fd = SerialOpen(port);
  if (fd < 0) {
    nero_nfc::NeroNfcStderrLine("error: cannot open {}: {}", port,
                                std::strerror(errno));
    return 1;
  }
  int rc = SendLine(fd, command);
  (void)SerialClose(fd);
  return (rc == 0) ? 0 : 1;
}

int RunSendThenMonitor(const DriverOptions& opts, const std::string& command) {
  std::string port = ResolvePort(opts);
  if (port.empty()) {
    return 1;
  }
  int fd = SerialOpen(port);
  if (fd < 0) {
    nero_nfc::NeroNfcStderrLine("error: cannot open {}: {}", port,
                                std::strerror(errno));
    return 1;
  }
  if (SendLine(fd, command) != 0) {
    (void)SerialClose(fd);
    return 1;
  }
  nero_nfc::NeroNfcStderrLine(
      "reader: CDC bridge on {}; ready to tap NFC tags (Ctrl+D to stop)", port);
  std::atomic<bool> stop{false};
  std::thread rt(RunReaderLoop, fd, std::cref(opts), &stop);
  char c;
  while (read(STDIN_FILENO, &c, 1) > 0) {
  }
  stop.store(true);
  rt.join();
  (void)SerialClose(fd);
  return 0;
}

int RunSendThenInteractive(const DriverOptions& opts,
                           const std::string& command,
                           const std::vector<std::string>& extra_args) {
  std::string port = ResolvePort(opts);
  if (port.empty()) {
    return 1;
  }
  int fd = SerialOpen(port);
  if (fd < 0) {
    nero_nfc::NeroNfcStderrLine("error: cannot open {}: {}", port,
                                std::strerror(errno));
    return 1;
  }
  std::string full_cmd = command;
  for (const auto& arg : extra_args) {
    full_cmd += " ";
    full_cmd += arg;
  }
  size_t start = 0u;
  while (start < full_cmd.size()) {
    const size_t kEnd = full_cmd.find('\n', start);
    const std::string kLine = full_cmd.substr(
        start, kEnd == std::string::npos ? std::string::npos : kEnd - start);
    if (!kLine.empty() && SendLine(fd, kLine) != 0) {
      (void)SerialClose(fd);
      return 1;
    }
    if (kEnd == std::string::npos) {
      break;
    }
    start = kEnd + 1u;
  }
  nero_nfc::NeroNfcStderrLine(
      "writer: CDC bridge on {}; ready to tap a writable NFC tag", port);
  std::atomic<bool> stop{false};
  std::thread rt(RunReaderLoop, fd, std::cref(opts), &stop);
  std::string line;
  bool oversized_line = false;
  char c;
  while (read(STDIN_FILENO, &c, 1) > 0) {
    if (c == '\n') {
      if (oversized_line) {
        nero_nfc::NeroNfcStderrLine("error: oversized command discarded");
      } else if (SendLine(fd, line) != 0) {
        break;
      }
      line.clear();
      oversized_line = false;
    } else if (line.size() < nero_nfc::LinePump::kMaxBufBytes) {
      if (!oversized_line) {
        line.push_back(c);
      }
    } else {
      line.clear();
      oversized_line = true;
    }
  }
  stop.store(true);
  rt.join();
  (void)SerialClose(fd);
  return 0;
}

}  // namespace nero_nfc
