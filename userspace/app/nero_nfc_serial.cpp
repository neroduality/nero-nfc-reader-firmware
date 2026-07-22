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

#include "nero_nfc_serial.hpp"
#include "nero_nfc_attrs.h"
#include "nero_nfc_limits.h"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <cerrno>
#include <ctime>
#include <unistd.h>

#ifdef NERO_HOST_UNIT_TEST_HOOKS
#include <functional>
namespace {
std::function<int(const std::string&)> g_serial_open_hook;
bool g_serial_reset_noop = false;
bool g_serial_reset_skip_delays = false;
}  // namespace
namespace nero_nfc {
void NeroNfcUtestSetSerialOpenHook(
    std::function<int(const std::string& path)> hook) {
  g_serial_open_hook = std::move(hook);
}
void NeroNfcUtestClearSerialOpenHook() { g_serial_open_hook = NERO_NFC_NULL; }
void NeroNfcUtestSetSerialResetNoop(bool noop) { g_serial_reset_noop = noop; }
void NeroNfcUtestSetSerialResetSkipDelays(bool skip) {
  g_serial_reset_skip_delays = skip;
}
}  // namespace nero_nfc
#endif

namespace nero_nfc {

static constexpr double kResetSettleS = 2.0;
static constexpr double kPostResetReopenWaitS = 2.5;
static constexpr double kNsPerSec = 1000000000.0;
static constexpr cc_t kSerialVtimeTenthsSec = 10;

static bool SleepFor(double seconds) {
  struct timespec delay{
      .tv_sec = static_cast<time_t>(seconds),
      .tv_nsec = static_cast<long>(
          (seconds - static_cast<double>(static_cast<time_t>(seconds))) *
          kNsPerSec)};
  while (nanosleep(&delay, &delay) != 0) {
    if (errno != EINTR) {
      return false;
    }
  }
  return true;
}

int SerialOpen(const std::string& path) {
#ifdef NERO_HOST_UNIT_TEST_HOOKS
  if (g_serial_open_hook) {
    return g_serial_open_hook(path);
  }
#endif
  if (path.empty() || path.size() > NERO_NFC_HOST_SERIAL_LINE_MAX ||
      path.find('\0') != std::string::npos) {
    return -1;
  }
  int fd = open(path.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }
  if (ioctl(fd, TIOCEXCL) != 0) {
    (void)close(fd);
    return -1;
  }

  struct termios tty{};
  if (tcgetattr(fd, &tty) != 0) {
    close(fd);
    return -1;
  }

  if (cfsetispeed(&tty, B115200) != 0 || cfsetospeed(&tty, B115200) != 0) {
    (void)close(fd);
    return -1;
  }
  cfmakeraw(&tty);

  tty.c_cflag &= static_cast<tcflag_t>(~(CSIZE | PARENB | CSTOPB));
  tty.c_cflag |= CS8 | CLOCAL | CREAD;
  tty.c_cc[VMIN] = 0;
  tty.c_cc[VTIME] = kSerialVtimeTenthsSec;  // 1 second read timeout

  if (tcsetattr(fd, TCSANOW, &tty) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

bool SerialReset(int fd) {
#ifdef NERO_HOST_UNIT_TEST_HOOKS
  if (g_serial_reset_noop) {
    (void)fd;
    return true;
  }
#endif
  if (fd < 0) {
    return false;
  }
  int bits = TIOCM_DTR | TIOCM_RTS;
  if (ioctl(fd, TIOCMBIS, &bits) != 0) {
    return false;
  }
#ifdef NERO_HOST_UNIT_TEST_HOOKS
  if (!g_serial_reset_skip_delays) {
    if (!SleepFor(kResetSettleS)) {
      (void)ioctl(fd, TIOCMBIC, &bits);
      return false;
    }
  }
#else
  if (!SleepFor(kResetSettleS)) {
    (void)ioctl(fd, TIOCMBIC, &bits);
    return false;
  }
#endif
  if (ioctl(fd, TIOCMBIC, &bits) != 0) {
    return false;
  }
#ifdef NERO_HOST_UNIT_TEST_HOOKS
  if (!g_serial_reset_skip_delays) {
    if (!SleepFor(kPostResetReopenWaitS)) {
      return false;
    }
  }
#else
  if (!SleepFor(kPostResetReopenWaitS)) {
    return false;
  }
#endif
  return true;
}

bool SerialClose(int fd) {
  if (fd < 0) {
    return false;
  }
  return close(fd) == 0;
}

}  // namespace nero_nfc
