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

#include "nero_nfc_serial.h"
#include "nero_nfc_attrs.h"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#ifdef NERO_HOST_UNIT_TEST_HOOKS
#include <functional>
namespace {
std::function<int(const std::string &)> g_serial_open_hook;
bool g_serial_reset_noop = false;
bool g_serial_reset_skip_delays = false;
} // namespace
namespace nero_nfc {
void nero_nfc_utest_set_serial_open_hook(std::function<int(const std::string &path)> hook) {
  g_serial_open_hook = std::move(hook);
}
void nero_nfc_utest_clear_serial_open_hook() {
  g_serial_open_hook = NERO_NFC_NULL;
}
void nero_nfc_utest_set_serial_reset_noop(bool noop) {
  g_serial_reset_noop = noop;
}
void nero_nfc_utest_set_serial_reset_skip_delays(bool skip) {
  g_serial_reset_skip_delays = skip;
}
} // namespace nero_nfc
#endif

namespace nero_nfc {

static constexpr double kResetSettleS = 2.0;
static constexpr double kPostResetReopenWaitS = 2.5;
static constexpr useconds_t kMicrosecondsPerSecond = 1000000;
static constexpr cc_t kSerialVtimeTenthsSec = 10;

int serial_open(const std::string &path) {
#ifdef NERO_HOST_UNIT_TEST_HOOKS
  if (g_serial_open_hook) {
    return g_serial_open_hook(path);
  }
#endif
  int fd = open(path.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }

  struct termios tty{};
  if (tcgetattr(fd, &tty) != 0) {
    close(fd);
    return -1;
  }

  cfsetispeed(&tty, B115200);
  cfsetospeed(&tty, B115200);
  cfmakeraw(&tty);

  tty.c_cflag &= static_cast<tcflag_t>(~(CSIZE | PARENB | CSTOPB));
  tty.c_cflag |= CS8 | CLOCAL | CREAD;
  tty.c_cc[VMIN] = 0;
  tty.c_cc[VTIME] = kSerialVtimeTenthsSec; // 1 second read timeout

  if (tcsetattr(fd, TCSANOW, &tty) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

void serial_reset(int fd) {
#ifdef NERO_HOST_UNIT_TEST_HOOKS
  if (g_serial_reset_noop) {
    (void)fd;
    return;
  }
#endif
  int bits = TIOCM_DTR | TIOCM_RTS;
  ioctl(fd, TIOCMBIS, &bits); // assert DTR + RTS
#ifdef NERO_HOST_UNIT_TEST_HOOKS
  if (!g_serial_reset_skip_delays) {
    usleep(static_cast<useconds_t>(kResetSettleS * kMicrosecondsPerSecond));
  }
#else
  usleep(static_cast<useconds_t>(kResetSettleS * kMicrosecondsPerSecond));
#endif
  ioctl(fd, TIOCMBIC, &bits); // release DTR + RTS
#ifdef NERO_HOST_UNIT_TEST_HOOKS
  if (!g_serial_reset_skip_delays) {
    usleep(static_cast<useconds_t>(kPostResetReopenWaitS * kMicrosecondsPerSecond));
  }
#else
  usleep(static_cast<useconds_t>(kPostResetReopenWaitS * kMicrosecondsPerSecond));
#endif
}

void serial_close(int fd) {
  if (fd >= 0) {
    close(fd);
  }
}

} // namespace nero_nfc
