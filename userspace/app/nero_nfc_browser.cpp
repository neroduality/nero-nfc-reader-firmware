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

#include "nero_nfc_browser.h"
#include "nero_nfc_attrs.h"

#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <utility>

#include "nero_nfc_io.h"

#ifdef NERO_HOST_UNIT_TEST_HOOKS
#include <cstdlib>
#include <functional>
namespace {
std::function<void(const std::string &)> g_open_url_hook;
}
namespace nero_nfc {
void nero_nfc_utest_set_open_url_hook(std::function<void(const std::string &url)> hook) {
  g_open_url_hook = std::move(hook);
}
void nero_nfc_utest_clear_open_url_hook() {
  g_open_url_hook = NERO_NFC_NULL;
}
} // namespace nero_nfc
#endif

namespace nero_nfc {

namespace {

static constexpr int kExecNotFoundExitStatus = 127;

void fork_exec_url_opener(const char *prog, const std::string &url) {
  pid_t pid = fork();
  if (pid < 0) {
    nero_nfc::nero_nfc_stderr_line("fork: {}", std::strerror(errno));
    return;
  }
  if (pid == 0) {
    // Child: double-fork to detach from parent.
    if (fork() == 0) {
      execlp(prog, prog, url.c_str(), NERO_NFC_NULL);
      _exit(kExecNotFoundExitStatus);
    }
    _exit(0);
  }
  // Parent: immediately reap the first child so it doesn't become a zombie.
  // Retry across signal interruptions (EINTR) so the child is always reaped.
  while ((waitpid(pid, NERO_NFC_NULL, 0) < 0) && (errno == EINTR)) {}
}

} // namespace

void open_url_nonblocking(const std::string &url) {
#ifdef NERO_HOST_UNIT_TEST_HOOKS
  if (g_open_url_hook) {
    g_open_url_hook(url);
    return;
  }
  const char *utest = std::getenv("NERO_NFC_UTEST_BROWSER_EXEC");
  if (utest != NERO_NFC_NULL && utest[0] != '\0') {
    fork_exec_url_opener(utest, url);
    return;
  }
#endif
#if defined(__APPLE__)
  fork_exec_url_opener("open", url);
#else
  fork_exec_url_opener("xdg-open", url);
#endif
}

} // namespace nero_nfc
