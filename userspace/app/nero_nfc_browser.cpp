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

#include "nero_nfc_browser.hpp"
#include "nero_nfc_bounds.hpp"
#include "nero_nfc_attrs.h"
#include "nfc_tag_geometry_limits.h"

#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <utility>

#include "nero_nfc_io.hpp"

#ifdef NERO_HOST_UNIT_TEST_HOOKS
#include <cstdlib>
#include <functional>
namespace {
std::function<void(const std::string&)> g_open_url_hook;
}
namespace nero_nfc {
void NeroNfcUtestSetOpenUrlHook(
    std::function<void(const std::string& url)> hook) {
  g_open_url_hook = std::move(hook);
}
void NeroNfcUtestClearOpenUrlHook() { g_open_url_hook = NERO_NFC_NULL; }
}  // namespace nero_nfc
#endif

namespace nero_nfc {

namespace {

constexpr int kExecNotFoundExitStatus = 127;
constexpr size_t kMaxUrlBytes = 2048u;
constexpr unsigned kAsciiPrintableMin = NFC_RFC6350_ASCII_FIRST_PRINTABLE;
constexpr unsigned kAsciiDel = NFC_RFC6350_ASCII_DELETE;

/* Reject URLs that would be unsafe to pass through an opener argv. */
bool UrlSafeForOpener(const std::string& url) {
  if (url.empty() || url.size() > kMaxUrlBytes) {
    return false;
  }
  const bool kAllowedScheme =
      url.starts_with("http://") || url.starts_with("https://") ||
      url.starts_with("mailto:") || url.starts_with("sms:");
  if (!kAllowedScheme) {
    return false;
  }
  return std::ranges::all_of(url, [](char ch) {
    const auto kC = static_cast<unsigned char>(ch);
    return (kC >= kAsciiPrintableMin) && (kC != kAsciiDel);
  });
}

void ForkExecUrlOpener(const char* prog, const std::string& url) {
  if (CstrEmpty(prog) || !UrlSafeForOpener(url)) {
    nero_nfc::NeroNfcStderrLine("open_url: rejected unsafe opener args");
    return;
  }
  /* Rebuild a scrubbed C string so execlp does not consume untrusted bytes. */
  char scrubbed[kMaxUrlBytes + 1u];
  auto scrub = AsSpan(scrubbed);
  const size_t kN = url.size();
  for (size_t i = 0u; i < kN; ++i) {
    At(scrubbed, i) = static_cast<char>(static_cast<unsigned char>(url[i]));
  }
  At(scrubbed, kN) = '\0';

  pid_t pid = fork();
  if (pid < 0) {
    nero_nfc::NeroNfcStderrLine("fork: {}", std::strerror(errno));
    return;
  }
  if (pid == 0) {
    // Child: double-fork to detach from parent.
    if (fork() == 0) {
      execlp(prog, prog, scrub.data(), NERO_NFC_NULL);
      _exit(kExecNotFoundExitStatus);
    }
    _exit(0);
  }
  // Parent: immediately reap the first child so it doesn't become a zombie.
  // Retry across signal interruptions (EINTR) so the child is always reaped.
  while ((waitpid(pid, NERO_NFC_NULL, 0) < 0) && (errno == EINTR)) {
  }
}

}  // namespace

void OpenUrlNonblocking(const std::string& url) {
#ifdef NERO_HOST_UNIT_TEST_HOOKS
  if (g_open_url_hook) {
    g_open_url_hook(url);
    return;
  }
  const char* utest = std::getenv("NERO_NFC_UTEST_BROWSER_EXEC");
  /* Map getenv to a string literal so execlp never receives tainted prog. */
  if ((utest != NERO_NFC_NULL) && (std::strcmp(utest, "/bin/true") == 0)) {
    ForkExecUrlOpener("/bin/true", url);
    return;
  }
  if ((utest != NERO_NFC_NULL) && (std::strcmp(utest, "true") == 0)) {
    ForkExecUrlOpener("true", url);
    return;
  }
#endif
#if defined(__APPLE__)
  ForkExecUrlOpener("open", url);
#else
  ForkExecUrlOpener("xdg-open", url);
#endif
}

#ifdef NERO_HOST_UNIT_TEST_HOOKS
bool NeroNfcUtestUrlSafeForOpener(const std::string& url) {
  return UrlSafeForOpener(url);
}
#endif

}  // namespace nero_nfc
