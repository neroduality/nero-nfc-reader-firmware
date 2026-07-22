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

#pragma once

#include <string>
#include <vector>

#ifdef NERO_HOST_UNIT_TEST_HOOKS
#include <atomic>
#endif

namespace nero_nfc {

struct DriverOptions {
  std::string port_;      // serial path; empty → $PORT if set, else auto-detect
  bool open_urls_{true};  // open BROWSER_OPEN: URLs in browser
};

// Read from device and print lines to stdout. Ctrl-C to stop.
int RunListenOnly(const DriverOptions& opts);

// Read device, print lines, and forward stdin to device interactively.
int RunInteractive(const DriverOptions& opts);

// Send a command line to the device then stop.
int RunSend(const DriverOptions& opts, const std::string& command);

// Send a command then monitor output until device is closed.
int RunSendThenMonitor(const DriverOptions& opts, const std::string& command);

// Send a command then enter interactive mode.
int RunSendThenInteractive(const DriverOptions& opts,
                           const std::string& command,
                           const std::vector<std::string>& extra_args);

#ifdef NERO_HOST_UNIT_TEST_HOOKS
void DriverDispatchLineForTest(const std::string& line,
                               const DriverOptions& opts);
void ReaderThreadForTest(int fd, const DriverOptions& opts,
                         std::atomic<bool>* stop);
#endif

}  // namespace nero_nfc
