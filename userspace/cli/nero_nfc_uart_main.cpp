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

// nero_nfc_uart — host-side UART bridge for Nero NFC firmware.
//
// Auto-detect order matches make flash-cdc (see PORT env).
//
// Usage:
//   nero_nfc_uart [--port DEV] [--no-browser] [--listen | --interactive |
//                  --send CMD | --send-watch CMD | --send-interactive CMD ...]
//
#include <getopt.h>
#include <span>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "nero_nfc_attrs.h"
#include "nero_nfc_cli_exit.hpp"
#include "nero_nfc_driver.hpp"
#include "nero_nfc_io.hpp"

namespace {

constexpr std::size_t kLongOptCount = 9u;

void Usage(const char* argv0) {
  nero_nfc::NeroNfcStderrLine("Usage: {} [--port DEV] [--no-browser]", argv0);
  nero_nfc::NeroNfcStderrLine(R"(          [--listen | --interactive |
           --send CMD | --send-watch CMD | --send-interactive CMD...]

Modes (default: --listen):
  --listen             Stream device output to stdout (default)
  -i, --interactive    Bidirectional: forward stdin to device
  --send CMD           Send CMD then exit
  --send-watch CMD     Send CMD then monitor output
  --send-interactive CMD [ARGS...]  Send CMD with args then enter interactive

Environment:
  PORT               Serial device when --port is omitted (same as make flash-cdc)

Options:
  --port DEV         Overrides PORT for this process
  --no-browser         Suppress BROWSER_OPEN: lines and do not open URLs
  -h, --help           Show this help)");
}

enum class Mode : std::uint8_t {
  kListen,
  kInteractive,
  kSend,
  kSendWatch,
  kSendInteractive,
};

}  // namespace

int main(int argc, char** argv) {
  const auto kArgs = std::span(argv, static_cast<std::size_t>(argc));
  static constexpr std::array<struct option, kLongOptCount> kLongOpts{{
      {.name = "port",
       .has_arg = required_argument,
       .flag = NERO_NFC_NULL,
       .val = 'p'},
      {.name = "no-browser",
       .has_arg = no_argument,
       .flag = NERO_NFC_NULL,
       .val = 'B'},
      {.name = "listen",
       .has_arg = no_argument,
       .flag = NERO_NFC_NULL,
       .val = 'l'},
      {.name = "interactive",
       .has_arg = no_argument,
       .flag = NERO_NFC_NULL,
       .val = 'i'},
      {.name = "send",
       .has_arg = required_argument,
       .flag = NERO_NFC_NULL,
       .val = 's'},
      {.name = "send-watch",
       .has_arg = required_argument,
       .flag = NERO_NFC_NULL,
       .val = 'w'},
      {.name = "send-interactive",
       .has_arg = required_argument,
       .flag = NERO_NFC_NULL,
       .val = 'I'},
      {.name = "help",
       .has_arg = no_argument,
       .flag = NERO_NFC_NULL,
       .val = 'h'},
      {.name = NERO_NFC_NULL, .has_arg = 0, .flag = NERO_NFC_NULL, .val = 0},
  }};

  nero_nfc::DriverOptions opts;
  Mode mode = Mode::kListen;
  std::string command;
  std::vector<std::string> extra_args;

  int c;
  int opt_idx = 0;
  while ((c = getopt_long(argc, argv, "iBhp:s:w:I:", kLongOpts.data(),
                          &opt_idx)) != -1) {
    switch (c) {
      case 'p':
        opts.port_ = optarg;
        break;
      case 'B':
        opts.open_urls_ = false;
        break;
      case 'l':
        mode = Mode::kListen;
        break;
      case 'i':
        mode = Mode::kInteractive;
        break;
      case 's':
        mode = Mode::kSend;
        command = optarg;
        break;
      case 'w':
        mode = Mode::kSendWatch;
        command = optarg;
        break;
      case 'I':
        mode = Mode::kSendInteractive;
        command = optarg;
        break;
      case 'h':
        Usage(kArgs[0]);
        return nero_nfc::kCliExitSuccess;
      default:
        Usage(kArgs[0]);
        return nero_nfc::kCliExitUsageError;
    }
  }
  for (auto i = static_cast<std::size_t>(optind); i < kArgs.size(); ++i) {
    extra_args.emplace_back(kArgs[i]);
  }

  switch (mode) {
    case Mode::kListen:
      return nero_nfc::RunListenOnly(opts);
    case Mode::kInteractive:
      return nero_nfc::RunInteractive(opts);
    case Mode::kSend:
      return nero_nfc::RunSend(opts, command);
    case Mode::kSendWatch:
      return nero_nfc::RunSendThenMonitor(opts, command);
    case Mode::kSendInteractive:
      return nero_nfc::RunSendThenInteractive(opts, command, extra_args);
  }
  return nero_nfc::kCliExitSuccess;
}
