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

// reader — read NFC tags through CDC serial or PC/SC CCID.
//
// Serial port: set PORT=/dev/ttyACM0 (optional); otherwise auto-detect.
//
#include <optional>
#include <string>

#include "nero_nfc_bridge.h"
#include "nero_nfc_cli_exit.h"
#include "nero_nfc_driver.h"
#include "nero_nfc_io.h"
#include "nero_nfc_pcsc.h"

namespace {

void usage(const char *argv0) {
  nero_nfc::nero_nfc_stderr_line("Usage: {} [help] [--bridge=cdc|pcsc] [--port=DEV] "
                                 "[--pcsc-reader=SUBSTR] "
                                 "[--pcsc-share=shared|exclusive] [--no-open-url]",
                                 argv0);
  nero_nfc::nero_nfc_stderr_line(R"(
Bridge selection:
  omit --bridge       Auto-select PC/SC when available, else CDC serial
  --bridge=cdc        Require the CDC/UART firmware interface
  --bridge=pcsc       Require the CCID firmware interface

Options:
  --port=DEV          Serial device to use with CDC
  --pcsc-reader=TEXT  PC/SC reader exact name or unique substring; omit for card-presence auto-pick
  --pcsc-share=MODE   PC/SC share mode: shared (default) or exclusive
  --no-open-url       Suppress BROWSER_OPEN: lines and do not open URLs
  -h, --help, help    Show this help

PC/SC note:
  With no --pcsc-reader, PC/SC mode accepts all non-SAM readers and picks the
  reader that has a tag present for each operation. NFC_PCSC_READER provides
  the same reader substring as --pcsc-reader.)");
}

bool is_help_arg(std::string_view arg) {
  return arg == "-h" || arg == "--help" || arg == "help";
}

} // namespace

int main(int argc, char **argv) {
  nero_nfc::DriverOptions opts;
  nero_nfc::PcscReadOptions pcsc_opts;
  std::optional<nero_nfc::HostBridge> requested_bridge;
  std::string pcsc_reader;
  bool pcsc_share_specified = false;

  for (int i = 1; i < argc; ++i) {
    std::string arg(argv[i]);
    if (is_help_arg(arg)) {
      usage(argv[0]);
      return nero_nfc::kCliExitSuccess;
    }
    if (arg.starts_with("--bridge=")) {
      auto parsed = nero_nfc::parse_host_bridge(arg.substr(std::string("--bridge=").size()));
      if (!parsed.has_value()) {
        nero_nfc::nero_nfc_stderr_line("error: unsupported --bridge value \"{}\" (use cdc or pcsc)",
                                       arg.substr(std::string("--bridge=").size()));
        usage(argv[0]);
        return nero_nfc::kCliExitUsageError;
      }
      requested_bridge = parsed;
    } else if (arg.starts_with("--pcsc-reader=")) {
      pcsc_reader = arg.substr(std::string("--pcsc-reader=").size());
    } else if (arg.starts_with("--pcsc-share=")) {
      auto parsed =
        nero_nfc::parse_pcsc_share_mode(arg.substr(std::string("--pcsc-share=").size()));
      if (!parsed.has_value()) {
        nero_nfc::nero_nfc_stderr_line(
          "error: unsupported --pcsc-share value \"{}\" (use shared or "
          "exclusive)",
          arg.substr(std::string("--pcsc-share=").size()));
        usage(argv[0]);
        return nero_nfc::kCliExitUsageError;
      }
      pcsc_opts.share_mode = *parsed;
      pcsc_share_specified = true;
    } else if (arg.starts_with("--port=")) {
      opts.port = arg.substr(std::string("--port=").size());
    } else if (arg == "--no-open-url") {
      opts.open_urls = false;
    } else {
      nero_nfc::nero_nfc_stderr_line("error: unrecognized argument \"{}\"", arg);
      usage(argv[0]);
      return nero_nfc::kCliExitUsageError;
    }
  }

  nero_nfc::HostBridgeSelection selection;
  std::string err;
  if (!nero_nfc::choose_host_bridge(requested_bridge, opts.port, pcsc_reader, selection, err,
                                    pcsc_share_specified)) {
    nero_nfc::nero_nfc_stderr_line("error: {}", err);
    return nero_nfc::kCliExitUsageError;
  }
  if (selection.bridge == nero_nfc::HostBridge::Pcsc) {
    return nero_nfc::run_pcsc_reader(selection.pcsc_reader, pcsc_opts);
  }
  opts.port = selection.serial_port;
  return nero_nfc::run_send_then_monitor(opts, "mode reader");
}
