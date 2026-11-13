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

// fido_token -- reset an NFC FIDO2 security key and manage its PIN over PC/SC,
// modeled on libfido2's fido2-token (-L/-I/-R/-S/-C).
//
#include <csignal>
#include <span>
#include <string>
#include <string_view>

#include <termios.h>
#include <unistd.h>

#include "nero_nfc_cli_exit.hpp"
#include "nero_nfc_ctap_pin.hpp"
#include "nero_nfc_fido_token.hpp"
#include "nero_nfc_io.hpp"
#include "nero_nfc_pcsc.hpp"
#include "nero_nfc_bounds.hpp"

namespace {

inline constexpr int kExitFailure = 1;
/* Longest accepted input line; real PINs are capped at 63 bytes later. */
inline constexpr std::size_t kMaxInputLine = 256u;

void Usage(const char* argv0) {
  nero_nfc::NeroNfcStderrLine(
      "Usage: {} [help] (-L | -I | -R [-S] | -S | -C) [--pcsc-reader=SUBSTR] "
      "[--pcsc-share=shared|exclusive] [--yes]",
      argv0);
  nero_nfc::NeroNfcStderrLine(R"(
Actions:
  -L, --list          List PC/SC readers
  -I, --info          Show security key info (versions, options, PIN retries)
  -R, --reset         Factory-reset the key: erases ALL credentials and the PIN
  -S, --set-pin       Set a PIN on a key that has none; with -R, reset first
  -C, --change-pin    Change the key's existing PIN

Options:
  --pcsc-reader=TEXT  PC/SC reader exact name or unique substring; omit to use
                      whichever reader the key is tapped on
  --pcsc-share=MODE   PC/SC share mode: shared (default) or exclusive
  -y, --yes           Do not ask for confirmation before a reset
  -h, --help, help    Show this help

PINs are read from the terminal without echo, or one per line from stdin
when stdin is not a terminal. Most keys only accept a reset within a few
seconds of being tapped; keep the key on the reader until the command ends.
NFC_PCSC_READER provides the same reader substring as --pcsc-reader.)");
}

bool IsHelpArg(std::string_view arg) {
  return arg == "-h" || arg == "--help" || arg == "help";
}

/* Restores terminal echo if the user interrupts a PIN prompt. */
struct termios g_saved_termios{};
volatile std::sig_atomic_t g_echo_disabled = 0;

extern "C" void RestoreEchoAndExit(int sig) {
  if (g_echo_disabled != 0) {
    (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved_termios);
  }
  (void)std::signal(sig, SIG_DFL);
  (void)std::raise(sig);
}

bool ReadLine(std::string& out, std::string& err) {
  out.clear();
  for (;;) {
    char c = '\0';
    const ssize_t n = read(STDIN_FILENO, &c, 1u);
    if (n < 0) {
      err = "failed to read input";
      return false;
    }
    if (n == 0 || c == '\n') {
      if (n == 0 && out.empty()) {
        err = "unexpected end of input";
        return false;
      }
      break;
    }
    if (out.size() >= kMaxInputLine) {
      nero_nfc::ctap::SecureWipe(out);
      err = "input line too long";
      return false;
    }
    out.push_back(c);
  }
  if (!out.empty() && out.back() == '\r') {
    out.pop_back();
  }
  return true;
}

bool ReadSecret(std::string_view prompt, std::string& out, std::string& err) {
  if (isatty(STDIN_FILENO) == 0) {
    return ReadLine(out, err);
  }
  if (tcgetattr(STDIN_FILENO, &g_saved_termios) != 0) {
    err = "failed to read terminal settings";
    return false;
  }
  struct termios silent = g_saved_termios;
  silent.c_lflag &= ~static_cast<tcflag_t>(ECHO);
  (void)std::signal(SIGINT, RestoreEchoAndExit);
  (void)std::signal(SIGTERM, RestoreEchoAndExit);
  nero_nfc::NeroNfcStderrPrompt(prompt);
  if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &silent) != 0) {
    err = "failed to disable terminal echo";
    return false;
  }
  g_echo_disabled = 1;
  const bool ok = ReadLine(out, err);
  (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved_termios);
  g_echo_disabled = 0;
  (void)std::signal(SIGINT, SIG_DFL);
  (void)std::signal(SIGTERM, SIG_DFL);
  nero_nfc::NeroNfcStderrLine("");
  return ok;
}

bool ReadNewPin(std::string& pin, std::string& err) {
  std::string confirm;
  if (!ReadSecret("Enter new PIN: ", pin, err)) {
    return false;
  }
  if (!nero_nfc::ctap::ValidateNewPin(pin, nero_nfc::ctap::kPinDefaultMinLength,
                                      err)) {
    nero_nfc::ctap::SecureWipe(pin);
    return false;
  }
  if (!ReadSecret("Confirm new PIN: ", confirm, err)) {
    nero_nfc::ctap::SecureWipe(pin);
    return false;
  }
  const bool match = confirm == pin;
  nero_nfc::ctap::SecureWipe(confirm);
  if (!match) {
    nero_nfc::ctap::SecureWipe(pin);
    err = "PINs do not match";
    return false;
  }
  return true;
}

bool ConfirmReset(std::string& err) {
  if (isatty(STDIN_FILENO) == 0) {
    err = "refusing to reset without confirmation; pass --yes";
    return false;
  }
  nero_nfc::NeroNfcStderrLine(
      "WARNING: a reset permanently deletes every passkey/credential on the "
      "security key and removes its PIN.");
  nero_nfc::NeroNfcStderrPrompt("Type 'yes' to continue: ");
  std::string answer;
  if (!ReadLine(answer, err)) {
    return false;
  }
  if (answer != "yes") {
    err = "reset cancelled";
    return false;
  }
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  nero_nfc::FidoTokenRequest request;
  bool list = false;
  bool assume_yes = false;
  std::string pcsc_reader;
  const auto args = std::span(argv, static_cast<std::size_t>(argc));

  for (std::size_t i = 1u; i < args.size(); ++i) {
    const std::string arg(nero_nfc::At(args, i));
    if (IsHelpArg(arg)) {
      Usage(nero_nfc::At(args, 0));
      return nero_nfc::kCliExitSuccess;
    }
    if (arg == "-L" || arg == "--list") {
      list = true;
    } else if (arg == "-I" || arg == "--info") {
      request.info_ = true;
    } else if (arg == "-R" || arg == "--reset") {
      request.reset_ = true;
    } else if (arg == "-S" || arg == "--set-pin") {
      request.set_pin_ = true;
    } else if (arg == "-C" || arg == "--change-pin") {
      request.change_pin_ = true;
    } else if (arg == "-y" || arg == "--yes") {
      assume_yes = true;
    } else if (arg.starts_with("--pcsc-reader=")) {
      pcsc_reader = arg.substr(std::string("--pcsc-reader=").size());
    } else if (arg.starts_with("--pcsc-share=")) {
      const auto parsed = nero_nfc::ParsePcscShareMode(
          arg.substr(std::string("--pcsc-share=").size()));
      if (!parsed.has_value()) {
        nero_nfc::NeroNfcStderrLine(
            "error: unsupported --pcsc-share value \"{}\" (use shared or "
            "exclusive)",
            arg.substr(std::string("--pcsc-share=").size()));
        Usage(nero_nfc::At(args, 0));
        return nero_nfc::kCliExitUsageError;
      }
      request.share_mode_ = *parsed;
    } else {
      nero_nfc::NeroNfcStderrLine("error: unrecognized argument \"{}\"", arg);
      Usage(nero_nfc::At(args, 0));
      return nero_nfc::kCliExitUsageError;
    }
  }

  const int actions = static_cast<int>(list) + static_cast<int>(request.info_) +
                      static_cast<int>(request.reset_) +
                      static_cast<int>(request.set_pin_) +
                      static_cast<int>(request.change_pin_);
  const bool reset_then_set =
      actions == 2 && request.reset_ && request.set_pin_;
  if (actions == 0 || (actions > 1 && !reset_then_set)) {
    nero_nfc::NeroNfcStderrLine(
        "error: choose one action (-L, -I, -R, -S, -C); only -R and -S may be "
        "combined");
    Usage(nero_nfc::At(args, 0));
    return nero_nfc::kCliExitUsageError;
  }
  if (list) {
    return nero_nfc::RunFidoTokenList();
  }

  /* Collect every PIN and confirmation before the tap: a reset must follow
   * the tap within seconds. */
  std::string err;
  if (request.change_pin_ &&
      !ReadSecret("Enter current PIN: ", request.current_pin_, err)) {
    nero_nfc::NeroNfcStderrLine("error: {}", err);
    return kExitFailure;
  }
  if ((request.set_pin_ || request.change_pin_) &&
      !ReadNewPin(request.new_pin_, err)) {
    nero_nfc::ctap::SecureWipe(request.current_pin_);
    nero_nfc::NeroNfcStderrLine("error: {}", err);
    return kExitFailure;
  }
  if (request.reset_ && !assume_yes && !ConfirmReset(err)) {
    nero_nfc::ctap::SecureWipe(request.new_pin_);
    nero_nfc::NeroNfcStderrLine("error: {}", err);
    return kExitFailure;
  }
  return nero_nfc::RunFidoToken(pcsc_reader, request);
}
