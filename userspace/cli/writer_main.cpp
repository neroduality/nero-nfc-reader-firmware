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

// writer — write NDEF through CDC serial or PC/SC CCID.
//
// Serial port: set PORT=/dev/ttyACM0 (optional); otherwise auto-detect.
// Remaining args are forwarded as writer payload command tail.
//
#include <cstdint>
#include <span>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "nero_nfc_bridge.hpp"
#include "nero_nfc_cli_exit.hpp"
#include "nero_nfc_driver.hpp"
#include "nero_nfc_io.hpp"
#include "nero_nfc_pcsc.hpp"
#include "nero_nfc_writer_payload.hpp"

namespace {

void Usage(const char* argv0) {
  nero_nfc::NeroNfcStderrLine(
      "Usage: {} [help] [--bridge=cdc|pcsc] [--port=DEV] "
      "[--pcsc-reader=SUBSTR] "
      "[--pcsc-share=shared|exclusive] [payload flags] [writer-args...]",
      argv0);
  nero_nfc::NeroNfcStderrLine(R"(
Bridge selection:
  omit --bridge       Auto-select PC/SC when available, else CDC serial
  --bridge=cdc        Require the CDC/UART firmware interface
  --bridge=pcsc       Require the CCID firmware interface

Options:
  --port=DEV          Serial device to use with CDC
  --pcsc-reader=TEXT  PC/SC reader exact name or unique substring; omit for card-presence auto-pick
  --pcsc-share=MODE   PC/SC share mode: shared (default) or exclusive
  --uri=URI           Add a URI/link NDEF record (repeatable)
  --link=URI, --unit-link=URI
  --text=TEXT         Add a text NDEF record (repeatable)
  --search=QUERY      Add web-search URI
  --social=URI        Add social-network/profile URI
  --video=URI         Add video URI
  --file=URI          Add file URI
  --application=URI   Add app/deep-link URI
  --mail=ADDR[|SUBJECT|BODY], --mailto=...
  --contact=NAME|TEL|EMAIL
  --phone=NUMBER, --phone-number=NUMBER
  --sms=NUMBER[|BODY]
  --location=LAT,LON, --custom-location=URI_OR_GEO
  --address=TEXT, --destination-address=TEXT
  --bluetooth=AA:BB:CC:DD:EE:FF
  --wifi=SSID|PSK
  --data=TEXT         Add generic text data
  --ndef-hex=HEX      Raw NDEF bytes; complete storage TLV input is unwrapped
  -h, --help, help    Show this help

Notes:
  Payload flags are supported for both CDC and PC/SC; CDC receives the same
  raw NDEF message as PC/SC. Unrecognized trailing arguments are forwarded to
  the CDC writer shell only when no payload flags are used.
  With no --pcsc-reader, PC/SC mode accepts all non-SAM readers and picks the
  reader that has a tag present for each operation. NFC_PCSC_READER provides
  the same reader substring as --pcsc-reader.)");
}

bool IsHelpArg(std::string_view arg) {
  return arg == "-h" || arg == "--help" || arg == "help";
}

std::optional<std::string> FlagValue(const std::string& arg,
                                     std::string_view name) {
  std::string prefix = "--" + std::string(name) + "=";
  if (arg.starts_with(prefix)) {
    return arg.substr(prefix.size());
  }
  return std::nullopt;
}

}  // namespace

int main(int argc, char** argv) {
  nero_nfc::DriverOptions opts;
  std::optional<nero_nfc::HostBridge> requested_bridge;
  std::string pcsc_reader;
  auto pcsc_share_mode = nero_nfc::PcscShareMode::kShared;
  bool pcsc_share_specified = false;
  std::vector<std::uint8_t> ndef_message;
  std::vector<std::vector<std::uint8_t>> ndef_records;
  std::vector<std::string> cdc_extra;
  std::vector<std::string> pcsc_unsupported_args;
  auto add_record = [&](std::vector<std::uint8_t> record,
                        std::string_view flag) {
    if (record.empty()) {
      nero_nfc::NeroNfcStderrLine("error: invalid or too-large {}", flag);
      return false;
    }
    ndef_records.push_back(std::move(record));
    return true;
  };

  const auto kArgs = std::span(argv, static_cast<std::size_t>(argc));
  for (std::size_t i = 1u; i < kArgs.size(); ++i) {
    std::string arg(kArgs[i]);
    auto uri = FlagValue(arg, "uri");
    auto link = FlagValue(arg, "link");
    auto unit_link = FlagValue(arg, "unit-link");
    auto text = FlagValue(arg, "text");
    auto search = FlagValue(arg, "search");
    auto social = FlagValue(arg, "social");
    auto video = FlagValue(arg, "video");
    auto file = FlagValue(arg, "file");
    auto application = FlagValue(arg, "application");
    auto mail = FlagValue(arg, "mail");
    auto mailto = FlagValue(arg, "mailto");
    auto contact = FlagValue(arg, "contact");
    auto phone = FlagValue(arg, "phone");
    auto phone_number = FlagValue(arg, "phone-number");
    auto sms = FlagValue(arg, "sms");
    auto location = FlagValue(arg, "location");
    auto custom_location = FlagValue(arg, "custom-location");
    auto address = FlagValue(arg, "address");
    auto destination = FlagValue(arg, "destination-address");
    auto bluetooth = FlagValue(arg, "bluetooth");
    auto wifi = FlagValue(arg, "wifi");
    auto data = FlagValue(arg, "data");
    if (IsHelpArg(arg)) {
      Usage(kArgs[0]);
      return nero_nfc::kCliExitSuccess;
    }
    if (arg.starts_with("--bridge=")) {
      auto parsed = nero_nfc::ParseHostBridge(
          arg.substr(std::string("--bridge=").size()));
      if (!parsed.has_value()) {
        nero_nfc::NeroNfcStderrLine(
            "error: unsupported --bridge value \"{}\" (use cdc or pcsc)",
            arg.substr(std::string("--bridge=").size()));
        Usage(kArgs[0]);
        return nero_nfc::kCliExitUsageError;
      }
      requested_bridge = parsed;
    } else if (arg.starts_with("--pcsc-reader=")) {
      pcsc_reader = arg.substr(std::string("--pcsc-reader=").size());
    } else if (arg.starts_with("--pcsc-share=")) {
      auto parsed = nero_nfc::ParsePcscShareMode(
          arg.substr(std::string("--pcsc-share=").size()));
      if (!parsed.has_value()) {
        nero_nfc::NeroNfcStderrLine(
            "error: unsupported --pcsc-share value \"{}\" (use shared or "
            "exclusive)",
            arg.substr(std::string("--pcsc-share=").size()));
        Usage(kArgs[0]);
        return nero_nfc::kCliExitUsageError;
      }
      pcsc_share_mode = *parsed;
      pcsc_share_specified = true;
    } else if (arg.starts_with("--port=")) {
      opts.port_ = arg.substr(std::string("--port=").size());
    } else if (uri || link || unit_link) {
      std::string uri_value;
      if (uri) {
        uri_value = *uri;
      } else if (link) {
        uri_value = *link;
      } else {
        uri_value = *unit_link;
      }
      if (!add_record(nero_nfc::BuildNdefUriRecord(uri_value),
                      "--uri/--link")) {
        return nero_nfc::kCliExitUsageError;
      }
    } else if (text) {
      if (!add_record(nero_nfc::BuildNdefTextRecord(*text), "--text")) {
        return nero_nfc::kCliExitUsageError;
      }
    } else if (search) {
      if (!add_record(nero_nfc::BuildNdefUriRecord(
                          "https://www.google.com/search?q=" +
                          nero_nfc::WriterUrlComponentEncode(*search)),
                      "--search")) {
        return nero_nfc::kCliExitUsageError;
      }
    } else if (social || video || file || application) {
      std::string value;
      std::string_view flag;
      if (social) {
        value = *social;
        flag = "--social";
      } else if (video) {
        value = *video;
        flag = "--video";
      } else if (file) {
        value = *file;
        flag = "--file";
      } else {
        value = *application;
        flag = "--application";
      }
      if (!add_record(nero_nfc::BuildNdefUriRecord(value), flag)) {
        return nero_nfc::kCliExitUsageError;
      }
    } else if (mail || mailto) {
      if (!add_record(nero_nfc::BuildWriterMailRecord(mail ? *mail : *mailto),
                      "--mail")) {
        return nero_nfc::kCliExitUsageError;
      }
    } else if (contact) {
      if (!add_record(nero_nfc::BuildWriterVcardRecord(*contact),
                      "--contact")) {
        return nero_nfc::kCliExitUsageError;
      }
    } else if (phone || phone_number) {
      if (!add_record(nero_nfc::BuildNdefUriRecord(
                          "tel:" + (phone ? *phone : *phone_number)),
                      "--phone")) {
        return nero_nfc::kCliExitUsageError;
      }
    } else if (sms) {
      if (!add_record(nero_nfc::BuildWriterSmsRecord(*sms), "--sms")) {
        return nero_nfc::kCliExitUsageError;
      }
    } else if (location || custom_location) {
      std::string value = location ? *location : *custom_location;
      if (!value.starts_with("geo:")) {
        value.insert(0, "geo:");
      }
      if (!add_record(nero_nfc::BuildNdefUriRecord(value), "--location")) {
        return nero_nfc::kCliExitUsageError;
      }
    } else if (address || destination) {
      std::string value =
          address ? "https://www.google.com/maps/search/?api=1&query=" +
                        nero_nfc::WriterUrlComponentEncode(*address)
                  : "https://www.google.com/maps/dir/?api=1&destination=" +
                        nero_nfc::WriterUrlComponentEncode(*destination);
      if (!add_record(nero_nfc::BuildNdefUriRecord(value),
                      address ? "--address" : "--destination-address")) {
        return nero_nfc::kCliExitUsageError;
      }
    } else if (bluetooth) {
      if (!add_record(nero_nfc::BuildWriterBluetoothRecord(*bluetooth),
                      "--bluetooth")) {
        return nero_nfc::kCliExitUsageError;
      }
    } else if (wifi) {
      if (!add_record(nero_nfc::BuildWriterWifiRecord(*wifi), "--wifi")) {
        return nero_nfc::kCliExitUsageError;
      }
    } else if (data) {
      if (!add_record(nero_nfc::BuildNdefTextRecord(*data), "--data")) {
        return nero_nfc::kCliExitUsageError;
      }
    } else if (arg.starts_with("--ndef-hex=")) {
      if (!nero_nfc::ParseHexBytes(
              arg.substr(std::string("--ndef-hex=").size()), ndef_message) ||
          ndef_message.empty()) {
        nero_nfc::NeroNfcStderrLine("error: invalid or empty --ndef-hex");
        return nero_nfc::kCliExitUsageError;
      }
      nero_nfc::NormalizeWriterNdefHexPayload(ndef_message);
      ndef_records.clear();
    } else {
      cdc_extra.emplace_back(arg);
      pcsc_unsupported_args.emplace_back(arg);
    }
  }

  nero_nfc::HostBridgeSelection selection;
  std::string err;
  if (!nero_nfc::ChooseHostBridge(requested_bridge, opts.port_, pcsc_reader,
                                  selection, err, pcsc_share_specified)) {
    nero_nfc::NeroNfcStderrLine("error: {}", err);
    return nero_nfc::kCliExitUsageError;
  }

  if (selection.bridge_ == nero_nfc::HostBridge::kPcsc) {
    if (!ndef_records.empty()) {
      ndef_message = nero_nfc::BuildNdefMessage(ndef_records);
    }
    if (ndef_message.empty()) {
      nero_nfc::NeroNfcStderrLine(
          "error: PC/SC writes require a payload flag; run writer help");
      return nero_nfc::kCliExitUsageError;
    }
    if (!pcsc_unsupported_args.empty()) {
      nero_nfc::NeroNfcStderrLine(
          "error: PC/SC writes do not accept forwarded CDC writer arguments "
          "such as \"{}\"",
          pcsc_unsupported_args.front());
      return nero_nfc::kCliExitUsageError;
    }
    nero_nfc::PcscWriteRequest req;
    req.ndef_message_ = std::move(ndef_message);
    req.share_mode_ = pcsc_share_mode;
    return nero_nfc::RunPcscWriter(selection.pcsc_reader_, req);
  }
  opts.port_ = selection.serial_port_;
  opts.open_urls_ = false;
  if (!ndef_records.empty()) {
    ndef_message = nero_nfc::BuildNdefMessage(ndef_records);
  }
  if (!ndef_message.empty()) {
    if (!cdc_extra.empty()) {
      nero_nfc::NeroNfcStderrLine(
          "error: CDC payload flags cannot be combined with interactive writer "
          "argument \"{}\"",
          cdc_extra.front());
      return nero_nfc::kCliExitUsageError;
    }
    std::string command = "mode writer\nndef-hex ";
    command += nero_nfc::HexBytes(ndef_message, '\0');
    return nero_nfc::RunSendThenInteractive(opts, command, {});
  }
  return nero_nfc::RunSendThenInteractive(opts, "mode writer", cdc_extra);
}
