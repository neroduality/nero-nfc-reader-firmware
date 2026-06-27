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
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "nero_nfc_bridge.h"
#include "nero_nfc_cli_exit.h"
#include "nero_nfc_driver.h"
#include "nero_nfc_io.h"
#include "nero_nfc_pcsc.h"
#include "nero_nfc_writer_payload.h"

namespace {

void usage(const char *argv0) {
  nero_nfc::nero_nfc_stderr_line("Usage: {} [help] [--bridge=cdc|pcsc] [--port=DEV] "
                                 "[--pcsc-reader=SUBSTR] "
                                 "[--pcsc-share=shared|exclusive] [payload flags] [writer-args...]",
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

bool is_help_arg(std::string_view arg) {
  return arg == "-h" || arg == "--help" || arg == "help";
}

std::optional<std::string> flag_value(const std::string &arg, std::string_view name) {
  std::string prefix = "--" + std::string(name) + "=";
  if (arg.starts_with(prefix)) {
    return arg.substr(prefix.size());
  }
  return std::nullopt;
}

} // namespace

int main(int argc, char **argv) {
  nero_nfc::DriverOptions opts;
  std::optional<nero_nfc::HostBridge> requested_bridge;
  std::string pcsc_reader;
  auto pcsc_share_mode = nero_nfc::PcscShareMode::Shared;
  bool pcsc_share_specified = false;
  std::vector<std::uint8_t> ndef_message;
  std::vector<std::vector<std::uint8_t>> ndef_records;
  std::vector<std::string> cdc_extra;
  std::vector<std::string> pcsc_unsupported_args;
  auto add_record = [&](std::vector<std::uint8_t> record, std::string_view flag) {
    if (record.empty()) {
      nero_nfc::nero_nfc_stderr_line("error: invalid or too-large {}", flag);
      return false;
    }
    ndef_records.push_back(std::move(record));
    return true;
  };

  for (int i = 1; i < argc; ++i) {
    std::string arg(argv[i]);
    auto uri = flag_value(arg, "uri");
    auto link = flag_value(arg, "link");
    auto unit_link = flag_value(arg, "unit-link");
    auto text = flag_value(arg, "text");
    auto search = flag_value(arg, "search");
    auto social = flag_value(arg, "social");
    auto video = flag_value(arg, "video");
    auto file = flag_value(arg, "file");
    auto application = flag_value(arg, "application");
    auto mail = flag_value(arg, "mail");
    auto mailto = flag_value(arg, "mailto");
    auto contact = flag_value(arg, "contact");
    auto phone = flag_value(arg, "phone");
    auto phone_number = flag_value(arg, "phone-number");
    auto sms = flag_value(arg, "sms");
    auto location = flag_value(arg, "location");
    auto custom_location = flag_value(arg, "custom-location");
    auto address = flag_value(arg, "address");
    auto destination = flag_value(arg, "destination-address");
    auto bluetooth = flag_value(arg, "bluetooth");
    auto wifi = flag_value(arg, "wifi");
    auto data = flag_value(arg, "data");
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
      pcsc_share_mode = *parsed;
      pcsc_share_specified = true;
    } else if (arg.starts_with("--port=")) {
      opts.port = arg.substr(std::string("--port=").size());
    } else if (uri || link || unit_link) {
      std::string uri_value;
      if (uri) {
        uri_value = *uri;
      } else if (link) {
        uri_value = *link;
      } else {
        uri_value = *unit_link;
      }
      if (!add_record(nero_nfc::build_ndef_uri_record(uri_value), "--uri/--link")) {
        return nero_nfc::kCliExitUsageError;
      }
    } else if (text) {
      if (!add_record(nero_nfc::build_ndef_text_record(*text), "--text")) {
        return nero_nfc::kCliExitUsageError;
      }
    } else if (search) {
      if (!add_record(
            nero_nfc::build_ndef_uri_record("https://www.google.com/search?q=" +
                                            nero_nfc::writer_url_component_encode(*search)),
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
      if (!add_record(nero_nfc::build_ndef_uri_record(value), flag)) {
        return nero_nfc::kCliExitUsageError;
      }
    } else if (mail || mailto) {
      if (!add_record(nero_nfc::build_writer_mail_record(mail ? *mail : *mailto), "--mail")) {
        return nero_nfc::kCliExitUsageError;
      }
    } else if (contact) {
      if (!add_record(nero_nfc::build_writer_vcard_record(*contact), "--contact")) {
        return nero_nfc::kCliExitUsageError;
      }
    } else if (phone || phone_number) {
      if (!add_record(nero_nfc::build_ndef_uri_record("tel:" + (phone ? *phone : *phone_number)),
                      "--phone")) {
        return nero_nfc::kCliExitUsageError;
      }
    } else if (sms) {
      if (!add_record(nero_nfc::build_writer_sms_record(*sms), "--sms")) {
        return nero_nfc::kCliExitUsageError;
      }
    } else if (location || custom_location) {
      std::string value = location ? *location : *custom_location;
      if (!value.starts_with("geo:")) {
        value.insert(0, "geo:");
      }
      if (!add_record(nero_nfc::build_ndef_uri_record(value), "--location")) {
        return nero_nfc::kCliExitUsageError;
      }
    } else if (address || destination) {
      std::string value = address ? "https://www.google.com/maps/search/?api=1&query=" +
                                      nero_nfc::writer_url_component_encode(*address)
                                  : "https://www.google.com/maps/dir/?api=1&destination=" +
                                      nero_nfc::writer_url_component_encode(*destination);
      if (!add_record(nero_nfc::build_ndef_uri_record(value),
                      address ? "--address" : "--destination-address")) {
        return nero_nfc::kCliExitUsageError;
      }
    } else if (bluetooth) {
      if (!add_record(nero_nfc::build_writer_bluetooth_record(*bluetooth), "--bluetooth")) {
        return nero_nfc::kCliExitUsageError;
      }
    } else if (wifi) {
      if (!add_record(nero_nfc::build_writer_wifi_record(*wifi), "--wifi")) {
        return nero_nfc::kCliExitUsageError;
      }
    } else if (data) {
      if (!add_record(nero_nfc::build_ndef_text_record(*data), "--data")) {
        return nero_nfc::kCliExitUsageError;
      }
    } else if (arg.starts_with("--ndef-hex=")) {
      if (!nero_nfc::parse_hex_bytes(arg.substr(std::string("--ndef-hex=").size()), ndef_message) ||
          ndef_message.empty()) {
        nero_nfc::nero_nfc_stderr_line("error: invalid or empty --ndef-hex");
        return nero_nfc::kCliExitUsageError;
      }
      nero_nfc::normalize_writer_ndef_hex_payload(ndef_message);
      ndef_records.clear();
    } else {
      cdc_extra.emplace_back(arg);
      pcsc_unsupported_args.emplace_back(arg);
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
    if (!ndef_records.empty()) {
      ndef_message = nero_nfc::build_ndef_message(ndef_records);
    }
    if (ndef_message.empty()) {
      nero_nfc::nero_nfc_stderr_line("error: PC/SC writes require a payload flag; run writer help");
      return nero_nfc::kCliExitUsageError;
    }
    if (!pcsc_unsupported_args.empty()) {
      nero_nfc::nero_nfc_stderr_line(
        "error: PC/SC writes do not accept forwarded CDC writer arguments "
        "such as \"{}\"",
        pcsc_unsupported_args.front());
      return nero_nfc::kCliExitUsageError;
    }
    nero_nfc::PcscWriteRequest req;
    req.ndef_message = std::move(ndef_message);
    req.share_mode = pcsc_share_mode;
    return nero_nfc::run_pcsc_writer(selection.pcsc_reader, req);
  }
  opts.port = selection.serial_port;
  opts.open_urls = false;
  if (!ndef_records.empty()) {
    ndef_message = nero_nfc::build_ndef_message(ndef_records);
  }
  if (!ndef_message.empty()) {
    if (!cdc_extra.empty()) {
      nero_nfc::nero_nfc_stderr_line(
        "error: CDC payload flags cannot be combined with interactive writer "
        "argument \"{}\"",
        cdc_extra.front());
      return nero_nfc::kCliExitUsageError;
    }
    std::string command = "mode writer\nndef-hex ";
    command += nero_nfc::hex_bytes(ndef_message, '\0');
    return nero_nfc::run_send_then_interactive(opts, command, {});
  }
  return nero_nfc::run_send_then_interactive(opts, "mode writer", cdc_extra);
}
