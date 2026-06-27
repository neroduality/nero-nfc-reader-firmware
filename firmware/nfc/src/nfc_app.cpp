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

/*
 * nfc_app.cpp — combined firmware mode-switcher.
 *
 * Sits between the Arduino sketch shell (nfc.ino) and the existing
 * reader/writer application layers.  Each call to nfc_app_loop():
 *   1. Drains USB serial into the pushback ring buffer
 * (nfc_hal_preload_serial).
 *   2. Scans the ring buffer for a "mode reader\n" or "mode writer\n" line.
 *      Non-command bytes are returned to the ring buffer so the active app
 *      sees them unchanged.
 *      After a successful switch, scanning continues in the same pass so a
 *      USB batch with several mode lines (or leftover bytes after a switch)
 *      does not strand the next command until a later loop.
 *   3. Calls the active application's loop function.
 *
 * Serial fairness: UART consumers such as `writer_serial_cli_poll` read bounded
 * bursts so `scan_mode_switch()` can interleave — bulk-draining would swallow
 * mode lines.
 *
 * Runtime mode switch:  send "mode reader\n" or "mode writer\n" via serial.
 * Build-time default:   reader (override: NFC_MODE=writer when invoking make).
 */

#include <cstdint>

extern "C" {
#include "nfc_mode_line_scan.h"
}

#include "nero_nfc_log.h"

#include "nfc_app.h"
#include "nfc_board_defaults.h"
#include "nfc_combined_shell.h"
#include "nfc_runtime_mode_poll.h"

#include "reader_app.h"
#include "writer_app.h"
#if defined(NERO_CCID_ONLY_BUILD)
#include "reader_ccid.h"
#include "reader_context.h"
#include "reader_hal.h"
#endif

void nfc_hal_preload_serial(void);
int nfc_hal_pushback_available(void);
int nfc_hal_pushback_read(void);
void nfc_hal_pushback_return(const uint8_t *bytes, uint16_t len);
void nfc_hal_usb_begin(void);
#if defined(NERO_CCID_STM32_USB_BUILD)
extern "C" bool reader_hal_ccid_usb_configured(void);
extern "C" void reader_hal_ccid_usb_service_poll(void);
#else
extern "C" bool reader_hal_ccid_usb_configured(void) __attribute__((weak));
extern "C" void reader_hal_ccid_usb_service_poll(void) __attribute__((weak));

extern "C" bool reader_hal_ccid_usb_configured(void) {
  return true;
}

extern "C" void reader_hal_ccid_usb_service_poll(void) {}
#endif

typedef enum {
  kNfcModeReader = 0,
  kNfcModeWriter = 1,
} nfc_mode_t;

#ifdef NFC_DEFAULT_WRITER
static nfc_mode_t g_mode = kNfcModeWriter;
#else
static nfc_mode_t g_mode = kNfcModeReader;
#endif

#if !defined(NERO_CCID_ONLY_BUILD)
enum {
  kSerialReadyWaitMs = 250u,
  kSerialSettleMs = 40u,
};

static const char *mode_name(nfc_mode_t m) {
  return (m == kNfcModeReader) ? "reader" : "writer";
}

static void print_banner(void) {
  nero_nfc_log_write("\r\n[nfc] Active mode: ");
  nero_nfc_log_write(mode_name(g_mode));
  nero_nfc_log_line(" · UART switch:  mode reader  |  mode writer  (newline; "
                    "banner repeats after switch)");
}

static nfc_mode_scan_state_t g_mode_scan;

static void do_mode_switch(nfc_mode_t new_mode) {
  if (new_mode == g_mode) {
    /* Default image is reader; the host `reader` CLI sends `mode reader\n`
     * even when already in reader — re-run setup so the banner appears after
     * USB attach. */
    if (g_mode == kNfcModeReader) {
      reader_setup();
    } else {
      nero_nfc_log_line("\r\n[nfc] already in writer mode");
    }
    return;
  }
  g_mode = new_mode;
  nfc_mode_scan_reset(&g_mode_scan);
  nero_nfc_log_write("\r\n[nfc] switching to ");
  nero_nfc_log_write(mode_name(g_mode));
  nero_nfc_log_line(" mode...");
  if (g_mode == kNfcModeReader) {
    reader_setup();
  } else {
    writer_setup();
  }
}

static bool scan_mode_switch(void) {
  bool switched = false;
  uint8_t pb[NFC_MODE_SCAN_CAP + NFC_MODE_SCAN_PUSHBACK_BUF_EXTRA];
  uint16_t pblen = 0u;

  while (nfc_hal_pushback_available() > 0) {
    int b = nfc_hal_pushback_read();
    if (b < 0) {
      break;
    }
    const uint8_t ch = static_cast<uint8_t>(b);
    nfc_mode_scan_result_t r =
      nfc_mode_scan_feed(&g_mode_scan, ch, pb, &pblen, static_cast<uint16_t>(sizeof(pb)));
    switch (r) {
    case NFC_MODE_SCAN_INGESTED:
      break;
    case NFC_MODE_SCAN_GOT_READER:
      do_mode_switch(kNfcModeReader);
      switched = true;
      break;
    case NFC_MODE_SCAN_GOT_WRITER:
      do_mode_switch(kNfcModeWriter);
      switched = true;
      break;
    case NFC_MODE_SCAN_PUSHBACK_STOP:
      if (pblen > 0u) {
        nfc_hal_pushback_return(pb, pblen);
      }
      return switched;
    }
  }

  return switched;
}
#endif

bool nfc_app_scan_mode_uart() {
#if defined(NERO_CCID_ONLY_BUILD)
  return false;
#else
  const nfc_mode_t before = g_mode;
  (void)scan_mode_switch();
  return g_mode != before;
#endif
}

bool nfc_app_poll_mode_switch() {
#if defined(NERO_CCID_ONLY_BUILD)
  return false;
#else
  nfc_hal_preload_serial();
  return nfc_app_scan_mode_uart();
#endif
}

bool nfc_app_runtime_is_reader() {
  return g_mode == kNfcModeReader;
}

void nfc_app_setup(void) {
#if defined(NERO_CCID_ONLY_BUILD)
  g_mode = kNfcModeReader;
  nfc_hal_usb_begin();
#else
  nfc_combined_shell_serial_begin(NFC_HOST_SERIAL_BAUD);
  const auto t0 = static_cast<std::uint32_t>(nfc_combined_shell_millis());
  while (!nfc_combined_shell_serial_ready() &&
         (static_cast<std::uint32_t>(nfc_combined_shell_millis()) - t0) < kSerialReadyWaitMs) {}
  if (nfc_combined_shell_serial_ready()) {
    const auto settle_t0 = static_cast<std::uint32_t>(nfc_combined_shell_millis());
    while ((static_cast<std::uint32_t>(nfc_combined_shell_millis()) - settle_t0) <
           kSerialSettleMs) {}
  }
  print_banner();

  if (g_mode == kNfcModeReader) {
    reader_setup();
  } else {
    writer_setup();
  }
#endif
}

void nfc_app_loop(void) {
#if defined(NERO_CCID_ONLY_BUILD)
  enum { kCcidUsbConfiguredNfcStartDelayMs = 2000u };
  static bool ccid_bootstrapped = false;
  if (!ccid_bootstrapped) {
    reader_context_reset(&g_reader);
    ccid_bootstrapped = true;
  }

  reader_hal_ccid_usb_service_poll();
  reader_ccid_poll();

  if (!reader_hal_ccid_usb_configured()) {
    return;
  }

  static uint32_t configured_at_ms = 0u;
  if (configured_at_ms == 0u) {
    configured_at_ms = reader_hal_millis();
  }
  static bool nfc_hardware_started = false;
  if (!nfc_hardware_started &&
      (reader_hal_millis() - configured_at_ms) >= kCcidUsbConfiguredNfcStartDelayMs) {
    reader_setup_nfc_hardware();
    nfc_hardware_started = true;
  }

  reader_loop();
#else
  if (nfc_app_poll_mode_switch()) {
    return;
  }

  if (g_mode == kNfcModeReader) {
    reader_loop();
  } else {
    writer_loop();
  }
#endif
}
