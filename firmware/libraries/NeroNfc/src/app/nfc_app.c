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
 * nfc_app.c — combined firmware mode-switcher.
 *
 * Combined-mode and serial pushback state live in nero_nfc_app_t (§2).
 */

#include "nfc_mode_line_scan.h"

#include "nero_nfc_app.h"
#include "nero_nfc_board.h"
#include "nero_nfc_log.h"
#include "nero_nfc_null.h"
#include "reader_hal_ccid_usb.h"

#include "nfc_app.h"
#include "nfc_board_defaults.h"
#include "nfc_combined_shell.h"
#include "nfc_runtime_mode_poll.h"

#include "reader_app.h"
#include "reader_hal.h"
#if !defined(NERO_CCID_USB_BUILD) || defined(NERO_HOST_UNIT_TEST_HOOKS)
#include "writer_app.h"
#endif
#if defined(NERO_CCID_ONLY_BUILD)
#include "reader_ccid.h"
#include "reader_context.h"
#endif

#include "nero_nfc_platform.h"

void nfc_hal_preload_serial(void);
int nfc_hal_pushback_available(void);
int nfc_hal_pushback_read(void);
void nfc_hal_pushback_return(const uint8_t* bytes, uint16_t len);
void nfc_hal_usb_begin(void);

#if !defined(NERO_CCID_ONLY_BUILD)
enum {
  K_SERIAL_READY_WAIT_MS = 250u,
  K_SERIAL_SETTLE_MS = 40u,
};

static const char* mode_name(nero_nfc_runtime_mode_t mode) {
  return (mode == NERO_NFC_RUNTIME_MODE_READER) ? "reader" : "writer";
}

static void print_banner(void) {
  nero_nfc_app_t* app = nero_nfc_app_active();
  nero_nfc_log_write("\r\n[nfc] Active mode: ");
  nero_nfc_log_write(mode_name(nero_nfc_app_runtime_mode(app)));
  nero_nfc_log_line(
      " · UART switch:  mode reader  |  mode writer  (newline; "
      "banner repeats after switch)");
}

static void do_mode_switch(nero_nfc_runtime_mode_t new_mode) {
  nero_nfc_app_t* app = nero_nfc_app_active();
  const nero_nfc_runtime_mode_t cur = nero_nfc_app_runtime_mode(app);
  if (new_mode == cur) {
    if (cur == NERO_NFC_RUNTIME_MODE_READER) {
      reader_setup();
    } else {
      nero_nfc_log_line("\r\n[nfc] already in writer mode");
    }
    return;
  }
  nero_nfc_app_set_runtime_mode(app, new_mode);
  nfc_mode_scan_reset(nero_nfc_app_mode_scan(app));
  nero_nfc_log_write("\r\n[nfc] switching to ");
  nero_nfc_log_write(mode_name(new_mode));
  nero_nfc_log_line(" mode...");
  if (new_mode == NERO_NFC_RUNTIME_MODE_READER) {
    reader_setup();
  } else {
    writer_setup();
  }
}

static bool scan_mode_switch(void) {
  bool switched = false;
  uint8_t pb[NFC_MODE_SCAN_CAP + NFC_MODE_SCAN_PUSHBACK_BUF_EXTRA];
  uint16_t pblen = 0u;
  nfc_mode_scan_state_t* scan = nero_nfc_app_mode_scan(nero_nfc_app_active());

  while (nfc_hal_pushback_available() > 0) {
    int b = nfc_hal_pushback_read();
    if (b < 0) {
      break;
    }
    const uint8_t k_ch = (uint8_t)(b);
    nfc_mode_scan_result_t r =
        nfc_mode_scan_feed(scan, k_ch, pb, &pblen, (uint16_t)(sizeof(pb)));
    switch (r) {
      case NFC_MODE_SCAN_INGESTED:
        break;
      case NFC_MODE_SCAN_GOT_READER:
        do_mode_switch(NERO_NFC_RUNTIME_MODE_READER);
        switched = true;
        break;
      case NFC_MODE_SCAN_GOT_WRITER:
        do_mode_switch(NERO_NFC_RUNTIME_MODE_WRITER);
        switched = true;
        break;
      case NFC_MODE_SCAN_PUSHBACK_STOP:
        /*
         * Writer mode: return non-mode bytes to the ring for
         * writer_serial_cli (ndef-hex / url / …).
         *
         * Reader mode: discard them and keep scanning. Reader never drains
         * the pushback ring, so a leading glitch (or a premature ndef-hex)
         * would permanently hide a later "mode writer" and leave CDC writer
         * stuck dumping tags with no SUCCESS.
         */
        if (nero_nfc_app_runtime_mode(nero_nfc_app_active()) ==
            NERO_NFC_RUNTIME_MODE_WRITER) {
          if (pblen > 0u) {
            nfc_hal_pushback_return(pb, pblen);
          }
          return switched;
        }
        break;
    }
  }

  return switched;
}
#endif

bool nfc_app_scan_mode_uart(void) {
#if defined(NERO_CCID_ONLY_BUILD)
  return false;
#else
  nero_nfc_app_t* app = nero_nfc_app_active();
  nero_nfc_runtime_mode_t before;

  if (app == NERO_NFC_NULL) {
    return false;
  }
  if (nero_nfc_app_product(app) != NERO_NFC_PRODUCT_COMBINED) {
    return false;
  }
  before = nero_nfc_app_runtime_mode(app);
  (void)scan_mode_switch();
  return nero_nfc_app_runtime_mode(app) != before;
#endif
}

bool nfc_app_poll_mode_switch(void) {
#if defined(NERO_CCID_ONLY_BUILD)
  return false;
#else
  nfc_hal_preload_serial();
  return nfc_app_scan_mode_uart();
#endif
}

bool nfc_app_runtime_is_reader(void) {
  nero_nfc_app_t* app = nero_nfc_app_active();
  if (app == NERO_NFC_NULL) {
    return true;
  }
  switch (nero_nfc_app_product(app)) {
    case NERO_NFC_PRODUCT_WRITER:
      return false;
    case NERO_NFC_PRODUCT_COMBINED:
      return nero_nfc_app_runtime_mode(app) == NERO_NFC_RUNTIME_MODE_READER;
    case NERO_NFC_PRODUCT_READER:
    case NERO_NFC_PRODUCT_INVALID:
    default:
      return true;
  }
}

static bool ensure_combined_app(void) {
  nero_nfc_app_t* app = nero_nfc_app_active();
  bool product_valid;

  if (app == NERO_NFC_NULL) {
    return false;
  }
#if defined(NERO_CCID_ONLY_BUILD)
  product_valid = nero_nfc_app_product(app) == NERO_NFC_PRODUCT_READER;
#else
  product_valid = nero_nfc_app_product(app) == NERO_NFC_PRODUCT_COMBINED;
#endif
  if (!product_valid) {
    return false;
  }
#ifdef NFC_DEFAULT_WRITER
  nero_nfc_app_set_runtime_mode(app, NERO_NFC_RUNTIME_MODE_WRITER);
#else
  nero_nfc_app_set_runtime_mode(app, NERO_NFC_RUNTIME_MODE_READER);
#endif
  return true;
}

void nfc_app_setup(void) {
  if (!ensure_combined_app()) {
    return;
  }
#if defined(NERO_CCID_ONLY_BUILD)
  nero_nfc_app_set_runtime_mode(nero_nfc_app_active(),
                                NERO_NFC_RUNTIME_MODE_READER);
  nfc_hal_usb_begin();
#else
  const nero_nfc_board_config_t* board =
      nero_nfc_app_board(nero_nfc_app_active());
  if (board == NERO_NFC_NULL) {
    return;
  }
  nfc_combined_shell_serial_begin((unsigned long)board->serial_baud);
  nero_nfc_log_set_sink(&reader_hal_serial_write_char);
  const uint32_t k_t0 = nfc_combined_shell_millis();
  while (!nfc_combined_shell_serial_ready() &&
         (nfc_combined_shell_millis() - k_t0) < K_SERIAL_READY_WAIT_MS) {
  }
  if (nfc_combined_shell_serial_ready()) {
    const uint32_t k_settle_t0 = nfc_combined_shell_millis();
    while ((nfc_combined_shell_millis() - k_settle_t0) < K_SERIAL_SETTLE_MS) {
    }
  }
  print_banner();

  if (nfc_app_runtime_is_reader()) {
    reader_setup();
  } else {
    writer_setup();
  }
#endif
}

void nfc_app_loop(void) {
#if defined(NERO_CCID_ONLY_BUILD)
  enum { K_CCID_USB_CONFIGURED_NFC_START_DELAY_MS = 2000u };
  nero_nfc_app_t* app = nero_nfc_app_active();
  uint32_t configured_at_ms;

  if (app == NERO_NFC_NULL) {
    return;
  }
  if (!nero_nfc_app_ccid_bootstrapped(app)) {
    reader_context_reset(reader_context_active());
    reader_context_active()->frontend = nero_nfc_app_frontend(app);
    nero_nfc_app_set_ccid_bootstrapped(app);
  }

  reader_hal_ccid_usb_service_poll();
  reader_ccid_poll();

  if (!reader_hal_ccid_usb_configured()) {
    return;
  }

  configured_at_ms = nero_nfc_app_ccid_configured_at_ms(app);
  if (configured_at_ms == 0u) {
    configured_at_ms = reader_hal_millis();
    nero_nfc_app_set_ccid_configured_at_ms(app, configured_at_ms);
  }
  if (!nero_nfc_app_ccid_hardware_started(app) &&
      (reader_hal_millis() - configured_at_ms) >=
          K_CCID_USB_CONFIGURED_NFC_START_DELAY_MS) {
    reader_setup_nfc_hardware();
    nero_nfc_app_set_ccid_hardware_started(app);
  }

  reader_loop();
#else
  if (nero_nfc_app_active() == NERO_NFC_NULL) {
    return;
  }
  if (nfc_app_poll_mode_switch()) {
    return;
  }

  if (nfc_app_runtime_is_reader()) {
    reader_loop();
  } else {
    writer_loop();
  }
#endif
}
