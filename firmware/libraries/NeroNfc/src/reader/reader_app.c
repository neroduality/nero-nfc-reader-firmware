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

#include "nero_nfc_null.h"
/*
 * reader_app.c — Unified NFC reader for the X-NUCLEO-NFC08A1 (ST25R3916B)
 * on supported Arduino-class host boards (UNO R4 WiFi, Nucleo-WBA65RI, …).
 *
 * One firmware target supports:
 *   - NFC Forum Type 2 tags  (NTAG213/215/216, ST25TN512/ST25TN01K) over
 * ISO 14443-A
 *   - NFC Forum Type 4 tags  (ST25TA02K, NTAG I2C Plus) over ISO 14443-A /
 * ISO-DEP
 *   - NFC Forum Type 5 tags  (ST25DV64KC, ST25TV02KC) over ISO 15693
 *
 * Auto-detection runs every poll cycle:
 *   1. Configure ISO 14443-A and try a WUPA. If a tag answers and SAK bit 6
 *      (0x20, ISO-DEP) is set, the CDC firmware treats it as an NFC Forum
 *      Type 4 NDEF tag.
 *   2. If SAK bit 6 is clear the tag is NFC Forum Type 2 — read pages and
 * parse NDEF.
 *   3. If 14443-A fails, configure ISO 15693 and try inventory. If a UID
 *      answers, this is a Type 5 tag — read its Capability Container and parse
 *      the NDEF message from user memory.
 *
 * Security boundary: WebAuthn/FIDO is exposed by the CCID firmware path only.
 * CDC reader/writer mode is limited to tag read/write workflows.
 */

#include "nero_nfc_app.h"
#include "nero_nfc_board.h"
#include "nero_nfc_mem_util.h"
#include "nfc_board_defaults.h"
#include "nfc_runtime_mode_poll.h"
#include "nfc_tag_geometry_limits.h"
#include "reader_app.h"
#include "reader_context.h"
#if defined(NERO_CCID_USB_BUILD)
#include "nfc_ccid_frame.h"
#include "reader_ccid.h"
#endif
#include "nero_nfc_format.h"
#include "nero_nfc_frontend.h"
#include "nfc_iso_dep_timing.h"
#include "reader_hal.h"
#include "reader_output.h"
#include "reader_protocol.h"
#include "reader_security_key_iso_dep_session.h"
#include "reader_tags.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static const nero_nfc_board_config_t* reader_board(void) {
  return nero_nfc_app_board(nero_nfc_app_active());
}

static uint8_t reader_cs_pin(void) {
  const nero_nfc_board_config_t* board = reader_board();
  return (board == NERO_NFC_NULL) ? 0u : board->cs_pin;
}

static uint8_t reader_irq_pin(void) {
  const nero_nfc_board_config_t* board = reader_board();
  return (board == NERO_NFC_NULL) ? 0u : board->irq_pin;
}

static uint8_t reader_led_pin(void) {
  const nero_nfc_board_config_t* board = reader_board();
  return (board == NERO_NFC_NULL) ? 0u : board->led_pin;
}

#define CS_PIN reader_cs_pin()
#define IRQ_PIN reader_irq_pin()
#define LED_PIN reader_led_pin()

#define LOW_LEVEL 0u
#define HIGH_LEVEL 1u
#define RF_READY_LED_LEVEL HIGH_LEVEL

/* Removal detection: require this many back-to-back probe rounds where both
 * ISO 14443-A (WUPA) and ISO 15693 inventory see nothing. */
#define TAG_REMOVE_CONSECUTIVE_MISSES 2u
/* Brief pause between miss rounds so the field can recover before retry. */
#define TAG_REMOVE_MISS_RETRY_MS 50u
/* Reuse the existing field-load threshold for host-owned CCID sessions. Full
 * activation/inventory probes can disturb an active storage or ISO-DEP
 * exchange. */
#define CCID_ACTIVE_TYPE4_FIELD_LOAD_PRESENT 3

enum {
  READER_APP_SERIAL_READY_WAIT_MS = 250u,
  READER_APP_SERIAL_SETTLE_MS = 40u,
  READER_APP_FIELD_BAR_WIDTH = 20u,
  READER_APP_FIELD_AMP_MAX = 255u,
  READER_APP_FIELD_AMP_PAD_HUNDREDS = 100u,
  READER_APP_FIELD_AMP_PAD_TENS = 10u,
  READER_APP_CCID_POLL_INTERVAL_MS = 100u,
  READER_APP_NEAR_POLL_INTERVAL_MS = 50u,
  READER_APP_FIELD_PRINT_NEAR_MS = 200u,
  READER_APP_FIELD_PRINT_IDLE_MS = 1500u,
  READER_APP_TAG_REMOVE_WAIT_MS = 5000u,
  READER_APP_TAG_REMOVE_SETTLE_MS = 50u,
  READER_APP_TAG_REMOVE_FINAL_MS = 20u,
  READER_APP_COUPLING_TAG_ON = 10u,
  READER_APP_COUPLING_APPROACH = 3u,
  READER_APP_FIELD_LOAD_NEAR = 3u,
  READER_APP_FATAL_BLINK_MS = 200u,
  READER_APP_RF_FORCE_MS = 10u,
};

static bool ensure_reader_app(void) {
  const nero_nfc_app_t* app = nero_nfc_app_active();
  return (app != NERO_NFC_NULL) &&
         (nero_nfc_app_product(app) != NERO_NFC_PRODUCT_WRITER);
}

bool reader_ccid_prepare_tag_for_power_on(reader_tag_kind_t tag_kind) {
#if defined(NERO_CCID_USB_BUILD)
  nfc_frontend_quiesce(READER_FRONTEND);
  if ((tag_kind == READER_TAG_KIND_TYPE2) ||
      (tag_kind == READER_TAG_KIND_TYPE4)) {
    reader_protocol_configure_iso14443a();
    nfc_frontend_ensure_tx_rx(READER_FRONTEND);
    if (!reader_protocol_activate_iso14443a()) {
      return false;
    }
    return (((G_SAK & NFC_TAG_T4T_SAK_ISO14443_4_BIT) != 0u)
                ? READER_TAG_KIND_TYPE4
                : READER_TAG_KIND_TYPE2) == tag_kind;
  }
  if (tag_kind == READER_TAG_KIND_TYPE5) {
    reader_protocol_configure_iso15693();
    return reader_tags_iso15693_inventory_step();
  }
#else
  (void)tag_kind;
#endif
  return true;
}

static uint8_t measure_amplitude(void) {
  return nfc_frontend_measure_amplitude(READER_FRONTEND);
}

#if defined(NERO_CCID_ONLY_BUILD)
static void ccid_service_delay_ms(uint32_t ms) {
  const uint32_t deadline = reader_hal_millis() + ms;
  while ((int32_t)(reader_hal_millis() - deadline) < 0) {
    reader_ccid_poll();
  }
}
#endif

static void print_field_strength(uint8_t amp, uint8_t baseline) {
#if defined(NERO_CCID_USB_BUILD)
  (void)amp;
  (void)baseline;
#else
  uint8_t bar_len = (uint8_t)(((uint16_t)amp * READER_APP_FIELD_BAR_WIDTH) /
                              READER_APP_FIELD_AMP_MAX);
  nero_nfc_log_write("[NFC reader] Field ");
  if (amp < READER_APP_FIELD_AMP_PAD_HUNDREDS) {
    nero_nfc_log_putc(' ');
  }
  if (amp < READER_APP_FIELD_AMP_PAD_TENS) {
    nero_nfc_log_putc(' ');
  }
  {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(amp));
    nero_nfc_log_write(ndc);
  }
  nero_nfc_log_write("/255 |");
  for (unsigned i = 0u; i < (unsigned)READER_APP_FIELD_BAR_WIDTH; i++) {
    nero_nfc_log_putc(i < bar_len ? '#' : '-');
  }
  nero_nfc_log_write("| ");
  if (baseline > 0u) {
    int16_t coupling = (int16_t)((int16_t)baseline - (int16_t)amp);
    nero_nfc_log_write("coupling=");
    if (coupling > 0) {
      nero_nfc_log_putc('+');
    }
    {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%d", (int)(int32_t)(coupling));
      nero_nfc_log_write(ndc);
    }
    nero_nfc_log_write(" | ");
    if (coupling > READER_APP_COUPLING_TAG_ON) {
      nero_nfc_log_write("tag on antenna");
    } else if (coupling > READER_APP_COUPLING_APPROACH) {
      nero_nfc_log_write("tag approaching");
    }
  }
  nero_nfc_log_write("\r\n");
#endif
}

/* ── Chip + RF init ───────────────────────────────────────────── */

static bool init_chip(void) {
  nfc_frontend_init_status_t s;
  uint8_t chip_id = 0u;
  uint16_t vdd_mv = 0u;

#if !defined(NERO_CCID_USB_BUILD)
  nero_nfc_log_write("  ── ");
  nero_nfc_log_write(NFC_FRONTEND_MODEL_NAME);
  nero_nfc_log_line(" Initialization ──");
#endif
  s = nfc_frontend_init(READER_FRONTEND, &chip_id, &vdd_mv);
#if !defined(NERO_CCID_USB_BUILD)
  nero_nfc_log_write("  Chip ID: 0x");
  {
    char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
    (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)chip_id);
    nero_nfc_log_write(nhx);
  }
  nero_nfc_log_write("\r\n");
#endif
  if (s == NFC_FRONTEND_INIT_CHIP_ID_FAIL) {
#if !defined(NERO_CCID_USB_BUILD)
    nero_nfc_log_line("  ERROR: Cannot read chip ID! Check wiring.");
#endif
    return false;
  }
#if !defined(NERO_CCID_USB_BUILD)
  nero_nfc_log_write("  Oscillator...");
#endif
  if (s == NFC_FRONTEND_INIT_OSC_FAIL) {
#if !defined(NERO_CCID_USB_BUILD)
    nero_nfc_log_line(" FAILED");
#endif
    return false;
  }
#if !defined(NERO_CCID_USB_BUILD)
  nero_nfc_log_write(" OK\r\n  VDD: ");
  {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                            (unsigned)(uint32_t)(vdd_mv));
    nero_nfc_log_write(ndc);
  }
  nero_nfc_log_line(" mV\r\n  Init complete!");
#endif
  (void)chip_id;
  (void)vdd_mv;
  return true;
}

#if !defined(NERO_CCID_USB_BUILD)
static void open_in_browser(void) {
  if ((!G_URL_DETECTED || (G_DETECTED_URL[0] == '\0')) &&
      (G_DETECTED_URL_COUNT == 0u)) {
    return;
  }
  if (G_DETECTED_URL_COUNT != 0u) {
    for (uint8_t i = 0u; i < G_DETECTED_URL_COUNT; i++) {
      if (reader_is_browser_safe_url(G_DETECTED_URLS[i])) {
        nero_nfc_log_write("BROWSER_OPEN:");
        nero_nfc_log_write(G_DETECTED_URLS[i]);
        nero_nfc_log_write("\r\n");
      }
    }
  } else {
    if (!reader_is_browser_safe_url(G_DETECTED_URL)) {
      nero_nfc_log_line(
          "  URL scheme blocked; only http(s) auto-open is allowed.");
      G_URL_DETECTED = false;
      return;
    }
    nero_nfc_log_write("BROWSER_OPEN:");
    nero_nfc_log_write(G_DETECTED_URL);
    nero_nfc_log_write("\r\n");
  }
  G_DETECTED_URL_COUNT = 0u;
  G_URL_DETECTED = false;
}

static void reader_read_type4_ndef_tag(void) {
  nero_nfc_log_line("\r\n╔════════════════════════════════════════╗");
  nero_nfc_log_line("║     NFC FORUM TYPE 4 TAG               ║");
  nero_nfc_log_line("╚════════════════════════════════════════╝");
  nero_nfc_log_line("  ISO-DEP: opening NFC Forum Type 4 NDEF session.");
  if (!reader_security_key_iso_dep_session_open_quiet(
          SECURITY_KEY_RATS_TIMEOUT_MS)) {
    nero_nfc_log_write(
        "\r\n  [TYPE4] ISO-DEP session failed — cannot read NDEF.\r\n");
    return;
  }
  (void)reader_tags_read_type4_ndef();
  reader_security_key_iso_dep_send_deselect();
}
#endif

/* ── Top-level detection cycle ────────────────────────────────── */

/*
 * Returns true if a tag was found and processed; the caller then enters its
 * "wait for tag removal" debounce loop. Returning false means no tag at all.
 */
static bool reader_poll_handle_iso14443a(void) {
  bool same = (G_UID14_LEN == G_LAST_UID_LEN) &&
              (memcmp(G_UID14, G_LAST_UID, G_UID14_LEN) == 0);
  if (same) {
#if defined(NERO_CCID_USB_BUILD)
    /* pcscd drives the active ISO-DEP session after NotifySlotChange; do not
     * fall into the generic WUPA-based removal debounce loop because it can
     * disturb the host-owned CCID exchange before the first XfrBlock. */
    return false;
#else
    return true;
#endif
  }
  if (!nero_nfc_copy_bytes(G_LAST_UID, sizeof(G_LAST_UID), 0u, G_UID14,
                           G_UID14_LEN)) {
    return false;
  }
  G_LAST_UID_LEN = G_UID14_LEN;

  reader_hal_digital_write(LED_PIN, LOW_LEVEL);
#if defined(NERO_CCID_USB_BUILD)
  /* In CCID mode the host owns all supported tag operations after
   * NotifySlotChange. The CCID layer differentiates Type 2 / Type 4 via SAK. */
  reader_ccid_on_tag_detected(((G_SAK & NFC_TAG_T4T_SAK_ISO14443_4_BIT) != 0u)
                                  ? READER_TAG_KIND_TYPE4
                                  : READER_TAG_KIND_TYPE2);
  reader_hal_digital_write(LED_PIN, RF_READY_LED_LEVEL);
  return false;
#else
  if ((G_SAK & NFC_TAG_T4T_SAK_ISO14443_4_BIT) != 0u) {
    reader_read_type4_ndef_tag();
    open_in_browser();
  } else {
    reader_tags_read_ntag_tag();
    open_in_browser();
  }
  reader_hal_digital_write(LED_PIN, HIGH_LEVEL);
  return true;
#endif
}

static bool reader_poll_handle_iso15693(void) {
  /* Use the last-uid slot to gate repeated prints */
  bool same = (G_LAST_UID_LEN == NFC_FRONTEND_ISO15693_UID_LEN) &&
              (memcmp(G_UID15, G_LAST_UID, NFC_FRONTEND_ISO15693_UID_LEN) == 0);
  if (same) {
    return true;
  }
  if (!nero_nfc_copy_bytes(G_LAST_UID, sizeof(G_LAST_UID), 0u, G_UID15,
                           NFC_FRONTEND_ISO15693_UID_LEN)) {
    return false;
  }
  G_LAST_UID_LEN = NFC_FRONTEND_ISO15693_UID_LEN;

  reader_hal_digital_write(LED_PIN, LOW_LEVEL);
#if defined(NERO_CCID_USB_BUILD)
  reader_ccid_on_tag_detected(READER_TAG_KIND_TYPE5);
  reader_hal_digital_write(LED_PIN, HIGH_LEVEL);
  return false;
#else
  reader_tags_read_dynamic_or_static_type5();
  open_in_browser();
  reader_hal_digital_write(LED_PIN, HIGH_LEVEL);
  return true;
#endif
}

static bool poll_one_cycle(void) {
  reader_protocol_configure_iso14443a();
  nfc_frontend_ensure_tx_rx(READER_FRONTEND);

  if (reader_protocol_activate_iso14443a()) {
    return reader_poll_handle_iso14443a();
  }

  /* Phase 2: ISO 15693 inventory. Quiesce the radio first so the previous
   * 14443-A WUPA does not leave the NRT timer or FIFO in a state that
   * stalls the next frame. */
  nfc_frontend_quiesce(READER_FRONTEND);
  reader_protocol_configure_iso15693();
  if (reader_tags_iso15693_inventory_step()) {
    return reader_poll_handle_iso15693();
  }

  return false;
}

#if defined(NERO_CCID_USB_BUILD)
static bool ccid_last_uid_matches(const uint8_t* uid, uint8_t uid_len) {
  return (uid != NERO_NFC_NULL) && (uid_len == G_LAST_UID_LEN) &&
         (memcmp(uid, G_LAST_UID, uid_len) == 0);
}

static bool ccid_remember_last_uid(const uint8_t* uid, uint8_t uid_len) {
  if ((uid == NERO_NFC_NULL) ||
      !nero_nfc_copy_bytes(G_LAST_UID, sizeof(G_LAST_UID), 0u, uid, uid_len)) {
    return false;
  }
  G_LAST_UID_LEN = uid_len;
  return true;
}

static bool ccid_probe_present_tag(reader_tag_kind_t* tag_kind_out,
                                   bool* same_uid_out) {
  if (tag_kind_out != NERO_NFC_NULL) {
    *tag_kind_out = READER_TAG_KIND_NONE;
  }
  if (same_uid_out != NERO_NFC_NULL) {
    *same_uid_out = false;
  }
  if ((tag_kind_out == NERO_NFC_NULL) || (same_uid_out == NERO_NFC_NULL)) {
    return false;
  }

  reader_protocol_configure_iso14443a();
  nfc_frontend_ensure_tx_rx(READER_FRONTEND);
  if (reader_protocol_activate_iso14443a()) {
    *tag_kind_out = ((G_SAK & NFC_TAG_T4T_SAK_ISO14443_4_BIT) != 0u)
                        ? READER_TAG_KIND_TYPE4
                        : READER_TAG_KIND_TYPE2;
    *same_uid_out = ccid_last_uid_matches(G_UID14, G_UID14_LEN);
    return true;
  }

  nfc_frontend_quiesce(READER_FRONTEND);
  reader_protocol_configure_iso15693();
  if (reader_tags_iso15693_inventory_step()) {
    *tag_kind_out = READER_TAG_KIND_TYPE5;
    *same_uid_out =
        ccid_last_uid_matches(G_UID15, NFC_FRONTEND_ISO15693_UID_LEN);
    return true;
  }

  return false;
}

static bool ccid_active_type4_field_present(void) {
  if (G_BASELINE_AMP == 0u) {
    G_BASELINE_AMP = measure_amplitude();
    return true;
  }
  const uint8_t amp = measure_amplitude();
  const int16_t load = (int16_t)((int16_t)G_BASELINE_AMP - (int16_t)amp);
  return load > CCID_ACTIVE_TYPE4_FIELD_LOAD_PRESENT;
}
#endif

/* ── Public API ───────────────────────────────────────────────── */

void reader_setup(void) {
  const nero_nfc_board_config_t* board;
  reader_context_t* ctx;

  if (!ensure_reader_app()) {
    return;
  }
  board = reader_board();
  if (board == NERO_NFC_NULL) {
    return;
  }
  ctx = reader_context_active();
  reader_context_reset(ctx);
  ctx->frontend = nero_nfc_app_frontend(nero_nfc_app_active());
  ctx->app.poll_interval_ms = READER_APP_CCID_POLL_INTERVAL_MS;
#if defined(NERO_CCID_USB_BUILD)
  ctx->app.last_ccid_icc_status = (uint8_t)(NFC_CCID_ICC_NO_ICC);
#endif
#if !defined(NERO_CCID_ONLY_BUILD)
  reader_hal_serial_begin((unsigned long)board->serial_baud);
#endif
#if !defined(NERO_CCID_USB_BUILD)
  const uint32_t t0 = reader_hal_millis();
  /* In standalone serial mode, allow a brief host attach window without
   * delaying startup by multiple seconds when no terminal is listening yet. */
  while (!reader_hal_serial_ready() &&
         ((reader_hal_millis() - t0) < READER_APP_SERIAL_READY_WAIT_MS)) {
  }
  if (reader_hal_serial_ready()) {
    reader_hal_delay_ms(READER_APP_SERIAL_SETTLE_MS);
  }
#endif /* !NERO_CCID_USB_BUILD */

#if !defined(NERO_CCID_USB_BUILD)
  nero_nfc_log_line("\r\n========================================");
  nero_nfc_log_line("  Unified NFC Reader (Type 2 + Type 4 + Type 5)");
  nero_nfc_log_line("========================================");
  nero_nfc_log_write("  Board:  ");
  nero_nfc_log_write(board->host_board_name);
  nero_nfc_log_line("");
  nero_nfc_log_write("  Shield: ");
  nero_nfc_log_write(NFC_FRONTEND_REFERENCE_BOARD_NAME);
  nero_nfc_log_write(" (");
  nero_nfc_log_write(NFC_FRONTEND_MODEL_NAME);
  nero_nfc_log_line(")");
  nero_nfc_log_line("  Supported tags:");
  nero_nfc_log_line("    Type 2: NTAG213/215/216, ST25TN512/ST25TN01K");
  nero_nfc_log_line(
      "    Type 4: ST25TA02K, NTAG I2C Plus, NTAG424 DNA (plain NDEF only)");
  nero_nfc_log_line("    Type 5: ST25DV64KC (dynamic tag), ST25TV02KC");
  nero_nfc_log_line("  Tags & URLs (reader mode):");
  nero_nfc_log_write(
      "    Tap tags for NDEF; http(s) lines emit BROWSER_OPEN for the "
      "desktop opener\r\n");
  nero_nfc_log_line("  UART (combined firmware):");
  nero_nfc_log_write(
      "    mode writer  · tag payloads (help for URL/text/…);  mode "
      "reader  · this "
      "reader\r\n");
#endif

  reader_setup_nfc_hardware();
}

void reader_setup_nfc_hardware(void) {
#if defined(NERO_CCID_ONLY_BUILD)
  G_READER.app.nfc_frontend_ready = false;
#endif
  reader_hal_pin_mode(CS_PIN, READER_HAL_PIN_OUTPUT);
  reader_hal_digital_write(CS_PIN, HIGH_LEVEL);
  reader_hal_pin_mode(IRQ_PIN, 0);
  reader_hal_pin_mode(LED_PIN, READER_HAL_PIN_OUTPUT);
  reader_hal_digital_write(LED_PIN, HIGH_LEVEL);

  reader_hal_spi_begin();

  if (!init_chip()) {
#if defined(NERO_CCID_ONLY_BUILD)
    /* USB CCID must keep answering pcscd even when the NFC frontend is absent.
     */
    return;
#else
    nero_nfc_log_line("\r\n*** FATAL: Chip init failed! Check wiring. ***");
    nero_nfc_log_line("    CS=D10 MOSI=D11 MISO=D12 SCK=D13 IRQ=A0");
    for (;;) {
      reader_hal_digital_write(LED_PIN,
                               (uint8_t)!reader_hal_digital_read(LED_PIN));
      reader_hal_delay_ms(READER_APP_FATAL_BLINK_MS);
    }
#endif
  }

  reader_protocol_configure_iso14443a();
  if (!reader_protocol_field_on()) {
#if !defined(NERO_CCID_USB_BUILD)
    nero_nfc_log_line("  Forcing field on...");
#endif
    nfc_frontend_enable_tx_rx(READER_FRONTEND);
#if defined(NERO_CCID_ONLY_BUILD)
    ccid_service_delay_ms(READER_APP_RF_FORCE_MS);
#else
    reader_hal_delay_ms(READER_APP_RF_FORCE_MS);
#endif
  }

#if defined(NERO_CCID_ONLY_BUILD)
  ccid_service_delay_ms(READER_APP_TAG_REMOVE_SETTLE_MS);
#else
  reader_hal_delay_ms(READER_APP_TAG_REMOVE_SETTLE_MS);
#endif
  G_BASELINE_AMP = measure_amplitude();
#if !defined(NERO_CCID_USB_BUILD)
  nero_nfc_log_write("  Baseline: ");
  {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                            (unsigned)(uint32_t)(G_BASELINE_AMP));
    nero_nfc_log_write(ndc);
  }
  nero_nfc_log_line("/255");

  nero_nfc_log_line("\r\n========================================");
  nero_nfc_log_line("  READY! Tap any supported NFC tag.");
  nero_nfc_log_line("========================================\r\n");
  print_field_strength(measure_amplitude(), G_BASELINE_AMP);
#endif
  G_READER.app.last_field_print_ms = reader_hal_millis();
#if defined(NERO_CCID_ONLY_BUILD)
  G_READER.app.nfc_frontend_ready = true;
#endif
}

#if defined(NERO_CCID_USB_BUILD)
static void reader_ccid_loop_step(void) {
  reader_app_runtime_t* runtime = &reader_context_active()->app;
  uint32_t now_ccid = reader_hal_millis();
  uint8_t icc_status = reader_ccid_icc_status();

  if (icc_status != runtime->last_ccid_icc_status) {
    runtime->last_ccid_icc_status = icc_status;
    runtime->ccid_remove_misses = 0u;
  }

  if (icc_status != (uint8_t)(NFC_CCID_ICC_NO_ICC)) {
    reader_tag_kind_t probed_kind = READER_TAG_KIND_NONE;
    bool same_uid = false;
    const bool active_session = icc_status == (uint8_t)(NFC_CCID_ICC_ACTIVE);
    const reader_tag_kind_t active_kind = reader_ccid_tag_kind();
    if (active_session && active_kind == READER_TAG_KIND_TYPE4 &&
        reader_ccid_fido_session_active()) {
      /* CTAP NFC user presence and PIN-token state both depend on one stable
       * powered ISO-DEP session. Do not issue frontend measurement or polling
       * commands between ClientPIN and getAssertion. Removal is observed by
       * the next host exchange or when CCID tears down the session. */
      return;
    }
    if ((now_ccid - runtime->last_ccid_remove_probe_ms) <
        TAG_REMOVE_MISS_RETRY_MS) {
      return;
    }
    runtime->last_ccid_remove_probe_ms = now_ccid;
    bool still_present;
    if (active_session && active_kind == READER_TAG_KIND_TYPE4) {
      still_present = ccid_active_type4_field_present();
      same_uid = true;
      probed_kind = active_kind;
    } else {
      if (active_session && !reader_ccid_removal_probe_due(now_ccid)) {
        return;
      }
      still_present = ccid_probe_present_tag(&probed_kind, &same_uid);
    }
    if (still_present) {
      runtime->ccid_remove_misses = 0u;
      if (!same_uid) {
        const uint8_t* uid =
            (probed_kind == READER_TAG_KIND_TYPE5) ? G_UID15 : G_UID14;
        const uint8_t uid_len = (probed_kind == READER_TAG_KIND_TYPE5)
                                    ? NFC_FRONTEND_ISO15693_UID_LEN
                                    : G_UID14_LEN;
        if (ccid_remember_last_uid(uid, uid_len)) {
          reader_ccid_on_tag_removed_from_field();
          reader_ccid_on_tag_detected(probed_kind);
        }
      }
      return;
    }
    runtime->ccid_remove_misses++;
    if (runtime->ccid_remove_misses >= TAG_REMOVE_CONSECUTIVE_MISSES) {
      runtime->ccid_remove_misses = 0u;
      G_LAST_UID_LEN = 0u;
      reader_ccid_on_tag_removed_from_field();
    }
    return;
  }
  runtime->ccid_remove_misses = 0u;
  if ((now_ccid - runtime->last_ccid_poll_ms) <
      READER_APP_CCID_POLL_INTERVAL_MS) {
    return;
  }
  runtime->last_ccid_poll_ms = now_ccid;
  (void)poll_one_cycle();
}
#endif

void reader_loop(void) {
  reader_app_runtime_t* runtime = &reader_context_active()->app;

#if defined(NERO_CCID_USB_BUILD)
  reader_ccid_poll();
#endif

#if defined(NERO_CCID_ONLY_BUILD)
  if (!G_READER.app.nfc_frontend_ready) {
    return;
  }
#endif

#if defined(NERO_CCID_USB_BUILD)
  reader_ccid_loop_step();
  return;
#endif

  uint32_t now = reader_hal_millis();
  uint8_t amp;
  int16_t load;

  amp = measure_amplitude();
  load = (int16_t)((int16_t)G_BASELINE_AMP - (int16_t)amp);

  if ((now - runtime->last_poll_ms) < runtime->poll_interval_ms) {
    return;
  }
  runtime->last_poll_ms = now;

  /* Use the field-load gauge so the firmware prints meaningful "approaching"
   * feedback even before any anticollision succeeds. */
  if (load > READER_APP_FIELD_LOAD_NEAR) {
    runtime->poll_interval_ms = READER_APP_NEAR_POLL_INTERVAL_MS;
    if (!runtime->was_near) {
#if !defined(NERO_CCID_USB_BUILD)
      nero_nfc_log_line("\r\n  >> Field change — polling faster");
#endif
    }
    runtime->was_near = true;
  } else {
    runtime->poll_interval_ms = READER_APP_CCID_POLL_INTERVAL_MS;
    if (runtime->was_near) {
#if !defined(NERO_CCID_USB_BUILD)
      nero_nfc_log_line("  >> Field returned to baseline\r\n");
#endif
      runtime->was_near = false;
#if defined(NERO_CCID_USB_BUILD)
      if (reader_ccid_icc_status() != (uint8_t)(NFC_CCID_ICC_NO_ICC)) {
        reader_ccid_on_tag_removed_from_field();
      }
#endif
      G_LAST_UID_LEN = 0u; /* re-arm same-tag suppressor */
    }
  }
  /* Idle refreshes slowly by design (~1.5s) so CDC is not flooded; near-tag
   * path is faster. */
  if ((now - G_READER.app.last_field_print_ms) >=
      (runtime->was_near ? READER_APP_FIELD_PRINT_NEAR_MS
                         : READER_APP_FIELD_PRINT_IDLE_MS)) {
    print_field_strength(amp, G_BASELINE_AMP);
    G_READER.app.last_field_print_ms = now;
  }

  if (!poll_one_cycle()) {
    return;
  }

  /* Tag was processed: wait briefly for removal so we don't spam. */
  uint32_t remove_start = reader_hal_millis();
  uint8_t remove_misses = 0u;
  while ((reader_hal_millis() - remove_start) < READER_APP_TAG_REMOVE_WAIT_MS) {
#if defined(NERO_CCID_USB_BUILD)
    reader_ccid_poll();
#endif
    if (nfc_app_poll_mode_switch()) {
      return;
    }
    /* Re-probe with whichever stack just succeeded. We cycle both so a tag
     * removed and a different one placed are detected without a delay. */
    reader_protocol_configure_iso14443a();
    nfc_frontend_ensure_tx_rx(READER_FRONTEND);
    uint8_t atqa[NFC_TAG_ATQA_LEN];
    if (reader_protocol_send_wupa(atqa)) {
      remove_misses = 0u;
      reader_hal_delay_ms(READER_APP_TAG_REMOVE_SETTLE_MS);
      continue;
    }
    reader_protocol_configure_iso15693();
    if (reader_tags_iso15693_inventory_step()) {
      remove_misses = 0u;
      reader_hal_delay_ms(READER_APP_TAG_REMOVE_SETTLE_MS);
      continue;
    }
    remove_misses++;
    if (remove_misses < TAG_REMOVE_CONSECUTIVE_MISSES) {
      reader_hal_delay_ms(TAG_REMOVE_MISS_RETRY_MS);
      continue;
    }
    G_LAST_UID_LEN = 0u;
#if defined(NERO_CCID_USB_BUILD)
    reader_ccid_on_tag_removed_from_field();
#endif
    reader_hal_delay_ms(READER_APP_TAG_REMOVE_FINAL_MS);
    G_BASELINE_AMP = measure_amplitude();
#if !defined(NERO_CCID_USB_BUILD)
    nero_nfc_log_write("  Tag removed. Baseline ");
    {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                              (unsigned)(uint32_t)(G_BASELINE_AMP));
      nero_nfc_log_write(ndc);
    }
    nero_nfc_log_line("/255. Ready.\r\n");
#endif
    break;
  }
  runtime->was_near = false;
}
