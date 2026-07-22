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
 * writer_app.c — Writer orchestration (setup, loop, RF init, tag polling).
 *
 * Tag NDEF write paths live in writer_tag_write.c for the X-NUCLEO-NFC08A1
 * reader.
 *
 * Serial CLI configures payload (`writer_serial_cli`); encoding lives in
 * `writer_payload`. Tags supported:
 *   - NFC Forum Type 2 (NTAG213/215/216 + ST25TN512/ST25TN01K) —
 *     4-byte page writes
 *     · NTAG21x is identified via NXP-proprietary GET_VERSION (0x60).
 *     · ST25TN does NOT implement GET_VERSION (per DS13433); it is
 *       identified by UID byte 0 = 0x02 (STMicroelectronics IC manufacturer
 *       code per ISO/IEC 7816-5) and confirmed by reading the CC magic
 *       byte 0xE1 from block 3.
 *     · Writes up to WRITER_NDEF_MAX_BYTES (880 B), covering NTAG216 (868 B).
 *   - NFC Forum Type 4 (ST25TA02K + NTAG I2C Plus) — ISO-DEP APDU writes
 *     · Full T4T write sequence: RATS → SELECT NDEF App → SELECT CC →
 *       READ CC → SELECT NDEF file → clear NLEN → write data in MLc-bounded
 *       UPDATE BINARY chunks → set NLEN. APDU status words gate each step;
 *       use CDC reader mode for a full read-back round trip.
 *     · Tags identified by SAK bit 6 (0x20, ISO-DEP) set.
 *   - NFC Forum Type 5 (ST25DV64KC + ST25TV02KC)     — 4-byte block writes
 *     · ST25TV02KC (DS13304) only implements the standard one-byte-addressed
 *       ReadSingleBlock/WriteSingleBlock (0x20/0x21) — extended commands
 *       0x30/0x31 are not supported.
 *     · ST25DV64KC (DS13519) supports both forms; we use 1-byte addressing
 *       while the CC + NDEF TLV fits in blocks 0..0xFF (1 KB).
 *
 */

#include "nero_nfc_app.h"
#include "nero_nfc_board.h"
#include "nero_nfc_format.h"
#include "nero_nfc_frontend.h"
#include "nero_nfc_log.h"
#include "nero_nfc_mem_util.h"
#include "nfc_board_defaults.h"
#include "nfc_runtime_mode_poll.h"
#include "nfc_tag_geometry_limits.h"
#include "writer_app.h"
#include "writer_app_io.h"
#include "writer_app_state.h"
#include "writer_context.h"
#include "writer_hal.h"
#include "writer_payload.h"
#include "writer_serial_cli.h"
#include "writer_tag_write.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static const nero_nfc_board_config_t* writer_board(void) {
  return nero_nfc_app_board(nero_nfc_app_active());
}

static uint8_t writer_cs_pin(void) {
  const nero_nfc_board_config_t* board = writer_board();
  return (board == NERO_NFC_NULL) ? 0u : board->cs_pin;
}

static uint8_t writer_irq_pin(void) {
  const nero_nfc_board_config_t* board = writer_board();
  return (board == NERO_NFC_NULL) ? 0u : board->irq_pin;
}

static uint8_t writer_led_pin(void) {
  const nero_nfc_board_config_t* board = writer_board();
  return (board == NERO_NFC_NULL) ? 0u : board->led_pin;
}

#define CS_PIN writer_cs_pin()
#define IRQ_PIN writer_irq_pin()
#define LED_PIN writer_led_pin()

#define LOW_LEVEL 0u
#define HIGH_LEVEL 1u

enum {
  WRITER_APP_HAL_PIN_INPUT = 0,
  WRITER_APP_SERIAL_READY_WAIT_MS = 250u,
  WRITER_APP_SERIAL_SETTLE_MS = 40u,
  WRITER_APP_FIELD_GAUGE_MAX = 255u,
  WRITER_APP_FIELD_BAR_WIDTH = 20u,
  WRITER_APP_FIELD_ALIGN100 = 100u,
  WRITER_APP_FIELD_ALIGN10 = 10u,
  WRITER_APP_COUPLING_TAG_ON = 10u,
  WRITER_APP_COUPLING_APPROACH = 3u,
  WRITER_APP_POLL_INTERVAL_MS = 100u,
  WRITER_APP_POLL_INTERVAL_NEAR_MS = 50u,
  WRITER_APP_FIELD_PRINT_NEAR_MS = 200u,
  WRITER_APP_FIELD_PRINT_IDLE_MS = 3000u,
  WRITER_APP_SAME_TAG_COOLDOWN_MS = 1500u,
  WRITER_APP_REMOVAL_STABLE_SAMPLES = 3u,
  WRITER_APP_FATAL_BLINK_MS = 200u,
  WRITER_APP_RF_SETTLE_MS = 50u,
  WRITER_APP_RF_FORCE_MS = 10u,
};

/* ── App-owned writer context (payload + RF + loop state) ─────── */

static bool ensure_writer_app(void) {
  const nero_nfc_app_t* app = nero_nfc_app_active();
  return (app != NERO_NFC_NULL) &&
         (nero_nfc_app_product(app) != NERO_NFC_PRODUCT_READER);
}

static void serial_print_ready_banner(void) {
  nero_nfc_log_line("\r\n========================================");
  nero_nfc_log_line("  READY! Place a writable tag on antenna.");
  nero_nfc_log_line("========================================\r\n");
}

/* ── Field measurement ────────────────────────────────────────── */

static uint8_t measure_amplitude(void) {
  return nfc_frontend_measure_amplitude(WRITER_FRONTEND);
}

static void print_field_strength(uint8_t amp, uint8_t baseline) {
  uint8_t bar_len = (uint8_t)(((uint16_t)(amp)*WRITER_APP_FIELD_BAR_WIDTH) /
                              WRITER_APP_FIELD_GAUGE_MAX);
  nero_nfc_log_write("[NFC writer] Field ");
  if (amp < WRITER_APP_FIELD_ALIGN100) {
    nero_nfc_log_putc(' ');
  }
  if (amp < WRITER_APP_FIELD_ALIGN10) {
    nero_nfc_log_putc(' ');
  }
  {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)((uint32_t)(amp)));
    nero_nfc_log_write(ndc);
  }
  nero_nfc_log_write("/255 |");
  for (unsigned i = 0u; i < (unsigned)WRITER_APP_FIELD_BAR_WIDTH; i++) {
    nero_nfc_log_putc(i < bar_len ? '#' : '-');
  }
  nero_nfc_log_write("| ");
  if (baseline > 0u) {
    int16_t coupling = (int16_t)((int16_t)(baseline) - (int16_t)(amp));
    nero_nfc_log_write("coupling=");
    if (coupling > 0) {
      nero_nfc_log_putc('+');
    }
    {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%d",
                              (int)((int32_t)(coupling)));
      nero_nfc_log_write(ndc);
    }
    nero_nfc_log_write(" | ");
    if (coupling > WRITER_APP_COUPLING_TAG_ON) {
      nero_nfc_log_write("tag on antenna");
    } else if (coupling > WRITER_APP_COUPLING_APPROACH) {
      nero_nfc_log_write("tag approaching");
    }
  }
  nero_nfc_log_write("\r\n");
}

/* ── Chip + RF init ───────────────────────────────────────────── */

static bool init_chip(void) {
  nfc_frontend_init_status_t s;
  uint8_t chip_id = 0u;
  uint16_t vdd_mv = 0u;

  nero_nfc_log_write("  ── ");
  nero_nfc_log_write(NFC_FRONTEND_MODEL_NAME);
  nero_nfc_log_line(" Initialization ──");
  s = nfc_frontend_init(WRITER_FRONTEND, &chip_id, &vdd_mv);
  nero_nfc_log_write("  Chip ID: 0x");
  {
    char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
    (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(chip_id));
    nero_nfc_log_write(nhx);
  }
  nero_nfc_log_write("\r\n");
  if (s == NFC_FRONTEND_INIT_CHIP_ID_FAIL) {
    nero_nfc_log_line("  ERROR: Cannot read chip ID! Check wiring.");
    return false;
  }
  nero_nfc_log_write("  Oscillator...");
  if (s == NFC_FRONTEND_INIT_OSC_FAIL) {
    nero_nfc_log_line(" FAILED");
    return false;
  }
  nero_nfc_log_write(" OK\r\n  VDD: ");
  {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                            (unsigned)((uint32_t)(vdd_mv)));
    nero_nfc_log_write(ndc);
  }
  nero_nfc_log_line(" mV\r\n  Init complete!");
  return true;
}

static void configure_iso14443a(void) {
  nfc_frontend_configure_iso14443a(WRITER_FRONTEND);
}
static void configure_iso15693(void) {
  nfc_frontend_configure_iso15693(WRITER_FRONTEND);
}

static bool writer_rf_field_on(void) {
  bool used_direct = false;
  nfc_frontend_field_on_status_t s;

  nero_nfc_log_write("  RF field...");
  s = nfc_frontend_field_on(WRITER_FRONTEND, &used_direct);
  if (used_direct) {
    nero_nfc_log_write("(direct) ");
  }
  if (s == NFC_FRONTEND_FIELD_ON_TXRX_VERIFY_FAIL) {
    nero_nfc_log_line(" ERROR: TX/RX not enabled!");
    return false;
  }
  if (s != NFC_FRONTEND_FIELD_ON_OK) {
    return false;
  }
  nero_nfc_log_line(" OK");
  return true;
}

/* ── Type 2 operations ────────────────────────────────────────── */

int writer_rf_transceive14(const uint8_t* tx, uint16_t tx_len, uint8_t* rx,
                           uint16_t rx_max, bool with_crc, uint16_t timeout_ms,
                           bool anticol, bool no_rx_par) {
  if (((tx == NERO_NFC_NULL) && (tx_len != 0u)) || (rx == NERO_NFC_NULL)) {
    return -1;
  }
  return nfc_frontend_transceive(WRITER_FRONTEND, tx, tx_len, rx, rx_max,
                                 with_crc, timeout_ms, anticol, no_rx_par,
                                 false, false, false);
}

static int writer_rf_transceive14_i(void* context, const uint8_t* tx,
                                    uint16_t tx_len, uint8_t* rx,
                                    uint16_t rx_max, int with_crc,
                                    uint16_t timeout_ms, int anticol,
                                    int no_rx_par) {
  if ((context == NERO_NFC_NULL) || ((tx == NERO_NFC_NULL) && (tx_len != 0u)) ||
      (rx == NERO_NFC_NULL)) {
    return -1;
  }
  return nfc_frontend_transceive(
      (nfc_frontend_t*)context, tx, tx_len, rx, rx_max, with_crc != 0,
      timeout_ms, anticol != 0, no_rx_par != 0, false, false, false);
}

static bool send_wupa(void* context, uint8_t* atqa) {
  const bool ok = nfc_frontend_send_wupa((nfc_frontend_t*)context, atqa);

  WRITER_APP_ATQA_VALID = false;
  if (ok && atqa != NERO_NFC_NULL) {
    WRITER_APP_ATQA[0] = atqa[0];
    WRITER_APP_ATQA[1] = atqa[1];
    WRITER_APP_ATQA_VALID = true;
  }
  return ok;
}
static int anticollision_select(void* context, uint8_t sel, uint8_t* uid_out) {
  return nfc_frontend_anticollision_select(sel, uid_out,
                                           writer_rf_transceive14_i, context);
}
static void writer_frontend_delay(void* context, uint32_t ms) {
  (void)context;
  writer_hal_delay_ms(ms);
}
bool writer_rf_activate_iso14443a(void) {
  return nfc_frontend_activate_iso14443a(
      send_wupa, NERO_NFC_NULL, writer_frontend_delay, WRITER_FRONTEND, false,
      anticollision_select, WRITER_APP_UID14,
      (uint8_t)(sizeof(WRITER_APP_UID14)), &WRITER_APP_UID14_LEN,
      &WRITER_APP_SAK);
}

/*
 * Resets the radio between protocol attempts so the next mode change starts
 * from a known idle state. Without this, a NACK/timeout from the previous
 * frame can leave the NRT timer running or the FIFO partially populated,
 * which manifests as the firmware appearing to "hang" inside the next
 * transceive call.
 */
static void radio_quiesce(void) { nfc_frontend_quiesce(WRITER_FRONTEND); }

static void writer_print_tag_banner(const char* title) {
  nero_nfc_log_line("\r\n╔════════════════════════════════════════╗");
  nero_nfc_log_write(title);
  nero_nfc_log_line("\r\n╚════════════════════════════════════════╝");
}

static void writer_finish_write_attempt(bool ok, const char* failure_line) {
  if (ok) {
    WRITER_APP_TAG_WRITTEN = true;
    WRITER_APP_LAST_WRITE_MS = writer_hal_millis();
    WRITER_APP_REMOVED_STABLE_SAMPLES = 0u;
  } else {
    nero_nfc_log_write(failure_line);
  }
  writer_hal_digital_write(LED_PIN, HIGH_LEVEL);
}

/* Returns true when one tag was processed (success or failure). */
static bool try_one_tag(void) {
  if (!writer_payload_configured(&WRITER_APP_PAYLOAD)) {
    return false;
  }
  /* ISO 14443-A: Type 2 or Type 4 (ISO 14443-4), distinguished by
   * SAK. */
  radio_quiesce();
  configure_iso14443a();
  nfc_frontend_ensure_tx_rx(WRITER_FRONTEND);
  if (writer_rf_activate_iso14443a()) {
    if ((WRITER_APP_SAK & NFC_TAG_T4T_SAK_ISO14443_4_BIT) != 0u) {
      /* SAK bit 6 (0x20) set → ISO 14443-4 compliant tag (ST25TA, NTAG I2C
       * Plus, etc.)
       */
      writer_print_tag_banner("║  NFC FORUM TYPE 4 TAG (ISO 14443-4)    ║");
      writer_hal_digital_write(LED_PIN, LOW_LEVEL);
      {
        const bool ok = writer_tag_write_type4_ndef();
        writer_finish_write_attempt(ok, "  Type 4 write failed.\r\n");
        if (ok) {
          nero_nfc_log_line("\r\n  *** SUCCESS - Wrote NDEF message ***");
        }
      }
      return true;
    }

    /* SAK bit 6 clear → NFC Forum Type 2 */
    writer_type2_family_t fam;

    writer_print_tag_banner("║  NFC FORUM TYPE 2 TAG (ISO 14443-A)    ║");

    writer_hal_digital_write(LED_PIN, LOW_LEVEL);
    fam = writer_tag_identify_type2();
    if (fam == WRITER_TYPE2_FAMILY_UNKNOWN) {
      nero_nfc_log_line("  Unrecognised Type 2 IC. Skipping write.");
      writer_hal_digital_write(LED_PIN, HIGH_LEVEL);
      return true;
    }
    writer_finish_write_attempt(writer_tag_write_type2_ndef(fam),
                                "  Write failed.\r\n");
    return true;
  }

  /* Type 5 (ISO 15693): quiesce the radio so the previous WUPA / SDD does
   * not leave the NRT timer or FIFO in a state that stalls the next frame. */
  radio_quiesce();
  configure_iso15693();
  if (writer_tag_type5_inventory()) {
    writer_print_tag_banner("║  NFC FORUM TYPE 5 TAG (ISO 15693)      ║");
    writer_hal_digital_write(LED_PIN, LOW_LEVEL);
    writer_finish_write_attempt(writer_tag_write_type5_ndef(),
                                "  Write failed.\r\n");
    return true;
  }

  return false;
}

/* ── Public API ───────────────────────────────────────────────── */

void writer_setup(void) {
  const nero_nfc_board_config_t* board;
  writer_context_t* ctx;

  if (!ensure_writer_app()) {
    return;
  }
  board = writer_board();
  if (board == NERO_NFC_NULL) {
    return;
  }
  ctx = writer_context_active();
  writer_context_reset(ctx);
  ctx->poll_interval_ms = WRITER_APP_POLL_INTERVAL_MS;

  const uint32_t t0 = writer_hal_millis();

  writer_hal_serial_begin((unsigned long)board->serial_baud);
  while (!writer_hal_serial_ready() &&
         ((writer_hal_millis() - t0) < WRITER_APP_SERIAL_READY_WAIT_MS)) {
  }
  if (writer_hal_serial_ready()) {
    writer_hal_delay_ms(WRITER_APP_SERIAL_SETTLE_MS);
  }

  writer_serial_cli_init();
  writer_tag_write_reset_type4_session();

  nero_nfc_log_line("\r\n========================================");
  nero_nfc_log_line("  Unified NFC Writer (Type 2 + Type 4 + Type 5)");
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
  nero_nfc_log_write(
      "  Serial: configure payload first (help, "
      "url/text/wifi/vcard/geo/sms/mailto/uri/ndef-hex)\r\n");

  writer_hal_pin_mode(CS_PIN, WRITER_HAL_PIN_OUTPUT);
  writer_hal_digital_write(CS_PIN, HIGH_LEVEL);
  writer_hal_pin_mode(IRQ_PIN, WRITER_APP_HAL_PIN_INPUT);
  writer_hal_pin_mode(LED_PIN, WRITER_HAL_PIN_OUTPUT);
  writer_hal_digital_write(LED_PIN, HIGH_LEVEL);
  writer_hal_spi_begin();

  if (!init_chip()) {
    nero_nfc_log_line("\r\n*** FATAL: Init failed! ***");
    while (true) {
      writer_hal_digital_write(LED_PIN, LOW_LEVEL);
      writer_hal_delay_ms(WRITER_APP_FATAL_BLINK_MS);
      writer_hal_digital_write(LED_PIN, HIGH_LEVEL);
      writer_hal_delay_ms(WRITER_APP_FATAL_BLINK_MS);
    }
  }

  nero_nfc_log_line("  Configuring ISO 14443-A...");
  configure_iso14443a();
  nero_nfc_log_line("  RF field on...");
  if (!writer_rf_field_on()) {
    nero_nfc_log_line("  Forcing field on...");
    nfc_frontend_enable_tx_rx(WRITER_FRONTEND);
    writer_hal_delay_ms(WRITER_APP_RF_FORCE_MS);
  }
  writer_hal_delay_ms(WRITER_APP_RF_SETTLE_MS);
  WRITER_APP_BASELINE_AMP = measure_amplitude();
  nero_nfc_log_write("  Baseline: ");
  {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                            (unsigned)((uint32_t)(WRITER_APP_BASELINE_AMP)));
    nero_nfc_log_write(ndc);
  }
  nero_nfc_log_line("/255");

  WRITER_APP_TAG_WRITTEN = false;
  WRITER_APP_LAST_WRITE_MS = 0u;
  WRITER_APP_REMOVED_STABLE_SAMPLES = 0u;
}

void writer_loop(void) {
  writer_context_t* ctx = writer_context_active();
  uint32_t now = writer_hal_millis();
  uint8_t amp;
  int16_t load;

  if (ctx == NERO_NFC_NULL) {
    return;
  }
  if (writer_serial_cli_poll(&WRITER_APP_PAYLOAD) &&
      writer_payload_configured(&WRITER_APP_PAYLOAD)) {
    serial_print_ready_banner();
  }

  if (nfc_app_runtime_is_reader()) {
    return;
  }

  if ((now - ctx->last_poll_ms) < ctx->poll_interval_ms) {
    return;
  }
  ctx->last_poll_ms = now;

  amp = measure_amplitude();
  load = (int16_t)((int16_t)(WRITER_APP_BASELINE_AMP) - (int16_t)(amp));
  if (WRITER_APP_TAG_WRITTEN) {
    if ((now - WRITER_APP_LAST_WRITE_MS) < WRITER_APP_SAME_TAG_COOLDOWN_MS) {
      return;
    }
    if ((load <= WRITER_APP_COUPLING_APPROACH) ||
        (amp >= WRITER_APP_BASELINE_AMP)) {
      if (WRITER_APP_REMOVED_STABLE_SAMPLES <
          (uint8_t)(WRITER_APP_REMOVAL_STABLE_SAMPLES)) {
        ++WRITER_APP_REMOVED_STABLE_SAMPLES;
      }
    } else {
      WRITER_APP_REMOVED_STABLE_SAMPLES = 0u;
    }
    if (WRITER_APP_REMOVED_STABLE_SAMPLES >=
        (uint8_t)(WRITER_APP_REMOVAL_STABLE_SAMPLES)) {
      WRITER_APP_TAG_WRITTEN = false;
      WRITER_APP_BASELINE_AMP = amp;
      WRITER_APP_REMOVED_STABLE_SAMPLES = 0u;
      nero_nfc_log_line("\r\n  Ready for next tag...\r\n");
    }
    return; /* avoid double-writing the same tag while it's still on the antenna
             */
  }

  if (load > WRITER_APP_COUPLING_APPROACH) {
    ctx->poll_interval_ms = WRITER_APP_POLL_INTERVAL_NEAR_MS;
    if (!ctx->was_near) {
      nero_nfc_log_line("\r\n  >> Field change — polling faster");
      ctx->was_near = true;
    }
  } else {
    ctx->poll_interval_ms = WRITER_APP_POLL_INTERVAL_MS;
    if (ctx->was_near) {
      nero_nfc_log_line("  >> Field returned to baseline\r\n");
      ctx->was_near = false;
    }
  }
  if ((now - ctx->last_field_print_ms) >=
      (ctx->was_near ? WRITER_APP_FIELD_PRINT_NEAR_MS
                     : WRITER_APP_FIELD_PRINT_IDLE_MS)) {
    print_field_strength(amp, WRITER_APP_BASELINE_AMP);
    ctx->last_field_print_ms = now;
  }

  (void)try_one_tag();
}

/* Device CCID is reader-only: omit writer TU bodies so UNO RAM fits.
 * CDC keeps identical library commands; host tests keep writer bodies. */
#if !defined(NERO_CCID_USB_BUILD) || defined(NERO_HOST_UNIT_TEST_HOOKS)

#endif /* !CCID device || host tests */
