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
 * writer_app.cpp — Writer orchestration (setup, loop, RF init, tag polling).
 *
 * Tag NDEF write paths live in writer_tag_write.cpp for the X-NUCLEO-NFC08A1 reader.
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

#include "writer_app.h"
#include "nfc_board_defaults.h"
#include "nero_nfc_format.h"
#include "nero_nfc_log.h"
#include "nfc_runtime_mode_poll.h"
#include "nero_nfc_mem_util.h"
#include "nfc_tag_geometry_limits.h"
#include "writer_frontend.h"
#include "writer_hal.h"
#include "writer_payload.h"
#include "writer_serial_cli.h"
#include "writer_app_io.h"
#include "writer_app_state.h"
#include "writer_tag_write.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define CS_PIN NFC_BOARD_CS_PIN
#define IRQ_PIN NFC_BOARD_IRQ_PIN
#define LED_PIN NFC_BOARD_LED_PIN

#define LOW_LEVEL 0u
#define HIGH_LEVEL 1u

enum {
  kWriterAppHalPinInput = 0,
  kWriterAppSerialReadyWaitMs = 250u,
  kWriterAppSerialSettleMs = 40u,
  kWriterAppFieldGaugeMax = 255u,
  kWriterAppFieldBarWidth = 20u,
  kWriterAppFieldAlign_100 = 100u,
  kWriterAppFieldAlign_10 = 10u,
  kWriterAppCouplingTagOn = 10u,
  kWriterAppCouplingApproach = 3u,
  kWriterAppPollIntervalMs = 100u,
  kWriterAppPollIntervalNearMs = 50u,
  kWriterAppFieldPrintNearMs = 200u,
  kWriterAppFieldPrintIdleMs = 3000u,
  kWriterAppSameTagCooldownMs = 1500u,
  kWriterAppRemovalStableSamples = 3u,
  kWriterAppFatalBlinkMs = 200u,
  kWriterAppRfSettleMs = 50u,
  kWriterAppRfForceMs = 10u,
};

/* ── Payload + RF state ───────────────────────────────────────── */

writer_payload_config_t writer_app_payload;

/* ── State ────────────────────────────────────────────────────── */

uint8_t writer_app_uid14[NFC_TAG_TYPEA_UID_MAX];
uint8_t writer_app_uid14_len;
uint8_t writer_app_atqa[NFC_TAG_ATQA_LEN];
bool writer_app_atqa_valid;
uint8_t writer_app_sak;
uint8_t writer_app_ats[NFC_ISO14443_ATS_MAX];
uint8_t writer_app_ats_len;
uint8_t writer_app_uid15[NFC_FRONTEND_ISO15693_UID_LEN];
uint8_t writer_app_tag_version[NFC_TAG_NTAG_VER_REPLY_LEN];
uint8_t writer_app_tag_version_len;
/* Page-3 capability container when valid (preferred over GET_VERSION for
 * geometry). */
bool writer_app_t2_cc_from_tag_valid;
uint8_t writer_app_t2_cc_page3[NFC_TAG_T2T_PAGE_SIZE_BYTES];
static uint8_t g_baseline_amp;
static bool g_tag_written;
static uint32_t g_last_write_ms;
static uint8_t g_removed_stable_samples;

static void serial_print_ready_banner(void) {
  nero_nfc_log_line("\r\n========================================");
  nero_nfc_log_line("  READY! Place a writable tag on antenna.");
  nero_nfc_log_line("========================================\r\n");
}

/* ── Field measurement ────────────────────────────────────────── */

static uint8_t measure_amplitude(void) {
  return writer_frontend_measure_amplitude();
}

static void print_field_strength(uint8_t amp, uint8_t baseline) {
  uint8_t bar_len = (uint8_t)(((uint16_t)amp * kWriterAppFieldBarWidth) / kWriterAppFieldGaugeMax);
  nero_nfc_log_write("[NFC writer] Field ");
  if (amp < kWriterAppFieldAlign_100) {
    nero_nfc_log_putc(' ');
  }
  if (amp < kWriterAppFieldAlign_10) {
    nero_nfc_log_putc(' ');
  }
  do {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(amp));
    nero_nfc_log_write(ndc);
  } while (0);
  nero_nfc_log_write("/255 |");
  for (uint8_t i = 0u; i < kWriterAppFieldBarWidth; i++) {
    nero_nfc_log_putc(i < bar_len ? '#' : '-');
  }
  nero_nfc_log_write("| ");
  if (baseline > 0u) {
    int16_t coupling = (int16_t)baseline - (int16_t)amp;
    nero_nfc_log_write("coupling=");
    if (coupling > 0) {
      nero_nfc_log_putc('+');
    }
    do {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%d", (int)(int32_t)(coupling));
      nero_nfc_log_write(ndc);
    } while (0);
    nero_nfc_log_write(" | ");
    if (coupling > kWriterAppCouplingTagOn) {
      nero_nfc_log_write("tag on antenna");
    } else if (coupling > kWriterAppCouplingApproach) {
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
  s = writer_frontend_init(&chip_id, &vdd_mv);
  nero_nfc_log_write("  Chip ID: 0x");
  do {
    char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
    (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(chip_id));
    nero_nfc_log_write(nhx);
  } while (0);
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
  do {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(vdd_mv));
    nero_nfc_log_write(ndc);
  } while (0);
  nero_nfc_log_line(" mV\r\n  Init complete!");
  return true;
}

static void configure_iso14443a(void) {
  writer_frontend_configure_iso14443a();
}
static void configure_iso15693(void) {
  writer_frontend_configure_iso15693();
}

static bool writer_rf_field_on(void) {
  bool used_direct = false;
  nfc_frontend_field_on_status_t s;

  nero_nfc_log_write("  RF field...");
  s = writer_frontend_field_on(&used_direct);
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

int writer_rf_transceive14(const uint8_t *tx, uint16_t tx_len, uint8_t *rx, uint16_t rx_max,
                           bool with_crc, uint16_t timeout_ms, bool anticol, bool no_rx_par) {
  if (((tx == NERO_NFC_NULL) && (tx_len != 0u)) || (rx == NERO_NFC_NULL)) {
    return -1;
  }
  return writer_frontend_transceive(tx, tx_len, rx, rx_max, with_crc, timeout_ms, anticol,
                                    no_rx_par, false, false, false);
}

static int writer_rf_transceive14_i(const uint8_t *tx, uint16_t tx_len, uint8_t *rx,
                                    uint16_t rx_max, int with_crc, uint16_t timeout_ms, int anticol,
                                    int no_rx_par) {
  return writer_rf_transceive14(tx, tx_len, rx, rx_max, with_crc != 0, timeout_ms, anticol != 0,
                                no_rx_par != 0);
}

static bool send_wupa(uint8_t *atqa) {
  const bool ok = writer_frontend_send_wupa(atqa);

  writer_app_atqa_valid = false;
  if (ok && atqa != NERO_NFC_NULL) {
    writer_app_atqa[0] = atqa[0];
    writer_app_atqa[1] = atqa[1];
    writer_app_atqa_valid = true;
  }
  return ok;
}
static int anticollision_select(uint8_t sel, uint8_t *uid_out) {
  return nfc_frontend_anticollision_select(sel, uid_out, writer_rf_transceive14_i);
}
bool writer_rf_activate_iso14443a(void) {
  return nfc_frontend_activate_iso14443a(
    send_wupa, NERO_NFC_NULL, writer_hal_delay_ms, false, anticollision_select, writer_app_uid14,
    (uint8_t)sizeof(writer_app_uid14), &writer_app_uid14_len, &writer_app_sak);
}

/*
 * Resets the radio between protocol attempts so the next mode change starts
 * from a known idle state. Without this, a NACK/timeout from the previous
 * frame can leave the NRT timer running or the FIFO partially populated,
 * which manifests as the firmware appearing to "hang" inside the next
 * transceive call.
 */
static void radio_quiesce(void) {
  writer_frontend_quiesce();
}

static void writer_print_tag_banner(const char *title) {
  nero_nfc_log_line("\r\n╔════════════════════════════════════════╗");
  nero_nfc_log_write(title);
  nero_nfc_log_line("\r\n╚════════════════════════════════════════╝");
}

static void writer_finish_write_attempt(bool ok, const char *failure_line) {
  if (ok) {
    g_tag_written = true;
    g_last_write_ms = writer_hal_millis();
    g_removed_stable_samples = 0u;
  } else {
    nero_nfc_log_write(failure_line);
  }
  writer_hal_digital_write(LED_PIN, HIGH_LEVEL);
}

/* Returns true when one tag was processed (success or failure). */
static bool try_one_tag(void) {
  if (!writer_payload_configured(&writer_app_payload)) {
    return false;
  }
  /* ISO 14443-A: Type 2 or Type 4 (ISO 14443-4), distinguished by
   * SAK. */
  radio_quiesce();
  configure_iso14443a();
  writer_frontend_ensure_tx_rx();
  if (writer_rf_activate_iso14443a()) {
    if ((writer_app_sak & NFC_TAG_T4T_SAK_ISO14443_4_BIT) != 0u) {
      /* SAK bit 6 (0x20) set → ISO 14443-4 compliant tag (ST25TA, NTAG I2C Plus, etc.)
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
    writer_finish_write_attempt(writer_tag_write_type2_ndef(fam), "  Write failed.\r\n");
    return true;
  }

  /* Type 5 (ISO 15693): quiesce the radio so the previous WUPA / SDD does
   * not leave the NRT timer or FIFO in a state that stalls the next frame. */
  radio_quiesce();
  configure_iso15693();
  if (writer_tag_type5_inventory()) {
    writer_print_tag_banner("║  NFC FORUM TYPE 5 TAG (ISO 15693)      ║");
    writer_hal_digital_write(LED_PIN, LOW_LEVEL);
    writer_finish_write_attempt(writer_tag_write_type5_ndef(), "  Write failed.\r\n");
    return true;
  }

  return false;
}

/* ── Public API ───────────────────────────────────────────────── */

void writer_setup(void) {
  const uint32_t t0 = writer_hal_millis();

  writer_hal_serial_begin(NFC_HOST_SERIAL_BAUD);
  while (!writer_hal_serial_ready() && ((writer_hal_millis() - t0) < kWriterAppSerialReadyWaitMs)) {
  }
  if (writer_hal_serial_ready()) {
    writer_hal_delay_ms(kWriterAppSerialSettleMs);
  }

  writer_payload_default(&writer_app_payload);
  writer_serial_cli_init();
  writer_tag_write_reset_type4_session();

  nero_nfc_log_line("\r\n========================================");
  nero_nfc_log_line("  Unified NFC Writer (Type 2 + Type 4 + Type 5)");
  nero_nfc_log_line("========================================");
  nero_nfc_log_write("  Board:  ");
  nero_nfc_log_write(NFC_HOST_BOARD_NAME);
  nero_nfc_log_line("");
  nero_nfc_log_write("  Shield: ");
  nero_nfc_log_write(NFC_FRONTEND_REFERENCE_BOARD_NAME);
  nero_nfc_log_write(" (");
  nero_nfc_log_write(NFC_FRONTEND_MODEL_NAME);
  nero_nfc_log_line(")");
  nero_nfc_log_line("  Supported tags:");
  nero_nfc_log_line("    Type 2: NTAG213/215/216, ST25TN512/ST25TN01K");
  nero_nfc_log_line("    Type 4: ST25TA02K, NTAG I2C Plus, NTAG424 DNA (plain NDEF only)");
  nero_nfc_log_line("    Type 5: ST25DV64KC (dynamic tag), ST25TV02KC");
  nero_nfc_log_write("  Serial: configure payload first (help, "
                     "url/text/wifi/vcard/geo/sms/mailto/uri/ndef-hex)\r\n");

  writer_hal_pin_mode(CS_PIN, WRITER_HAL_PIN_OUTPUT);
  writer_hal_digital_write(CS_PIN, HIGH_LEVEL);
  writer_hal_pin_mode(IRQ_PIN, kWriterAppHalPinInput);
  writer_hal_pin_mode(LED_PIN, WRITER_HAL_PIN_OUTPUT);
  writer_hal_digital_write(LED_PIN, HIGH_LEVEL);
  writer_hal_spi_begin();

  if (!init_chip()) {
    nero_nfc_log_line("\r\n*** FATAL: Init failed! ***");
    while (1) {
      writer_hal_digital_write(LED_PIN, LOW_LEVEL);
      writer_hal_delay_ms(kWriterAppFatalBlinkMs);
      writer_hal_digital_write(LED_PIN, HIGH_LEVEL);
      writer_hal_delay_ms(kWriterAppFatalBlinkMs);
    }
  }

  nero_nfc_log_line("  Configuring ISO 14443-A...");
  configure_iso14443a();
  nero_nfc_log_line("  RF field on...");
  if (!writer_rf_field_on()) {
    nero_nfc_log_line("  Forcing field on...");
    writer_frontend_enable_tx_rx();
    writer_hal_delay_ms(kWriterAppRfForceMs);
  }
  writer_hal_delay_ms(kWriterAppRfSettleMs);
  g_baseline_amp = measure_amplitude();
  nero_nfc_log_write("  Baseline: ");
  do {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(g_baseline_amp));
    nero_nfc_log_write(ndc);
  } while (0);
  nero_nfc_log_line("/255");

  g_tag_written = false;
  g_last_write_ms = 0u;
  g_removed_stable_samples = 0u;
}

void writer_loop(void) {
  static uint32_t last_poll = 0u;
  static uint32_t last_field_print = 0u;
  static uint32_t poll_interval = kWriterAppPollIntervalMs;
  static bool was_near = false;

  uint32_t now = writer_hal_millis();
  uint8_t amp;
  int16_t load;

  if (writer_serial_cli_poll(&writer_app_payload) &&
      writer_payload_configured(&writer_app_payload)) {
    serial_print_ready_banner();
  }

  if (nfc_app_runtime_is_reader()) {
    return;
  }

  if ((now - last_poll) < poll_interval) {
    return;
  }
  last_poll = now;

  amp = measure_amplitude();
  load = (int16_t)g_baseline_amp - (int16_t)amp;
  if (g_tag_written) {
    if ((now - g_last_write_ms) < kWriterAppSameTagCooldownMs) {
      return;
    }
    if ((load <= kWriterAppCouplingApproach) || (amp >= g_baseline_amp)) {
      if (g_removed_stable_samples < (uint8_t)kWriterAppRemovalStableSamples) {
        ++g_removed_stable_samples;
      }
    } else {
      g_removed_stable_samples = 0u;
    }
    if (g_removed_stable_samples >= (uint8_t)kWriterAppRemovalStableSamples) {
      g_tag_written = false;
      g_baseline_amp = amp;
      g_removed_stable_samples = 0u;
      nero_nfc_log_line("\r\n  Ready for next tag...\r\n");
    }
    return; /* avoid double-writing the same tag while it's still on the antenna */
  }

  if (load > kWriterAppCouplingApproach) {
    poll_interval = kWriterAppPollIntervalNearMs;
    if (!was_near) {
      nero_nfc_log_line("\r\n  >> Field change — polling faster");
      was_near = true;
    }
  } else {
    poll_interval = kWriterAppPollIntervalMs;
    if (was_near) {
      nero_nfc_log_line("  >> Field returned to baseline\r\n");
      was_near = false;
    }
  }
  if ((now - last_field_print) >=
      (was_near ? kWriterAppFieldPrintNearMs : kWriterAppFieldPrintIdleMs)) {
    print_field_strength(amp, g_baseline_amp);
    last_field_print = now;
  }

  (void)try_one_tag();
}
