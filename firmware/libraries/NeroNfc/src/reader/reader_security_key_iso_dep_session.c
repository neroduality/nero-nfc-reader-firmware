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
#include "reader_security_key_iso_dep_session.h"

#include "nero_nfc_mem_util.h"
#include "nero_nfc_frontend.h"
#include "reader_hal.h"
#include "reader_iso_dep_ats.h"
#include "reader_iso_dep_timing.h"
#include "reader_output.h"
#include "reader_protocol.h"
#include "reader_security_key.h"
#include "reader_iso_dep_debug.h"

#include "nfc_tag_geometry_limits.h"
#include "nfc_pcsc_contactless.h"

#if defined(NERO_HOST_UNIT_TEST_HOOKS)
/* Relay host tests do not link the ST25 bind object. */
void nfc_frontend_ensure_tx_rx(nfc_frontend_t* frontend) { (void)frontend; }
#endif

#include <stdbool.h>
#include <stdint.h>
#include "nero_nfc_format.h"

enum {
  READER_SECURITY_KEY_ISO_DEP_RATS_FSDI7_CID0 =
      (uint8_t)(NFC_TAG_T4T_RATS_PARAM_FSDI7),
  READER_SECURITY_KEY_ISO_DEP_RATS_FSDI7_CID1 = 0x71u,
  READER_SECURITY_KEY_ISO_DEP_RATS_FSDI4_CID0 = 0x40u,
  READER_SECURITY_KEY_ISO_DEP_RATS_FSDI4_CID1 = 0x41u,
  READER_SECURITY_KEY_ISO14443A_ANTICOLLISION_TX_LEN = 2u,
  READER_SECURITY_KEY_ISO14443A_ANTICOLLISION_NVB = 0x20u,
  READER_SECURITY_KEY_ISO14443A_SELECT_NVB = 0x70u,
  READER_SECURITY_KEY_ISO14443A_ANTICOLLISION_RESP_MIN = 5u,
  READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE0 = 0u,
  READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE1 = 1u,
  READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE2 = 2u,
  READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE3 = 3u,
  READER_SECURITY_KEY_ISO14443A_ANTICOLL_BCC_OFFSET = 4u,
  READER_SECURITY_KEY_ISO14443A_SELECT_UID_TX_OFFSET = 2u,
  READER_SECURITY_KEY_ISO14443A_SELECT_UID_BYTE0 = 2u,
  READER_SECURITY_KEY_ISO14443A_SELECT_UID_BYTE1 = 3u,
  READER_SECURITY_KEY_ISO14443A_SELECT_UID_BYTE2 = 4u,
  READER_SECURITY_KEY_ISO14443A_SELECT_UID_BYTE3 = 5u,
  READER_SECURITY_KEY_ISO14443A_SELECT_BCC_TX_OFFSET = 6u,
  READER_SECURITY_KEY_ISO14443A_ANTICOLL_TX_CAP = 9u,
  READER_SECURITY_KEY_ISO14443A_SHORT_RX_CAP = 8u,
  READER_SECURITY_KEY_ISO14443A_ATQA_LEN = NFC_TAG_ATQA_LEN,
  READER_SECURITY_KEY_ISO_DEP_RATS_RX_CAP = (uint16_t)(NFC_ISO14443_ATS_MAX),
  READER_SECURITY_KEY_ISO_DEP_SBLOCK_TX_CAP = 3u,
  READER_SECURITY_KEY_ISO14443A_CL1_UID_CASCADE_START = 1u,
  READER_SECURITY_KEY_ISO14443A_CL1_UID_CASCADE_END = 3u,
  READER_SECURITY_KEY_ISO14443A_G_UID14_CL1_SLOT0 = 0u,
  READER_SECURITY_KEY_ISO14443A_G_UID14_CL1_SLOT1 = 1u,
  READER_SECURITY_KEY_ISO14443A_G_UID14_CL1_SLOT2 = 2u,
  READER_SECURITY_KEY_ISO14443A_G_UID14_CL2_SLOT0 = 3u,
  READER_SECURITY_KEY_ISO14443A_G_UID14_CL2_SLOT1 = 4u,
  READER_SECURITY_KEY_ISO14443A_G_UID14_CL2_SLOT2 = 5u,
  READER_SECURITY_KEY_ISO14443A_G_UID14_CL2_SLOT3 = 6u,
  READER_SECURITY_KEY_ISO14443A_SELECT_TX_LEN = 7u,
  READER_SECURITY_KEY_ISO14443A_UID_LEN = 4u,
  READER_SECURITY_KEY_ISO14443A_CASCADE_UID_LEN = 7u,
  READER_SECURITY_KEY_ISO14443A_SAK_CASCADE_BIT = 0x04u,
  READER_SECURITY_KEY_ISO_DEP_CCID_HEARTBEAT_MS = 2000u,
  READER_SECURITY_KEY_ISO_DEP_FWT_TENTHS_DIVISOR = 100u,
  READER_SECURITY_KEY_ISO_DEP_FWT_TENTHS_ROUNDING = 50u,
  READER_SECURITY_KEY_ISO_DEP_FWT_PRINT_SCALE = 10u,
  READER_SECURITY_KEY_ISO_DEP_SBLOCK_DESELECT =
      (uint8_t)(NFC_PCSC_ESCAPE_TRANSPARENT_INS),
  READER_SECURITY_KEY_ISO_DEP_SBLOCK_CID_BIT = ISO_DEP_PCB_CID_BIT,
  READER_SECURITY_KEY_ISO_DEP_SBLOCK_TX_LEN_WITH_CID = 2u,
  ISO_DEP_HW_SETTLE_MS = 2u,
  ISO_DEP_READER_RECONFIG_SETTLE_MS = 8u,
  ISO_DEP14443A_CMD_TIMEOUT_MS = 20u,
  ISO_DEP_WUPA_MAX_ATTEMPTS = 3u,
  SECURITY_KEY_SBLOCK_TRANSCEIVE_MS =
      (uint16_t)(NFC_TAG_T4T_DESELECT_TRANSCEIVE_TIMEOUT_MS),
  SECURITY_KEY_DESELECT_HALT_GUARD_MS =
      (uint16_t)(NFC_TAG_T4T_DESELECT_SETTLE_MS),
  SECURITY_KEY_POST_DESELECT_MIN_GAP_MS = 235u,
  SECURITY_KEY_POST_RECOVER_SETTLE_MS = 72u,
};

#if defined(NERO_HOST_UNIT_TEST_HOOKS)
typedef reader_iso_dep_utest_transceive_fn_t
    reader_security_key_utest_iso_dep_transceive_fn_t;

void reader_security_key_utest_reset_iso_dep(void) {
  G_READER.iso_dep_session.utest_transceive = NERO_NFC_NULL;
}

void reader_security_key_utest_set_iso_dep_transceive(
    reader_security_key_utest_iso_dep_transceive_fn_t fn) {
  G_READER.iso_dep_session.utest_transceive = fn;
}
#endif

static void parse_ats(void);
static void parse_ats_quiet(void);
static void iso_dep_enforce_tx_rx_carrier(void);
static void iso_dep_reconfig_settle(void);
static bool iso_dep_activate_after_hlta_quiet(void);
static bool iso_dep_open_main_from_active_quiet(uint16_t rats_timeout_ms);
static bool iso_dep_recover_session_quiet(void);
static bool iso_dep_rats_quiet(uint16_t timeout_ms, uint8_t rats_param);
static bool iso_dep_rats_traced(uint16_t timeout_ms, uint8_t rats_param,
                                const char* step_label);

void reader_security_key_iso_dep_ccid_heartbeat(void) {
#if defined(NERO_CCID_USB_BUILD)
  reader_iso_dep_session_runtime_t* session = &G_READER.iso_dep_session;

  if (session->ccid_time_extension_cb != NERO_NFC_NULL) {
    uint32_t now_ms = reader_hal_millis();
    if ((session->ccid_time_extension_last_ms == 0u) ||
        ((now_ms - session->ccid_time_extension_last_ms) >=
         READER_SECURITY_KEY_ISO_DEP_CCID_HEARTBEAT_MS)) {
      session->ccid_time_extension_cb(session->ccid_time_extension_ctx);
      session->ccid_time_extension_last_ms = now_ms;
    }
  }
#endif
}

int reader_security_key_iso_dep_transceive(const uint8_t* tx, uint16_t tx_len,
                                           uint8_t* rx, uint16_t rx_max,
                                           bool with_crc, uint16_t timeout_ms) {
  if (((tx == NERO_NFC_NULL) && (tx_len != 0u)) || (rx == NERO_NFC_NULL)) {
    return -1;
  }
#if defined(NERO_HOST_UNIT_TEST_HOOKS)
  if (G_READER.iso_dep_session.utest_transceive != NERO_NFC_NULL) {
    return G_READER.iso_dep_session.utest_transceive(tx, tx_len, rx, rx_max,
                                                     with_crc, timeout_ms);
  }
  return -1;
#else
  reader_security_key_iso_dep_ccid_heartbeat();
  int rlen = nfc_frontend_transceive_diag(
      READER_FRONTEND, tx, tx_len, rx, rx_max, with_crc, timeout_ms, false,
      false, true, true, true, &G_ISO_DEP_LAST_XCVR_DIAG);
  reader_security_key_iso_dep_ccid_heartbeat();
  reader_iso_dep_debug_dump_xcvr_diag(tx_len, timeout_ms, rlen);
  return rlen;
#endif
}

#if defined(NERO_CCID_USB_BUILD)
void reader_security_key_iso_dep_set_last_error(uint8_t code) {
  G_READER.iso_dep_session.last_error = code;
}

uint8_t reader_security_key_iso_dep_last_error(void) {
  return G_READER.iso_dep_session.last_error;
}
#endif

static void reader_security_key_iso_dep_reset_framing(void) {
  G_ISO_DEP_RATS_PARAM = (uint8_t)(READER_SECURITY_KEY_ISO_DEP_RATS_FSDI7_CID0);
  G_ISO_DEP_CID = 0u;
  G_ISO_DEP_PCB_HAS_CID = false;
  G_ISO_DEP_LAST_INF_OFF = 0u;
  G_ISO_DEP_FWI = (uint8_t)(ISO_DEP_FWI_DEFAULT);
  G_ISO_DEP_FWT_US = reader_iso_dep_fwt_us_from_fwi(G_ISO_DEP_FWI);
  G_ISO_DEP_PIC_FRAME_MAX = NFC_ISO14443_FSC_MAX;
}

void reader_security_key_iso_dep_protocol_settle(void) {
  reader_hal_delay_ms(ISO_DEP_HW_SETTLE_MS);
}

void reader_security_key_iso_dep_pre_first_iblock_delay(void) {
  reader_hal_delay_ms(
      reader_iso_dep_pre_first_iblock_delay_ms(G_ISO_DEP_FWT_US));
}

uint16_t reader_security_key_iso_dep_link_response_timeout_ms(void) {
  return reader_iso_dep_link_response_timeout_ms(G_ISO_DEP_FWT_US);
}

static void iso_dep_reconfig_settle(void) {
  reader_hal_delay_ms(ISO_DEP_READER_RECONFIG_SETTLE_MS);
}

static void iso_dep_dump_bytes(const char* label, const uint8_t* buf, int len) {
  nero_nfc_log_write("  [ISO-DEP]   ");
  nero_nfc_log_write(label);
  nero_nfc_log_write(" len=");
  {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(ndc, sizeof ndc, "%d", (int)((int32_t)(len)));
    nero_nfc_log_write(ndc);
  }
  if ((buf != NERO_NFC_NULL) && (len > 0)) {
    nero_nfc_log_write(" hex=");
    for (int i = 0; i < len; i++) {
      nero_nfc_log_hex_u8(buf[i]);
      if (i + 1 < len) {
        nero_nfc_log_putc(' ');
      }
    }
  }
  nero_nfc_log_write("\r\n");
}

static const char* iso_dep_sel_label(uint8_t sel_cmd) {
  return (sel_cmd == NFC_FRONTEND_ISO14443A_SEL_CL2) ? "SEL_CL2" : "SEL_CL1";
}

static bool iso_dep_select_uid_traced(uint8_t sel_cmd, uint8_t* uid_out,
                                      uint8_t* sak_out) {
  uint8_t tx_buffer[READER_SECURITY_KEY_ISO14443A_ANTICOLL_TX_CAP];
  uint8_t rx_buffer[READER_SECURITY_KEY_ISO14443A_SHORT_RX_CAP];
  uint8_t bcc;
  int rx_len;
  int sak_len;

  if ((uid_out == NERO_NFC_NULL) || (sak_out == NERO_NFC_NULL)) {
    return false;
  }

  tx_buffer[0] = sel_cmd;
  tx_buffer[1] = (uint8_t)(READER_SECURITY_KEY_ISO14443A_ANTICOLLISION_NVB);
  iso_dep_dump_bytes("anticoll TX", tx_buffer,
                     READER_SECURITY_KEY_ISO14443A_ANTICOLLISION_TX_LEN);
  rx_len = reader_protocol_transceive14(
      tx_buffer, READER_SECURITY_KEY_ISO14443A_ANTICOLLISION_TX_LEN, rx_buffer,
      sizeof(rx_buffer), false, ISO_DEP14443A_CMD_TIMEOUT_MS, true, false);
  iso_dep_dump_bytes("anticoll RX", rx_buffer, rx_len);
  if (rx_len < READER_SECURITY_KEY_ISO14443A_ANTICOLLISION_RESP_MIN) {
    nero_nfc_log_write("  [ISO-DEP]   ");
    nero_nfc_log_write(iso_dep_sel_label(sel_cmd));
    nero_nfc_log_line(" anticoll FAIL: need 5 bytes");
    return false;
  }

  bcc = (uint8_t)(rx_buffer[READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE0] ^
                  rx_buffer[READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE1] ^
                  rx_buffer[READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE2] ^
                  rx_buffer[READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE3]);
  if (bcc != rx_buffer[READER_SECURITY_KEY_ISO14443A_ANTICOLL_BCC_OFFSET]) {
    nero_nfc_log_write("  [ISO-DEP]   ");
    nero_nfc_log_write(iso_dep_sel_label(sel_cmd));
    nero_nfc_log_write(" anticoll FAIL: BCC got=0x");
    {
      char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
      (void)nero_nfc_snprintf(
          nhx, sizeof nhx, "%02X",
          (unsigned)(rx_buffer
                         [READER_SECURITY_KEY_ISO14443A_ANTICOLL_BCC_OFFSET]));
      nero_nfc_log_write(nhx);
    }
    nero_nfc_log_write(" expect=0x");
    {
      char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
      (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(bcc));
      nero_nfc_log_write(nhx);
    }
    nero_nfc_log_write("\r\n");
    return false;
  }

  if (!nero_nfc_copy_bytes(uid_out, READER_SECURITY_KEY_ISO14443A_UID_LEN, 0u,
                           rx_buffer, READER_SECURITY_KEY_ISO14443A_UID_LEN)) {
    return false;
  }

  tx_buffer[0] = sel_cmd;
  tx_buffer[1] = (uint8_t)(READER_SECURITY_KEY_ISO14443A_SELECT_NVB);
  tx_buffer[READER_SECURITY_KEY_ISO14443A_SELECT_UID_BYTE0] =
      rx_buffer[READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE0];
  tx_buffer[READER_SECURITY_KEY_ISO14443A_SELECT_UID_BYTE1] =
      rx_buffer[READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE1];
  tx_buffer[READER_SECURITY_KEY_ISO14443A_SELECT_UID_BYTE2] =
      rx_buffer[READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE2];
  tx_buffer[READER_SECURITY_KEY_ISO14443A_SELECT_UID_BYTE3] =
      rx_buffer[READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE3];
  tx_buffer[READER_SECURITY_KEY_ISO14443A_SELECT_BCC_TX_OFFSET] =
      rx_buffer[READER_SECURITY_KEY_ISO14443A_ANTICOLL_BCC_OFFSET];
  iso_dep_dump_bytes("select TX", tx_buffer,
                     READER_SECURITY_KEY_ISO14443A_SELECT_TX_LEN);
  sak_len = reader_protocol_transceive14(
      tx_buffer, READER_SECURITY_KEY_ISO14443A_SELECT_TX_LEN, rx_buffer,
      sizeof(rx_buffer), true, ISO_DEP14443A_CMD_TIMEOUT_MS, false, false);
  iso_dep_dump_bytes("select RX", rx_buffer, sak_len);
  if (sak_len < 1) {
    nero_nfc_log_write("  [ISO-DEP]   ");
    nero_nfc_log_write(iso_dep_sel_label(sel_cmd));
    nero_nfc_log_line(" select FAIL: no SAK");
    return false;
  }

  *sak_out = rx_buffer[0];
  return true;
}

bool reader_security_key_iso_dep_activate_after_hlta(void) {
  uint8_t atqa[READER_SECURITY_KEY_ISO14443A_ATQA_LEN];
  uint8_t cl1_uid[READER_SECURITY_KEY_ISO14443A_UID_LEN];
  uint8_t cl2_uid[READER_SECURITY_KEY_ISO14443A_UID_LEN];
  uint8_t sak1;
  uint8_t sak2;

  for (unsigned attempt = 0u; attempt < ISO_DEP_WUPA_MAX_ATTEMPTS; attempt++) {
    if (attempt > 0u) {
      reader_protocol_configure_iso14443a();
      iso_dep_enforce_tx_rx_carrier();
      iso_dep_reconfig_settle();
    }

    nero_nfc_log_write("  [ISO-DEP]   attempt ");
    {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                              (unsigned)((uint32_t)((attempt + 1u))));
      nero_nfc_log_write(ndc);
    }
    nero_nfc_log_write(" short-frame=");
    nero_nfc_log_write("WUPA");
    nero_nfc_log_write("\r\n");

    if (!reader_protocol_send_wupa(atqa)) {
      nero_nfc_log_line("  [ISO-DEP]   no ATQA");
      continue;
    }

    nero_nfc_log_write("  [ISO-DEP]   ATQA=0x");
    {
      char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
      (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(atqa[0]));
      nero_nfc_log_write(nhx);
    }
    {
      char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
      (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(atqa[1]));
      nero_nfc_log_write(nhx);
    }
    nero_nfc_log_write("\r\n");

    if (!iso_dep_select_uid_traced(NFC_FRONTEND_ISO14443A_SEL_CL1, cl1_uid,
                                   &sak1)) {
      continue;
    }

    if ((sak1 & READER_SECURITY_KEY_ISO14443A_SAK_CASCADE_BIT) != 0u) {
      if (!iso_dep_select_uid_traced(NFC_FRONTEND_ISO14443A_SEL_CL2, cl2_uid,
                                     &sak2)) {
        continue;
      }
      G_UID14[READER_SECURITY_KEY_ISO14443A_G_UID14_CL1_SLOT0] =
          cl1_uid[READER_SECURITY_KEY_ISO14443A_CL1_UID_CASCADE_START];
      G_UID14[READER_SECURITY_KEY_ISO14443A_G_UID14_CL1_SLOT1] =
          cl1_uid[READER_SECURITY_KEY_ISO14443A_CL1_UID_CASCADE_START + 1u];
      G_UID14[READER_SECURITY_KEY_ISO14443A_G_UID14_CL1_SLOT2] =
          cl1_uid[READER_SECURITY_KEY_ISO14443A_CL1_UID_CASCADE_END];
      G_UID14[READER_SECURITY_KEY_ISO14443A_G_UID14_CL2_SLOT0] =
          cl2_uid[READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE0];
      G_UID14[READER_SECURITY_KEY_ISO14443A_G_UID14_CL2_SLOT1] =
          cl2_uid[READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE1];
      G_UID14[READER_SECURITY_KEY_ISO14443A_G_UID14_CL2_SLOT2] =
          cl2_uid[READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE2];
      G_UID14[READER_SECURITY_KEY_ISO14443A_G_UID14_CL2_SLOT3] =
          cl2_uid[READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE3];
      G_UID14_LEN = READER_SECURITY_KEY_ISO14443A_CASCADE_UID_LEN;
      G_SAK = sak2;
    } else {
      if (!nero_nfc_copy_bytes(G_UID14, sizeof(G_UID14), 0u, cl1_uid,
                               READER_SECURITY_KEY_ISO14443A_UID_LEN)) {
        return false;
      }
      G_UID14_LEN = READER_SECURITY_KEY_ISO14443A_UID_LEN;
      G_SAK = sak1;
    }
    return true;
  }

  return false;
}

static bool iso_dep_select_uid_quiet(uint8_t sel_cmd, uint8_t* uid_out,
                                     uint8_t* sak_out) {
  uint8_t tx_buffer[READER_SECURITY_KEY_ISO14443A_ANTICOLL_TX_CAP];
  uint8_t rx_buffer[READER_SECURITY_KEY_ISO14443A_SHORT_RX_CAP];
  uint8_t bcc;
  int rx_len;
  int sak_len;

  if ((uid_out == NERO_NFC_NULL) || (sak_out == NERO_NFC_NULL)) {
    return false;
  }

  tx_buffer[0] = sel_cmd;
  tx_buffer[1] = (uint8_t)(READER_SECURITY_KEY_ISO14443A_ANTICOLLISION_NVB);
  rx_len = reader_protocol_transceive14(
      tx_buffer, READER_SECURITY_KEY_ISO14443A_ANTICOLLISION_TX_LEN, rx_buffer,
      sizeof(rx_buffer), false, ISO_DEP14443A_CMD_TIMEOUT_MS, true, false);
  if (rx_len < READER_SECURITY_KEY_ISO14443A_ANTICOLLISION_RESP_MIN) {
    return false;
  }

  bcc = (uint8_t)(rx_buffer[READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE0] ^
                  rx_buffer[READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE1] ^
                  rx_buffer[READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE2] ^
                  rx_buffer[READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE3]);
  if (bcc != rx_buffer[READER_SECURITY_KEY_ISO14443A_ANTICOLL_BCC_OFFSET]) {
    return false;
  }

  if (!nero_nfc_copy_bytes(uid_out, READER_SECURITY_KEY_ISO14443A_UID_LEN, 0u,
                           rx_buffer, READER_SECURITY_KEY_ISO14443A_UID_LEN)) {
    return false;
  }

  tx_buffer[0] = sel_cmd;
  tx_buffer[1] = (uint8_t)(READER_SECURITY_KEY_ISO14443A_SELECT_NVB);
  tx_buffer[READER_SECURITY_KEY_ISO14443A_SELECT_UID_BYTE0] =
      rx_buffer[READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE0];
  tx_buffer[READER_SECURITY_KEY_ISO14443A_SELECT_UID_BYTE1] =
      rx_buffer[READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE1];
  tx_buffer[READER_SECURITY_KEY_ISO14443A_SELECT_UID_BYTE2] =
      rx_buffer[READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE2];
  tx_buffer[READER_SECURITY_KEY_ISO14443A_SELECT_UID_BYTE3] =
      rx_buffer[READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE3];
  tx_buffer[READER_SECURITY_KEY_ISO14443A_SELECT_BCC_TX_OFFSET] =
      rx_buffer[READER_SECURITY_KEY_ISO14443A_ANTICOLL_BCC_OFFSET];
  sak_len = reader_protocol_transceive14(
      tx_buffer, READER_SECURITY_KEY_ISO14443A_SELECT_TX_LEN, rx_buffer,
      sizeof(rx_buffer), true, ISO_DEP14443A_CMD_TIMEOUT_MS, false, false);
  if (sak_len < 1) {
    return false;
  }

  *sak_out = rx_buffer[0];
  return true;
}

static bool iso_dep_activate_after_hlta_quiet(void) {
  uint8_t atqa[READER_SECURITY_KEY_ISO14443A_ATQA_LEN];
  uint8_t cl1_uid[READER_SECURITY_KEY_ISO14443A_UID_LEN];
  uint8_t cl2_uid[READER_SECURITY_KEY_ISO14443A_UID_LEN];
  uint8_t sak1;
  uint8_t sak2;

  for (unsigned attempt = 0u; attempt < ISO_DEP_WUPA_MAX_ATTEMPTS; attempt++) {
    if (attempt > 0u) {
      reader_protocol_configure_iso14443a();
      iso_dep_enforce_tx_rx_carrier();
      iso_dep_reconfig_settle();
    }

    if (!reader_protocol_send_wupa(atqa)) {
      continue;
    }

    if (!iso_dep_select_uid_quiet(NFC_FRONTEND_ISO14443A_SEL_CL1, cl1_uid,
                                  &sak1)) {
      continue;
    }

    if ((sak1 & READER_SECURITY_KEY_ISO14443A_SAK_CASCADE_BIT) != 0u) {
      if (!iso_dep_select_uid_quiet(NFC_FRONTEND_ISO14443A_SEL_CL2, cl2_uid,
                                    &sak2)) {
        continue;
      }
      G_UID14[READER_SECURITY_KEY_ISO14443A_G_UID14_CL1_SLOT0] =
          cl1_uid[READER_SECURITY_KEY_ISO14443A_CL1_UID_CASCADE_START];
      G_UID14[READER_SECURITY_KEY_ISO14443A_G_UID14_CL1_SLOT1] =
          cl1_uid[READER_SECURITY_KEY_ISO14443A_CL1_UID_CASCADE_START + 1u];
      G_UID14[READER_SECURITY_KEY_ISO14443A_G_UID14_CL1_SLOT2] =
          cl1_uid[READER_SECURITY_KEY_ISO14443A_CL1_UID_CASCADE_END];
      G_UID14[READER_SECURITY_KEY_ISO14443A_G_UID14_CL2_SLOT0] =
          cl2_uid[READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE0];
      G_UID14[READER_SECURITY_KEY_ISO14443A_G_UID14_CL2_SLOT1] =
          cl2_uid[READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE1];
      G_UID14[READER_SECURITY_KEY_ISO14443A_G_UID14_CL2_SLOT2] =
          cl2_uid[READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE2];
      G_UID14[READER_SECURITY_KEY_ISO14443A_G_UID14_CL2_SLOT3] =
          cl2_uid[READER_SECURITY_KEY_ISO14443A_ANTICOLL_UID_BYTE3];
      G_UID14_LEN = READER_SECURITY_KEY_ISO14443A_CASCADE_UID_LEN;
      G_SAK = sak2;
    } else {
      if (!nero_nfc_copy_bytes(G_UID14, sizeof(G_UID14), 0u, cl1_uid,
                               READER_SECURITY_KEY_ISO14443A_UID_LEN)) {
        return false;
      }
      G_UID14_LEN = READER_SECURITY_KEY_ISO14443A_UID_LEN;
      G_SAK = sak1;
    }
    return true;
  }

  return false;
}

static bool iso_dep_rats_quiet(uint16_t timeout_ms, uint8_t rats_param) {
  const uint8_t rats_cmd[NFC_TAG_T4T_RATS_CMD_LEN] = {
      NFC_FRONTEND_ISO14443_CMD_RATS, rats_param};
  uint8_t rx[READER_SECURITY_KEY_ISO_DEP_RATS_RX_CAP];
  int rlen = reader_security_key_iso_dep_transceive(
      rats_cmd, (uint16_t)(NFC_TAG_T4T_RATS_CMD_LEN), rx,
      (uint16_t)(sizeof(rx)), true, timeout_ms);

  return reader_security_key_iso_dep_commit_rats_rx(rlen, rx, rats_param);
}

static bool iso_dep_rats_traced(uint16_t timeout_ms, uint8_t rats_param,
                                const char* step_label) {
  const uint8_t rats_cmd[NFC_TAG_T4T_RATS_CMD_LEN] = {
      NFC_FRONTEND_ISO14443_CMD_RATS, rats_param};
  uint8_t rx[READER_SECURITY_KEY_ISO_DEP_RATS_RX_CAP];
  int rlen = reader_security_key_iso_dep_transceive(
      rats_cmd, (uint16_t)(NFC_TAG_T4T_RATS_CMD_LEN), rx,
      (uint16_t)(sizeof(rx)), true, timeout_ms);

  nero_nfc_log_write("\r\n  [ISO-DEP] ");
  nero_nfc_log_write(step_label);
  nero_nfc_log_write(": RATS E0 ");
  {
    char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
    (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(rats_param));
    nero_nfc_log_write(nhx);
  }
  nero_nfc_log_write(" → rx_len=");
  {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(ndc, sizeof ndc, "%d", (int)((int32_t)(rlen)));
    nero_nfc_log_write(ndc);
  }
  if (rlen >= 1) {
    nero_nfc_log_write(" rx[0]=0x");
    {
      char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
      (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(rx[0]));
      nero_nfc_log_write(nhx);
    }
  }
  if (!reader_security_key_iso_dep_commit_rats_rx(rlen, rx, rats_param)) {
    nero_nfc_log_line(" → FAIL (need rx_len>=2)");
    return false;
  }
  nero_nfc_log_line(" → OK");
  return true;
}

static void iso_dep_enforce_tx_rx_carrier(void) {
  nfc_frontend_ensure_tx_rx(READER_FRONTEND);
}

bool reader_security_key_iso_dep_session_open(uint16_t rats_timeout_ms) {
  nero_nfc_log_line("\r\n  [ISO-DEP] ═══ session ═══");
  nero_nfc_log_line("  [ISO-DEP] Plan: (1) probe RATS E0/70 -> ATS");
  nero_nfc_log_write(
      "  [ISO-DEP]       (2) if TC requests CID: full reopen (DESELECT→WUPA→"
      "RATS 5a), not software CID on probe session\r\n");
  nero_nfc_log_line(
      "  [ISO-DEP]       (3) else keep probe session (no CID in PCB)");

  reader_security_key_iso_dep_reset_framing();
  nero_nfc_log_line("\r\n  [ISO-DEP] Step 1 — probe RATS (discover ATS / TC)");
  if (!iso_dep_rats_traced(
          rats_timeout_ms,
          (uint8_t)(READER_SECURITY_KEY_ISO_DEP_RATS_FSDI7_CID0), "Step 1")) {
    nero_nfc_log_line("  [ISO-DEP] ABORT: probe RATS produced no ATS.");
    return false;
  }
  parse_ats();

  if (reader_security_key_iso_dep_probe_can_upgrade_cid()) {
    nero_nfc_log_write(
        "\r\n  [ISO-DEP] Step 2 — TC advertises CID; full ISO-DEP reopen for "
        "stable CID framing (see "
        "reader_security_key_iso_dep_recover_session)\r\n");
    if (!reader_security_key_iso_dep_recover_session()) {
      nero_nfc_log_line(
          "  [ISO-DEP] ABORT: CID reopen failed after probe RATS.");
      return false;
    }
    reader_security_key_iso_dep_post_recover_rf_settle();
    nero_nfc_log_write("  [ISO-DEP] DONE: CID in PCB after reopen (CID=0x");
    {
      char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
      (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X",
                              (unsigned)(G_ISO_DEP_CID));
      nero_nfc_log_write(nhx);
    }
    nero_nfc_log_line(").");
    return true;
  }

  nero_nfc_log_line(
      "\r\n  [ISO-DEP] Step 2 — TC has no CID requirement in PCB");
  nero_nfc_log_line("  [ISO-DEP] DONE: probe session (no CID in PCB).");
  return true;
}

bool reader_security_key_iso_dep_session_open_quiet(uint16_t rats_timeout_ms) {
  reader_security_key_iso_dep_reset_framing();
  if (!iso_dep_rats_quiet(
          rats_timeout_ms,
          (uint8_t)(READER_SECURITY_KEY_ISO_DEP_RATS_FSDI7_CID0))) {
    return false;
  }
  parse_ats_quiet();

  if (reader_security_key_iso_dep_probe_can_upgrade_cid()) {
    if (!iso_dep_recover_session_quiet()) {
      return false;
    }
    reader_security_key_iso_dep_post_recover_rf_settle();
  }
  return true;
}

static void parse_ats(void) {
  reader_iso_dep_ats_profile_t ats_profile;

  if (!reader_iso_dep_parse_ats_profile(G_ATS_DATA, G_ATS_LEN, &ats_profile)) {
    G_ISO_DEP_HAVE_TC = false;
    G_ISO_DEP_FWI = (uint8_t)(ISO_DEP_FWI_DEFAULT);
    G_ISO_DEP_FWT_US = reader_iso_dep_fwt_us_from_fwi(G_ISO_DEP_FWI);
    return;
  }
  G_ISO_DEP_HAVE_TC = ats_profile.has_tc;
  G_ISO_DEP_FWI = ats_profile.fwi;
  G_ISO_DEP_FWT_US = ats_profile.fwt_us;
  G_ISO_DEP_PIC_FRAME_MAX = ats_profile.pic_frame_max;
  if (ats_profile.has_tc) {
    G_ISO_DEP_TC_BYTE = ats_profile.tc;
  }

  nero_nfc_log_write("\r\n  ── ISO 14443-4 ATS ──\r\n  Raw: ");
  for (uint8_t i = 0u; i < G_ATS_LEN; i++) {
    {
      char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
      (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X",
                              (unsigned)(G_ATS_DATA[i]));
      nero_nfc_log_write(nhx);
    }
    nero_nfc_log_putc(' ');
  }
  nero_nfc_log_write("\r\n");

  nero_nfc_log_write("  Max frame size (FSC): ");
  {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                            (unsigned)((uint32_t)(ats_profile.pic_frame_max)));
    nero_nfc_log_write(ndc);
  }
  nero_nfc_log_line(" bytes");

  if (ats_profile.has_ta) {
    nero_nfc_log_write("  TA(1): 0x");
    {
      char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
      (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X",
                              (unsigned)(ats_profile.ta));
      nero_nfc_log_write(nhx);
    }
    nero_nfc_log_line("  (TX/RX bitrate caps)");
  }
  if (ats_profile.has_tb) {
    uint32_t fwt_tenths_ms;

    fwt_tenths_ms =
        (G_ISO_DEP_FWT_US + READER_SECURITY_KEY_ISO_DEP_FWT_TENTHS_ROUNDING) /
        READER_SECURITY_KEY_ISO_DEP_FWT_TENTHS_DIVISOR;
    nero_nfc_log_write("  TB(1): 0x");
    {
      char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
      (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X",
                              (unsigned)(ats_profile.tb));
      nero_nfc_log_write(nhx);
    }
    nero_nfc_log_write("  FWI=");
    {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                              (unsigned)((uint32_t)(G_ISO_DEP_FWI)));
      nero_nfc_log_write(ndc);
    }
    nero_nfc_log_write(" (~");
    {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(
          ndc, sizeof ndc, "%u",
          (unsigned)((fwt_tenths_ms /
                      READER_SECURITY_KEY_ISO_DEP_FWT_PRINT_SCALE)));
      nero_nfc_log_write(ndc);
    }
    nero_nfc_log_putc('.');
    {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(
          ndc, sizeof ndc, "%u",
          (unsigned)((fwt_tenths_ms %
                      READER_SECURITY_KEY_ISO_DEP_FWT_PRINT_SCALE)));
      nero_nfc_log_write(ndc);
    }
    nero_nfc_log_line("ms)");
  }
  if (ats_profile.has_tc) {
    nero_nfc_log_write("  TC(1): 0x");
    {
      char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
      (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X",
                              (unsigned)(ats_profile.tc));
      nero_nfc_log_write(nhx);
    }
    nero_nfc_log_write("  CID ");
    nero_nfc_log_write(ats_profile.supports_cid ? "yes" : "no");
    nero_nfc_log_write(", NAD ");
    nero_nfc_log_write(ats_profile.supports_nad ? "yes" : "no");
    nero_nfc_log_write("\r\n");
  }
  if (ats_profile.historical_len != 0u) {
    nero_nfc_log_write("  Historical (");
    {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(
          ndc, sizeof ndc, "%u",
          (unsigned)((uint32_t)(ats_profile.historical_len)));
      nero_nfc_log_write(ndc);
    }
    nero_nfc_log_write("): ");
    for (uint8_t i = ats_profile.historical_offset; i < G_ATS_LEN; i++) {
      {
        char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
        (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X",
                                (unsigned)(G_ATS_DATA[i]));
        nero_nfc_log_write(nhx);
      }
      nero_nfc_log_putc(' ');
    }
    nero_nfc_log_write("\r\n");
  }
}

static void parse_ats_quiet(void) {
  reader_iso_dep_ats_profile_t ats_profile;

  if (!reader_iso_dep_parse_ats_profile(G_ATS_DATA, G_ATS_LEN, &ats_profile)) {
    G_ISO_DEP_HAVE_TC = false;
    G_ISO_DEP_FWI = (uint8_t)(ISO_DEP_FWI_DEFAULT);
    G_ISO_DEP_FWT_US = reader_iso_dep_fwt_us_from_fwi(G_ISO_DEP_FWI);
    return;
  }
  G_ISO_DEP_HAVE_TC = ats_profile.has_tc;
  G_ISO_DEP_FWI = ats_profile.fwi;
  G_ISO_DEP_FWT_US = ats_profile.fwt_us;
  G_ISO_DEP_PIC_FRAME_MAX = ats_profile.pic_frame_max;
  if (ats_profile.has_tc) {
    G_ISO_DEP_TC_BYTE = ats_profile.tc;
  }
}

static bool iso_dep_open_main_from_active_quiet(uint16_t rats_timeout_ms) {
  if (iso_dep_rats_quiet(
          rats_timeout_ms,
          (uint8_t)(READER_SECURITY_KEY_ISO_DEP_RATS_FSDI7_CID0))) {
    parse_ats_quiet();
    G_ISO_DEP_CID = 0u;
    G_ISO_DEP_PCB_HAS_CID = true;
    return true;
  }

  if (iso_dep_rats_quiet(
          rats_timeout_ms,
          (uint8_t)(READER_SECURITY_KEY_ISO_DEP_RATS_FSDI4_CID0))) {
    parse_ats_quiet();
    G_ISO_DEP_CID = 0u;
    G_ISO_DEP_PCB_HAS_CID = true;
    return true;
  }

  if (iso_dep_rats_quiet(
          rats_timeout_ms,
          (uint8_t)(READER_SECURITY_KEY_ISO_DEP_RATS_FSDI4_CID1))) {
    parse_ats_quiet();
    G_ISO_DEP_CID = 1u;
    G_ISO_DEP_PCB_HAS_CID = true;
    return true;
  }

  return false;
}

bool reader_security_key_iso_dep_open_main_from_active(
    uint16_t rats_timeout_ms) {
  nero_nfc_log_line(
      "\r\n  [ISO-DEP] Step 5a — main RATS FSDI=7 CID=0 + CID in PCB (E0 70)");
  if (iso_dep_rats_traced(
          rats_timeout_ms,
          (uint8_t)(READER_SECURITY_KEY_ISO_DEP_RATS_FSDI7_CID0), "Step 5a")) {
    parse_ats();
    G_ISO_DEP_CID = 0u;
    G_ISO_DEP_PCB_HAS_CID = true;
    return true;
  }

  nero_nfc_log_line(
      "\r\n  [ISO-DEP] Step 5b — fallback RATS FSDI=4 CID=0 + CID (E0 40)");
  if (iso_dep_rats_traced(
          rats_timeout_ms,
          (uint8_t)(READER_SECURITY_KEY_ISO_DEP_RATS_FSDI4_CID0), "Step 5b")) {
    parse_ats();
    G_ISO_DEP_CID = 0u;
    G_ISO_DEP_PCB_HAS_CID = true;
    return true;
  }

  nero_nfc_log_line(
      "\r\n  [ISO-DEP] Step 5c — fallback RATS FSDI=4 CID=1 (E0 41)");
  if (iso_dep_rats_traced(
          rats_timeout_ms,
          (uint8_t)(READER_SECURITY_KEY_ISO_DEP_RATS_FSDI4_CID1), "Step 5c")) {
    parse_ats();
    G_ISO_DEP_CID = 1u;
    G_ISO_DEP_PCB_HAS_CID = true;
    return true;
  }

  nero_nfc_log_line(
      "\r\n  [ISO-DEP] ABORT: CID RATS attempts (E0 70/40/41) failed.");
  return false;
}

void reader_security_key_iso_dep_send_deselect(void) {
  uint8_t tx[READER_SECURITY_KEY_ISO_DEP_SBLOCK_TX_CAP];
  uint8_t rx[READER_SECURITY_KEY_ISO14443A_SHORT_RX_CAP];
  uint8_t tx_len = 1u;

  tx[0] = (uint8_t)(READER_SECURITY_KEY_ISO_DEP_SBLOCK_DESELECT);
  if (G_ISO_DEP_PCB_HAS_CID) {
    tx[0] = (uint8_t)(READER_SECURITY_KEY_ISO_DEP_SBLOCK_DESELECT |
                      READER_SECURITY_KEY_ISO_DEP_SBLOCK_CID_BIT);
    tx[1] = G_ISO_DEP_CID;
    tx_len = READER_SECURITY_KEY_ISO_DEP_SBLOCK_TX_LEN_WITH_CID;
  }
  (void)reader_security_key_iso_dep_transceive(
      tx, tx_len, rx, sizeof(rx), true, SECURITY_KEY_SBLOCK_TRANSCEIVE_MS);
  reader_hal_delay_ms(SECURITY_KEY_DESELECT_HALT_GUARD_MS);
  G_READER.iso_dep_session.last_deselect_ms = reader_hal_millis();
}

void reader_security_key_iso_dep_post_recover_rf_settle(void) {
  reader_security_key_iso_dep_protocol_settle();
  reader_hal_delay_ms(SECURITY_KEY_POST_RECOVER_SETTLE_MS);
}

bool reader_security_key_iso_dep_recover_session(void) {
  reader_security_key_iso_dep_send_deselect();
  reader_security_key_iso_dep_protocol_settle();
  if (!reader_security_key_iso_dep_activate_after_hlta()) {
    return false;
  }
  reader_security_key_iso_dep_protocol_settle();
  return reader_security_key_iso_dep_open_main_from_active(
      SECURITY_KEY_RATS_TIMEOUT_MS);
}

static bool iso_dep_recover_session_quiet(void) {
  reader_security_key_iso_dep_send_deselect();
  reader_security_key_iso_dep_protocol_settle();
  if (!iso_dep_activate_after_hlta_quiet()) {
    return false;
  }
  reader_security_key_iso_dep_protocol_settle();
  return iso_dep_open_main_from_active_quiet(SECURITY_KEY_RATS_TIMEOUT_MS);
}

void reader_security_key_iso_dep_wait_post_deselect_gap(void) {
  uint32_t elapsed;
  uint32_t remaining;
  reader_iso_dep_session_runtime_t* session = &G_READER.iso_dep_session;

  if (session->last_deselect_ms == 0u) {
    return;
  }
  elapsed = reader_hal_millis() - session->last_deselect_ms;
  if (elapsed >= SECURITY_KEY_POST_DESELECT_MIN_GAP_MS) {
    return;
  }
  remaining = (uint32_t)(SECURITY_KEY_POST_DESELECT_MIN_GAP_MS)-elapsed;
  reader_hal_delay_ms(remaining);
}

void reader_security_key_iso_dep_clear_last_deselect_ms(void) {
  G_READER.iso_dep_session.last_deselect_ms = 0u;
}

uint32_t reader_security_key_iso_dep_last_deselect_ms(void) {
  return G_READER.iso_dep_session.last_deselect_ms;
}

#if defined(NERO_CCID_USB_BUILD)

void reader_security_key_iso_dep_bind_ccid_time_extension(
    reader_security_key_ccid_time_extension_cb_t cb, void* ctx) {
  reader_iso_dep_session_runtime_t* session = &G_READER.iso_dep_session;

  session->ccid_time_extension_cb = cb;
  session->ccid_time_extension_ctx = ctx;
  session->ccid_time_extension_last_ms =
      (cb == NERO_NFC_NULL) ? 0u : reader_hal_millis();
}

#endif
