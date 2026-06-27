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
#if !defined(NERO_HOST_UNIT_TEST_HOOKS)
#include "reader_frontend.h"
#else
static inline void reader_frontend_ensure_tx_rx(void) {}
#endif
#include "reader_hal.h"
#include "reader_iso_dep_ats.h"
#include "reader_iso_dep_timing.h"
#include "reader_output.h"
#include "reader_protocol.h"
#include "reader_security_key.h"
#include "reader_iso_dep_debug.h"

#include "nfc_tag_geometry_limits.h"
#include "nfc_frontend.h"
#include "nfc_pcsc_contactless.h"

#include <stdbool.h>
#include <stdint.h>
#include "nero_nfc_format.h"

enum {
  kReaderSecurityKeyIsoDepRatsFsdi7Cid0 = (uint8_t)NFC_TAG_T4T_RATS_PARAM_FSDI7,
  kReaderSecurityKeyIsoDepRatsFsdi7Cid1 = 0x71u,
  kReaderSecurityKeyIsoDepRatsFsdi4Cid0 = 0x40u,
  kReaderSecurityKeyIsoDepRatsFsdi4Cid1 = 0x41u,
  kReaderSecurityKeyIso14443aAnticollisionTxLen = 2u,
  kReaderSecurityKeyIso14443aAnticollisionNvb = 0x20u,
  kReaderSecurityKeyIso14443aSelectNvb = 0x70u,
  kReaderSecurityKeyIso14443aAnticollisionRespMin = 5u,
  kReaderSecurityKeyIso14443aAnticollUidByte0 = 0u,
  kReaderSecurityKeyIso14443aAnticollUidByte1 = 1u,
  kReaderSecurityKeyIso14443aAnticollUidByte2 = 2u,
  kReaderSecurityKeyIso14443aAnticollUidByte3 = 3u,
  kReaderSecurityKeyIso14443aAnticollBccOffset = 4u,
  kReaderSecurityKeyIso14443aSelectUidTxOffset = 2u,
  kReaderSecurityKeyIso14443aSelectUidByte0 = 2u,
  kReaderSecurityKeyIso14443aSelectUidByte1 = 3u,
  kReaderSecurityKeyIso14443aSelectUidByte2 = 4u,
  kReaderSecurityKeyIso14443aSelectUidByte3 = 5u,
  kReaderSecurityKeyIso14443aSelectBccTxOffset = 6u,
  kReaderSecurityKeyIso14443aAnticollTxCap = 9u,
  kReaderSecurityKeyIso14443aShortRxCap = 8u,
  kReaderSecurityKeyIso14443aAtqaLen = NFC_TAG_ATQA_LEN,
  kReaderSecurityKeyIsoDepRatsRxCap = (uint16_t)NFC_ISO14443_ATS_MAX,
  kReaderSecurityKeyIsoDepSblockTxCap = 3u,
  kReaderSecurityKeyIso14443aCl1UidCascadeStart = 1u,
  kReaderSecurityKeyIso14443aCl1UidCascadeEnd = 3u,
  kReaderSecurityKeyIso14443aGUid14Cl1Slot0 = 0u,
  kReaderSecurityKeyIso14443aGUid14Cl1Slot1 = 1u,
  kReaderSecurityKeyIso14443aGUid14Cl1Slot2 = 2u,
  kReaderSecurityKeyIso14443aGUid14Cl2Slot0 = 3u,
  kReaderSecurityKeyIso14443aGUid14Cl2Slot1 = 4u,
  kReaderSecurityKeyIso14443aGUid14Cl2Slot2 = 5u,
  kReaderSecurityKeyIso14443aGUid14Cl2Slot3 = 6u,
  kReaderSecurityKeyIso14443aSelectTxLen = 7u,
  kReaderSecurityKeyIso14443aUidLen = 4u,
  kReaderSecurityKeyIso14443aCascadeUidLen = 7u,
  kReaderSecurityKeyIso14443aSakCascadeBit = 0x04u,
  kReaderSecurityKeyIsoDepCcidHeartbeatMs = 2000u,
  kReaderSecurityKeyIsoDepFwtTenthsDivisor = 100u,
  kReaderSecurityKeyIsoDepFwtTenthsRounding = 50u,
  kReaderSecurityKeyIsoDepFwtPrintScale = 10u,
  kReaderSecurityKeyIsoDepSblockDeselect = (uint8_t)NFC_PCSC_ESCAPE_TRANSPARENT_INS,
  kReaderSecurityKeyIsoDepSblockCidBit = ISO_DEP_PCB_CID_BIT,
  kReaderSecurityKeyIsoDepSblockTxLenWithCid = 2u,
  kIsoDepHwSettleMs = 2u,
  kIsoDepReaderReconfigSettleMs = 8u,
  kIsoDep14443aCmdTimeoutMs = 20u,
  kIsoDepWupaMaxAttempts = 3u,
  kSecurityKeySblockTransceiveMs = (uint16_t)NFC_TAG_T4T_DESELECT_TRANSCEIVE_TIMEOUT_MS,
  kSecurityKeyDeselectHaltGuardMs = (uint16_t)NFC_TAG_T4T_DESELECT_SETTLE_MS,
  kSecurityKeyPostDeselectMinGapMs = 235u,
  kSecurityKeyPostRecoverSettleMs = 72u,
};

#if defined(NERO_CCID_USB_BUILD)
static reader_security_key_ccid_time_extension_cb_t g_ccid_time_extension_cb;
static void *g_ccid_time_extension_ctx;
static uint32_t g_ccid_time_extension_last_ms;
static uint8_t g_iso_dep_last_error;
#endif

static uint32_t g_iso_dep_last_deselect_ms;

#if defined(NERO_HOST_UNIT_TEST_HOOKS)
typedef int (*reader_security_key_utest_iso_dep_transceive_fn)(const uint8_t *tx, uint16_t tx_len,
                                                               uint8_t *rx, uint16_t rx_max,
                                                               bool with_crc, uint16_t timeout_ms);
static reader_security_key_utest_iso_dep_transceive_fn g_utest_iso_dep_transceive;

extern "C" void reader_security_key_utest_reset_iso_dep(void) {
  g_utest_iso_dep_transceive = NERO_NFC_NULL;
}

extern "C" void reader_security_key_utest_set_iso_dep_transceive(
  reader_security_key_utest_iso_dep_transceive_fn fn) {
  g_utest_iso_dep_transceive = fn;
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
static bool iso_dep_rats_traced(uint16_t timeout_ms, uint8_t rats_param, const char *step_label);

void reader_security_key_iso_dep_ccid_heartbeat(void) {
#if defined(NERO_CCID_USB_BUILD)
  if (g_ccid_time_extension_cb != NERO_NFC_NULL) {
    uint32_t now_ms = reader_hal_millis();
    if ((g_ccid_time_extension_last_ms == 0u) ||
        ((now_ms - g_ccid_time_extension_last_ms) >= kReaderSecurityKeyIsoDepCcidHeartbeatMs)) {
      g_ccid_time_extension_cb(g_ccid_time_extension_ctx);
      g_ccid_time_extension_last_ms = now_ms;
    }
  }
#endif
}

int reader_security_key_iso_dep_transceive(const uint8_t *tx, uint16_t tx_len, uint8_t *rx,
                                           uint16_t rx_max, bool with_crc, uint16_t timeout_ms) {
  if (((tx == NERO_NFC_NULL) && (tx_len != 0u)) || (rx == NERO_NFC_NULL)) {
    return -1;
  }
#if defined(NERO_HOST_UNIT_TEST_HOOKS)
  if (g_utest_iso_dep_transceive != NERO_NFC_NULL) {
    return g_utest_iso_dep_transceive(tx, tx_len, rx, rx_max, with_crc, timeout_ms);
  }
  return -1;
#else
  reader_security_key_iso_dep_ccid_heartbeat();
  int rlen = reader_frontend_transceive_diag(tx, tx_len, rx, rx_max, with_crc, timeout_ms, false,
                                             false, true, true, true, &g_iso_dep_last_xcvr_diag);
  reader_security_key_iso_dep_ccid_heartbeat();
  reader_iso_dep_debug_dump_xcvr_diag(tx_len, timeout_ms, rlen);
  return rlen;
#endif
}

#if defined(NERO_CCID_USB_BUILD)
void reader_security_key_iso_dep_set_last_error(uint8_t code) {
  g_iso_dep_last_error = code;
}

uint8_t reader_security_key_iso_dep_last_error(void) {
  return g_iso_dep_last_error;
}
#endif

static void reader_security_key_iso_dep_reset_framing(void) {
  g_iso_dep_rats_param = (uint8_t)kReaderSecurityKeyIsoDepRatsFsdi7Cid0;
  g_iso_dep_cid = 0u;
  g_iso_dep_pcb_has_cid = false;
  g_iso_dep_last_inf_off = 0u;
  g_iso_dep_fwi = (uint8_t)ISO_DEP_FWI_DEFAULT;
  g_iso_dep_fwt_us = reader_iso_dep_fwt_us_from_fwi(g_iso_dep_fwi);
  g_iso_dep_pic_frame_max = NFC_ISO14443_FSC_MAX;
}

void reader_security_key_iso_dep_protocol_settle(void) {
  reader_hal_delay_ms(kIsoDepHwSettleMs);
}

void reader_security_key_iso_dep_pre_first_iblock_delay(void) {
  reader_hal_delay_ms(reader_iso_dep_pre_first_iblock_delay_ms(g_iso_dep_fwt_us));
}

uint16_t reader_security_key_iso_dep_link_response_timeout_ms(void) {
  return reader_iso_dep_link_response_timeout_ms(g_iso_dep_fwt_us);
}

static void iso_dep_reconfig_settle(void) {
  reader_hal_delay_ms(kIsoDepReaderReconfigSettleMs);
}

static void iso_dep_dump_bytes(const char *label, const uint8_t *buf, int len) {
  nero_nfc_log_write("  [ISO-DEP]   ");
  nero_nfc_log_write(label);
  nero_nfc_log_write(" len=");
  do {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(ndc, sizeof ndc, "%d", (int)(int32_t)(len));
    nero_nfc_log_write(ndc);
  } while (0);
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

static const char *iso_dep_sel_label(uint8_t sel_cmd) {
  return (sel_cmd == NFC_FRONTEND_ISO14443A_SEL_CL2) ? "SEL_CL2" : "SEL_CL1";
}

static bool iso_dep_select_uid_traced(uint8_t sel_cmd, uint8_t *uid_out, uint8_t *sak_out) {
  uint8_t tx_buffer[kReaderSecurityKeyIso14443aAnticollTxCap];
  uint8_t rx_buffer[kReaderSecurityKeyIso14443aShortRxCap];
  uint8_t bcc;
  int rx_len;
  int sak_len;

  if ((uid_out == NERO_NFC_NULL) || (sak_out == NERO_NFC_NULL)) {
    return false;
  }

  tx_buffer[0] = sel_cmd;
  tx_buffer[1] = (uint8_t)kReaderSecurityKeyIso14443aAnticollisionNvb;
  iso_dep_dump_bytes("anticoll TX", tx_buffer, kReaderSecurityKeyIso14443aAnticollisionTxLen);
  rx_len = reader_protocol_transceive14(tx_buffer, kReaderSecurityKeyIso14443aAnticollisionTxLen,
                                        rx_buffer, sizeof(rx_buffer), false,
                                        kIsoDep14443aCmdTimeoutMs, true, false);
  iso_dep_dump_bytes("anticoll RX", rx_buffer, rx_len);
  if (rx_len < kReaderSecurityKeyIso14443aAnticollisionRespMin) {
    nero_nfc_log_write("  [ISO-DEP]   ");
    nero_nfc_log_write(iso_dep_sel_label(sel_cmd));
    nero_nfc_log_line(" anticoll FAIL: need 5 bytes");
    return false;
  }

  bcc = (uint8_t)(rx_buffer[kReaderSecurityKeyIso14443aAnticollUidByte0] ^
                  rx_buffer[kReaderSecurityKeyIso14443aAnticollUidByte1] ^
                  rx_buffer[kReaderSecurityKeyIso14443aAnticollUidByte2] ^
                  rx_buffer[kReaderSecurityKeyIso14443aAnticollUidByte3]);
  if (bcc != rx_buffer[kReaderSecurityKeyIso14443aAnticollBccOffset]) {
    nero_nfc_log_write("  [ISO-DEP]   ");
    nero_nfc_log_write(iso_dep_sel_label(sel_cmd));
    nero_nfc_log_write(" anticoll FAIL: BCC got=0x");
    do {
      char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
      (void)nero_nfc_snprintf(
        nhx, sizeof nhx, "%02X",
        (unsigned)(uint8_t)(rx_buffer[kReaderSecurityKeyIso14443aAnticollBccOffset]));
      nero_nfc_log_write(nhx);
    } while (0);
    nero_nfc_log_write(" expect=0x");
    do {
      char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
      (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(bcc));
      nero_nfc_log_write(nhx);
    } while (0);
    nero_nfc_log_write("\r\n");
    return false;
  }

  if (!nero_nfc_copy_bytes(uid_out, kReaderSecurityKeyIso14443aUidLen, 0u, rx_buffer,
                           kReaderSecurityKeyIso14443aUidLen)) {
    return false;
  }

  tx_buffer[0] = sel_cmd;
  tx_buffer[1] = (uint8_t)kReaderSecurityKeyIso14443aSelectNvb;
  tx_buffer[kReaderSecurityKeyIso14443aSelectUidByte0] =
    rx_buffer[kReaderSecurityKeyIso14443aAnticollUidByte0];
  tx_buffer[kReaderSecurityKeyIso14443aSelectUidByte1] =
    rx_buffer[kReaderSecurityKeyIso14443aAnticollUidByte1];
  tx_buffer[kReaderSecurityKeyIso14443aSelectUidByte2] =
    rx_buffer[kReaderSecurityKeyIso14443aAnticollUidByte2];
  tx_buffer[kReaderSecurityKeyIso14443aSelectUidByte3] =
    rx_buffer[kReaderSecurityKeyIso14443aAnticollUidByte3];
  tx_buffer[kReaderSecurityKeyIso14443aSelectBccTxOffset] =
    rx_buffer[kReaderSecurityKeyIso14443aAnticollBccOffset];
  iso_dep_dump_bytes("select TX", tx_buffer, kReaderSecurityKeyIso14443aSelectTxLen);
  sak_len =
    reader_protocol_transceive14(tx_buffer, kReaderSecurityKeyIso14443aSelectTxLen, rx_buffer,
                                 sizeof(rx_buffer), true, kIsoDep14443aCmdTimeoutMs, false, false);
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
  uint8_t atqa[kReaderSecurityKeyIso14443aAtqaLen];
  uint8_t cl1_uid[kReaderSecurityKeyIso14443aUidLen];
  uint8_t cl2_uid[kReaderSecurityKeyIso14443aUidLen];
  uint8_t sak1;
  uint8_t sak2;

  for (uint8_t attempt = 0u; attempt < kIsoDepWupaMaxAttempts; attempt++) {
    if (attempt > 0u) {
      reader_protocol_configure_iso14443a();
      iso_dep_enforce_tx_rx_carrier();
      iso_dep_reconfig_settle();
    }

    nero_nfc_log_write("  [ISO-DEP]   attempt ");
    do {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)((attempt + 1u)));
      nero_nfc_log_write(ndc);
    } while (0);
    nero_nfc_log_write(" short-frame=");
    nero_nfc_log_write("WUPA");
    nero_nfc_log_write("\r\n");

    if (!reader_protocol_send_wupa(atqa)) {
      nero_nfc_log_line("  [ISO-DEP]   no ATQA");
      continue;
    }

    nero_nfc_log_write("  [ISO-DEP]   ATQA=0x");
    do {
      char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
      (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(atqa[0]));
      nero_nfc_log_write(nhx);
    } while (0);
    do {
      char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
      (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(atqa[1]));
      nero_nfc_log_write(nhx);
    } while (0);
    nero_nfc_log_write("\r\n");

    if (!iso_dep_select_uid_traced(NFC_FRONTEND_ISO14443A_SEL_CL1, cl1_uid, &sak1)) {
      continue;
    }

    if ((sak1 & kReaderSecurityKeyIso14443aSakCascadeBit) != 0u) {
      if (!iso_dep_select_uid_traced(NFC_FRONTEND_ISO14443A_SEL_CL2, cl2_uid, &sak2)) {
        continue;
      }
      g_uid14[kReaderSecurityKeyIso14443aGUid14Cl1Slot0] =
        cl1_uid[kReaderSecurityKeyIso14443aCl1UidCascadeStart];
      g_uid14[kReaderSecurityKeyIso14443aGUid14Cl1Slot1] =
        cl1_uid[kReaderSecurityKeyIso14443aCl1UidCascadeStart + 1u];
      g_uid14[kReaderSecurityKeyIso14443aGUid14Cl1Slot2] =
        cl1_uid[kReaderSecurityKeyIso14443aCl1UidCascadeEnd];
      g_uid14[kReaderSecurityKeyIso14443aGUid14Cl2Slot0] =
        cl2_uid[kReaderSecurityKeyIso14443aAnticollUidByte0];
      g_uid14[kReaderSecurityKeyIso14443aGUid14Cl2Slot1] =
        cl2_uid[kReaderSecurityKeyIso14443aAnticollUidByte1];
      g_uid14[kReaderSecurityKeyIso14443aGUid14Cl2Slot2] =
        cl2_uid[kReaderSecurityKeyIso14443aAnticollUidByte2];
      g_uid14[kReaderSecurityKeyIso14443aGUid14Cl2Slot3] =
        cl2_uid[kReaderSecurityKeyIso14443aAnticollUidByte3];
      g_uid14_len = kReaderSecurityKeyIso14443aCascadeUidLen;
      g_sak = sak2;
    } else {
      if (!nero_nfc_copy_bytes(g_uid14, sizeof(g_uid14), 0u, cl1_uid,
                               kReaderSecurityKeyIso14443aUidLen)) {
        return false;
      }
      g_uid14_len = kReaderSecurityKeyIso14443aUidLen;
      g_sak = sak1;
    }
    return true;
  }

  return false;
}

static bool iso_dep_select_uid_quiet(uint8_t sel_cmd, uint8_t *uid_out, uint8_t *sak_out) {
  uint8_t tx_buffer[kReaderSecurityKeyIso14443aAnticollTxCap];
  uint8_t rx_buffer[kReaderSecurityKeyIso14443aShortRxCap];
  uint8_t bcc;
  int rx_len;
  int sak_len;

  if ((uid_out == NERO_NFC_NULL) || (sak_out == NERO_NFC_NULL)) {
    return false;
  }

  tx_buffer[0] = sel_cmd;
  tx_buffer[1] = (uint8_t)kReaderSecurityKeyIso14443aAnticollisionNvb;
  rx_len = reader_protocol_transceive14(tx_buffer, kReaderSecurityKeyIso14443aAnticollisionTxLen,
                                        rx_buffer, sizeof(rx_buffer), false,
                                        kIsoDep14443aCmdTimeoutMs, true, false);
  if (rx_len < kReaderSecurityKeyIso14443aAnticollisionRespMin) {
    return false;
  }

  bcc = (uint8_t)(rx_buffer[kReaderSecurityKeyIso14443aAnticollUidByte0] ^
                  rx_buffer[kReaderSecurityKeyIso14443aAnticollUidByte1] ^
                  rx_buffer[kReaderSecurityKeyIso14443aAnticollUidByte2] ^
                  rx_buffer[kReaderSecurityKeyIso14443aAnticollUidByte3]);
  if (bcc != rx_buffer[kReaderSecurityKeyIso14443aAnticollBccOffset]) {
    return false;
  }

  if (!nero_nfc_copy_bytes(uid_out, kReaderSecurityKeyIso14443aUidLen, 0u, rx_buffer,
                           kReaderSecurityKeyIso14443aUidLen)) {
    return false;
  }

  tx_buffer[0] = sel_cmd;
  tx_buffer[1] = (uint8_t)kReaderSecurityKeyIso14443aSelectNvb;
  tx_buffer[kReaderSecurityKeyIso14443aSelectUidByte0] =
    rx_buffer[kReaderSecurityKeyIso14443aAnticollUidByte0];
  tx_buffer[kReaderSecurityKeyIso14443aSelectUidByte1] =
    rx_buffer[kReaderSecurityKeyIso14443aAnticollUidByte1];
  tx_buffer[kReaderSecurityKeyIso14443aSelectUidByte2] =
    rx_buffer[kReaderSecurityKeyIso14443aAnticollUidByte2];
  tx_buffer[kReaderSecurityKeyIso14443aSelectUidByte3] =
    rx_buffer[kReaderSecurityKeyIso14443aAnticollUidByte3];
  tx_buffer[kReaderSecurityKeyIso14443aSelectBccTxOffset] =
    rx_buffer[kReaderSecurityKeyIso14443aAnticollBccOffset];
  sak_len =
    reader_protocol_transceive14(tx_buffer, kReaderSecurityKeyIso14443aSelectTxLen, rx_buffer,
                                 sizeof(rx_buffer), true, kIsoDep14443aCmdTimeoutMs, false, false);
  if (sak_len < 1) {
    return false;
  }

  *sak_out = rx_buffer[0];
  return true;
}

static bool iso_dep_activate_after_hlta_quiet(void) {
  uint8_t atqa[kReaderSecurityKeyIso14443aAtqaLen];
  uint8_t cl1_uid[kReaderSecurityKeyIso14443aUidLen];
  uint8_t cl2_uid[kReaderSecurityKeyIso14443aUidLen];
  uint8_t sak1;
  uint8_t sak2;

  for (uint8_t attempt = 0u; attempt < kIsoDepWupaMaxAttempts; attempt++) {
    if (attempt > 0u) {
      reader_protocol_configure_iso14443a();
      iso_dep_enforce_tx_rx_carrier();
      iso_dep_reconfig_settle();
    }

    if (!reader_protocol_send_wupa(atqa)) {
      continue;
    }

    if (!iso_dep_select_uid_quiet(NFC_FRONTEND_ISO14443A_SEL_CL1, cl1_uid, &sak1)) {
      continue;
    }

    if ((sak1 & kReaderSecurityKeyIso14443aSakCascadeBit) != 0u) {
      if (!iso_dep_select_uid_quiet(NFC_FRONTEND_ISO14443A_SEL_CL2, cl2_uid, &sak2)) {
        continue;
      }
      g_uid14[kReaderSecurityKeyIso14443aGUid14Cl1Slot0] =
        cl1_uid[kReaderSecurityKeyIso14443aCl1UidCascadeStart];
      g_uid14[kReaderSecurityKeyIso14443aGUid14Cl1Slot1] =
        cl1_uid[kReaderSecurityKeyIso14443aCl1UidCascadeStart + 1u];
      g_uid14[kReaderSecurityKeyIso14443aGUid14Cl1Slot2] =
        cl1_uid[kReaderSecurityKeyIso14443aCl1UidCascadeEnd];
      g_uid14[kReaderSecurityKeyIso14443aGUid14Cl2Slot0] =
        cl2_uid[kReaderSecurityKeyIso14443aAnticollUidByte0];
      g_uid14[kReaderSecurityKeyIso14443aGUid14Cl2Slot1] =
        cl2_uid[kReaderSecurityKeyIso14443aAnticollUidByte1];
      g_uid14[kReaderSecurityKeyIso14443aGUid14Cl2Slot2] =
        cl2_uid[kReaderSecurityKeyIso14443aAnticollUidByte2];
      g_uid14[kReaderSecurityKeyIso14443aGUid14Cl2Slot3] =
        cl2_uid[kReaderSecurityKeyIso14443aAnticollUidByte3];
      g_uid14_len = kReaderSecurityKeyIso14443aCascadeUidLen;
      g_sak = sak2;
    } else {
      if (!nero_nfc_copy_bytes(g_uid14, sizeof(g_uid14), 0u, cl1_uid,
                               kReaderSecurityKeyIso14443aUidLen)) {
        return false;
      }
      g_uid14_len = kReaderSecurityKeyIso14443aUidLen;
      g_sak = sak1;
    }
    return true;
  }

  return false;
}

static bool iso_dep_rats_quiet(uint16_t timeout_ms, uint8_t rats_param) {
  const uint8_t rats_cmd[NFC_TAG_T4T_RATS_CMD_LEN] = {NFC_FRONTEND_ISO14443_CMD_RATS, rats_param};
  uint8_t rx[kReaderSecurityKeyIsoDepRatsRxCap];
  int rlen = reader_security_key_iso_dep_transceive(rats_cmd, (uint16_t)NFC_TAG_T4T_RATS_CMD_LEN,
                                                    rx, (uint16_t)sizeof(rx), true, timeout_ms);

  return reader_security_key_iso_dep_commit_rats_rx(rlen, rx, rats_param);
}

static bool iso_dep_rats_traced(uint16_t timeout_ms, uint8_t rats_param, const char *step_label) {
  const uint8_t rats_cmd[NFC_TAG_T4T_RATS_CMD_LEN] = {NFC_FRONTEND_ISO14443_CMD_RATS, rats_param};
  uint8_t rx[kReaderSecurityKeyIsoDepRatsRxCap];
  int rlen = reader_security_key_iso_dep_transceive(rats_cmd, (uint16_t)NFC_TAG_T4T_RATS_CMD_LEN,
                                                    rx, (uint16_t)sizeof(rx), true, timeout_ms);

  nero_nfc_log_write("\r\n  [ISO-DEP] ");
  nero_nfc_log_write(step_label);
  nero_nfc_log_write(": RATS E0 ");
  do {
    char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
    (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(rats_param));
    nero_nfc_log_write(nhx);
  } while (0);
  nero_nfc_log_write(" → rx_len=");
  do {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(ndc, sizeof ndc, "%d", (int)(int32_t)(rlen));
    nero_nfc_log_write(ndc);
  } while (0);
  if (rlen >= 1) {
    nero_nfc_log_write(" rx[0]=0x");
    do {
      char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
      (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(rx[0]));
      nero_nfc_log_write(nhx);
    } while (0);
  }
  if (!reader_security_key_iso_dep_commit_rats_rx(rlen, rx, rats_param)) {
    nero_nfc_log_line(" → FAIL (need rx_len>=2)");
    return false;
  }
  nero_nfc_log_line(" → OK");
  return true;
}

static void iso_dep_enforce_tx_rx_carrier(void) {
  reader_frontend_ensure_tx_rx();
}

bool reader_security_key_iso_dep_session_open(uint16_t rats_timeout_ms) {
  nero_nfc_log_line("\r\n  [ISO-DEP] ═══ session ═══");
  nero_nfc_log_line("  [ISO-DEP] Plan: (1) probe RATS E0/70 -> ATS");
  nero_nfc_log_write("  [ISO-DEP]       (2) if TC requests CID: full reopen (DESELECT→WUPA→"
                     "RATS 5a), not software CID on probe session\r\n");
  nero_nfc_log_line("  [ISO-DEP]       (3) else keep probe session (no CID in PCB)");

  reader_security_key_iso_dep_reset_framing();
  nero_nfc_log_line("\r\n  [ISO-DEP] Step 1 — probe RATS (discover ATS / TC)");
  if (!iso_dep_rats_traced(rats_timeout_ms, (uint8_t)kReaderSecurityKeyIsoDepRatsFsdi7Cid0,
                           "Step 1")) {
    nero_nfc_log_line("  [ISO-DEP] ABORT: probe RATS produced no ATS.");
    return false;
  }
  parse_ats();

  if (reader_security_key_iso_dep_probe_can_upgrade_cid()) {
    nero_nfc_log_write("\r\n  [ISO-DEP] Step 2 — TC advertises CID; full ISO-DEP reopen for "
                       "stable CID framing (see reader_security_key_iso_dep_recover_session)\r\n");
    if (!reader_security_key_iso_dep_recover_session()) {
      nero_nfc_log_line("  [ISO-DEP] ABORT: CID reopen failed after probe RATS.");
      return false;
    }
    reader_security_key_iso_dep_post_recover_rf_settle();
    nero_nfc_log_write("  [ISO-DEP] DONE: CID in PCB after reopen (CID=0x");
    do {
      char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
      (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(g_iso_dep_cid));
      nero_nfc_log_write(nhx);
    } while (0);
    nero_nfc_log_line(").");
    return true;
  }

  nero_nfc_log_line("\r\n  [ISO-DEP] Step 2 — TC has no CID requirement in PCB");
  nero_nfc_log_line("  [ISO-DEP] DONE: probe session (no CID in PCB).");
  return true;
}

bool reader_security_key_iso_dep_session_open_quiet(uint16_t rats_timeout_ms) {
  reader_security_key_iso_dep_reset_framing();
  if (!iso_dep_rats_quiet(rats_timeout_ms, (uint8_t)kReaderSecurityKeyIsoDepRatsFsdi7Cid0)) {
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

  if (!reader_iso_dep_parse_ats_profile(g_ats_data, g_ats_len, &ats_profile)) {
    g_iso_dep_have_tc = false;
    g_iso_dep_fwi = (uint8_t)ISO_DEP_FWI_DEFAULT;
    g_iso_dep_fwt_us = reader_iso_dep_fwt_us_from_fwi(g_iso_dep_fwi);
    return;
  }
  g_iso_dep_have_tc = ats_profile.has_tc;
  g_iso_dep_fwi = ats_profile.fwi;
  g_iso_dep_fwt_us = ats_profile.fwt_us;
  g_iso_dep_pic_frame_max = ats_profile.pic_frame_max;
  if (ats_profile.has_tc) {
    g_iso_dep_tc_byte = ats_profile.tc;
  }

  nero_nfc_log_write("\r\n  ── ISO 14443-4 ATS ──\r\n  Raw: ");
  for (uint8_t i = 0u; i < g_ats_len; i++) {
    do {
      char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
      (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(g_ats_data[i]));
      nero_nfc_log_write(nhx);
    } while (0);
    nero_nfc_log_putc(' ');
  }
  nero_nfc_log_write("\r\n");

  nero_nfc_log_write("  Max frame size (FSC): ");
  do {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(ats_profile.pic_frame_max));
    nero_nfc_log_write(ndc);
  } while (0);
  nero_nfc_log_line(" bytes");

  if (ats_profile.has_ta) {
    nero_nfc_log_write("  TA(1): 0x");
    do {
      char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
      (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(ats_profile.ta));
      nero_nfc_log_write(nhx);
    } while (0);
    nero_nfc_log_line("  (TX/RX bitrate caps)");
  }
  if (ats_profile.has_tb) {
    uint32_t fwt_tenths_ms;

    fwt_tenths_ms = (g_iso_dep_fwt_us + kReaderSecurityKeyIsoDepFwtTenthsRounding) /
                    kReaderSecurityKeyIsoDepFwtTenthsDivisor;
    nero_nfc_log_write("  TB(1): 0x");
    do {
      char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
      (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(ats_profile.tb));
      nero_nfc_log_write(nhx);
    } while (0);
    nero_nfc_log_write("  FWI=");
    do {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(g_iso_dep_fwi));
      nero_nfc_log_write(ndc);
    } while (0);
    nero_nfc_log_write(" (~");
    do {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(
        ndc, sizeof ndc, "%u",
        (unsigned)(uint32_t)(fwt_tenths_ms / kReaderSecurityKeyIsoDepFwtPrintScale));
      nero_nfc_log_write(ndc);
    } while (0);
    nero_nfc_log_putc('.');
    do {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(
        ndc, sizeof ndc, "%u",
        (unsigned)(uint32_t)(fwt_tenths_ms % kReaderSecurityKeyIsoDepFwtPrintScale));
      nero_nfc_log_write(ndc);
    } while (0);
    nero_nfc_log_line("ms)");
  }
  if (ats_profile.has_tc) {
    nero_nfc_log_write("  TC(1): 0x");
    do {
      char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
      (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(ats_profile.tc));
      nero_nfc_log_write(nhx);
    } while (0);
    nero_nfc_log_write("  CID ");
    nero_nfc_log_write(ats_profile.supports_cid ? "yes" : "no");
    nero_nfc_log_write(", NAD ");
    nero_nfc_log_write(ats_profile.supports_nad ? "yes" : "no");
    nero_nfc_log_write("\r\n");
  }
  if (ats_profile.historical_len != 0u) {
    nero_nfc_log_write("  Historical (");
    do {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                              (unsigned)(uint32_t)(ats_profile.historical_len));
      nero_nfc_log_write(ndc);
    } while (0);
    nero_nfc_log_write("): ");
    for (uint8_t i = ats_profile.historical_offset; i < g_ats_len; i++) {
      do {
        char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
        (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(g_ats_data[i]));
        nero_nfc_log_write(nhx);
      } while (0);
      nero_nfc_log_putc(' ');
    }
    nero_nfc_log_write("\r\n");
  }
}

static void parse_ats_quiet(void) {
  reader_iso_dep_ats_profile_t ats_profile;

  if (!reader_iso_dep_parse_ats_profile(g_ats_data, g_ats_len, &ats_profile)) {
    g_iso_dep_have_tc = false;
    g_iso_dep_fwi = (uint8_t)ISO_DEP_FWI_DEFAULT;
    g_iso_dep_fwt_us = reader_iso_dep_fwt_us_from_fwi(g_iso_dep_fwi);
    return;
  }
  g_iso_dep_have_tc = ats_profile.has_tc;
  g_iso_dep_fwi = ats_profile.fwi;
  g_iso_dep_fwt_us = ats_profile.fwt_us;
  g_iso_dep_pic_frame_max = ats_profile.pic_frame_max;
  if (ats_profile.has_tc) {
    g_iso_dep_tc_byte = ats_profile.tc;
  }
}

static bool iso_dep_open_main_from_active_quiet(uint16_t rats_timeout_ms) {
  if (iso_dep_rats_quiet(rats_timeout_ms, (uint8_t)kReaderSecurityKeyIsoDepRatsFsdi7Cid0)) {
    parse_ats_quiet();
    g_iso_dep_cid = 0u;
    g_iso_dep_pcb_has_cid = true;
    return true;
  }

  if (iso_dep_rats_quiet(rats_timeout_ms, (uint8_t)kReaderSecurityKeyIsoDepRatsFsdi4Cid0)) {
    parse_ats_quiet();
    g_iso_dep_cid = 0u;
    g_iso_dep_pcb_has_cid = true;
    return true;
  }

  if (iso_dep_rats_quiet(rats_timeout_ms, (uint8_t)kReaderSecurityKeyIsoDepRatsFsdi4Cid1)) {
    parse_ats_quiet();
    g_iso_dep_cid = 1u;
    g_iso_dep_pcb_has_cid = true;
    return true;
  }

  return false;
}

bool reader_security_key_iso_dep_open_main_from_active(uint16_t rats_timeout_ms) {
  nero_nfc_log_line("\r\n  [ISO-DEP] Step 5a — main RATS FSDI=7 CID=0 + CID in PCB (E0 70)");
  if (iso_dep_rats_traced(rats_timeout_ms, (uint8_t)kReaderSecurityKeyIsoDepRatsFsdi7Cid0,
                          "Step 5a")) {
    parse_ats();
    g_iso_dep_cid = 0u;
    g_iso_dep_pcb_has_cid = true;
    return true;
  }

  nero_nfc_log_line("\r\n  [ISO-DEP] Step 5b — fallback RATS FSDI=4 CID=0 + CID (E0 40)");
  if (iso_dep_rats_traced(rats_timeout_ms, (uint8_t)kReaderSecurityKeyIsoDepRatsFsdi4Cid0,
                          "Step 5b")) {
    parse_ats();
    g_iso_dep_cid = 0u;
    g_iso_dep_pcb_has_cid = true;
    return true;
  }

  nero_nfc_log_line("\r\n  [ISO-DEP] Step 5c — fallback RATS FSDI=4 CID=1 (E0 41)");
  if (iso_dep_rats_traced(rats_timeout_ms, (uint8_t)kReaderSecurityKeyIsoDepRatsFsdi4Cid1,
                          "Step 5c")) {
    parse_ats();
    g_iso_dep_cid = 1u;
    g_iso_dep_pcb_has_cid = true;
    return true;
  }

  nero_nfc_log_line("\r\n  [ISO-DEP] ABORT: CID RATS attempts (E0 70/40/41) failed.");
  return false;
}

void reader_security_key_iso_dep_send_deselect(void) {
  uint8_t tx[kReaderSecurityKeyIsoDepSblockTxCap];
  uint8_t rx[kReaderSecurityKeyIso14443aShortRxCap];
  uint8_t tx_len = 1u;

  tx[0] = (uint8_t)kReaderSecurityKeyIsoDepSblockDeselect;
  if (g_iso_dep_pcb_has_cid) {
    tx[0] =
      (uint8_t)(kReaderSecurityKeyIsoDepSblockDeselect | kReaderSecurityKeyIsoDepSblockCidBit);
    tx[1] = g_iso_dep_cid;
    tx_len = kReaderSecurityKeyIsoDepSblockTxLenWithCid;
  }
  (void)reader_security_key_iso_dep_transceive(tx, tx_len, rx, sizeof(rx), true,
                                               kSecurityKeySblockTransceiveMs);
  reader_hal_delay_ms(kSecurityKeyDeselectHaltGuardMs);
  g_iso_dep_last_deselect_ms = reader_hal_millis();
}

void reader_security_key_iso_dep_post_recover_rf_settle(void) {
  reader_security_key_iso_dep_protocol_settle();
  reader_hal_delay_ms(kSecurityKeyPostRecoverSettleMs);
}

bool reader_security_key_iso_dep_recover_session(void) {
  reader_security_key_iso_dep_send_deselect();
  reader_security_key_iso_dep_protocol_settle();
  if (!reader_security_key_iso_dep_activate_after_hlta()) {
    return false;
  }
  reader_security_key_iso_dep_protocol_settle();
  return reader_security_key_iso_dep_open_main_from_active(SECURITY_KEY_RATS_TIMEOUT_MS);
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

  if (g_iso_dep_last_deselect_ms == 0u) {
    return;
  }
  elapsed = reader_hal_millis() - g_iso_dep_last_deselect_ms;
  if (elapsed >= kSecurityKeyPostDeselectMinGapMs) {
    return;
  }
  remaining = (uint32_t)kSecurityKeyPostDeselectMinGapMs - elapsed;
  reader_hal_delay_ms(remaining);
}

void reader_security_key_iso_dep_clear_last_deselect_ms(void) {
  g_iso_dep_last_deselect_ms = 0u;
}

uint32_t reader_security_key_iso_dep_last_deselect_ms(void) {
  return g_iso_dep_last_deselect_ms;
}

#if defined(NERO_CCID_USB_BUILD)

void reader_security_key_iso_dep_bind_ccid_time_extension(
  reader_security_key_ccid_time_extension_cb_t cb, void *ctx) {
  g_ccid_time_extension_cb = cb;
  g_ccid_time_extension_ctx = ctx;
  g_ccid_time_extension_last_ms = (cb == NERO_NFC_NULL) ? 0u : reader_hal_millis();
}

#endif
