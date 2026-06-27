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
 * writer_tag_write_type4.cpp — ISO-DEP Type 4 NDEF write path.
 */

#include "writer_tag_write.h"
#include "writer_tag_write_internal.h"
#include "nero_nfc_log.h"

#include "writer_app_state.h"
#include "writer_frontend.h"
#include "writer_hal.h"
#include "writer_payload.h"

#include "nfc_byte_tutorial.h"
#include "nfc_frontend.h"
#include "nfc_iso_dep_timing.h"
#include "nfc_pcsc_contactless.h"
#include "nero_nfc_mem_util.h"
#include "nfc_tag_geometry_limits.h"
#include "nfc_tag_info.h"
#include "nfc_tag_info_print.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "nero_nfc_format.h"

enum { kWriterType4IsoDepRespMax = NFC_PCSC_ISO_DEP_APDU_RESP_STACK };

enum { kWriterType4WtxAckBufLen = 4u, kWriterType4SelectApduBufLen = 14u };

/* ISO-DEP I-block exchange retry budget (PCB toggle / WTX handling). */
enum { kWriterType4IsoDepMaxRetries = 8u };

/* ISO-DEP PCB / ATS wire values used only in this Type 4 write path. */
enum {
  kWriterIsoDepPcbCidBit = 0x08u,
  kWriterIsoDepPcbNadBit = 0x04u,
  kWriterIsoDepPcbIBlockBase = 0x02u,
  kWriterIsoDepPcbSWtx = 0xF2u,
  kWriterIsoDepPcbSWtxMask = 0xF7u,
  kWriterIsoDepWtxmMask = 0x3Fu,
  kWriterIsoDepBlockNumMask = 0x01u,
  kWriterIsoDepAtsT0TcPresent = 0x10u,
  kWriterIsoDepAtsT0TbPresent = 0x20u,
  kWriterIsoDepAtsTbFwiShift = 4u,
  kWriterIsoDepSDeselReq = 0xC2u,
  kWriterIsoDepSDeselCidReq = 0xCAu,
  kWriterIsoDepSDeselParam = 0x00u,
  kWriterIsoDepHdrBaseLen = 1u,
  kWriterIsoDepCrcALen = 2u,
};

static uint32_t writer_iso_dep_pre_first_iblock_delay_ms(void) {
  uint8_t t0;
  bool has_tb = false;
  uint8_t idx = 1u;
  uint8_t fwi = reader_iso_dep_fwi_default();

  if (writer_app_ats_len < NFC_ISO7816_SW_LEN) {
    return reader_iso_dep_pre_first_iblock_delay_default_ms();
  }
  t0 = writer_app_ats[1];
  if ((t0 & kWriterIsoDepAtsT0TcPresent) != 0u) {
    ++idx;
  }
  has_tb = (t0 & kWriterIsoDepAtsT0TbPresent) != 0u;
  if (has_tb && idx < writer_app_ats_len) {
    fwi = (uint8_t)(writer_app_ats[idx] >> kWriterIsoDepAtsTbFwiShift);
  }
  fwi = reader_iso_dep_fwi_clamp(fwi);
  return reader_iso_dep_pre_first_iblock_delay_ms(reader_iso_dep_fwt_us_from_fwi(fwi));
}

static int writer_iso_dep_transceive_frame(const uint8_t *tx, uint16_t tx_len, uint8_t *rx,
                                           uint16_t rx_max, uint16_t timeout_ms) {
  return writer_frontend_transceive(tx, tx_len, rx, rx_max, true, timeout_ms, false, false, true,
                                    true, true);
}

/*
 * RATS: E0 70 = FSDI=7 (256-byte frames), CID=0.
 * Prints the ATS response and resets the block-number toggle.
 */
static bool writer_iso_dep_open(void) {
  const uint8_t rats[NFC_TAG_T4T_RATS_CMD_LEN] = {NFC_TAG_T4T_RATS_START_BYTE,
                                                  NFC_TAG_T4T_RATS_PARAM_FSDI7};
  uint8_t ats[NFC_ISO14443_ATS_MAX];
  int len = writer_iso_dep_transceive_frame(rats, NFC_TAG_T4T_RATS_CMD_LEN, ats, sizeof(ats),
                                            SECURITY_KEY_RATS_TIMEOUT_MS);
  writer_tag_t4_blk = 0u;
  writer_app_ats_len = 0u;
  writer_tag_t4_pcb_has_cid = false;
  writer_tag_t4_cid = 0u;
  writer_tag_t4_need_first_iblock_delay = false;
  if (len < NFC_ISO7816_SW_LEN) {
    nero_nfc_log_line("  [T4] RATS failed");
    return false;
  }
  writer_app_ats_len =
    (uint8_t)((len > (int)sizeof(writer_app_ats)) ? sizeof(writer_app_ats) : len);
  (void)nero_nfc_copy_bytes(writer_app_ats, sizeof(writer_app_ats), 0u, ats, writer_app_ats_len);
  writer_tag_t4_pcb_has_cid = true;
  writer_tag_t4_need_first_iblock_delay = true;
  return true;
}

static uint8_t writer_iso_dep_rx_hdr_skip(uint8_t pcb) {
  uint8_t n = kWriterIsoDepHdrBaseLen;
  if ((pcb & kWriterIsoDepPcbCidBit) != 0u) {
    n++;
  }
  if ((pcb & kWriterIsoDepPcbNadBit) != 0u) {
    n++;
  }
  return n;
}

/*
 * Send one ISO-DEP APDU as an I-block and wait for the APDU response.
 * Transparently acknowledges any S(WTX) requests from the PICC before
 * returning the actual response.
 * Returns number of APDU response bytes (including SW1 SW2), -1 on error.
 */
static int writer_iso_dep_transact(const uint8_t *apdu, uint16_t apdu_len, uint8_t *resp,
                                   uint16_t resp_max) {
  uint8_t tx[NFC_PCSC_ISO_DEP_APDU_RESP_STACK];
  uint8_t rx[NFC_PCSC_ISO_DEP_APDU_RESP_STACK];
  int rlen;

  if (apdu_len > (uint16_t)(sizeof(tx) - 1u)) {
    return -1;
  }
  if (!nero_nfc_span_ok(kWriterIsoDepHdrBaseLen, (size_t)apdu_len + kWriterIsoDepCrcALen,
                        sizeof(tx))) {
    return -1;
  }
  if (writer_tag_t4_need_first_iblock_delay) {
    writer_hal_delay_ms(writer_iso_dep_pre_first_iblock_delay_ms());
    writer_tag_t4_need_first_iblock_delay = false;
  }
  /* PCB = 0x02 | block_number, plus CID when assigned by RATS. */
  tx[0] = (uint8_t)(kWriterIsoDepPcbIBlockBase | (writer_tag_t4_blk & kWriterIsoDepBlockNumMask));
  uint8_t tx_pos = kWriterIsoDepHdrBaseLen;
  if (writer_tag_t4_pcb_has_cid) {
    tx[0] = (uint8_t)(tx[0] | kWriterIsoDepPcbCidBit);
    if (!nero_nfc_span_ok((size_t)tx_pos, 1u, sizeof(tx))) {
      return -1;
    }
    tx[tx_pos++] = writer_tag_t4_cid;
  }
  for (uint16_t i = 0u; i < apdu_len; i++) {
    tx[tx_pos + i] = apdu[i];
  }
  uint16_t frame_len = (uint16_t)(tx_pos + apdu_len);

  rlen = writer_iso_dep_transceive_frame(tx, frame_len, rx, sizeof(rx),
                                         NFC_TAG_T4T_ISO_DEP_TRANSCEIVE_TIMEOUT_MS);
  for (uint8_t retry = 0u; retry < kWriterType4IsoDepMaxRetries; retry++) {
    if (rlen < 1) {
      return -1;
    }
    /* S(WTX): bits 7-6=11 (S-block), bits 5-4=11 (WTX), bit 1=1 → masked PCB =
     * 0xF2. */
    if ((rx[0] & kWriterIsoDepPcbSWtxMask) == kWriterIsoDepPcbSWtx) {
      uint8_t hdr_skip = writer_iso_dep_rx_hdr_skip(rx[0]);
      if (rlen < (int)(hdr_skip + kWriterIsoDepHdrBaseLen)) {
        return -1;
      }
      uint8_t wtx_ack[kWriterType4WtxAckBufLen];
      uint8_t wtxm = (uint8_t)(rx[hdr_skip] & kWriterIsoDepWtxmMask);
      if (!reader_iso_dep_wtxm_valid(wtxm)) {
        return -1;
      }
      if ((uint8_t)(hdr_skip + 1u) > (uint8_t)sizeof(wtx_ack)) {
        return -1;
      }
      for (uint8_t i = 0u; i < (uint8_t)(hdr_skip + 1u); i++) {
        wtx_ack[i] = rx[i];
      }
      wtx_ack[hdr_skip] = wtxm;
      rlen = writer_iso_dep_transceive_frame(wtx_ack, (uint16_t)(hdr_skip + 1u), rx, sizeof(rx),
                                             NFC_TAG_T4T_ISO_DEP_TRANSCEIVE_TIMEOUT_MS);
      if (rlen < 1) {
        return -1;
      }
      continue;
    }
    /* Normal I-block response — done. */
    break;
  }

  if ((rlen < 1) || ((rx[0] & kWriterIsoDepPcbSWtxMask) == kWriterIsoDepPcbSWtx)) {
    return -1;
  }

  /* Strip ISO-DEP PCB/CID/NAD header and CRC-A; remainder is APDU response. */
  uint8_t hdr_skip = writer_iso_dep_rx_hdr_skip(rx[0]);
  int data_len = rlen - (int)hdr_skip - kWriterIsoDepCrcALen;
  if (data_len < 0) {
    return -1;
  }
  if ((uint16_t)data_len > resp_max) {
    data_len = (int)resp_max;
  }
  for (int i = 0; i < data_len; i++) {
    resp[i] = rx[hdr_skip + i];
  }
  writer_tag_t4_blk ^= 1u;
  return data_len;
}

/* S(DESELECT): releases the tag from ISO-DEP without a full RF field cycle. */
static void writer_iso_dep_deselect(void) {
  uint8_t s_desel[NFC_TAG_T4T_RATS_CMD_LEN] = {kWriterIsoDepSDeselReq, kWriterIsoDepSDeselParam};
  uint8_t tx_len = kWriterIsoDepHdrBaseLen;
  uint8_t rx[NFC_TAG_T2T_PAGE_SIZE_BYTES];
  if (writer_tag_t4_pcb_has_cid) {
    s_desel[0] = kWriterIsoDepSDeselCidReq;
    s_desel[1] = writer_tag_t4_cid;
    tx_len = NFC_ISO7816_SW_LEN;
  }
  (void)writer_iso_dep_transceive_frame(s_desel, tx_len, rx, sizeof(rx),
                                        NFC_TAG_T4T_DESELECT_TRANSCEIVE_TIMEOUT_MS);
  writer_hal_delay_ms(NFC_TAG_T4T_DESELECT_SETTLE_MS);
}

static bool writer_iso_dep_select_app(const uint8_t *aid, uint8_t aid_len, uint8_t p2,
                                      bool add_le_00) {
  uint8_t apdu[kWriterType4SelectApduBufLen];
  uint8_t resp[kWriterType4IsoDepRespMax];
  uint16_t apdu_len = 0u;

  if (!nfc_pcsc_build_select_aid_apdu(aid, aid_len, p2, add_le_00, apdu, (uint16_t)sizeof(apdu),
                                      &apdu_len)) {
    return false;
  }
  const int rlen = writer_iso_dep_transact(apdu, apdu_len, resp, sizeof(resp));
  return nfc_iso7816_response_sw_ok(resp, rlen);
}

static bool writer_iso_dep_select_ndef_app(void) {
  for (uint8_t i = 0u; i < (uint8_t)NFC_PCSC_NDEF_APP_SELECT_VARIANT_COUNT; ++i) {
    nfc_pcsc_ndef_app_select_variant_t variant;

    if (!nfc_pcsc_ndef_app_select_variant(i, &variant)) {
      break;
    }
    if (writer_iso_dep_select_app(variant.aid, variant.aid_len, variant.p2, variant.add_le_00)) {
      return true;
    }
  }
  return false;
}

static bool writer_type4_typea_info(nfc_tag_typea_info_t *typea) {
  if (typea == NERO_NFC_NULL) {
    return false;
  }
  *typea = {};
  if (writer_app_uid14_len > (uint8_t)sizeof(typea->uid) ||
      writer_app_ats_len > (uint8_t)sizeof(typea->ats)) {
    return false;
  }
  if (!nero_nfc_copy_bytes(typea->uid, sizeof(typea->uid), 0u, writer_app_uid14,
                           writer_app_uid14_len) ||
      !nero_nfc_copy_bytes(typea->ats, sizeof(typea->ats), 0u, writer_app_ats,
                           writer_app_ats_len)) {
    return false;
  }
  typea->uid_len = writer_app_uid14_len;
  if (writer_app_atqa_valid) {
    typea->atqa[0] = writer_app_atqa[0];
    typea->atqa[1] = writer_app_atqa[1];
    typea->atqa_valid = true;
  }
  typea->sak = writer_app_sak;
  typea->ats_len = writer_app_ats_len;
  return true;
}

static void writer_type4_print_tag_profile(const nfc_tag_type4_info_t *type4) {
  nfc_tag_typea_info_t typea;
  if ((type4 == NERO_NFC_NULL) || !writer_type4_typea_info(&typea)) {
    return;
  }
  nero_nfc_log_line("    NDEF: YES");
  nfc_tag_print_type4_debug(nero_nfc_log_putc, &typea, type4);
}

/*
 * Full T4T NDEF write sequence ([T4T-ISO14443-4] / [ISO7816-4] ISO-DEP):
 *   1. RATS + ATS ([ISO14443-4] section 5.1)
 *   2. SELECT NDEF application (AID D2760000850101 — [T4T-ISO14443-4] / [T4T-ISO14443-4-NT4H424]
 * section 8.2.3)
 *   3. SELECT CC file (NFC_TAG_T4T_CC_FILE_ID / E103h)
 *   4. READ BINARY CC — parse NDEF file ID, check write access byte, log MLe/MLc
 *   5. SELECT NDEF file
 *   6. UPDATE BINARY offset 0: clear NLEN=0x0000 (marks file invalid during write)
 *   7. UPDATE BINARY offset 2+: NDEF message data in MLc-bounded chunks
 *   8. UPDATE BINARY offset 0: set NLEN to actual length (finalise)
 *   9. S(DESELECT)
 */
bool writer_tag_write_type4_impl(void) {
  uint8_t ndef[WRITER_NDEF_MAX_BYTES];
  uint8_t resp[NFC_PCSC_ISO_DEP_APDU_RESP_STACK];
  uint8_t ndef_file_hi;
  uint8_t ndef_file_lo;
  uint16_t max_ndef_message_size = 0u;
  uint16_t mlc = (uint16_t)NFC_PCSC_T4_UPDATE_BINARY_DATA_MAX;
  nfc_tag_type4_info_t type4_info{};
  int rlen;

  if (!writer_payload_configured(&writer_app_payload)) {
    nero_nfc_log_write(
      "  ERROR: no payload configured — enter url/text/wifi/ndef-hex/... first\r\n");
    return false;
  }
  uint16_t ndef_len = writer_payload_build_ndef(&writer_app_payload, ndef, sizeof(ndef));
  if (ndef_len == 0u) {
    nero_nfc_log_line("  [T4] NDEF encode failed");
    return false;
  }
  if (!writer_iso_dep_open()) {
    return false;
  }
  nero_nfc_log_line("  ISO-DEP: opening NFC Forum Type 4 NDEF session.");

  if (!writer_iso_dep_select_ndef_app()) {
    nero_nfc_log_line("  [T4] NDEF application not found.");
    nero_nfc_log_write("  [T4] Generic ISO 14443-4 device without NFC Forum NDEF application.\r\n");
    writer_iso_dep_deselect();
    return false;
  }

  /* SELECT CC file (file ID E103 mandatory per [T4T-ISO14443-4] section 7.2 /
   * [T4T-ISO14443-4-NT4H424] section 8.2.3). */
  {
    uint8_t sel_cc[NFC_PCSC_T4_SELECT_FILE_APDU_LEN];
    uint8_t sel_cc_len = 0u;
    if (!nfc_pcsc_build_t4_select_file_apdu((uint16_t)NFC_PCSC_T4_CC_FILE_ID, sel_cc,
                                            (uint8_t)sizeof(sel_cc), &sel_cc_len)) {
      writer_iso_dep_deselect();
      return false;
    }
    rlen = writer_iso_dep_transact(sel_cc, sel_cc_len, resp, sizeof(resp));
    if ((rlen < (int)NFC_ISO7816_SW_LEN) || !nfc_iso7816_response_sw_ok(resp, rlen)) {
      nero_nfc_log_line("  [T4] CC file select failed");
      writer_iso_dep_deselect();
      return false;
    }
  }

  /*
   * READ BINARY CC: NFC_TAG_T4T_CC_MIN_LEN bytes from offset 0 ([T4T-ISO14443-4] section 7.5.1).
   * Layout: CCLEN(2) | MappingVer(1) | MLe(2) | MLc(2) | NDEF_TLV_type(1) |
   *         NDEF_TLV_len(1) | NDEF_FileID(2) | MaxNDEF(2) | ReadAcc(1) |
   * WriteAcc(1). [T4T-ISO14443-4-NT4H424] ships a 23-byte CC file; plain NDEF uses the first 15
   * bytes.
   */
  {
    uint8_t read_cc[NFC_PCSC_T4_READ_BINARY_APDU_LEN];
    uint8_t read_cc_len = 0u;
    uint16_t cc_len;
    if (!nfc_pcsc_build_t4_read_binary_apdu(0u, (uint8_t)NFC_PCSC_T4_CC_FILE_LEN, read_cc,
                                            (uint8_t)sizeof(read_cc), &read_cc_len)) {
      writer_iso_dep_deselect();
      return false;
    }
    rlen = writer_iso_dep_transact(read_cc, read_cc_len, resp, sizeof(resp));
    if ((rlen < (int)(NFC_PCSC_T4_CC_FILE_LEN + NFC_ISO7816_SW_LEN)) ||
        !nfc_iso7816_response_sw_ok(resp, rlen)) {
      nero_nfc_log_line("  [T4] CC read failed");
      writer_iso_dep_deselect();
      return false;
    }
    cc_len =
      (uint16_t)(((uint16_t)resp[NFC_TAG_CC_CCLEN_MSB_INDEX] << NFC_ISO7816_U16_HIGH_BYTE_SHIFT) |
                 resp[NFC_TAG_CC_CCLEN_LSB_INDEX]);
    if (cc_len < (uint16_t)NFC_PCSC_T4_CC_FILE_LEN ||
        cc_len > (uint16_t)(sizeof(resp) - NFC_ISO7816_SW_LEN)) {
      nero_nfc_log_write("  [T4] CC parse failed (CCLEN=");
      do {
        char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
        (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(cc_len));
        nero_nfc_log_write(ndc);
      } while (0);
      nero_nfc_log_line(")");
      writer_iso_dep_deselect();
      return false;
    }
    if (cc_len > (uint16_t)NFC_PCSC_T4_CC_FILE_LEN) {
      if (!nfc_pcsc_build_t4_read_binary_apdu(0u, (uint8_t)cc_len, read_cc,
                                              (uint8_t)sizeof(read_cc), &read_cc_len)) {
        writer_iso_dep_deselect();
        return false;
      }
      rlen = writer_iso_dep_transact(read_cc, read_cc_len, resp, sizeof(resp));
      if ((rlen < (int)(cc_len + NFC_ISO7816_SW_LEN)) || !nfc_iso7816_response_sw_ok(resp, rlen)) {
        nero_nfc_log_line("  [T4] CC full read failed");
        writer_iso_dep_deselect();
        return false;
      }
    }
    {
      if (!nfc_tag_type4_apply_cc(&type4_info, resp, (uint8_t)cc_len)) {
        nero_nfc_log_write("  [T4] CC parse failed (CCLEN=");
        do {
          char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
          (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(cc_len));
          nero_nfc_log_write(ndc);
        } while (0);
        nero_nfc_log_line(")");
        writer_iso_dep_deselect();
        return false;
      }
      if (!type4_info.write_access_open) {
        nero_nfc_log_write("  [T4] NDEF file write-protected (CC write-access=0x");
        do {
          char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
          (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X",
                                  (unsigned)(uint8_t)(type4_info.write_access));
          nero_nfc_log_write(nhx);
        } while (0);
        nero_nfc_log_line(")");
        writer_iso_dep_deselect();
        return false;
      }
      if (!nfc_pcsc_type4_max_message_size(type4_info.max_ndef_size, &max_ndef_message_size)) {
        nero_nfc_log_line("  [T4] Max NDEF file size too small for NLEN");
        writer_iso_dep_deselect();
        return false;
      }
      if (ndef_len > max_ndef_message_size) {
        nero_nfc_log_write("  [T4] NDEF payload exceeds CC Max NDEF message size (");
        do {
          char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
          (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                                  (unsigned)(uint32_t)(max_ndef_message_size));
          nero_nfc_log_write(ndc);
        } while (0);
        nero_nfc_log_line(" bytes)");
        writer_iso_dep_deselect();
        return false;
      }
      if (type4_info.mlc < NFC_PCSC_T4_NLEN_LEN) {
        nero_nfc_log_line("  [T4] MLc too small for NDEF writes");
        writer_iso_dep_deselect();
        return false;
      }
      if (type4_info.mlc < mlc) {
        mlc = type4_info.mlc;
      }
      ndef_file_hi = type4_info.ndef_file_id[0];
      ndef_file_lo = type4_info.ndef_file_id[1];
    }
  }
  writer_type4_print_tag_profile(&type4_info);

  /* SELECT NDEF file using the file ID read from the CC. */
  {
    uint8_t sel_ndef[NFC_PCSC_T4_SELECT_FILE_APDU_LEN];
    uint8_t sel_ndef_len = 0u;
    if (!nfc_pcsc_build_t4_select_file_apdu(
          (uint16_t)(((uint16_t)ndef_file_hi << NFC_ISO7816_U16_HIGH_BYTE_SHIFT) | ndef_file_lo),
          sel_ndef, (uint8_t)sizeof(sel_ndef), &sel_ndef_len)) {
      writer_iso_dep_deselect();
      return false;
    }
    rlen = writer_iso_dep_transact(sel_ndef, sel_ndef_len, resp, sizeof(resp));
    if ((rlen < (int)NFC_ISO7816_SW_LEN) || !nfc_iso7816_response_sw_ok(resp, rlen)) {
      nero_nfc_log_line("  [T4] NDEF file select failed");
      writer_iso_dep_deselect();
      return false;
    }
  }

  nero_nfc_log_write("\r\n  ── Writing NDEF (Type 4) ──\r\n  Bytes (");
  do {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(ndef_len));
    nero_nfc_log_write(ndc);
  } while (0);
  nero_nfc_log_write("): ");
  for (uint16_t i = 0u; i < ndef_len; i++) {
    nero_nfc_log_hex_u8(ndef[i]);
    nero_nfc_log_putc(' ');
  }
  nero_nfc_log_write("\r\n");

  nero_nfc_log_line("\r\n  ── Byte-level explainer (write) ──");
  nfc_tutorial_t4t_select_file(nero_nfc_log_putc, ndef_file_hi, ndef_file_lo);
  nfc_tutorial_t4t_nlen(nero_nfc_log_putc, 0u);

  /* Clear NLEN=0x0000 — marks the NDEF file invalid during write. */
  {
    const uint8_t clear_nlen[NFC_ISO7816_SHORT_APDU_HDR_LEN + NFC_PCSC_T4_NLEN_LEN] = {
      (uint8_t)NFC_ISO7816_CLA_ISO,  (uint8_t)NFC_ISO7816_INS_UPDATE_BINARY,
      (uint8_t)NFC_ISO7816_CLA_ISO,  (uint8_t)NFC_ISO7816_CLA_ISO,
      (uint8_t)NFC_PCSC_T4_NLEN_LEN, (uint8_t)NFC_ISO7816_CLA_ISO,
      (uint8_t)NFC_ISO7816_CLA_ISO,
    };
    rlen = writer_iso_dep_transact(clear_nlen, sizeof(clear_nlen), resp, sizeof(resp));
    if ((rlen < (int)NFC_ISO7816_SW_LEN) || !nfc_iso7816_response_sw_ok(resp, rlen)) {
      nero_nfc_log_write("  [T4] NLEN clear failed");
      {
        uint8_t sw1 = 0u;
        uint8_t sw2 = 0u;
        if (nfc_iso7816_response_sw(resp, rlen, &sw1, &sw2)) {
          nero_nfc_log_write(" (SW=0x");
          do {
            char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
            (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(sw1));
            nero_nfc_log_write(nhx);
          } while (0);
          do {
            char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
            (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(sw2));
            nero_nfc_log_write(nhx);
          } while (0);
          nero_nfc_log_putc(')');
        }
      }
      nero_nfc_log_write("\r\n");
      writer_iso_dep_deselect();
      return false;
    }
  }

  /* Write NDEF message data at offset 2+ (after NLEN). UPDATE BINARY Lc
   * respects the tag's CC MLc and the short-form APDU body limit. */
  {
    uint8_t write_cmd[NFC_PCSC_T4_UPDATE_BINARY_APDU_MAX];
    uint16_t written = 0u;
    while (written < ndef_len) {
      uint16_t offset = (uint16_t)(NFC_PCSC_T4_NLEN_LEN + written);
      uint16_t remaining = (uint16_t)(ndef_len - written);
      uint8_t chunk = (uint8_t)((remaining > mlc) ? mlc : remaining);
      write_cmd[0] = (uint8_t)NFC_ISO7816_CLA_ISO;
      write_cmd[1] = (uint8_t)NFC_ISO7816_INS_UPDATE_BINARY;
      write_cmd[NFC_ISO7816_APDU_IDX_P1] = (uint8_t)(offset >> NFC_ISO7816_U16_HIGH_BYTE_SHIFT);
      write_cmd[NFC_ISO7816_APDU_IDX_P2] = (uint8_t)(offset & NFC_ISO7816_LOW_BYTE_MASK);
      write_cmd[NFC_ISO7816_APDU_IDX_LC] = chunk;
      if (!nero_nfc_copy_bytes(write_cmd, sizeof(write_cmd), NFC_ISO7816_SHORT_APDU_HDR_LEN,
                               &ndef[written], chunk)) {
        writer_iso_dep_deselect();
        return false;
      }
      nfc_tutorial_t4t_update_binary(nero_nfc_log_putc, offset, &ndef[written], chunk);
      rlen = writer_iso_dep_transact(write_cmd, (uint16_t)(NFC_ISO7816_SHORT_APDU_HDR_LEN + chunk),
                                     resp, sizeof(resp));
      if ((rlen < (int)NFC_ISO7816_SW_LEN) || !nfc_iso7816_response_sw_ok(resp, rlen)) {
        nero_nfc_log_write("  [T4] NDEF write failed at offset ");
        do {
          char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
          (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(offset));
          nero_nfc_log_write(ndc);
        } while (0);
        {
          uint8_t sw1 = 0u;
          uint8_t sw2 = 0u;
          if (nfc_iso7816_response_sw(resp, rlen, &sw1, &sw2)) {
            nero_nfc_log_write(" (SW=0x");
            do {
              char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
              (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(sw1));
              nero_nfc_log_write(nhx);
            } while (0);
            do {
              char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
              (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(sw2));
              nero_nfc_log_write(nhx);
            } while (0);
            nero_nfc_log_putc(')');
          }
        }
        nero_nfc_log_write("\r\n");
        writer_iso_dep_deselect();
        return false;
      }
      written = (uint16_t)(written + chunk);
    }
    nero_nfc_log_line("  NDEF data: OK");
  }

  /* Finalise — set NLEN to the actual NDEF message length. */
  {
    uint8_t set_nlen[NFC_ISO7816_SHORT_APDU_HDR_LEN + NFC_PCSC_T4_NLEN_LEN] = {
      (uint8_t)NFC_ISO7816_CLA_ISO,
      (uint8_t)NFC_ISO7816_INS_UPDATE_BINARY,
      (uint8_t)NFC_ISO7816_CLA_ISO,
      (uint8_t)NFC_ISO7816_CLA_ISO,
      (uint8_t)NFC_PCSC_T4_NLEN_LEN,
      (uint8_t)(ndef_len >> NFC_ISO7816_U16_HIGH_BYTE_SHIFT),
      (uint8_t)(ndef_len & NFC_ISO7816_LOW_BYTE_MASK),
    };
    nfc_tutorial_t4t_nlen(nero_nfc_log_putc, ndef_len);
    rlen = writer_iso_dep_transact(set_nlen, sizeof(set_nlen), resp, sizeof(resp));
    if ((rlen < (int)NFC_ISO7816_SW_LEN) || !nfc_iso7816_response_sw_ok(resp, rlen)) {
      nero_nfc_log_write("  [T4] NLEN finalise failed");
      {
        uint8_t sw1 = 0u;
        uint8_t sw2 = 0u;
        if (nfc_iso7816_response_sw(resp, rlen, &sw1, &sw2)) {
          nero_nfc_log_write(" (SW=0x");
          do {
            char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
            (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(sw1));
            nero_nfc_log_write(nhx);
          } while (0);
          do {
            char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
            (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(sw2));
            nero_nfc_log_write(nhx);
          } while (0);
          nero_nfc_log_putc(')');
        }
      }
      nero_nfc_log_write("\r\n");
      writer_iso_dep_deselect();
      return false;
    }
  }

  writer_iso_dep_deselect();
  return true;
}
