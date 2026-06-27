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
 * writer_tag_write_type2.cpp — NFC Forum Type 2 NDEF write path.
 */

#include "writer_tag_write_internal.h"

#include "writer_app_state.h"
#include "writer_frontend.h"
#include "writer_hal.h"
#include "writer_payload.h"
#include "writer_type2_geometry.h"

#include "nfc_byte_tutorial.h"
#include "nfc_frontend.h"
#include "nfc_ndef_tlv.h"
#include "nero_nfc_mem_util.h"
#include "nfc_tag_info.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "nero_nfc_format.h"

enum { kWriterType2PostWriteSettleMs = 2u };

static int ntag_read_page(uint8_t page, uint8_t *buf) {
  const uint8_t cmd[NFC_TAG_T2T_READ_CMD_LEN] = {NFC_FRONTEND_NTAG_CMD_READ, page};
  if (buf == NERO_NFC_NULL) {
    return -1;
  }
  return writer_rf_transceive14(cmd, NFC_TAG_T2T_READ_CMD_LEN, buf, NFC_TAG_T2T_READ_RESP_BYTES,
                                true, NFC_TAG_T2T_READ_TIMEOUT_MS, false, false);
}

static int type2_get_version(uint8_t *out, uint8_t out_cap) {
  const uint8_t cmd[1] = {NFC_FRONTEND_NTAG_CMD_GET_VERSION};
  uint8_t scratch[NFC_TAG_NTAG_GET_VERSION_RX_BUF_MAX];
  uint8_t *dst = (out != NERO_NFC_NULL) ? out : scratch;
  uint8_t cap = (out != NERO_NFC_NULL) ? out_cap : (uint8_t)sizeof(scratch);
  int ver_len = writer_rf_transceive14(cmd, NFC_TAG_T2T_GET_VERSION_CMD_LEN, dst, cap, true,
                                       NFC_TAG_T2T_READ_TIMEOUT_MS, false, false);

  if (ver_len < (int)NFC_TAG_NTAG_VER_REPLY_LEN) {
    (void)writer_rf_activate_iso14443a();
  }
  return ver_len;
}

static int type2_read_signature(uint8_t *out, uint8_t out_cap) {
  const uint8_t cmd[NFC_TAG_T2T_READ_CMD_LEN] = {NFC_FRONTEND_NTAG_CMD_READ_SIG, 0x00u};
  int sig_len = writer_rf_transceive14(cmd, sizeof(cmd), out, out_cap, true,
                                       NFC_TAG_T2T_READ_SIG_TIMEOUT_MS, false, false);
  if (sig_len < (int)NFC_TAG_NTAG_SIG_REPLY_LEN) {
    (void)writer_rf_activate_iso14443a();
  }
  return sig_len;
}

bool writer_collect_type2_info(writer_type2_family_t fam, nfc_tag_type2_info_t *type2_out) {
  uint8_t page3[NFC_TAG_T2T_READ_RESP_BYTES];
  int page_len;

  if (type2_out == NERO_NFC_NULL) {
    return false;
  }
  nero_nfc_zero_bytes(type2_out, sizeof(*type2_out));
  if (writer_app_tag_version_len != 0u) {
    nfc_tag_type2_apply_version(type2_out, writer_app_tag_version, writer_app_tag_version_len);
  } else if (fam == WRITER_TYPE2_FAMILY_NTAG21X) {
    int version_len = type2_get_version(type2_out->version, (uint8_t)sizeof(type2_out->version));
    if (version_len > 0) {
      type2_out->version_len =
        (uint8_t)((version_len > (int)NFC_TAG_NTAG_VER_REPLY_LEN) ? (int)NFC_TAG_NTAG_VER_REPLY_LEN
                                                                  : version_len);
      nfc_tag_type2_apply_version(type2_out, type2_out->version, type2_out->version_len);
      (void)nero_nfc_copy_bytes(writer_app_tag_version, sizeof(writer_app_tag_version), 0u,
                                type2_out->version, type2_out->version_len);
      writer_app_tag_version_len = type2_out->version_len;
    }
  }

  page_len = ntag_read_page(NFC_TAG_T2T_CC_PAGE_INDEX, page3);
  if (page_len >= (int)NFC_TAG_T2T_PAGE_SIZE_BYTES) {
    nfc_tag_type2_apply_cc(type2_out, page3, NFC_TAG_T2T_PAGE_SIZE_BYTES);
    (void)nero_nfc_copy_bytes(writer_app_t2_cc_page3, sizeof(writer_app_t2_cc_page3), 0u, page3,
                              sizeof(writer_app_t2_cc_page3));
    writer_app_t2_cc_from_tag_valid = true;
  } else if (writer_app_t2_cc_from_tag_valid) {
    nfc_tag_type2_apply_cc(type2_out, writer_app_t2_cc_page3, sizeof(writer_app_t2_cc_page3));
  }

  if ((fam == WRITER_TYPE2_FAMILY_ST25TN) ||
      ((type2_out->family == NFC_TAG_TYPE2_FAMILY_UNKNOWN) && (writer_app_uid14_len != 0u) &&
       (writer_app_uid14[0] == NFC_TAG_MFR_CODE_ST) && type2_out->cc_valid &&
       (type2_out->cc[0] == NFC_FORUM_CC_MAGIC))) {
    nfc_tag_type2_apply_family_hint(type2_out, NFC_TAG_TYPE2_FAMILY_ST25TN);
  }

  if ((fam == WRITER_TYPE2_FAMILY_NTAG21X) || (type2_out->family == NFC_TAG_TYPE2_FAMILY_NTAG21X)) {
    uint8_t signature[NFC_TAG_NTAG_SIG_REPLY_LEN];
    int sig_len = type2_read_signature(signature, (uint8_t)sizeof(signature));

    if (sig_len >= (int)sizeof(signature)) {
      nfc_tag_type2_apply_signature(type2_out, signature, (uint8_t)sizeof(signature));
    }
    if (type2_out->max_user_page != 0u) {
      uint8_t cfg[NFC_TAG_T2T_READ_RESP_BYTES];
      uint8_t auth0_page = (uint8_t)(type2_out->max_user_page + NFC_TAG_NTAG_AUTH0_PAGE_OFFSET);
      int cfg_len = ntag_read_page(auth0_page, cfg);

      if (cfg_len >= (int)NFC_TAG_T2T_PAGE_SIZE_BYTES) {
        nfc_tag_type2_apply_auth0(type2_out, cfg[NFC_TAG_NTAG_CFG_AUTH0_BYTE_INDEX]);
      }
    }
  }
  return true;
}
static bool ntag_write_page(uint8_t page, const uint8_t *data) {
  if ((data == NERO_NFC_NULL) ||
      !nero_nfc_span_ok(NFC_TAG_T2T_PAGE_BYTE3, 1u, NFC_TAG_T2T_PAGE_SIZE_BYTES)) {
    return false;
  }
  uint8_t cmd[NFC_TAG_T2T_WRITE_CMD_LEN];
  cmd[0] = NFC_FRONTEND_NTAG_CMD_WRITE;
  cmd[1] = page;
  if (!nero_nfc_copy_bytes(cmd, sizeof(cmd), NFC_TAG_T2T_WRITE_CMD_DATA_OFFSET, data,
                           NFC_TAG_T2T_PAGE_SIZE_BYTES)) {
    return false;
  }
  uint8_t rx[NFC_TAG_T2T_PAGE_SIZE_BYTES];
  int rlen = writer_rf_transceive14(cmd, NFC_TAG_T2T_WRITE_CMD_LEN, rx, sizeof(rx), true,
                                    NFC_TAG_T2T_WRITE_ACK_TIMEOUT_MS, false, true);
  /*
   * [T2T-ISO14443-A-NTAG21x] section 10.4 Table 34 — TTimeOut for WRITE ACK/NAK (10 ms).
   * [T2T-ISO14443-A] section 5.2 — WRITE is confirmed only by the 4-bit ACK 1010b (0Ah).
   */
  return (rlen >= 1) && ((rx[0] & NFC_TAG_T2T_ACK_NIBBLE_MASK) == NFC_TAG_T2T_ACK_NIBBLE);
}

static bool writer_type2_write_page(uint8_t page, const uint8_t *data) {
  if (data == NERO_NFC_NULL) {
    return false;
  }
  for (uint8_t attempt = 0u; attempt < NFC_TAG_READER_TYPE2_WRITE_ATTEMPTS; ++attempt) {
    uint8_t verify[NFC_TAG_T2T_READ_RESP_BYTES];
    bool write_ack;

    if (attempt != 0u && !writer_rf_activate_iso14443a()) {
      continue;
    }
    write_ack = ntag_write_page(page, data);
    writer_hal_delay_ms(write_ack ? NFC_TAG_T2T_WRITE_VERIFY_SETTLE_MS
                                  : NFC_TAG_T2T_WRITE_FAIL_SETTLE_MS);
    if ((ntag_read_page(page, verify) >= (int)NFC_TAG_T2T_PAGE_SIZE_BYTES) &&
        (memcmp(verify, data, NFC_TAG_T2T_PAGE_SIZE_BYTES) == 0)) {
      return true;
    }
    (void)writer_rf_activate_iso14443a();
  }
  return false;
}

static bool writer_type2_write_unit(uint16_t unit, const uint8_t *data, uint8_t data_len) {
  if ((data == NERO_NFC_NULL) || (data_len != NFC_STORAGE_TYPE2_UNIT_SIZE) || (unit > UINT8_MAX)) {
    return false;
  }
  return writer_type2_write_page((uint8_t)unit, data);
}

/*
 * [T2T-ISO14443-A-NTAG21x] section 10.1 / Table 28 — GET_VERSION returns
 * NFC_TAG_NTAG_VER_REPLY_LEN bytes (optional CRC-A may follow in the FIFO).
 * Tries command 0x60; ST25TN-class ICs ignore it (see [T2T-ISO14443-A-ST25TN] — no GET_VERSION).
 */
static bool ntag_try_get_version(void) {
  uint8_t cmd = NFC_FRONTEND_NTAG_CMD_GET_VERSION;
  uint8_t rx[NFC_TAG_NTAG_GET_VERSION_RX_BUF_MAX];
  nfc_tag_type2_info_t version_info;
  int len = writer_rf_transceive14(&cmd, NFC_TAG_T2T_GET_VERSION_CMD_LEN, rx, sizeof(rx), true,
                                   NFC_TAG_T2T_READ_TIMEOUT_MS, false, false);
  if (len < (int)NFC_TAG_NTAG_VER_REPLY_LEN) {
    writer_app_tag_version_len = 0u;
    return false;
  }
  for (int i = 0; i < (int)NFC_TAG_NTAG_VER_REPLY_LEN; i++) {
    if (!nero_nfc_span_ok((size_t)i, 1u, (size_t)len)) {
      return false;
    }
    writer_app_tag_version[i] = rx[i];
  }
  writer_app_tag_version_len = (uint8_t)sizeof(writer_app_tag_version);
  nero_nfc_log_write("  Version: ");
  for (int i = 0; i < len; i++) {
    if (!nero_nfc_span_ok((size_t)i, 1u, (size_t)len)) {
      return false;
    }
    nero_nfc_log_hex_u8(rx[i]);
    nero_nfc_log_putc(' ');
  }
  nero_nfc_log_write("\r\n");
  nero_nfc_zero_bytes(&version_info, sizeof(version_info));
  nfc_tag_type2_apply_version(&version_info, rx, (uint8_t)len);
  if (version_info.family != NFC_TAG_TYPE2_FAMILY_NTAG21X) {
    return false;
  }
  if (version_info.vendor_id != NFC_TAG_NTAG_VER_VENDOR_NXP) {
    nero_nfc_log_write("  NXP NTAG21x (GET_VERSION vendor byte 0x");
    do {
      char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
      (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)version_info.vendor_id);
      nero_nfc_log_write(nhx);
    } while (0);
    nero_nfc_log_line(" != 04h — accepting NTAG fingerprint)");
  } else {
    nero_nfc_log_line("  NXP NTAG21x");
  }
  switch (version_info.size_id) {
  case NFC_TAG_NTAG213_SIZE_ID:
    nero_nfc_log_write("    GET_VERSION byte 6 = 0x0F (common on NTAG213; not "
                       "authoritative alone)\r\n");
    break;
  case NFC_TAG_NTAG216_SIZE_ID:
    nero_nfc_log_line("    GET_VERSION byte 6 = 0x13 (common on NTAG216)");
    break;
  case NFC_TAG_NTAG215_SIZE_ID:
    nero_nfc_log_line("    GET_VERSION byte 6 = 0x11 (common on NTAG215)");
    break;
  default:
    nero_nfc_log_write("    GET_VERSION byte 6 = 0x");
    do {
      char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
      (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)version_info.size_id);
      nero_nfc_log_write(nhx);
    } while (0);
    nero_nfc_log_write("\r\n");
    break;
  }
  nero_nfc_log_write("    Geometry follows CC page 3 MLEN when readable (may disagree on "
                     "non-NXP tags)\r\n");
  return true;
}

/*
 * Maps NFC Forum CC MLEN (byte 2, ×8 bytes) to the last user page index NXP
 * uses for each NTAG21x tier (factory defaults 12h / 3Eh / 6Dh per UM
 * NTAG213_215_216).
 */
static void serial_ntag21x_tier_hint_from_cc_mlen(uint8_t mlen) {
  nero_nfc_log_write("  Tier from CC MLEN 0x");
  do {
    char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
    (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(mlen));
    nero_nfc_log_write(nhx);
  } while (0);
  if (mlen <= NFC_TAG_NTAG213_CC_MLEN) {
    nero_nfc_log_line(": NTAG213-class");
  } else if (mlen <= NFC_TAG_NTAG215_CC_MLEN) {
    nero_nfc_log_line(": NTAG215-class");
  } else {
    nero_nfc_log_line(": NTAG216-class");
  }
}

/*
 * Last page index ceiling for clamping inflated MLEN (e.g. OTP-glitched CC).
 * Prefer CC MLEN whenever page 3 has NFC Forum magic 0xE1 — it matches factory
 * geometry even when GET_VERSION byte 6 disagrees (seen with UID/vendor-byte
 * clones).
 */
static void serial_ntag_version_cc_mismatch_hint(uint8_t cc_mlen) {
  if ((writer_app_tag_version_len < NFC_TAG_NTAG_VER_REPLY_LEN) ||
      !writer_type2_is_ntag21x_version_reply(writer_app_tag_version,
                                             (int)writer_app_tag_version_len)) {
    return;
  }
  uint8_t b6 =
    writer_type2_ntag21x_size_id(writer_app_tag_version, (int)writer_app_tag_version_len);
  uint16_t cc_cap = writer_type2_cap_last_page_from_mlen(cc_mlen);
  uint16_t ver_cap = 0u;
  switch (b6) {
  case NFC_TAG_NTAG213_SIZE_ID:
    ver_cap = NFC_TAG_NTAG213_LAST_PAGE;
    break;
  case NFC_TAG_NTAG215_SIZE_ID:
    ver_cap = NFC_TAG_NTAG215_LAST_PAGE;
    break;
  case NFC_TAG_NTAG216_SIZE_ID:
    ver_cap = NFC_TAG_NTAG216_LAST_PAGE;
    break;
  default:
    return;
  }
  if (ver_cap != cc_cap) {
    nero_nfc_log_write("  Note: GET_VERSION byte 6 disagrees with CC MLEN — using CC for "
                       "limits\r\n");
  }
}

/*
 * Returns the suggested CC byte 2 ("T2T_AREA_SIZE / 8") for the detected IC.
 * NTAG21x values come from NXP datasheet NT3H1101 / NTAG21x family. ST25TN
 * factory CC encodes 64 bytes as NFC_TAG_ST25TN512_CC_MLEN and 160 bytes as
 * NFC_TAG_ST25TN01K_CC_MLEN ([T2T-ISO14443-A-ST25TN] Table 28 / section 7).
 *
 * The return is informational: we do NOT rewrite the CC unless the tag is
 * truly blank, because both NTAG21x and ST25TN block 3 are OTP — bits can
 * only flip 0→1, never the other way.
 */
static uint8_t t2_cc_size(writer_type2_family_t fam) {
  return writer_type2_cc_size(fam, writer_app_t2_cc_from_tag_valid, writer_app_t2_cc_page3,
                              writer_app_tag_version_len, writer_app_tag_version);
}

static uint16_t t2_max_page(writer_type2_family_t fam) {
  return writer_type2_max_page(fam, writer_app_t2_cc_from_tag_valid, writer_app_t2_cc_page3,
                               writer_app_tag_version_len, writer_app_tag_version);
}

bool writer_tag_write_type2_impl(writer_type2_family_t fam) {
  uint8_t tlv[WRITER_NDEF_MAX_BYTES];
  uint16_t total = writer_payload_build_tlv(&writer_app_payload, tlv, sizeof(tlv));
  uint8_t cc_size_byte;
  uint16_t max_pg;
  uint16_t pages_needed;
  uint8_t need_mlen;
  size_t last_page_needed = 0u;
  nfc_tag_type2_info_t type2_info;

  if (!writer_payload_configured(&writer_app_payload)) {
    nero_nfc_log_write(
      "  ERROR: no payload configured — enter url/text/wifi/ndef-hex/... first\r\n");
    return false;
  }
  if (total == 0u) {
    nero_nfc_log_line("  ERROR: NDEF encode failed");
    return false;
  }

  nero_nfc_log_write("\r\n  ── Writing NDEF (Type 2) ──\r\n  Bytes (");
  do {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(total));
    nero_nfc_log_write(ndc);
  } while (0);
  nero_nfc_log_write("): ");
  for (uint16_t i = 0u; i < total; i++) {
    nero_nfc_log_hex_u8(tlv[i]);
    nero_nfc_log_putc(' ');
  }
  nero_nfc_log_write("\r\n");

  if (!writer_collect_type2_info(fam, &type2_info)) {
    nero_nfc_log_line("  ERROR: failed to inspect Type 2 access metadata");
    return false;
  }
  if (type2_info.cc_valid && !type2_info.write_access_open) {
    nero_nfc_log_line("  ERROR: tag reports Type 2 write access restricted");
    return false;
  }
  if (type2_info.password_protected) {
    nero_nfc_log_line("  ERROR: tag reports Type 2 password protection enabled");
    return false;
  }

  cc_size_byte = t2_cc_size(fam);
  need_mlen =
    (uint8_t)((total + NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES - 1u) / NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES);
  if (need_mlen > cc_size_byte) {
    cc_size_byte = need_mlen;
  }

  max_pg = t2_max_page(fam);
  pages_needed =
    (uint16_t)((total + NFC_TAG_T2T_PAGE_SIZE_BYTES - 1u) / NFC_TAG_T2T_PAGE_SIZE_BYTES);
  if (!nero_nfc_try_add_size(NFC_STORAGE_TYPE2_FIRST_DATA_PAGE, (size_t)pages_needed - 1u,
                             &last_page_needed) ||
      (last_page_needed > (size_t)max_pg)) {
    nero_nfc_log_line("  ERROR: Message too big for tag");
    return false;
  }

  {
    const uint8_t cc_bytes[NFC_TAG_T2T_PAGE_SIZE_BYTES] = {NFC_FORUM_CC_MAGIC, NFC_T2T_CC_VERSION,
                                                           cc_size_byte, 0x00u};
    nero_nfc_log_line("\r\n  ── Byte-level explainer (write) ──");
    nfc_tutorial_t2t_cc(nero_nfc_log_putc, cc_bytes);
    nfc_tutorial_t2t_write_cmd(nero_nfc_log_putc, NFC_STORAGE_TYPE2_FIRST_DATA_PAGE, tlv);
    nfc_tutorial_ndef_tlv(nero_nfc_log_putc, tlv, total);
  }
  /*
   * Update CC only when the tag is blank or its current MLEN is too small.
   * Both NTAG21x and ST25TN have OTP CC bits; rewriting a valid CC with the
   * same bytes is safe but wastes a programming cycle. If the existing MLEN
   * already covers our payload, leave it untouched.
   */
  {
    uint8_t rb[NFC_TAG_T2T_READ_RESP_BYTES];
    int r = ntag_read_page(NFC_TAG_T2T_CC_PAGE_INDEX, rb);
    bool needs_cc = (r < (int)NFC_TAG_T2T_PAGE_SIZE_BYTES) || (rb[0] != NFC_FORUM_CC_MAGIC) ||
                    (rb[NFC_TAG_T2T_CC_MLEN_INDEX] < cc_size_byte);
    if (needs_cc) {
      const uint8_t cc_page[NFC_TAG_T2T_PAGE_SIZE_BYTES] = {NFC_FORUM_CC_MAGIC, NFC_T2T_CC_VERSION,
                                                            cc_size_byte, 0x00u};
      nero_nfc_log_line("  Writing CC...");
      if (!ntag_write_page(NFC_TAG_T2T_CC_PAGE_INDEX, cc_page)) {
        nero_nfc_log_line("  CC write FAILED (CC bits are OTP — already locked?)");
        return false;
      }
      writer_hal_delay_ms(NFC_TAG_T2T_WRITE_VERIFY_SETTLE_MS);
    }
  }

  if (!writer_tag_write_storage_tlv_units(tlv, total, NFC_STORAGE_TYPE2_FIRST_DATA_PAGE,
                                          NFC_STORAGE_TYPE2_UNIT_SIZE, "Page",
                                          writer_type2_write_unit)) {
    return false;
  }
  nero_nfc_log_line("\r\n  *** SUCCESS - Wrote NDEF message ***\r\n");
  return true;
}
writer_type2_family_t writer_tag_write_identify_type2_family(void) {
  uint8_t rb[NFC_TAG_T2T_READ_RESP_BYTES];

  writer_app_t2_cc_from_tag_valid = false;
  if (ntag_try_get_version()) {
    int cr = ntag_read_page(NFC_TAG_T2T_CC_PAGE_INDEX, rb);
    if ((cr >= (int)NFC_TAG_T2T_PAGE_SIZE_BYTES) && (rb[0] == NFC_FORUM_CC_MAGIC)) {
      writer_app_t2_cc_page3[0] = rb[0];
      writer_app_t2_cc_page3[1] = rb[1];
      writer_app_t2_cc_page3[NFC_TAG_T2T_CC_MLEN_INDEX] = rb[NFC_TAG_T2T_CC_MLEN_INDEX];
      writer_app_t2_cc_page3[NFC_TAG_T2T_CC_ACCESS_INDEX] = rb[NFC_TAG_T2T_CC_ACCESS_INDEX];
      writer_app_t2_cc_from_tag_valid = true;
      nero_nfc_log_write("  CC page 3: ");
      do {
        char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
        (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(rb[0]));
        nero_nfc_log_write(nhx);
      } while (0);
      nero_nfc_log_putc(' ');
      do {
        char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
        (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(rb[1]));
        nero_nfc_log_write(nhx);
      } while (0);
      nero_nfc_log_putc(' ');
      do {
        char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
        (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X",
                                (unsigned)(uint8_t)(rb[NFC_TAG_T2T_CC_MLEN_INDEX]));
        nero_nfc_log_write(nhx);
      } while (0);
      nero_nfc_log_putc(' ');
      do {
        char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
        (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X",
                                (unsigned)(uint8_t)(rb[NFC_TAG_T2T_CC_ACCESS_INDEX]));
        nero_nfc_log_write(nhx);
      } while (0);
      nero_nfc_log_write("\r\n");
      if ((writer_app_tag_version_len >= NFC_TAG_NTAG_VER_REPLY_LEN) &&
          writer_type2_is_ntag21x_version_reply(writer_app_tag_version,
                                                (int)writer_app_tag_version_len)) {
        serial_ntag21x_tier_hint_from_cc_mlen(rb[NFC_TAG_T2T_CC_MLEN_INDEX]);
        serial_ntag_version_cc_mismatch_hint(rb[NFC_TAG_T2T_CC_MLEN_INDEX]);
      }
    }
    return WRITER_TYPE2_FAMILY_NTAG21X;
  }

  /* GET_VERSION failed → re-WUPA + select to leave the tag in ACTIVE. */
  writer_hal_delay_ms(kWriterType2PostWriteSettleMs);
  if (!writer_rf_activate_iso14443a()) {
    nero_nfc_log_line("  Re-activation after GET_VERSION failure: FAILED");
    return WRITER_TYPE2_FAMILY_UNKNOWN;
  }

  if ((writer_app_uid14_len >= 1u) && (writer_app_uid14[0] == NFC_TAG_MFR_CODE_ST)) {
    uint8_t cc[NFC_TAG_T2T_READ_RESP_BYTES];
    int rlen = ntag_read_page(NFC_TAG_T2T_CC_PAGE_INDEX, cc);
    if (rlen >= (int)NFC_TAG_T2T_PAGE_SIZE_BYTES) {
      if (cc[0] == NFC_FORUM_CC_MAGIC) {
        nero_nfc_log_write("  ST25TN-class tag (CC magic 0xE1, STMicroelectronics "
                           "manufacturer code "
                           "0x02)\r\n");
        return WRITER_TYPE2_FAMILY_ST25TN;
      }
      nero_nfc_log_write("  Non-NDEF ST tag (CC magic 0x");
      do {
        char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
        (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(cc[0]));
        nero_nfc_log_write(nhx);
      } while (0);
      nero_nfc_log_line(") — skipping");
      return WRITER_TYPE2_FAMILY_UNKNOWN;
    }
  }
  return WRITER_TYPE2_FAMILY_UNKNOWN;
}
