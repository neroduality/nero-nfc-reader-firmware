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
 * reader_tags_type4.cpp — ISO-DEP Type 4 tag read path.
 */

#include "reader_tags.h"
#include "reader_tags_internal.h"
#include "nfc_tag_info_print.h"

#include "nfc_frontend.h"
#include "nfc_byte_tutorial.h"
#include "nfc_ndef_tlv.h"
#include "nfc_pcsc_contactless.h"
#include "nero_nfc_mem_util.h"
#include "nfc_ccid_frame.h"
#include "reader_context.h"
#include "reader_frontend.h"
#include "reader_hal.h"
#include "reader_output.h"
#include "reader_protocol.h"

#include "reader_tags_ndef_decode.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "nero_nfc_format.h"

enum {
  kReaderTagsType4MinCmdLen = NFC_ISO7816_SHORT_APDU_HDR_LEN,
  kReaderTagsType4CcPayloadMin =
    (uint16_t)(NFC_PCSC_T4_CC_FILE_LEN + NFC_ISO7816_SW_STATUS_WORD_LEN),
  kReaderTagsType4CcLenFieldWidth = NFC_PCSC_T4_NLEN_LEN,
  kReaderTagsType4NdefLenReadMin = NFC_ISO7816_MIN_RESPONSE_WITH_STATUS_LEN,
  /* [T4T-ISO14443-4] NDEF file layout: 2-byte NLEN field followed immediately by the NDEF
   * message, so the message data begins one NLEN field (2 bytes) into the file. */
  kReaderTagsType4NdefDataOffset = NFC_PCSC_T4_NLEN_LEN,
};

static int reader_tags_type4_iso_read_binary(const uint8_t *cmd, uint8_t cmd_len, uint8_t *resp,
                                             uint16_t resp_cap) {
  int rlen;
  uint8_t correct_le = 0u;

  if ((cmd == NERO_NFC_NULL) || (cmd_len < kReaderTagsType4MinCmdLen) || (resp == NERO_NFC_NULL) ||
      (resp_cap < NFC_ISO7816_SW_STATUS_WORD_LEN)) {
    return -1;
  }
  rlen = reader_iso_dep_send_apdu(cmd, cmd_len, resp, resp_cap);
  if (nfc_iso7816_response_wrong_length(resp, rlen, &correct_le)) {
    uint8_t retry[NFC_PCSC_T4_READ_BINARY_APDU_LEN];
    uint8_t retry_len = 0u;
    const uint16_t offset =
      (uint16_t)(((uint16_t)cmd[NFC_ISO7816_APDU_IDX_P1] << NFC_CCID_U32_SHIFT_BYTE1) |
                 cmd[NFC_ISO7816_APDU_IDX_P2]);

    if (nfc_pcsc_build_t4_read_binary_apdu(offset, correct_le, retry, (uint8_t)sizeof(retry),
                                           &retry_len)) {
      rlen = reader_iso_dep_send_apdu(retry, retry_len, resp, resp_cap);
    }
  }
  return rlen;
}

bool reader_tags_type4_load_info(reader_tag_type4_info_t *info, uint8_t *ndef_file_hi_out,
                                 uint8_t *ndef_file_lo_out, bool log_errors) {
  uint8_t resp[NFC_PCSC_ISO_DEP_APDU_RESP_MAX];
  uint8_t sel_cc[NFC_PCSC_T4_SELECT_FILE_APDU_LEN];
  uint8_t read_cc[NFC_PCSC_T4_READ_BINARY_APDU_LEN];
  uint8_t sel_cc_len = 0u;
  uint8_t read_cc_len = 0u;
  int rlen;
  uint16_t cc_len = (uint16_t)NFC_PCSC_T4_CC_FILE_LEN;

  if (ndef_file_hi_out != NERO_NFC_NULL) {
    *ndef_file_hi_out = 0u;
  }
  if (ndef_file_lo_out != NERO_NFC_NULL) {
    *ndef_file_lo_out = 0u;
  }
  if (info == NERO_NFC_NULL || ndef_file_hi_out == NERO_NFC_NULL ||
      ndef_file_lo_out == NERO_NFC_NULL) {
    return false;
  }
  if (!nfc_pcsc_build_t4_select_file_apdu((uint16_t)NFC_PCSC_T4_CC_FILE_ID, sel_cc,
                                          (uint8_t)sizeof(sel_cc), &sel_cc_len) ||
      !nfc_pcsc_build_t4_read_binary_apdu(0u, (uint8_t)NFC_PCSC_T4_CC_FILE_LEN, read_cc,
                                          (uint8_t)sizeof(read_cc), &read_cc_len)) {
    return false;
  }

  if (!reader_iso_dep_select_ndef_app()) {
    if (log_errors) {
      nero_nfc_log_line("  NDEF application select failed");
    }
    return false;
  }

  rlen = reader_iso_dep_send_apdu(sel_cc, sel_cc_len, resp, sizeof(resp));
  if ((rlen < (int)NFC_ISO7816_SW_LEN) || !nfc_iso7816_response_sw_ok(resp, rlen)) {
    if (log_errors) {
      uint8_t sw1 = 0u;
      uint8_t sw2 = 0u;
      nero_nfc_log_write("  CC select failed (SW=");
      if (nfc_iso7816_response_sw(resp, rlen, &sw1, &sw2)) {
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
      } else {
        nero_nfc_log_write("??");
      }
      nero_nfc_log_line(")");
    }
    return false;
  }

  rlen = reader_tags_type4_iso_read_binary(read_cc, read_cc_len, resp, sizeof(resp));
  if ((rlen < (int)kReaderTagsType4CcPayloadMin) || !nfc_iso7816_response_sw_ok(resp, rlen)) {
    if (log_errors) {
      nero_nfc_log_write("  CC read failed (rlen=");
      do {
        char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
        (void)nero_nfc_snprintf(ndc, sizeof ndc, "%d", (int)(int32_t)(rlen));
        nero_nfc_log_write(ndc);
      } while (0);
      nero_nfc_log_line(")");
    }
    return false;
  }
  cc_len = (uint16_t)(((uint16_t)resp[NFC_TAG_CC_CCLEN_MSB_INDEX] << NFC_CCID_U32_SHIFT_BYTE1) |
                      resp[NFC_TAG_CC_CCLEN_LSB_INDEX]);
  if (cc_len < (uint16_t)NFC_PCSC_T4_CC_FILE_LEN ||
      cc_len > (uint16_t)(sizeof(resp) - NFC_ISO7816_SW_STATUS_WORD_LEN)) {
    if (log_errors) {
      nero_nfc_log_write("  CC parse failed (CCLEN=");
      do {
        char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
        (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(cc_len));
        nero_nfc_log_write(ndc);
      } while (0);
      nero_nfc_log_line(")");
    }
    return false;
  }
  if (cc_len > (uint16_t)NFC_PCSC_T4_CC_FILE_LEN) {
    if (!nfc_pcsc_build_t4_read_binary_apdu(0u, (uint8_t)cc_len, read_cc, (uint8_t)sizeof(read_cc),
                                            &read_cc_len)) {
      return false;
    }
    rlen = reader_tags_type4_iso_read_binary(read_cc, read_cc_len, resp, sizeof(resp));
    if ((rlen < (int)(cc_len + NFC_ISO7816_SW_STATUS_WORD_LEN)) ||
        !nfc_iso7816_response_sw_ok(resp, rlen)) {
      if (log_errors) {
        nero_nfc_log_write("  CC full read failed (CCLEN=");
        do {
          char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
          (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(cc_len));
          nero_nfc_log_write(ndc);
        } while (0);
        nero_nfc_log_write(" rlen=");
        do {
          char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
          (void)nero_nfc_snprintf(ndc, sizeof ndc, "%d", (int)(int32_t)(rlen));
          nero_nfc_log_write(ndc);
        } while (0);
        nero_nfc_log_line(")");
      }
      return false;
    }
  }
  if (!nfc_tag_type4_apply_cc(info, resp, (uint8_t)cc_len)) {
    if (log_errors) {
      nero_nfc_log_line("  CC parse failed");
    }
    return false;
  }

  *ndef_file_hi_out = info->ndef_file_id[0];
  *ndef_file_lo_out = info->ndef_file_id[1];
  return true;
}

bool reader_tags_read_type4_ndef(void) {
  uint8_t resp[NFC_PCSC_ISO_DEP_APDU_RESP_MAX];
  reader_tag_typea_info_t typea;
  reader_tag_type4_info_t type4;
  uint8_t sel_ndef[NFC_PCSC_T4_SELECT_FILE_APDU_LEN];
  uint8_t read_len_cmd[NFC_PCSC_T4_READ_BINARY_APDU_LEN];
  uint8_t sel_ndef_len = 0u;
  uint8_t read_len_cmd_len = 0u;
  int rlen;
  uint8_t ndef_file_hi;
  uint8_t ndef_file_lo;
  uint16_t ndef_msg_len;
  uint16_t max_ndef_message_size = 0u;

  reader_tags_reset_detected_urls();
  if (!reader_tags_get_typea_info(&typea) ||
      !reader_tags_type4_load_info(&type4, &ndef_file_hi, &ndef_file_lo, true)) {
    return false;
  }
  nfc_tag_print_type4_debug(nero_nfc_log_putc, &typea, &type4);

  nero_nfc_log_line("\r\n  ── Byte-level explainer (read-back) ──");
  nfc_tutorial_t4t_select_app(nero_nfc_log_putc, NFC_PCSC_NDEF_APP_AID,
                              (uint8_t)NFC_PCSC_NDEF_APP_AID_LEN);
  nfc_tutorial_t4t_select_file(nero_nfc_log_putc,
                               (uint8_t)(NFC_PCSC_T4_CC_FILE_ID >> NFC_BYTE_SHIFT_8),
                               (uint8_t)(NFC_PCSC_T4_CC_FILE_ID & NFC_BYTE_VALUE_MAX));
  nfc_tutorial_t4t_read_binary(nero_nfc_log_putc, 0u, (uint8_t)sizeof(type4.cc));
  nfc_tutorial_t4t_cc(nero_nfc_log_putc, type4.cc, (uint8_t)sizeof(type4.cc));
  if (!nfc_pcsc_type4_max_message_size(type4.max_ndef_size, &max_ndef_message_size)) {
    nero_nfc_log_line("  CC Max NDEF file size too small");
    return false;
  }
  if (!type4.read_access_open) {
    nero_nfc_log_line("  NDEF file read access closed");
    return false;
  }
  if (type4.mle < (uint16_t)NFC_PCSC_T4_NLEN_LEN) {
    nero_nfc_log_line("  MLe too small for NDEF length read");
    return false;
  }
  if (!nfc_pcsc_build_t4_select_file_apdu(
        (uint16_t)(((uint16_t)ndef_file_hi << NFC_CCID_U32_SHIFT_BYTE1) | ndef_file_lo), sel_ndef,
        (uint8_t)sizeof(sel_ndef), &sel_ndef_len) ||
      !nfc_pcsc_build_t4_read_binary_apdu(0u, (uint8_t)NFC_PCSC_T4_NLEN_LEN, read_len_cmd,
                                          (uint8_t)sizeof(read_len_cmd), &read_len_cmd_len)) {
    return false;
  }
  rlen = reader_iso_dep_send_apdu(sel_ndef, sel_ndef_len, resp, sizeof(resp));
  if ((rlen < (int)NFC_ISO7816_SW_LEN) || !nfc_iso7816_response_sw_ok(resp, rlen)) {
    uint8_t sw1 = 0u;
    uint8_t sw2 = 0u;
    nero_nfc_log_write("  NDEF file select failed (SW=");
    if (nfc_iso7816_response_sw(resp, rlen, &sw1, &sw2)) {
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
    } else {
      nero_nfc_log_write("??");
    }
    nero_nfc_log_line(")");
    return false;
  }

  rlen = reader_tags_type4_iso_read_binary(read_len_cmd, read_len_cmd_len, resp, sizeof(resp));
  if ((rlen < (int)kReaderTagsType4NdefLenReadMin) || !nfc_iso7816_response_sw_ok(resp, rlen)) {
    nero_nfc_log_line("  NDEF length read failed");
    return false;
  }
  ndef_msg_len = (uint16_t)(((uint16_t)resp[NFC_TAG_CC_CCLEN_MSB_INDEX] << NFC_BYTE_SHIFT_8) |
                            resp[NFC_TAG_CC_CCLEN_LSB_INDEX]);
  nfc_tutorial_t4t_select_file(nero_nfc_log_putc, ndef_file_hi, ndef_file_lo);
  nfc_tutorial_t4t_read_binary(nero_nfc_log_putc, 0u, (uint8_t)NFC_PCSC_T4_NLEN_LEN);
  nfc_tutorial_t4t_nlen(nero_nfc_log_putc, ndef_msg_len);
  if (ndef_msg_len == 0u) {
    nero_nfc_log_line("  NDEF message: 0 bytes");
    return true;
  }
  if (ndef_msg_len > max_ndef_message_size) {
    nero_nfc_log_line("  NDEF length exceeds CC Max NDEF message size");
    return false;
  }
  if (ndef_msg_len > READER_NDEF_BUF_MAX) {
    nero_nfc_log_write("  NDEF message too large (max ");
    do {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(READER_NDEF_BUF_MAX));
      nero_nfc_log_write(ndc);
    } while (0);
    nero_nfc_log_line(" bytes)");
    return false;
  }
  /* Read NDEF message data in 254-byte chunks — READ BINARY Le is limited to
   * 254 (resp[] is 256 bytes; data + 2 SW bytes = 256 max → 254 data bytes per
   * call). s_ndef_buf is a shared module-level static (also used by the T5
   * reader). */
  {
    uint16_t to_read = ndef_msg_len;
    uint16_t assembled = 0u;
    uint16_t mle_cap = (type4.mle != 0u) ? type4.mle : (uint16_t)NFC_PCSC_T4_CC_DEFAULT_MLE;
    uint16_t chunk_max = (mle_cap < (uint16_t)NFC_PCSC_T4_READ_BINARY_DATA_MAX)
                           ? mle_cap
                           : (uint16_t)NFC_PCSC_T4_READ_BINARY_DATA_MAX;
    while (assembled < to_read) {
      uint16_t offset = (uint16_t)(kReaderTagsType4NdefDataOffset + assembled);
      uint16_t remaining = (uint16_t)(to_read - assembled);
      uint8_t chunk = (remaining > chunk_max) ? (uint8_t)chunk_max : (uint8_t)remaining;
      uint8_t cmd[NFC_PCSC_T4_READ_BINARY_APDU_LEN];
      uint8_t cmd_len = 0u;
      if (!nfc_pcsc_build_t4_read_binary_apdu(offset, chunk, cmd, (uint8_t)sizeof(cmd), &cmd_len)) {
        return false;
      }
      nfc_tutorial_t4t_read_binary(nero_nfc_log_putc, offset, chunk);
      rlen = reader_tags_type4_iso_read_binary(cmd, cmd_len, resp, sizeof(resp));
      if ((rlen < (int)(chunk + NFC_ISO7816_SW_STATUS_WORD_LEN)) ||
          !nfc_iso7816_response_sw_ok(resp, rlen)) {
        nero_nfc_log_line("  NDEF read failed");
        return false;
      }
      if (!nero_nfc_copy_bytes(reader_tags_ndef_buf, sizeof(reader_tags_ndef_buf), assembled, resp,
                               chunk)) {
        nero_nfc_log_line("  NDEF read failed");
        return false;
      }
      assembled = (uint16_t)(assembled + chunk);
    }
    if (assembled != to_read) {
      nero_nfc_log_line("  NDEF read incomplete");
      return false;
    }
    nfc_tutorial_ndef_message(nero_nfc_log_putc, reader_tags_ndef_buf, assembled);
    nero_nfc_log_write("  NDEF message: ");
    do {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(ndef_msg_len));
      nero_nfc_log_write(ndc);
    } while (0);
    nero_nfc_log_line(" bytes");
    reader_tags_print_ndef_records(reader_tags_ndef_buf, assembled);
  }
  return true;
}

void reader_tags_read_type4_tag(void) {
  nero_nfc_log_line("\r\n╔════════════════════════════════════════╗");
  nero_nfc_log_line("║     NFC FORUM TYPE 4 TAG               ║");
  nero_nfc_log_line("╚════════════════════════════════════════╝");
  (void)reader_tags_read_type4_ndef();
}
