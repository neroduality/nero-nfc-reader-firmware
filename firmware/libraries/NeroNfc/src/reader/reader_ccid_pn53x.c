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
 * reader_ccid_pn53x.c — PN53x / ACR122 contactless emulation handlers.
 */

#if defined(NERO_CCID_USB_BUILD)

#include "reader_ccid_internal.h"

#include "reader_ccid.h"

#include "nfc_ccid_frame.h"

#include "nfc_ctap_codec.h"
#include "nfc_pcsc_contactless.h"
#include "nero_nfc_mem_util.h"
#include "nfc_session_owner.h"

#include "reader_ccid_protocol.h"
#include "reader_ccid_bulk_codec.h"
#include "reader_context.h"
#include "reader_hal.h"
#include "reader_security_key.h"
#include "reader_security_key_ccid_codec.h"

#if defined(NERO_HOST_UNIT_TEST_HOOKS)
#include "reader_ccid_utest.h"
#include "reader_hal_utest.h"
#endif

#include <stdint.h>
#include <string.h>

enum {
  PN53X_HOST_PREFIX = NFC_PN532_HOST_TO_PN532,
  PN53X_DEV_PREFIX = NFC_PN532_PN532_TO_HOST,
  PN53X_CMD_GET_FIRMWARE_VERSION = NFC_PN532_CMD_GET_FIRMWARE_VERSION,
  PN53X_CMD_IN_LIST_PASSIVE_TARGET = NFC_PN532_CMD_IN_LIST_PASSIVE_TARGET,
  PN53X_RSP_IN_LIST_PASSIVE_TARGET = NFC_PN532_RSP_IN_LIST_PASSIVE_TARGET,
  PN53X_CMD_IN_DATA_EXCHANGE = NFC_PN532_CMD_IN_DATA_EXCHANGE,
  PN53X_RSP_IN_DATA_EXCHANGE = NFC_PN532_RSP_IN_DATA_EXCHANGE,
  PN53X_CMD_IN_COMMUNICATE_THRU = NFC_PN532_CMD_IN_COMMUNICATE_THRU,
  PN53X_RSP_IN_COMMUNICATE_THRU = NFC_PN532_RSP_IN_COMMUNICATE_THRU,
  PN53X_CMD_IN_DESELECT = NFC_PN532_CMD_IN_DESELECT,
  PN53X_RSP_IN_DESELECT = NFC_PN532_RSP_IN_DESELECT,
  PN53X_CMD_IN_RELEASE = NFC_PN532_CMD_IN_RELEASE,
  PN53X_RSP_IN_RELEASE = NFC_PN532_RSP_IN_RELEASE,
  PN53X_STATUS_OK = NFC_PN532_STATUS_OK,
  PN53X_STATUS_TIMEOUT = NFC_PN532_STATUS_TIMEOUT,
  PN53X_STATUS_CONTEXT_ERROR = NFC_PN532_STATUS_CONTEXT_ERROR,
  PN53X_BR_TY106KBPS_TYPE_A = NFC_PN532_BRTY_106KBPS_TYPE_A,
  PN53X_SINGLE_TARGET = NFC_PN532_SINGLE_TARGET,
  ACR122_P1_GET_FIRMWARE = NFC_ACR122U_P1_GET_FIRMWARE_VERSION,
  PN53X_GET_FIRMWARE_VERSION_RSP_SUB = NFC_PN532_GET_FIRMWARE_VERSION_RSP_SUB,
  PN53X_FW_VERSION_IC = NFC_PN532_FW_VERSION_IC,
  PN53X_FW_VERSION_VER = NFC_PN532_FW_VERSION_VER,
  PN53X_FW_VERSION_REV = NFC_PN532_FW_VERSION_REV,
  PN53X_FW_VERSION_SUPPORT = NFC_PN532_FW_VERSION_SUPPORT,
  PN53X_TRANSCEIVE_HEADER_LEN = 3u,
  PN53X_LIST_PASSIVE_MIN_CMD_LEN = 4u,
  PN53X_COMMUNICATE_THRU_MIN_CMD_LEN = 3u,
  PN53X_DISPATCH_PAYLOAD_MIN_LEN = 2u,
  PN53X_LIST_PASSIVE_EMPTY_TAIL = 3u,
  PN53X_LIST_PASSIVE_BASE_NEEDED = 8u,
  PN53X_IN_DATA_EXCHANGE_PAYLOAD_SKIP = 3u,
  PN53X_COMMUNICATE_THRU_PAYLOAD_SKIP = 2u,
  PN53X_STATUS_REPLY_LEN = 5u,
  PN53X_FW_VERSION_REPLY_LEN = 8u,
  PN53X_TRANSCEIVE_OVERHEAD = 5u,
  PN53X_ISO_RSP_DATA_OFFSET = 3u,
  PN53X_RSP_FW_VER_IC_OFFSET = 2u,
  PN53X_RSP_FW_VER_VER_OFFSET = 3u,
  PN53X_RSP_FW_VER_REV_OFFSET = 4u,
  PN53X_RSP_FW_VER_SUPPORT_OFFSET = 5u,
  PN53X_RSP_SW1_OFFSET = 3u,
  PN53X_RSP_SW2_OFFSET = 4u,
  PN53X_RSP_STATUS_OFFSET = 2u,
  PN53X_CMD_TG_OFFSET = 2u,
  PN53X_CMD_BR_TY_OFFSET = 3u,
  PN53X_RSP_FW_VER_SW1_OFFSET = 6u,
  PN53X_RSP_FW_VER_SW2_OFFSET = 7u,
  PN53X_CMD_OPCODE_OFFSET = 1u,

};

static uint16_t build_pn53x_fw_version(uint8_t* rsp, uint16_t rsp_cap) {
  if ((rsp == NERO_NFC_NULL) || (rsp_cap < PN53X_FW_VERSION_REPLY_LEN) ||
      !nero_nfc_span_ok(0u, PN53X_FW_VERSION_REPLY_LEN, rsp_cap)) {
    return 0u;
  }
  if (!nero_nfc_store_u8(rsp, (size_t)(rsp_cap), (size_t)(0),
                         (uint8_t)(PN53X_DEV_PREFIX))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(rsp, (size_t)(rsp_cap), (size_t)(1),
                         (uint8_t)(PN53X_GET_FIRMWARE_VERSION_RSP_SUB))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(rsp, (size_t)(rsp_cap),
                         (size_t)(PN53X_RSP_FW_VER_IC_OFFSET),
                         (uint8_t)(PN53X_FW_VERSION_IC))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(rsp, (size_t)(rsp_cap),
                         (size_t)(PN53X_RSP_FW_VER_VER_OFFSET),
                         (uint8_t)(PN53X_FW_VERSION_VER))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(rsp, (size_t)(rsp_cap),
                         (size_t)(PN53X_RSP_FW_VER_REV_OFFSET),
                         (uint8_t)(PN53X_FW_VERSION_REV))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(rsp, (size_t)(rsp_cap),
                         (size_t)(PN53X_RSP_FW_VER_SUPPORT_OFFSET),
                         (uint8_t)(PN53X_FW_VERSION_SUPPORT))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(rsp, (size_t)(rsp_cap),
                         (size_t)(PN53X_RSP_FW_VER_SW1_OFFSET),
                         (uint8_t)(NFC_ISO7816_SW1_SUCCESS))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(rsp, (size_t)(rsp_cap),
                         (size_t)(PN53X_RSP_FW_VER_SW2_OFFSET),
                         (uint8_t)(NFC_ISO7816_SW2_SUCCESS))) {
    return 0u;
  }
  return PN53X_FW_VERSION_REPLY_LEN;
}

static uint16_t build_pn53x_status_reply(uint8_t response_code, uint8_t status,
                                         uint8_t* rsp, uint16_t rsp_cap) {
  if ((rsp == NERO_NFC_NULL) || (rsp_cap < PN53X_STATUS_REPLY_LEN) ||
      !nero_nfc_span_ok(0u, PN53X_STATUS_REPLY_LEN, rsp_cap)) {
    return 0u;
  }
  if (!nero_nfc_store_u8(rsp, (size_t)(rsp_cap), (size_t)(0),
                         (uint8_t)(PN53X_DEV_PREFIX))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(rsp, (size_t)(rsp_cap), (size_t)(1), response_code)) {
    return 0u;
  }
  if (!nero_nfc_store_u8(rsp, (size_t)(rsp_cap),
                         (size_t)(PN53X_RSP_STATUS_OFFSET), status)) {
    return 0u;
  }
  if (!nero_nfc_store_u8(rsp, (size_t)(rsp_cap), (size_t)(PN53X_RSP_SW1_OFFSET),
                         (uint8_t)(NFC_ISO7816_SW1_SUCCESS))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(rsp, (size_t)(rsp_cap), (size_t)(PN53X_RSP_SW2_OFFSET),
                         (uint8_t)(NFC_ISO7816_SW2_SUCCESS))) {
    return 0u;
  }
  return PN53X_STATUS_REPLY_LEN;
}

static uint16_t pn53x_overflow_reply(uint8_t response_code, uint8_t* rsp,
                                     uint16_t rsp_cap) {
  return build_pn53x_status_reply(response_code, PN53X_STATUS_TIMEOUT, rsp,
                                  rsp_cap);
}

static bool pn53x_write_iso7816_sw(uint8_t* out, uint16_t out_cap,
                                   uint16_t off) {
  static const uint8_t ISO7816_SW_OK[] = {
      (uint8_t)(NFC_ISO7816_SW1_SUCCESS),
      (uint8_t)(NFC_ISO7816_SW2_SUCCESS),
  };
  return nero_nfc_copy_bytes(out, out_cap, off, ISO7816_SW_OK,
                             sizeof(ISO7816_SW_OK));
}

static bool pn53x_write_sw_after_data(uint8_t* rsp, uint16_t rsp_cap,
                                      uint16_t data_len) {
  const uint16_t sw0 = (uint16_t)(PN53X_TRANSCEIVE_HEADER_LEN + data_len);
  return pn53x_write_iso7816_sw(rsp, rsp_cap, sw0);
}

static bool apdu_selects_ndef_app(const uint8_t* apdu, uint16_t apdu_len) {
  uint8_t lc = 0u;
  const uint8_t* aid = NERO_NFC_NULL;

  if ((apdu == NERO_NFC_NULL) ||
      (apdu_len < (uint16_t)(NFC_ISO7816_SHORT_APDU_HDR_LEN)) ||
      (nero_nfc_u8_at(apdu, (size_t)(apdu_len), (size_t)(0)) !=
       (uint8_t)(NFC_ISO7816_CLA_ISO)) ||
      (nero_nfc_u8_at(apdu, (size_t)(apdu_len), (size_t)(1)) !=
       (uint8_t)(NFC_ISO7816_INS_SELECT)) ||
      (nero_nfc_u8_at(apdu, (size_t)(apdu_len),
                      (size_t)(NFC_ISO7816_APDU_IDX_P1)) !=
       (uint8_t)(NFC_ISO7816_P1_SELECT_BY_DF_NAME))) {
    return false;
  }
  if (!nfc_iso7816_apdu_lc(apdu, apdu_len, &lc) || lc == 0u ||
      (!nfc_iso7816_apdu_lc_body_ok(apdu_len, lc) &&
       !nfc_iso7816_apdu_lc_body_with_le_ok(apdu_len, lc))) {
    return false;
  }
  aid = nfc_iso7816_apdu_data_ptr(apdu, apdu_len, lc);
  return nfc_pcsc_is_ndef_aid(aid, lc);
}

static uint16_t handle_pn53x_list_passive(const uint8_t* cmd, uint16_t cmd_len,
                                          uint8_t* rsp, uint16_t rsp_cap) {
  reader_tag_typea_info_t typea;
  uint16_t pos = 0u;
  size_t needed = 0u;

  if ((cmd == NERO_NFC_NULL) || (cmd_len < PN53X_LIST_PASSIVE_MIN_CMD_LEN) ||
      (rsp == NERO_NFC_NULL) || (rsp_cap < PN53X_STATUS_REPLY_LEN)) {
    return 0u;
  }
  if (!nero_nfc_store_u8(rsp, (size_t)(rsp_cap), (size_t)(pos++),
                         (uint8_t)(PN53X_DEV_PREFIX))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(rsp, (size_t)(rsp_cap), (size_t)(pos++),
                         (uint8_t)(PN53X_RSP_IN_LIST_PASSIVE_TARGET))) {
    return 0u;
  }
  if (!G_CARD_PRESENT ||
      (nero_nfc_u8_at(cmd, (size_t)(cmd_len), (size_t)(PN53X_CMD_TG_OFFSET)) !=
       PN53X_SINGLE_TARGET) ||
      (nero_nfc_u8_at(cmd, (size_t)(cmd_len),
                      (size_t)(PN53X_CMD_BR_TY_OFFSET)) !=
       PN53X_BR_TY106KBPS_TYPE_A) ||
      !reader_tags_get_typea_info(&typea) || !typea.atqa_valid) {
    if (!nero_nfc_store_u8(rsp, (size_t)(rsp_cap), (size_t)(pos++),
                           (uint8_t)(PN53X_STATUS_OK))) {
      return 0u;
    }
    if (!nero_nfc_store_u8(rsp, (size_t)(rsp_cap), (size_t)(pos++),
                           (uint8_t)(NFC_ISO7816_SW1_SUCCESS))) {
      return 0u;
    }
    if (!nero_nfc_store_u8(rsp, (size_t)(rsp_cap), (size_t)(pos++),
                           (uint8_t)(NFC_ISO7816_SW2_SUCCESS))) {
      return 0u;
    }
    return pos;
  }
  needed = PN53X_LIST_PASSIVE_BASE_NEEDED;
  if (!nero_nfc_try_add_size(needed, (size_t)(typea.uid_len), &needed) ||
      !nero_nfc_try_add_size(
          needed, (typea.ats_len != 0u) ? ((size_t)(typea.ats_len) + 1u) : 0u,
          &needed) ||
      !nero_nfc_try_add_size(needed, (size_t)(NFC_ISO7816_SW_LEN), &needed) ||
      (needed > (size_t)(rsp_cap))) {
    return pn53x_overflow_reply(PN53X_RSP_IN_LIST_PASSIVE_TARGET, rsp, rsp_cap);
  }
  rsp[pos++] = PN53X_SINGLE_TARGET; /* NbTg — one target found */
  rsp[pos++] = PN53X_SINGLE_TARGET; /* Tg — target number 1 */
  rsp[pos++] = typea.atqa[0];
  rsp[pos++] = typea.atqa[1];
  rsp[pos++] = typea.sak;
  rsp[pos++] = typea.uid_len;
  if (!nero_nfc_copy_bytes(rsp, rsp_cap, pos, typea.uid, typea.uid_len)) {
    return pn53x_overflow_reply(PN53X_RSP_IN_LIST_PASSIVE_TARGET, rsp, rsp_cap);
  }
  pos = (uint16_t)(pos + typea.uid_len);
  if (typea.ats_len != 0u) {
    rsp[pos++] = typea.ats_len;
    if (!nero_nfc_copy_bytes(rsp, rsp_cap, pos, typea.ats, typea.ats_len)) {
      return pn53x_overflow_reply(PN53X_RSP_IN_LIST_PASSIVE_TARGET, rsp,
                                  rsp_cap);
    }
    pos = (uint16_t)(pos + typea.ats_len);
  }
  if (!nero_nfc_try_add_size((size_t)(pos), (size_t)(NFC_ISO7816_SW_LEN),
                             &needed) ||
      (needed > (size_t)(rsp_cap))) {
    return pn53x_overflow_reply(PN53X_RSP_IN_LIST_PASSIVE_TARGET, rsp, rsp_cap);
  }
  rsp[pos++] = (uint8_t)(NFC_ISO7816_SW1_SUCCESS);
  rsp[pos++] = (uint8_t)(NFC_ISO7816_SW2_SUCCESS);
  return pos;
}

static uint16_t handle_pn53x_type2_transceive(uint8_t response_code,
                                              const uint8_t* tx,
                                              uint16_t tx_len, uint8_t* rsp,
                                              uint16_t rsp_cap) {
  int rlen;
  size_t rsp_need = 0u;

  if ((tx == NERO_NFC_NULL) || (tx_len == 0u) || (rsp == NERO_NFC_NULL) ||
      (rsp_cap < PN53X_STATUS_REPLY_LEN)) {
    return 0u;
  }
  if (!reader_ccid_type2_raw_transceive_allowed(tx, tx_len)) {
    return build_pn53x_status_reply(response_code, PN53X_STATUS_TIMEOUT, rsp,
                                    rsp_cap);
  }
  rlen = reader_tags_type2_transceive(
      tx, tx_len, rsp + PN53X_TRANSCEIVE_HEADER_LEN,
      (uint16_t)(rsp_cap - PN53X_TRANSCEIVE_OVERHEAD));
  if (!nero_nfc_store_u8(rsp, (size_t)(rsp_cap), (size_t)(0),
                         (uint8_t)(PN53X_DEV_PREFIX))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(rsp, (size_t)(rsp_cap), (size_t)(1), response_code)) {
    return 0u;
  }
  if (!nero_nfc_store_u8(
          rsp, (size_t)(rsp_cap), (size_t)(PN53X_RSP_STATUS_OFFSET),
          (uint8_t)((rlen >= 0) ? PN53X_STATUS_OK : PN53X_STATUS_TIMEOUT))) {
    return 0u;
  }
  if (rlen < 0) {
    if (!pn53x_write_iso7816_sw(rsp, rsp_cap, PN53X_ISO_RSP_DATA_OFFSET)) {
      return 0u;
    }
    return PN53X_STATUS_REPLY_LEN;
  }
  if (!nero_nfc_try_add_size((size_t)(rlen), PN53X_TRANSCEIVE_OVERHEAD,
                             &rsp_need) ||
      (rsp_need > (size_t)(rsp_cap))) {
    return pn53x_overflow_reply(response_code, rsp, rsp_cap);
  }
  if (!pn53x_write_sw_after_data(rsp, rsp_cap, (uint16_t)(rlen))) {
    return pn53x_overflow_reply(response_code, rsp, rsp_cap);
  }
  const uint32_t rsp_len = (uint32_t)(rlen) + PN53X_TRANSCEIVE_OVERHEAD;
  return (uint16_t)(rsp_len);
}

static uint16_t handle_pn53x_type5_transceive(uint8_t response_code,
                                              const uint8_t* tx,
                                              uint16_t tx_len, uint8_t* rsp,
                                              uint16_t rsp_cap) {
  int rlen;
  size_t rsp_need = 0u;

  if ((tx == NERO_NFC_NULL) || (tx_len == 0u) || (rsp == NERO_NFC_NULL) ||
      (rsp_cap < PN53X_STATUS_REPLY_LEN)) {
    return 0u;
  }
  if (!reader_ccid_type5_raw_transceive_allowed(tx, tx_len)) {
    return build_pn53x_status_reply(response_code, PN53X_STATUS_TIMEOUT, rsp,
                                    rsp_cap);
  }
  rlen = reader_tags_type5_transceive(
      tx, tx_len, rsp + PN53X_TRANSCEIVE_HEADER_LEN,
      (uint16_t)(rsp_cap - PN53X_TRANSCEIVE_OVERHEAD));
  if (!nero_nfc_store_u8(rsp, (size_t)(rsp_cap), (size_t)(0),
                         (uint8_t)(PN53X_DEV_PREFIX))) {
    return 0u;
  }
  if (!nero_nfc_store_u8(rsp, (size_t)(rsp_cap), (size_t)(1), response_code)) {
    return 0u;
  }
  if (!nero_nfc_store_u8(
          rsp, (size_t)(rsp_cap), (size_t)(PN53X_RSP_STATUS_OFFSET),
          (uint8_t)((rlen >= 0) ? PN53X_STATUS_OK : PN53X_STATUS_TIMEOUT))) {
    return 0u;
  }
  if (rlen < 0) {
    if (!pn53x_write_iso7816_sw(rsp, rsp_cap, PN53X_ISO_RSP_DATA_OFFSET)) {
      return 0u;
    }
    return PN53X_STATUS_REPLY_LEN;
  }
  if (!nero_nfc_try_add_size((size_t)(rlen), PN53X_TRANSCEIVE_OVERHEAD,
                             &rsp_need) ||
      (rsp_need > (size_t)(rsp_cap))) {
    return pn53x_overflow_reply(response_code, rsp, rsp_cap);
  }
  if (!pn53x_write_sw_after_data(rsp, rsp_cap, (uint16_t)(rlen))) {
    return pn53x_overflow_reply(response_code, rsp, rsp_cap);
  }
  const uint32_t rsp_len = (uint32_t)(rlen) + PN53X_TRANSCEIVE_OVERHEAD;
  return (uint16_t)(rsp_len);
}

static uint16_t handle_pn53x_in_data_exchange(const uint8_t* cmd,
                                              uint16_t cmd_len, uint8_t* rsp,
                                              uint16_t rsp_cap) {
  if ((cmd == NERO_NFC_NULL) || (cmd_len < PN53X_LIST_PASSIVE_MIN_CMD_LEN) ||
      (rsp == NERO_NFC_NULL) || (rsp_cap < PN53X_STATUS_REPLY_LEN)) {
    return 0u;
  }
  if (nero_nfc_u8_at(cmd, (size_t)(cmd_len), (size_t)(PN53X_CMD_TG_OFFSET)) !=
      PN53X_SINGLE_TARGET) { /* InDataExchange Tg — target number 1 */
    return build_pn53x_status_reply(PN53X_RSP_IN_DATA_EXCHANGE,
                                    PN53X_STATUS_TIMEOUT, rsp, rsp_cap);
  }
  if (G_TAG_KIND == READER_TAG_KIND_TYPE2) {
    return handle_pn53x_type2_transceive(
        PN53X_RSP_IN_DATA_EXCHANGE, cmd + PN53X_IN_DATA_EXCHANGE_PAYLOAD_SKIP,
        (uint16_t)(cmd_len - PN53X_IN_DATA_EXCHANGE_PAYLOAD_SKIP), rsp,
        rsp_cap);
  }
  if (G_TAG_KIND == READER_TAG_KIND_TYPE4) {
    const uint8_t* inner_apdu = cmd + PN53X_IN_DATA_EXCHANGE_PAYLOAD_SKIP;
    const uint16_t inner_len =
        (uint16_t)(cmd_len - PN53X_IN_DATA_EXCHANGE_PAYLOAD_SKIP);
    if (G_TYPE4_SECURITY_KEY_APP &&
        apdu_selects_ndef_app(inner_apdu, inner_len)) {
      return build_pn53x_status_reply(PN53X_RSP_IN_DATA_EXCHANGE,
                                      PN53X_STATUS_TIMEOUT, rsp, rsp_cap);
    }
    if (nfc_ctap_apdu_is_select_fido_aid(inner_apdu, inner_len,
                                         NERO_NFC_NULL) ||
        nfc_ctap_apdu_command(inner_apdu, inner_len, NERO_NFC_NULL) ||
        nfc_ctap_apdu_is_getresponse(inner_apdu, inner_len) ||
        nfc_ctap_apdu_is_control_end(inner_apdu, inner_len)) {
      return build_pn53x_status_reply(PN53X_RSP_IN_DATA_EXCHANGE,
                                      PN53X_STATUS_TIMEOUT, rsp, rsp_cap);
    }
    uint16_t iso_len = reader_security_key_apdu_exchange(
        cmd + PN53X_IN_DATA_EXCHANGE_PAYLOAD_SKIP,
        (uint16_t)(cmd_len - PN53X_IN_DATA_EXCHANGE_PAYLOAD_SKIP),
        rsp + PN53X_IN_DATA_EXCHANGE_PAYLOAD_SKIP,
        (uint16_t)(rsp_cap - PN53X_TRANSCEIVE_OVERHEAD));
    rsp[0] = PN53X_DEV_PREFIX;
    rsp[1] = PN53X_RSP_IN_DATA_EXCHANGE;
    rsp[PN53X_RSP_STATUS_OFFSET] = (iso_len >= (uint16_t)(NFC_ISO7816_SW_LEN))
                                       ? PN53X_STATUS_OK
                                       : PN53X_STATUS_TIMEOUT;
    if (iso_len < (uint16_t)(NFC_ISO7816_SW_LEN)) {
      if (!pn53x_write_iso7816_sw(rsp, rsp_cap, PN53X_ISO_RSP_DATA_OFFSET)) {
        return 0u;
      }
      return PN53X_STATUS_REPLY_LEN;
    }
    if (!pn53x_write_sw_after_data(rsp, rsp_cap, iso_len)) {
      return pn53x_overflow_reply(PN53X_RSP_IN_DATA_EXCHANGE, rsp, rsp_cap);
    }
    return (uint16_t)(iso_len + PN53X_TRANSCEIVE_OVERHEAD);
  }
  return build_pn53x_status_reply(PN53X_RSP_IN_DATA_EXCHANGE,
                                  PN53X_STATUS_TIMEOUT, rsp, rsp_cap);
}

static uint16_t handle_pn53x_in_communicate_thru(const uint8_t* cmd,
                                                 uint16_t cmd_len, uint8_t* rsp,
                                                 uint16_t rsp_cap) {
  if ((cmd == NERO_NFC_NULL) ||
      (cmd_len < PN53X_COMMUNICATE_THRU_MIN_CMD_LEN) ||
      (rsp == NERO_NFC_NULL)) {
    return 0u;
  }
  if (G_TAG_KIND == READER_TAG_KIND_TYPE2) {
    return handle_pn53x_type2_transceive(
        PN53X_RSP_IN_COMMUNICATE_THRU,
        cmd + PN53X_COMMUNICATE_THRU_PAYLOAD_SKIP,
        (uint16_t)(cmd_len - PN53X_COMMUNICATE_THRU_PAYLOAD_SKIP), rsp,
        rsp_cap);
  }
  if (G_TAG_KIND == READER_TAG_KIND_TYPE5) {
    return handle_pn53x_type5_transceive(
        PN53X_RSP_IN_COMMUNICATE_THRU,
        cmd + PN53X_COMMUNICATE_THRU_PAYLOAD_SKIP,
        (uint16_t)(cmd_len - PN53X_COMMUNICATE_THRU_PAYLOAD_SKIP), rsp,
        rsp_cap);
  }
  return build_pn53x_status_reply(PN53X_RSP_IN_COMMUNICATE_THRU,
                                  PN53X_STATUS_TIMEOUT, rsp, rsp_cap);
}

/* namespace */

uint16_t reader_ccid_handle_acr122_direct_apdu(const uint8_t* apdu,
                                               uint16_t apdu_len, uint8_t* rsp,
                                               uint16_t rsp_cap) {
  const uint8_t* cmd;
  uint8_t lc;

  if ((apdu == NERO_NFC_NULL) || (rsp == NERO_NFC_NULL) ||
      !nfc_iso7816_apdu_min_len(apdu_len, NFC_ISO7816_SHORT_APDU_HDR_LEN)) {
    return 0u;
  }
  if ((apdu_len == NFC_ISO7816_SHORT_APDU_HDR_LEN) &&
      (nero_nfc_u8_at(apdu, (size_t)(apdu_len), (size_t)(0)) ==
       (uint8_t)(NFC_ISO7816_CLA_PROPRIETARY)) &&
      (nero_nfc_u8_at(apdu, (size_t)(apdu_len), (size_t)(1)) ==
       (uint8_t)(NFC_ISO7816_CLA_ISO)) &&
      (nero_nfc_u8_at(apdu, (size_t)(apdu_len),
                      (size_t)(NFC_ISO7816_APDU_IDX_P1)) ==
       ACR122_P1_GET_FIRMWARE) &&
      (nero_nfc_u8_at(apdu, (size_t)(apdu_len),
                      (size_t)(NFC_ISO7816_APDU_IDX_P2)) ==
       (uint8_t)(NFC_ISO7816_P2_SELECT_FIRST)) &&
      (nero_nfc_u8_at(apdu, (size_t)(apdu_len),
                      (size_t)(NFC_ISO7816_APDU_IDX_LC)) ==
       (uint8_t)(NFC_ISO7816_SW2_SUCCESS))) {
    /* [ACR122U API] "Get Firmware Version" pseudo-APDU (FF 00 48 00 00) returns
     * the ASCII firmware revision string with no trailing ISO7816 status word;
     * the PC/SC host driver consumes the bare string. */
    static const uint8_t FW[] = {'A', 'C', 'R', '1', '2',
                                 '2', 'U', '2', '0', '3'};
    if (rsp_cap < (uint16_t)(sizeof(FW))) {
      return reader_ccid_apdu_failure_response(rsp, rsp_cap);
    }
    if (!nero_nfc_copy_bytes(rsp, rsp_cap, 0u, FW, sizeof(FW))) {
      return reader_ccid_apdu_failure_response(rsp, rsp_cap);
    }
    return (uint16_t)(sizeof(FW));
  }
  if ((nero_nfc_u8_at(apdu, (size_t)(apdu_len), (size_t)(0)) !=
       (uint8_t)(NFC_ISO7816_CLA_PROPRIETARY)) ||
      (nero_nfc_u8_at(apdu, (size_t)(apdu_len), (size_t)(1)) !=
       (uint8_t)(NFC_ISO7816_CLA_ISO)) ||
      (nero_nfc_u8_at(apdu, (size_t)(apdu_len),
                      (size_t)(NFC_ISO7816_APDU_IDX_P1)) !=
       (uint8_t)(NFC_ISO7816_CLA_ISO)) ||
      (nero_nfc_u8_at(apdu, (size_t)(apdu_len),
                      (size_t)(NFC_ISO7816_APDU_IDX_P2)) !=
       (uint8_t)(NFC_ISO7816_CLA_ISO))) {
    return reader_ccid_append_status(
        rsp, 0u, rsp_cap, (uint8_t)(NFC_ISO7816_SW1_INS_NOT_SUPPORTED),
        (uint8_t)(NFC_ISO7816_SW2_SUCCESS));
  }
  if (!nfc_iso7816_apdu_lc(apdu, apdu_len, &lc) ||
      !nfc_iso7816_apdu_lc_body_ok(apdu_len, lc) ||
      (lc < PN53X_DISPATCH_PAYLOAD_MIN_LEN)) {
    return reader_ccid_append_status(
        rsp, 0u, rsp_cap, (uint8_t)(NFC_ISO7816_SW1_WRONG_LENGTH_ALT),
        (uint8_t)(NFC_ISO7816_SW2_SUCCESS));
  }
  cmd = nfc_iso7816_apdu_data_ptr(apdu, apdu_len, lc);
  if (cmd == NERO_NFC_NULL) {
    return reader_ccid_append_status(
        rsp, 0u, rsp_cap, (uint8_t)(NFC_ISO7816_SW1_WRONG_LENGTH_ALT),
        (uint8_t)(NFC_ISO7816_SW2_SUCCESS));
  }
  if (cmd[0] != PN53X_HOST_PREFIX) {
    return reader_ccid_append_status(
        rsp, 0u, rsp_cap, (uint8_t)(NFC_ISO7816_SW1_INS_NOT_SUPPORTED),
        (uint8_t)(NFC_ISO7816_SW2_SUCCESS));
  }
  if (!nero_nfc_span_ok(PN53X_CMD_OPCODE_OFFSET, 1u, lc)) {
    return reader_ccid_append_status(
        rsp, 0u, rsp_cap, (uint8_t)(NFC_ISO7816_SW1_WRONG_LENGTH_ALT),
        (uint8_t)(NFC_ISO7816_SW2_SUCCESS));
  }
  switch (cmd[1]) {
    case PN53X_CMD_GET_FIRMWARE_VERSION:
      return build_pn53x_fw_version(rsp, rsp_cap);
    case PN53X_CMD_IN_LIST_PASSIVE_TARGET:
      return handle_pn53x_list_passive(cmd, lc, rsp, rsp_cap);
    case PN53X_CMD_IN_DATA_EXCHANGE:
      return handle_pn53x_in_data_exchange(cmd, lc, rsp, rsp_cap);
    case PN53X_CMD_IN_COMMUNICATE_THRU:
      return handle_pn53x_in_communicate_thru(cmd, lc, rsp, rsp_cap);
    case PN53X_CMD_IN_DESELECT:
      return build_pn53x_status_reply(PN53X_RSP_IN_DESELECT, PN53X_STATUS_OK,
                                      rsp, rsp_cap);
    case PN53X_CMD_IN_RELEASE:
      return build_pn53x_status_reply(PN53X_RSP_IN_RELEASE, PN53X_STATUS_OK,
                                      rsp, rsp_cap);
    default:
      return build_pn53x_status_reply((uint8_t)(cmd[1] + 1u),
                                      PN53X_STATUS_CONTEXT_ERROR, rsp, rsp_cap);
  }
}

uint16_t reader_ccid_dispatch_host_payload(const uint8_t* payload,
                                           uint16_t payload_len, uint8_t* rsp,
                                           uint16_t rsp_cap) {
  uint16_t rlen;

  if ((payload == NERO_NFC_NULL) ||
      (payload_len < PN53X_DISPATCH_PAYLOAD_MIN_LEN) ||
      (rsp == NERO_NFC_NULL) || (rsp_cap < (uint16_t)(NFC_ISO7816_SW_LEN))) {
    if ((rsp != NERO_NFC_NULL) && (rsp_cap >= (uint16_t)(NFC_ISO7816_SW_LEN))) {
      return reader_ccid_apdu_failure_response(rsp, rsp_cap);
    }
    return 0u;
  }
  if (nero_nfc_u8_at(payload, (size_t)(payload_len), (size_t)(0)) ==
      (uint8_t)(NFC_ISO7816_CLA_PROPRIETARY)) {
    switch (nero_nfc_u8_at(payload, (size_t)(payload_len), (size_t)(1))) {
      case (uint8_t)(NFC_ISO7816_CLA_ISO):
        rlen = reader_ccid_handle_acr122_direct_apdu(payload, payload_len, rsp,
                                                     rsp_cap);
        break;
      case (uint8_t)(NFC_ISO7816_INS_GET_DATA):
        rlen = reader_ccid_handle_get_data_apdu(payload, payload_len, rsp,
                                                rsp_cap);
        break;
      case (uint8_t)(NFC_ISO7816_INS_READ_BINARY):
        rlen = reader_ccid_handle_read_binary_apdu(payload, payload_len, rsp,
                                                   rsp_cap);
        break;
      case (uint8_t)(NFC_ISO7816_INS_UPDATE_BINARY):
        rlen = reader_ccid_handle_update_binary_apdu(payload, payload_len, rsp,
                                                     rsp_cap);
        break;
      case (uint8_t)(NFC_PCSC_ESCAPE_TRANSPARENT_INS):
        rlen = reader_ccid_handle_escape_transparent_apdu(payload, payload_len,
                                                          rsp, rsp_cap);
        break;
      default:
        rlen = reader_ccid_append_status(
            rsp, 0u, rsp_cap, (uint8_t)(NFC_ISO7816_SW1_INS_NOT_SUPPORTED),
            (uint8_t)(NFC_ISO7816_SW2_SUCCESS));
        break;
    }
  } else if (((G_TAG_KIND == READER_TAG_KIND_TYPE2) ||
              (G_TAG_KIND == READER_TAG_KIND_TYPE5))) {
    if (nero_nfc_u8_at(payload, (size_t)(payload_len), (size_t)(0)) !=
        (uint8_t)(NFC_ISO7816_CLA_ISO)) {
      return reader_ccid_append_status(
          rsp, 0u, rsp_cap, (uint8_t)(NFC_ISO7816_SW1_CLASS_NOT_SUPPORTED),
          (uint8_t)(NFC_ISO7816_SW2_SUCCESS));
    }
    rlen = reader_ccid_append_status(
        rsp, 0u, rsp_cap, (uint8_t)(NFC_ISO7816_SW1_INS_NOT_SUPPORTED),
        (uint8_t)(NFC_ISO7816_SW2_SUCCESS));
  } else if (G_TAG_KIND == READER_TAG_KIND_TYPE4) {
    if (G_TYPE4_SECURITY_KEY_APP &&
        apdu_selects_ndef_app(payload, payload_len)) {
      rlen = reader_ccid_append_status(
          rsp, 0u, rsp_cap, (uint8_t)(NFC_ISO7816_SW1_CONDITIONS_NOT_SATISFIED),
          (uint8_t)(NFC_ISO7816_SW2_COMMAND_NOT_ALLOWED));
    } else {
      const bool selects_fido = reader_security_key_apdu_is_select_fido_aid(
          payload, payload_len, NERO_NFC_NULL);
      uint16_t iso_len =
          reader_security_key_apdu_exchange(payload, payload_len, rsp, rsp_cap);
      if (selects_fido && nfc_iso7816_response_sw_ok(rsp, iso_len)) {
        G_TYPE4_SECURITY_KEY_APP = true;
      }
      rlen = (iso_len >= (uint16_t)(NFC_ISO7816_SW_LEN))
                 ? iso_len
                 : reader_ccid_append_status(
                       rsp, 0u, rsp_cap,
                       (uint8_t)(NFC_ISO7816_SW1_CONDITIONS_NOT_SATISFIED),
                       (uint8_t)(NFC_ISO7816_SW2_COMMAND_NOT_ALLOWED));
    }
  } else {
    rlen = reader_ccid_append_status(
        rsp, 0u, rsp_cap, (uint8_t)(NFC_ISO7816_SW1_INS_NOT_SUPPORTED),
        (uint8_t)(NFC_ISO7816_SW2_SUCCESS));
  }
  if (rlen != 0u) {
    reader_ccid_note_host_session_activity();
  }
  return rlen;
}

#endif /* NERO_CCID_USB_BUILD */
