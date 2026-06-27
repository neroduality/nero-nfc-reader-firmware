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
 * reader_ccid_pn53x.cpp — PN53x / ACR122 contactless emulation handlers.
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

#if defined(NERO_HOST_UNIT_TEST_HOOKS)
#include "reader_ccid_utest.h"
#include "reader_hal_utest.h"
#endif

#include <algorithm>
#include <cstdint>
#include <cstring>

namespace {

enum {
  kPn53xHostPrefix = NFC_PN532_HOST_TO_PN532,
  kPn53xDevPrefix = NFC_PN532_PN532_TO_HOST,
  kPn53xCmdGetFirmwareVersion = NFC_PN532_CMD_GET_FIRMWARE_VERSION,
  kPn53xCmdInListPassiveTarget = NFC_PN532_CMD_IN_LIST_PASSIVE_TARGET,
  kPn53xRspInListPassiveTarget = NFC_PN532_RSP_IN_LIST_PASSIVE_TARGET,
  kPn53xCmdInDataExchange = NFC_PN532_CMD_IN_DATA_EXCHANGE,
  kPn53xRspInDataExchange = NFC_PN532_RSP_IN_DATA_EXCHANGE,
  kPn53xCmdInCommunicateThru = NFC_PN532_CMD_IN_COMMUNICATE_THRU,
  kPn53xRspInCommunicateThru = NFC_PN532_RSP_IN_COMMUNICATE_THRU,
  kPn53xCmdInDeselect = NFC_PN532_CMD_IN_DESELECT,
  kPn53xRspInDeselect = NFC_PN532_RSP_IN_DESELECT,
  kPn53xCmdReadRegister = NFC_PN532_CMD_READ_REGISTER,
  kPn53xRspReadRegister = NFC_PN532_RSP_READ_REGISTER,
  kPn53xStatusOk = NFC_PN532_STATUS_OK,
  kPn53xStatusError = NFC_PN532_STATUS_ERROR,
  kPn53xStatusTimeout = NFC_PN532_STATUS_TIMEOUT,
  kPn53xBrTy106kbpsTypeA = NFC_PN532_BRTY_106KBPS_TYPE_A,
  kPn53xSingleTarget = NFC_PN532_SINGLE_TARGET,
  kAcr122InsGetFirmware = NFC_ACR122U_INS_GET_FIRMWARE_VERSION,
  kPn53xGetFirmwareVersionRspSub = NFC_PN532_GET_FIRMWARE_VERSION_RSP_SUB,
  kPn53xFwVersionIc = NFC_PN532_FW_VERSION_IC,
  kPn53xFwVersionVer = NFC_PN532_FW_VERSION_VER,
  kPn53xFwVersionRev = NFC_PN532_FW_VERSION_REV,
  kPn53xFwVersionSupport = NFC_PN532_FW_VERSION_SUPPORT,
  kPn53xTransceiveHeaderLen = 3u,
  kPn53xListPassiveMinCmdLen = 4u,
  kPn53xCommunicateThruMinCmdLen = 3u,
  kPn53xDispatchPayloadMinLen = 2u,
  kPn53xListPassiveEmptyTail = 3u,
  kPn53xListPassiveBaseNeeded = 8u,
  kPn53xInDataExchangePayloadSkip = 3u,
  kPn53xCommunicateThruPayloadSkip = 2u,
  kPn53xStatusReplyLen = 5u,
  kPn53xFwVersionReplyLen = 8u,
  kPn53xTransceiveOverhead = 5u,
  kPn53xIsoRspDataOffset = 3u,
  kPn53xRspFwVerIcOffset = 2u,
  kPn53xRspFwVerVerOffset = 3u,
  kPn53xRspFwVerRevOffset = 4u,
  kPn53xRspFwVerSupportOffset = 5u,
  kPn53xRspSw1Offset = 3u,
  kPn53xRspSw2Offset = 4u,
  kPn53xRspStatusOffset = 2u,
  kPn53xCmdTgOffset = 2u,
  kPn53xCmdBrTyOffset = 3u,
  kPn53xRspFwVerSw1Offset = 6u,
  kPn53xRspFwVerSw2Offset = 7u,
  kPn53xCmdOpcodeOffset = 1u,

};

static uint16_t build_pn53x_fw_version(uint8_t *rsp, uint16_t rsp_cap) {
  if ((rsp == NERO_NFC_NULL) || (rsp_cap < kPn53xFwVersionReplyLen) ||
      !nero_nfc_span_ok(0u, kPn53xFwVersionReplyLen, rsp_cap)) {
    return 0u;
  }
  rsp[0] = kPn53xDevPrefix;
  rsp[1] = kPn53xGetFirmwareVersionRspSub;
  rsp[kPn53xRspFwVerIcOffset] = kPn53xFwVersionIc;
  rsp[kPn53xRspFwVerVerOffset] = kPn53xFwVersionVer;
  rsp[kPn53xRspFwVerRevOffset] = kPn53xFwVersionRev;
  rsp[kPn53xRspFwVerSupportOffset] = kPn53xFwVersionSupport;
  rsp[kPn53xRspFwVerSw1Offset] = (uint8_t)NFC_ISO7816_SW1_SUCCESS;
  rsp[kPn53xRspFwVerSw2Offset] = (uint8_t)NFC_ISO7816_SW2_SUCCESS;
  return kPn53xFwVersionReplyLen;
}

static uint16_t build_pn53x_status_reply(uint8_t response_code, uint8_t status, uint8_t *rsp,
                                         uint16_t rsp_cap) {
  if ((rsp == NERO_NFC_NULL) || (rsp_cap < kPn53xStatusReplyLen) ||
      !nero_nfc_span_ok(0u, kPn53xStatusReplyLen, rsp_cap)) {
    return 0u;
  }
  rsp[0] = kPn53xDevPrefix;
  rsp[1] = response_code;
  rsp[kPn53xRspStatusOffset] = status;
  rsp[kPn53xRspSw1Offset] = (uint8_t)NFC_ISO7816_SW1_SUCCESS;
  rsp[kPn53xRspSw2Offset] = (uint8_t)NFC_ISO7816_SW2_SUCCESS;
  return kPn53xStatusReplyLen;
}

static uint16_t pn53x_overflow_reply(uint8_t response_code, uint8_t *rsp, uint16_t rsp_cap) {
  return build_pn53x_status_reply(response_code, kPn53xStatusError, rsp, rsp_cap);
}

static bool pn53x_write_iso7816_sw(uint8_t *out, uint16_t out_cap, uint16_t off) {
  static const uint8_t kIso7816SwOk[] = {
    (uint8_t)NFC_ISO7816_SW1_SUCCESS,
    (uint8_t)NFC_ISO7816_SW2_SUCCESS,
  };
  return nero_nfc_copy_bytes(out, out_cap, off, kIso7816SwOk, sizeof(kIso7816SwOk));
}

static bool pn53x_write_sw_after_data(uint8_t *rsp, uint16_t rsp_cap, uint16_t data_len) {
  const uint16_t sw0 = (uint16_t)(kPn53xTransceiveHeaderLen + data_len);
  return pn53x_write_iso7816_sw(rsp, rsp_cap, sw0);
}

static bool apdu_selects_ndef_app(const uint8_t *apdu, uint16_t apdu_len) {
  uint8_t lc = 0u;
  const uint8_t *aid = NERO_NFC_NULL;

  if ((apdu == NERO_NFC_NULL) || (apdu_len < (uint16_t)NFC_ISO7816_SHORT_APDU_HDR_LEN) ||
      (apdu[0] != (uint8_t)NFC_ISO7816_CLA_ISO) || (apdu[1] != (uint8_t)NFC_ISO7816_INS_SELECT) ||
      (apdu[NFC_ISO7816_APDU_IDX_P1] != (uint8_t)NFC_ISO7816_P1_SELECT_BY_DF_NAME)) {
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

static uint16_t handle_pn53x_list_passive(const uint8_t *cmd, uint16_t cmd_len, uint8_t *rsp,
                                          uint16_t rsp_cap) {
  reader_tag_typea_info_t typea;
  uint16_t pos = 0u;
  size_t needed = 0u;

  if ((cmd == NERO_NFC_NULL) || (cmd_len < kPn53xListPassiveMinCmdLen) || (rsp == NERO_NFC_NULL) ||
      (rsp_cap < kPn53xStatusReplyLen)) {
    return 0u;
  }
  rsp[pos++] = kPn53xDevPrefix;
  rsp[pos++] = kPn53xRspInListPassiveTarget;
  if (!g_card_present || (cmd[kPn53xCmdTgOffset] != kPn53xSingleTarget) ||
      (cmd[kPn53xCmdBrTyOffset] != kPn53xBrTy106kbpsTypeA) || !reader_tags_get_typea_info(&typea) ||
      !typea.atqa_valid) {
    if (!nero_nfc_span_ok((size_t)pos, kPn53xListPassiveEmptyTail, rsp_cap)) {
      return pn53x_overflow_reply(kPn53xRspInListPassiveTarget, rsp, rsp_cap);
    }
    rsp[pos++] = kPn53xStatusOk;
    rsp[pos++] = (uint8_t)NFC_ISO7816_SW1_SUCCESS;
    rsp[pos++] = (uint8_t)NFC_ISO7816_SW2_SUCCESS;
    return pos;
  }
  needed = kPn53xListPassiveBaseNeeded;
  if (!nero_nfc_try_add_size(needed, (size_t)typea.uid_len, &needed) ||
      !nero_nfc_try_add_size(needed, (typea.ats_len != 0u) ? ((size_t)typea.ats_len + 1u) : 0u,
                             &needed) ||
      !nero_nfc_try_add_size(needed, (size_t)NFC_ISO7816_SW_LEN, &needed) ||
      (needed > (size_t)rsp_cap)) {
    return pn53x_overflow_reply(kPn53xRspInListPassiveTarget, rsp, rsp_cap);
  }
  rsp[pos++] = kPn53xSingleTarget; /* NbTg — one target found */
  rsp[pos++] = kPn53xSingleTarget; /* Tg — target number 1 */
  rsp[pos++] = typea.atqa[0];
  rsp[pos++] = typea.atqa[1];
  rsp[pos++] = typea.sak;
  rsp[pos++] = typea.uid_len;
  if (!nero_nfc_copy_bytes(rsp, rsp_cap, pos, typea.uid, typea.uid_len)) {
    return pn53x_overflow_reply(kPn53xRspInListPassiveTarget, rsp, rsp_cap);
  }
  pos = (uint16_t)(pos + typea.uid_len);
  if (typea.ats_len != 0u) {
    rsp[pos++] = typea.ats_len;
    if (!nero_nfc_copy_bytes(rsp, rsp_cap, pos, typea.ats, typea.ats_len)) {
      return pn53x_overflow_reply(kPn53xRspInListPassiveTarget, rsp, rsp_cap);
    }
    pos = (uint16_t)(pos + typea.ats_len);
  }
  if (!nero_nfc_try_add_size((size_t)pos, (size_t)NFC_ISO7816_SW_LEN, &needed) ||
      (needed > (size_t)rsp_cap)) {
    return pn53x_overflow_reply(kPn53xRspInListPassiveTarget, rsp, rsp_cap);
  }
  rsp[pos++] = (uint8_t)NFC_ISO7816_SW1_SUCCESS;
  rsp[pos++] = (uint8_t)NFC_ISO7816_SW2_SUCCESS;
  return pos;
}

static uint16_t handle_pn53x_type2_transceive(uint8_t response_code, const uint8_t *tx,
                                              uint16_t tx_len, uint8_t *rsp, uint16_t rsp_cap) {
  int rlen;
  size_t rsp_need = 0u;

  if ((tx == NERO_NFC_NULL) || (tx_len == 0u) || (rsp == NERO_NFC_NULL) ||
      (rsp_cap < kPn53xStatusReplyLen)) {
    return 0u;
  }
  if (!reader_ccid_type2_raw_transceive_allowed(tx, tx_len)) {
    return build_pn53x_status_reply(response_code, kPn53xStatusError, rsp, rsp_cap);
  }
  rlen = reader_tags_type2_transceive(tx, tx_len, rsp + kPn53xTransceiveHeaderLen,
                                      (uint16_t)(rsp_cap - kPn53xTransceiveOverhead));
  rsp[0] = kPn53xDevPrefix;
  rsp[1] = response_code;
  rsp[kPn53xRspStatusOffset] = (rlen >= 0) ? kPn53xStatusOk : kPn53xStatusError;
  if (rlen < 0) {
    if (!pn53x_write_iso7816_sw(rsp, rsp_cap, kPn53xIsoRspDataOffset)) {
      return 0u;
    }
    return kPn53xStatusReplyLen;
  }
  if (!nero_nfc_try_add_size((size_t)rlen, kPn53xTransceiveOverhead, &rsp_need) ||
      (rsp_need > (size_t)rsp_cap)) {
    return pn53x_overflow_reply(response_code, rsp, rsp_cap);
  }
  if (!pn53x_write_sw_after_data(rsp, rsp_cap, (uint16_t)rlen)) {
    return pn53x_overflow_reply(response_code, rsp, rsp_cap);
  }
  const auto rsp_len = static_cast<uint32_t>(rlen) + kPn53xTransceiveOverhead;
  return static_cast<uint16_t>(rsp_len);
}

static uint16_t handle_pn53x_type5_transceive(uint8_t response_code, const uint8_t *tx,
                                              uint16_t tx_len, uint8_t *rsp, uint16_t rsp_cap) {
  int rlen;
  size_t rsp_need = 0u;

  if ((tx == NERO_NFC_NULL) || (tx_len == 0u) || (rsp == NERO_NFC_NULL) ||
      (rsp_cap < kPn53xStatusReplyLen)) {
    return 0u;
  }
  if (!reader_ccid_type5_raw_transceive_allowed(tx, tx_len)) {
    return build_pn53x_status_reply(response_code, kPn53xStatusError, rsp, rsp_cap);
  }
  rlen = reader_tags_type5_transceive(tx, tx_len, rsp + kPn53xTransceiveHeaderLen,
                                      (uint16_t)(rsp_cap - kPn53xTransceiveOverhead));
  rsp[0] = kPn53xDevPrefix;
  rsp[1] = response_code;
  rsp[kPn53xRspStatusOffset] = (rlen >= 0) ? kPn53xStatusOk : kPn53xStatusError;
  if (rlen < 0) {
    if (!pn53x_write_iso7816_sw(rsp, rsp_cap, kPn53xIsoRspDataOffset)) {
      return 0u;
    }
    return kPn53xStatusReplyLen;
  }
  if (!nero_nfc_try_add_size((size_t)rlen, kPn53xTransceiveOverhead, &rsp_need) ||
      (rsp_need > (size_t)rsp_cap)) {
    return pn53x_overflow_reply(response_code, rsp, rsp_cap);
  }
  if (!pn53x_write_sw_after_data(rsp, rsp_cap, (uint16_t)rlen)) {
    return pn53x_overflow_reply(response_code, rsp, rsp_cap);
  }
  const auto rsp_len = static_cast<uint32_t>(rlen) + kPn53xTransceiveOverhead;
  return static_cast<uint16_t>(rsp_len);
}

static uint16_t handle_pn53x_in_data_exchange(const uint8_t *cmd, uint16_t cmd_len, uint8_t *rsp,
                                              uint16_t rsp_cap) {
  if ((cmd == NERO_NFC_NULL) || (cmd_len < kPn53xListPassiveMinCmdLen) || (rsp == NERO_NFC_NULL) ||
      (rsp_cap < kPn53xStatusReplyLen)) {
    return 0u;
  }
  if (cmd[kPn53xCmdTgOffset] != kPn53xSingleTarget) { /* InDataExchange Tg — target number 1 */
    return build_pn53x_status_reply(kPn53xRspInDataExchange, kPn53xStatusError, rsp, rsp_cap);
  }
  if (g_tag_kind == READER_TAG_KIND_TYPE2) {
    return handle_pn53x_type2_transceive(
      kPn53xRspInDataExchange, cmd + kPn53xInDataExchangePayloadSkip,
      (uint16_t)(cmd_len - kPn53xInDataExchangePayloadSkip), rsp, rsp_cap);
  }
  if (g_tag_kind == READER_TAG_KIND_TYPE4) {
    const uint8_t *inner_apdu = cmd + kPn53xInDataExchangePayloadSkip;
    const uint16_t inner_len = (uint16_t)(cmd_len - kPn53xInDataExchangePayloadSkip);
    if (g_type4_security_key_app && apdu_selects_ndef_app(inner_apdu, inner_len)) {
      return build_pn53x_status_reply(kPn53xRspInDataExchange, kPn53xStatusError, rsp, rsp_cap);
    }
    if (nfc_ctap_apdu_is_select_fido_aid(inner_apdu, inner_len, NERO_NFC_NULL) ||
        nfc_ctap_apdu_command(inner_apdu, inner_len, NERO_NFC_NULL) ||
        nfc_ctap_apdu_is_getresponse(inner_apdu, inner_len) ||
        nfc_ctap_apdu_is_control_end(inner_apdu, inner_len)) {
      return build_pn53x_status_reply(kPn53xRspInDataExchange, kPn53xStatusError, rsp, rsp_cap);
    }
    uint16_t iso_len = reader_security_key_apdu_exchange(
      cmd + kPn53xInDataExchangePayloadSkip, (uint16_t)(cmd_len - kPn53xInDataExchangePayloadSkip),
      rsp + kPn53xInDataExchangePayloadSkip, (uint16_t)(rsp_cap - kPn53xTransceiveOverhead));
    rsp[0] = kPn53xDevPrefix;
    rsp[1] = kPn53xRspInDataExchange;
    rsp[kPn53xRspStatusOffset] =
      (iso_len >= (uint16_t)NFC_ISO7816_SW_LEN) ? kPn53xStatusOk : kPn53xStatusError;
    if (iso_len < (uint16_t)NFC_ISO7816_SW_LEN) {
      if (!pn53x_write_iso7816_sw(rsp, rsp_cap, kPn53xIsoRspDataOffset)) {
        return 0u;
      }
      return kPn53xStatusReplyLen;
    }
    return (uint16_t)(iso_len + kPn53xInDataExchangePayloadSkip);
  }
  return build_pn53x_status_reply(kPn53xRspInDataExchange, kPn53xStatusError, rsp, rsp_cap);
}

static uint16_t handle_pn53x_in_communicate_thru(const uint8_t *cmd, uint16_t cmd_len, uint8_t *rsp,
                                                 uint16_t rsp_cap) {
  if ((cmd == NERO_NFC_NULL) || (cmd_len < kPn53xCommunicateThruMinCmdLen) ||
      (rsp == NERO_NFC_NULL)) {
    return 0u;
  }
  if (g_tag_kind == READER_TAG_KIND_TYPE2) {
    return handle_pn53x_type2_transceive(
      kPn53xRspInCommunicateThru, cmd + kPn53xCommunicateThruPayloadSkip,
      (uint16_t)(cmd_len - kPn53xCommunicateThruPayloadSkip), rsp, rsp_cap);
  }
  if (g_tag_kind == READER_TAG_KIND_TYPE5) {
    return handle_pn53x_type5_transceive(
      kPn53xRspInCommunicateThru, cmd + kPn53xCommunicateThruPayloadSkip,
      (uint16_t)(cmd_len - kPn53xCommunicateThruPayloadSkip), rsp, rsp_cap);
  }
  return build_pn53x_status_reply(kPn53xRspInCommunicateThru, kPn53xStatusError, rsp, rsp_cap);
}

} /* namespace */

uint16_t reader_ccid_handle_acr122_direct_apdu(const uint8_t *apdu, uint16_t apdu_len, uint8_t *rsp,
                                               uint16_t rsp_cap) {
  const uint8_t *cmd;
  uint8_t lc;

  if ((apdu == NERO_NFC_NULL) || (rsp == NERO_NFC_NULL) ||
      !nfc_iso7816_apdu_min_len(apdu_len, NFC_ISO7816_SHORT_APDU_HDR_LEN)) {
    return 0u;
  }
  if ((apdu_len == NFC_ISO7816_SHORT_APDU_HDR_LEN) &&
      (apdu[0] == (uint8_t)NFC_ISO7816_CLA_PROPRIETARY) &&
      (apdu[1] == (uint8_t)NFC_ISO7816_CLA_ISO) &&
      (apdu[NFC_ISO7816_APDU_IDX_P1] == kAcr122InsGetFirmware) &&
      (apdu[NFC_ISO7816_APDU_IDX_P2] == (uint8_t)NFC_ISO7816_P2_SELECT_FIRST) &&
      (apdu[NFC_ISO7816_APDU_IDX_LC] == (uint8_t)NFC_ISO7816_SW2_SUCCESS)) {
    /* [ACR122U API] "Get Firmware Version" pseudo-APDU (FF 00 48 00 00) returns
     * the ASCII firmware revision string with no trailing ISO7816 status word;
     * the PC/SC host driver consumes the bare string. */
    static const uint8_t kFw[] = {'A', 'C', 'R', '1', '2', '2', 'U', '2', '0', '3'};
    if (rsp_cap < (uint16_t)sizeof(kFw)) {
      return reader_ccid_apdu_failure_response(rsp, rsp_cap);
    }
    if (!nero_nfc_copy_bytes(rsp, rsp_cap, 0u, kFw, sizeof(kFw))) {
      return reader_ccid_apdu_failure_response(rsp, rsp_cap);
    }
    return (uint16_t)sizeof(kFw);
  }
  if ((apdu[0] != (uint8_t)NFC_ISO7816_CLA_PROPRIETARY) ||
      (apdu[1] != (uint8_t)NFC_ISO7816_CLA_ISO) ||
      (apdu[NFC_ISO7816_APDU_IDX_P1] != (uint8_t)NFC_ISO7816_CLA_ISO) ||
      (apdu[NFC_ISO7816_APDU_IDX_P2] != (uint8_t)NFC_ISO7816_CLA_ISO)) {
    return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_INS_NOT_SUPPORTED,
                                     (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  }
  if (!nfc_iso7816_apdu_lc(apdu, apdu_len, &lc) || !nfc_iso7816_apdu_lc_body_ok(apdu_len, lc) ||
      (lc < kPn53xDispatchPayloadMinLen)) {
    return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_LENGTH_ALT,
                                     (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  }
  cmd = nfc_iso7816_apdu_data_ptr(apdu, apdu_len, lc);
  if (cmd == NERO_NFC_NULL) {
    return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_LENGTH_ALT,
                                     (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  }
  if (cmd[0] != kPn53xHostPrefix) {
    return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_INS_NOT_SUPPORTED,
                                     (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  }
  if (!nero_nfc_span_ok(kPn53xCmdOpcodeOffset, 1u, lc)) {
    return reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_WRONG_LENGTH_ALT,
                                     (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  }
  switch (cmd[1]) {
  case kPn53xCmdGetFirmwareVersion:
    return build_pn53x_fw_version(rsp, rsp_cap);
  case kPn53xCmdInListPassiveTarget:
    return handle_pn53x_list_passive(cmd, lc, rsp, rsp_cap);
  case kPn53xCmdInDataExchange:
    return handle_pn53x_in_data_exchange(cmd, lc, rsp, rsp_cap);
  case kPn53xCmdInCommunicateThru:
    return handle_pn53x_in_communicate_thru(cmd, lc, rsp, rsp_cap);
  case kPn53xCmdInDeselect:
    return build_pn53x_status_reply(kPn53xRspInDeselect, kPn53xStatusOk, rsp, rsp_cap);
  case kPn53xCmdReadRegister:
    return build_pn53x_status_reply(kPn53xRspReadRegister, kPn53xStatusOk, rsp, rsp_cap);
  default:
    return build_pn53x_status_reply((uint8_t)(cmd[1] + 1u), kPn53xStatusTimeout, rsp, rsp_cap);
  }
}

uint16_t reader_ccid_dispatch_host_payload(const uint8_t *payload, uint16_t payload_len,
                                           uint8_t *rsp, uint16_t rsp_cap) {
  uint16_t rlen;

  if ((payload == NERO_NFC_NULL) || (payload_len < kPn53xDispatchPayloadMinLen) ||
      (rsp == NERO_NFC_NULL) || (rsp_cap < (uint16_t)NFC_ISO7816_SW_LEN)) {
    if ((rsp != NERO_NFC_NULL) && (rsp_cap >= (uint16_t)NFC_ISO7816_SW_LEN)) {
      return reader_ccid_apdu_failure_response(rsp, rsp_cap);
    }
    return 0u;
  }
  if (payload[0] == (uint8_t)NFC_ISO7816_CLA_PROPRIETARY) {
    switch (payload[1]) {
    case (uint8_t)NFC_ISO7816_CLA_ISO:
      rlen = reader_ccid_handle_acr122_direct_apdu(payload, payload_len, rsp, rsp_cap);
      break;
    case (uint8_t)NFC_ISO7816_INS_GET_DATA:
      rlen = reader_ccid_handle_get_data_apdu(payload, payload_len, rsp, rsp_cap);
      break;
    case (uint8_t)NFC_ISO7816_INS_READ_BINARY:
      rlen = reader_ccid_handle_read_binary_apdu(payload, payload_len, rsp, rsp_cap);
      break;
    case (uint8_t)NFC_ISO7816_INS_UPDATE_BINARY:
      rlen = reader_ccid_handle_update_binary_apdu(payload, payload_len, rsp, rsp_cap);
      break;
    case (uint8_t)NFC_PCSC_ESCAPE_TRANSPARENT_INS:
      rlen = reader_ccid_handle_escape_transparent_apdu(payload, payload_len, rsp, rsp_cap);
      break;
    default:
      rlen = reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_INS_NOT_SUPPORTED,
                                       (uint8_t)NFC_ISO7816_SW2_SUCCESS);
      break;
    }
  } else if (((g_tag_kind == READER_TAG_KIND_TYPE2) || (g_tag_kind == READER_TAG_KIND_TYPE5))) {
    if (payload[0] != (uint8_t)NFC_ISO7816_CLA_ISO) {
      return reader_ccid_append_status(rsp, 0u, rsp_cap,
                                       (uint8_t)NFC_ISO7816_SW1_CLASS_NOT_SUPPORTED,
                                       (uint8_t)NFC_ISO7816_SW2_SUCCESS);
    }
    rlen = reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_INS_NOT_SUPPORTED,
                                     (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  } else if (g_tag_kind == READER_TAG_KIND_TYPE4) {
    if (g_type4_security_key_app && apdu_selects_ndef_app(payload, payload_len)) {
      rlen = reader_ccid_append_status(rsp, 0u, rsp_cap,
                                       (uint8_t)NFC_ISO7816_SW1_CONDITIONS_NOT_SATISFIED,
                                       (uint8_t)NFC_ISO7816_SW2_COMMAND_NOT_ALLOWED);
    } else {
      uint16_t iso_len = reader_security_key_apdu_exchange(payload, payload_len, rsp, rsp_cap);
      rlen = (iso_len >= (uint16_t)NFC_ISO7816_SW_LEN)
               ? iso_len
               : reader_ccid_append_status(rsp, 0u, rsp_cap,
                                           (uint8_t)NFC_ISO7816_SW1_CONDITIONS_NOT_SATISFIED,
                                           (uint8_t)NFC_ISO7816_SW2_COMMAND_NOT_ALLOWED);
    }
  } else {
    rlen = reader_ccid_append_status(rsp, 0u, rsp_cap, (uint8_t)NFC_ISO7816_SW1_INS_NOT_SUPPORTED,
                                     (uint8_t)NFC_ISO7816_SW2_SUCCESS);
  }
  if (rlen != 0u) {
    reader_ccid_note_host_session_activity();
  }
  return rlen;
}

#endif /* NERO_CCID_USB_BUILD */
