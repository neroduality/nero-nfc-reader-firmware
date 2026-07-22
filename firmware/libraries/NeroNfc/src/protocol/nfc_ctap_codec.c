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
#include "nfc_ctap_codec.h"

#include "nfc_pcsc_contactless.h"
#include "nero_nfc_mem_util.h"

#include <string.h>

static const uint8_t K_NFC_CTAP_PK_CRED_TYPE_KEY[] = {0x64u, 0x74u, 0x79u,
                                                      0x70u, 0x65u};
static const uint8_t K_NFC_CTAP_PK_CRED_TYPE_PUBLIC_KEY[] = {
    0x6Au, 0x70u, 0x75u, 0x62u, 0x6Cu, 0x69u, 0x63u, 0x2Du, 0x6Bu, 0x65u, 0x79u,
};
static const uint8_t K_NFC_CTAP_OPTIONS_UP[] = {0x62u, 0x75u, 0x70u,
                                                NFC_CBOR_BOOL_TRUE};
static const uint8_t K_NFC_CTAP_OPTIONS_UV[] = {0x62u, 0x75u, 0x76u,
                                                NFC_CBOR_BOOL_FALSE};

NERO_NFC_STATIC_ASSERT(
    sizeof(K_NFC_CTAP_OPTIONS_UP) + sizeof(K_NFC_CTAP_OPTIONS_UV) ==
        NFC_CTAP_GET_ASSERTION_OPTIONS_BODY_LEN,
    "getAssertion options body must match emitted \"up\"/\"uv\" bytes");

static bool emit_pk_cred_descriptor(const uint8_t* cred_id, uint16_t cred_len,
                                    uint8_t* buf, uint16_t buf_max,
                                    uint16_t* p_io) {
  uint16_t p;
  uint8_t id_hdr_len;
  size_t required = 0u;

  if ((cred_len == 0u) || (cred_id == NERO_NFC_NULL) ||
      (buf == NERO_NFC_NULL) || (p_io == NERO_NFC_NULL)) {
    return false;
  }
  p = *p_io;
  if (cred_len <= NFC_CBOR_AI_INLINE_MAX) {
    id_hdr_len = NFC_CBOR_HDR_INLINE;
  } else if (cred_len <= NFC_CBOR_ONE_BYTE_LEN_MAX) {
    id_hdr_len = NFC_CBOR_HDR_UINT8;
  } else {
    id_hdr_len = NFC_CBOR_HDR_UINT16;
  }
  if (!nero_nfc_try_add_size((size_t)p, NFC_CTAP_PK_CRED_DESCRIPTOR_EXTRA,
                             &required) ||
      !nero_nfc_try_add_size(required, (size_t)id_hdr_len, &required) ||
      !nero_nfc_try_add_size(required, (size_t)cred_len, &required) ||
      (required > (size_t)buf_max)) {
    return false;
  }
  buf[p++] = NFC_CTAP_CBOR_MAP_PK_CRED;
  if (!nero_nfc_copy_bytes(buf, buf_max, p, K_NFC_CTAP_PK_CRED_TYPE_KEY,
                           (uint16_t)sizeof(K_NFC_CTAP_PK_CRED_TYPE_KEY))) {
    return false;
  }
  p = (uint16_t)(p + (uint16_t)sizeof(K_NFC_CTAP_PK_CRED_TYPE_KEY));
  if (!nero_nfc_copy_bytes(
          buf, buf_max, p, K_NFC_CTAP_PK_CRED_TYPE_PUBLIC_KEY,
          (uint16_t)sizeof(K_NFC_CTAP_PK_CRED_TYPE_PUBLIC_KEY))) {
    return false;
  }
  p = (uint16_t)(p + (uint16_t)sizeof(K_NFC_CTAP_PK_CRED_TYPE_PUBLIC_KEY));
  if (cred_len <= NFC_CBOR_AI_INLINE_MAX) {
    buf[p++] = (uint8_t)(NFC_CBOR_INLINE_BYTES_BASE + cred_len);
  } else if (cred_len <= NFC_CBOR_ONE_BYTE_LEN_MAX) {
    buf[p++] = NFC_CBOR_HEADER_ONE_BYTE_BYTES;
    buf[p++] = (uint8_t)cred_len;
  } else {
    buf[p++] = NFC_CBOR_HEADER_TWO_BYTE_BYTES;
    buf[p++] =
        (uint8_t)((cred_len >> NFC_BYTE_SHIFT_8) & NFC_ISO7816_BYTE_MASK);
    buf[p++] = (uint8_t)(cred_len & NFC_ISO7816_BYTE_MASK);
  }
  if (!nero_nfc_copy_bytes(buf, buf_max, p, cred_id, cred_len)) {
    return false;
  }
  p = (uint16_t)(p + cred_len);
  *p_io = p;
  return true;
}

bool nfc_ctap_encode_get_assertion(const uint8_t* client_hash32,
                                   const char* rp_id, const uint8_t* allow_cred,
                                   uint16_t allow_cred_len, uint8_t* out,
                                   uint16_t out_max, uint16_t* out_len) {
  size_t rplen;
  size_t required = 0u;
  uint16_t p = 0u;
  bool has_allow_credential;

  if (out_len != NERO_NFC_NULL) {
    *out_len = 0u;
  }
  if ((client_hash32 == NERO_NFC_NULL) || (rp_id == NERO_NFC_NULL) ||
      (out == NERO_NFC_NULL) || (out_len == NERO_NFC_NULL)) {
    return false;
  }
  has_allow_credential = (allow_cred != NERO_NFC_NULL) && (allow_cred_len > 0u);
  if (!nero_nfc_bounded_strlen(rp_id, (size_t)NFC_CTAP_RP_ID_MAX + 1u,
                               &rplen) ||
      (rplen == 0u) || (rplen > NFC_CTAP_RP_ID_MAX)) {
    return false;
  }
  required =
      NFC_CTAP_GET_ASSERTION_MAP_HDR_LEN + NFC_CTAP_GET_ASSERTION_RP_KEY_LEN +
      ((rplen <= NFC_CBOR_AI_INLINE_MAX) ? NFC_CBOR_HDR_INLINE
                                         : NFC_CBOR_HDR_UINT8) +
      rplen + NFC_CTAP_GET_ASSERTION_CDH_PREFIX_LEN + NFC_CTAP_CLIENT_HASH_LEN +
      NFC_CTAP_GET_ASSERTION_OPTIONS_PREFIX_LEN +
      NFC_CTAP_GET_ASSERTION_OPTIONS_BODY_LEN;
  if (has_allow_credential) {
    uint8_t id_hdr_len;
    if (allow_cred_len <= NFC_CBOR_AI_INLINE_MAX) {
      id_hdr_len = NFC_CBOR_HDR_INLINE;
    } else if (allow_cred_len <= NFC_CBOR_ONE_BYTE_LEN_MAX) {
      id_hdr_len = NFC_CBOR_HDR_UINT8;
    } else {
      id_hdr_len = NFC_CBOR_HDR_UINT16;
    }
    if (!nero_nfc_try_add_size(required,
                               NFC_CBOR_HDR_UINT8 +
                                   NFC_CTAP_PK_CRED_DESCRIPTOR_HDR_LEN +
                                   (size_t)id_hdr_len + allow_cred_len,
                               &required)) {
      return false;
    }
  }
  if (required > out_max) {
    return false;
  }

  out[p++] = has_allow_credential ? NFC_CTAP_CBOR_MAP_GET_ASSERTION_WITH_ALLOW
                                  : NFC_CTAP_CBOR_MAP_GET_ASSERTION_NO_ALLOW;
  out[p++] = NFC_CTAP_CBOR_KEY_RP_ID;
  if (rplen <= NFC_CBOR_AI_INLINE_MAX) {
    out[p++] = (uint8_t)(NFC_CBOR_INLINE_TEXT_BASE + rplen);
  } else {
    out[p++] = NFC_CBOR_HEADER_ONE_BYTE_TEXT;
    out[p++] = (uint8_t)rplen;
  }
  if (!nero_nfc_copy_bytes(out, out_max, p, rp_id, (uint16_t)rplen)) {
    return false;
  }
  p = (uint16_t)(p + rplen);

  out[p++] = NFC_CTAP_CBOR_KEY_CLIENT_DATA_HASH;
  out[p++] = NFC_CBOR_HEADER_ONE_BYTE_BYTES;
  out[p++] = NFC_CTAP_CLIENT_HASH_LEN;
  if (!nero_nfc_copy_bytes(out, out_max, p, client_hash32,
                           NFC_CTAP_CLIENT_HASH_LEN)) {
    return false;
  }
  p = (uint16_t)(p + NFC_CTAP_CLIENT_HASH_LEN);

  if (has_allow_credential) {
    out[p++] = NFC_CTAP_CBOR_KEY_ALLOW_LIST;
    out[p++] = NFC_CTAP_CBOR_ARRAY_ONE;
    if (!emit_pk_cred_descriptor(allow_cred, allow_cred_len, out, out_max,
                                 &p)) {
      return false;
    }
  }

  out[p++] = NFC_CTAP_CBOR_KEY_OPTIONS;
  out[p++] = NFC_CTAP_CBOR_MAP_OPTIONS;
  if (!nero_nfc_copy_bytes(out, out_max, p, K_NFC_CTAP_OPTIONS_UP,
                           (uint16_t)sizeof(K_NFC_CTAP_OPTIONS_UP))) {
    return false;
  }
  p = (uint16_t)(p + (uint16_t)sizeof(K_NFC_CTAP_OPTIONS_UP));
  if (!nero_nfc_copy_bytes(out, out_max, p, K_NFC_CTAP_OPTIONS_UV,
                           (uint16_t)sizeof(K_NFC_CTAP_OPTIONS_UV))) {
    return false;
  }
  p = (uint16_t)(p + (uint16_t)sizeof(K_NFC_CTAP_OPTIONS_UV));

  *out_len = p;
  return true;
}

bool nfc_ctap_pack_cbor_apdu(uint8_t ctap_cmd, const uint8_t* cbor,
                             uint16_t cbor_len, bool force_extended,
                             uint8_t* apdu, uint16_t apdu_cap,
                             uint16_t* apdu_len) {
  uint16_t payload_len;
  uint16_t cmd_len = 0u;
  size_t required_len = 0u;

  if (apdu_len != NERO_NFC_NULL) {
    *apdu_len = 0u;
  }
  if (((cbor == NERO_NFC_NULL) && (cbor_len != 0u)) ||
      (apdu == NERO_NFC_NULL) || (apdu_len == NERO_NFC_NULL)) {
    return false;
  }
  if (cbor_len > (uint16_t)(UINT16_MAX - 1u)) {
    return false;
  }

  payload_len = (uint16_t)(cbor_len + NFC_CTAP_CBOR_HDR_INLINE);
  if (!nero_nfc_try_add_size(
          (size_t)payload_len,
          (!force_extended && (payload_len <= NFC_ISO7816_SHORT_LC_MAX))
              ? NFC_CTAP_APDU_PAYLOAD_HDR_SHORT
              : NFC_CTAP_APDU_PAYLOAD_HDR_EXTENDED,
          &required_len) ||
      (required_len > (size_t)apdu_cap)) {
    return false;
  }

  apdu[NFC_ISO7816_APDU_IDX_CLA] = NFC_CTAP_CLA;
  apdu[NFC_ISO7816_APDU_IDX_INS] = NFC_CTAP_INS_MSG;
  apdu[NFC_ISO7816_APDU_IDX_P1] =
      NFC_CTAP_P1_GETRESPONSE_SUPPORTED; /* [CTAP2.3] section 11.3.7.1 —
                      client supports GETRESPONSE */
  apdu[NFC_ISO7816_APDU_IDX_P2] = NFC_ISO7816_GET_DATA_P2_DEFAULT;

  if (!force_extended && (payload_len <= NFC_ISO7816_SHORT_LC_MAX)) {
    apdu[NFC_ISO7816_APDU_IDX_LC] = (uint8_t)payload_len;
    apdu[NFC_CTAP_APDU_SHORT_CMD_OFFSET] = ctap_cmd;
    if (!nero_nfc_copy_bytes(apdu, apdu_cap, NFC_CTAP_APDU_SHORT_HDR_LEN, cbor,
                             cbor_len)) {
      return false;
    }
    cmd_len = (uint16_t)(NFC_CTAP_APDU_SHORT_HDR_LEN + cbor_len +
                         NFC_CTAP_APDU_SHORT_TAIL_LEN);
    apdu[NFC_CTAP_APDU_SHORT_HDR_LEN + cbor_len] = NFC_ISO7816_SW2_SUCCESS;
  } else {
    apdu[NFC_ISO7816_APDU_IDX_LC] = NFC_ISO7816_SW2_SUCCESS;
    apdu[NFC_CTAP_APDU_EXTENDED_LC_MSB_OFFSET] =
        (uint8_t)((payload_len >> NFC_BYTE_SHIFT_8) & NFC_ISO7816_BYTE_MASK);
    apdu[NFC_CTAP_APDU_EXTENDED_LC_LSB_OFFSET] =
        (uint8_t)(payload_len & NFC_ISO7816_BYTE_MASK);
    apdu[NFC_CTAP_APDU_EXTENDED_CMD_OFFSET] = ctap_cmd;
    if (!nero_nfc_copy_bytes(apdu, apdu_cap, NFC_CTAP_APDU_EXTENDED_HDR_LEN,
                             cbor, cbor_len)) {
      return false;
    }
    cmd_len = (uint16_t)(NFC_CTAP_APDU_EXTENDED_HDR_LEN + cbor_len +
                         NFC_CTAP_APDU_EXTENDED_TAIL_LEN);
    apdu[NFC_CTAP_APDU_EXTENDED_HDR_LEN + cbor_len] = NFC_ISO7816_SW2_SUCCESS;
    apdu[NFC_CTAP_APDU_EXTENDED_HDR_LEN + cbor_len + NFC_CTAP_CBOR_HDR_INLINE] =
        NFC_ISO7816_SW2_SUCCESS;
  }

  *apdu_len = cmd_len;
  return true;
}

bool nfc_ctap_pack_select_fido_apdu(bool add_le_00, uint8_t* apdu,
                                    uint16_t apdu_cap, uint16_t* apdu_len) {
  nfc_ctap_fido_app_select_variant_t variant;

  if (apdu_len != NERO_NFC_NULL) {
    *apdu_len = 0u;
  }
  if ((apdu == NERO_NFC_NULL) || (apdu_len == NERO_NFC_NULL)) {
    return false;
  }
  if (!nfc_ctap_fido_app_select_variant_match(NFC_ISO7816_SW2_SUCCESS,
                                              add_le_00, &variant)) {
    return false;
  }
  return nfc_pcsc_build_select_aid_apdu(
      NFC_CTAP_FIDO_AID, (uint8_t)NFC_CTAP_FIDO_AID_LEN, variant.p2,
      variant.add_le_00, apdu, apdu_cap, apdu_len);
}

bool nfc_ctap_fido_webauthn_select_step(
    uint8_t step, nfc_ctap_fido_webauthn_select_step_t* out) {
  static const nfc_ctap_fido_webauthn_select_step_t
      K_STEPS[NFC_CTAP_FIDO_WEBAUTHN_SELECT_STEP_COUNT] = {
          {1u, NFC_CTAP_FIDO_SELECT_PREP_NONE, NFC_CTAP_FIDO_SELECT_LOG_NONE},
          {1u, NFC_CTAP_FIDO_SELECT_PREP_RECOVER,
           NFC_CTAP_FIDO_SELECT_LOG_REOPEN},
          {0u, NFC_CTAP_FIDO_SELECT_PREP_SETTLE, NFC_CTAP_FIDO_SELECT_LOG_NONE},
          {1u, NFC_CTAP_FIDO_SELECT_PREP_RECOVER,
           NFC_CTAP_FIDO_SELECT_LOG_LAST_CHANCE},
      };

  if (out != NERO_NFC_NULL) {
    out->variant_index = 0u;
    out->prep = NFC_CTAP_FIDO_SELECT_PREP_NONE;
    out->log_before_prep = 0u;
  }
  if ((out == NERO_NFC_NULL) ||
      (step >= (uint8_t)NFC_CTAP_FIDO_WEBAUTHN_SELECT_STEP_COUNT)) {
    return false;
  }
  *out = K_STEPS[step];
  return true;
}

bool nfc_ctap_apdu_is_select_fido_aid(const uint8_t* apdu, uint16_t apdu_len,
                                      bool* add_le_00_out) {
  uint8_t lc;
  const uint8_t* aid;

  if (add_le_00_out != NERO_NFC_NULL) {
    *add_le_00_out = false;
  }
  if ((apdu == NERO_NFC_NULL) ||
      !nfc_iso7816_apdu_min_len(apdu_len, NFC_ISO7816_SHORT_APDU_HDR_LEN)) {
    return false;
  }
  if ((apdu[NFC_ISO7816_APDU_IDX_CLA] != NFC_ISO7816_CLA_ISO) ||
      (apdu[NFC_ISO7816_APDU_IDX_INS] != NFC_ISO7816_INS_SELECT) ||
      (apdu[NFC_ISO7816_APDU_IDX_P1] != NFC_ISO7816_P1_SELECT_BY_DF_NAME) ||
      !nfc_ctap_fido_app_select_variant_match(apdu[NFC_ISO7816_APDU_IDX_P2],
                                              false, NERO_NFC_NULL)) {
    return false;
  }
  if (!nfc_iso7816_apdu_lc(apdu, apdu_len, &lc) ||
      (lc != (uint8_t)NFC_CTAP_FIDO_AID_LEN)) {
    return false;
  }
  if (!nfc_iso7816_apdu_lc_body_ok(apdu_len, lc) &&
      !nfc_iso7816_apdu_lc_body_with_le_ok(apdu_len, lc)) {
    return false;
  }
  aid = nfc_iso7816_apdu_data_ptr(apdu, apdu_len, lc);
  if ((aid == NERO_NFC_NULL) ||
      (memcmp(aid, NFC_CTAP_FIDO_AID, NFC_CTAP_FIDO_AID_LEN) != 0)) {
    return false;
  }
  if (nfc_iso7816_apdu_lc_body_with_le_ok(apdu_len, lc)) {
    if (!nero_nfc_span_ok((size_t)(NFC_ISO7816_SHORT_APDU_HDR_LEN + lc),
                          NFC_CTAP_CBOR_HDR_INLINE, apdu_len) ||
        (apdu[NFC_ISO7816_SHORT_APDU_HDR_LEN + lc] !=
         NFC_ISO7816_SW2_SUCCESS)) {
      return false;
    }
    if (!nfc_ctap_fido_app_select_variant_match(apdu[NFC_ISO7816_APDU_IDX_P2],
                                                true, NERO_NFC_NULL)) {
      return false;
    }
    if (add_le_00_out != NERO_NFC_NULL) {
      *add_le_00_out = true;
    }
  }
  return true;
}

bool nfc_ctap_apdu_command(const uint8_t* apdu, uint16_t apdu_len,
                           uint8_t* cmd_out) {
  uint16_t lc;
  uint8_t lc8;
  const uint8_t* data;

  if (cmd_out != NERO_NFC_NULL) {
    *cmd_out = 0u;
  }
  if ((apdu == NERO_NFC_NULL) ||
      !nfc_iso7816_apdu_min_len(apdu_len, NFC_ISO7816_SHORT_APDU_HDR_LEN)) {
    return false;
  }
  if ((apdu[NFC_ISO7816_APDU_IDX_CLA] != NFC_CTAP_CLA) ||
      (apdu[NFC_ISO7816_APDU_IDX_INS] != NFC_CTAP_INS_MSG) ||
      ((apdu[NFC_ISO7816_APDU_IDX_P1] & NFC_ISO7816_P1_IGNORE_MSB_MASK) !=
       NFC_ISO7816_SW2_SUCCESS) ||
      (apdu[NFC_ISO7816_APDU_IDX_P2] != NFC_ISO7816_GET_DATA_P2_DEFAULT)) {
    return false;
  }
  if (apdu[NFC_ISO7816_APDU_IDX_LC] != NFC_ISO7816_SW2_SUCCESS) {
    if (!nfc_iso7816_apdu_lc(apdu, apdu_len, &lc8)) {
      return false;
    }
    if (!nfc_iso7816_apdu_lc_body_ok(apdu_len, lc8) &&
        !nfc_iso7816_apdu_lc_body_with_le_ok(apdu_len, lc8)) {
      return false;
    }
    data = nfc_iso7816_apdu_data_ptr(apdu, apdu_len, lc8);
    if (data == NERO_NFC_NULL) {
      return false;
    }
    if (cmd_out != NERO_NFC_NULL) {
      *cmd_out = data[0];
    }
    return true;
  }
  if (apdu_len < NFC_ISO7816_MIN_EXTENDED_APDU_LEN) {
    return false;
  }
  lc = (uint16_t)(((uint16_t)apdu[NFC_CTAP_APDU_EXTENDED_LC_MSB_OFFSET]
                   << NFC_BYTE_SHIFT_8) |
                  apdu[NFC_CTAP_APDU_EXTENDED_LC_LSB_OFFSET]);
  {
    size_t expected_no_le = 0u;
    size_t expected_with_le = 0u;
    if ((lc == 0u) ||
        !nero_nfc_try_add_size(NFC_CTAP_APDU_EXTENDED_LC_HDR_OFFSET, (size_t)lc,
                               &expected_no_le) ||
        !nero_nfc_try_add_size(expected_no_le, NFC_CTAP_APDU_EXTENDED_TAIL_LEN,
                               &expected_with_le) ||
        (((size_t)apdu_len != expected_no_le) &&
         ((size_t)apdu_len != expected_with_le))) {
      return false;
    }
  }
  if (cmd_out != NERO_NFC_NULL) {
    *cmd_out = apdu[NFC_CTAP_APDU_EXTENDED_CMD_OFFSET];
  }
  return true;
}

bool nfc_ctap_response_more_data(const uint8_t* resp, int rlen) {
  uint8_t sw1 = 0u;
  uint8_t sw2 = 0u;

  /* [CTAP2.3] §11.3.7.2 — the NFCCTAP continuation status is exactly 0x9100
   * (SW2 == 0x00); any other 0x91xx is not a defined continuation. The status
   * word carries no remaining-byte count (unlike ISO7816 61xx). */
  return nfc_iso7816_response_sw(resp, rlen, &sw1, &sw2) &&
         (sw1 == NFC_ISO7816_SW1_MORE_DATA_VENDOR) &&
         (sw2 == NFC_ISO7816_SW2_SUCCESS);
}

bool nfc_ctap_apdu_is_getresponse(const uint8_t* apdu, uint16_t apdu_len) {
  if ((apdu == NERO_NFC_NULL) || (apdu_len < NFC_ISO7816_MIN_CMD_APDU_LEN)) {
    return false;
  }
  return (apdu[NFC_ISO7816_APDU_IDX_CLA] == NFC_CTAP_CLA) &&
         (apdu[NFC_ISO7816_APDU_IDX_INS] == NFC_CTAP_INS_GETRESPONSE) &&
         (apdu[NFC_ISO7816_APDU_IDX_P2] == NFC_ISO7816_GET_DATA_P2_DEFAULT) &&
         ((apdu[NFC_ISO7816_APDU_IDX_P1] == NFC_ISO7816_GET_DATA_P2_DEFAULT) ||
          (apdu[NFC_ISO7816_APDU_IDX_P1] == NFC_CTAP_P1_GETRESPONSE_CANCEL));
}

bool nfc_ctap_apdu_is_control_end(const uint8_t* apdu, uint16_t apdu_len) {
  if ((apdu == NERO_NFC_NULL) || (apdu_len < NFC_ISO7816_MIN_CMD_APDU_LEN)) {
    return false;
  }
  if ((apdu[NFC_ISO7816_APDU_IDX_CLA] != NFC_CTAP_CLA) ||
      (apdu[NFC_ISO7816_APDU_IDX_INS] != NFC_CTAP_INS_CONTROL) ||
      (apdu[NFC_ISO7816_APDU_IDX_P1] != NFC_CTAP_P1_CONTROL_END) ||
      (apdu[NFC_ISO7816_APDU_IDX_P2] != NFC_ISO7816_GET_DATA_P2_DEFAULT)) {
    return false;
  }
  return (apdu_len == NFC_ISO7816_MIN_CMD_APDU_LEN) ||
         ((apdu_len == NFC_ISO7816_APDU_LE_ONLY_LEN) &&
          (apdu[NFC_ISO7816_APDU_IDX_LC] == NFC_ISO7816_SW2_SUCCESS));
}

bool nfc_ctap_apdu_needs_ccid_time_extension(const uint8_t* apdu,
                                             uint16_t apdu_len) {
  uint8_t ctap_cmd = 0u;
  if (nfc_ctap_apdu_is_select_fido_aid(apdu, apdu_len, NERO_NFC_NULL)) {
    return true;
  }
  if (nfc_ctap_apdu_is_getresponse(apdu, apdu_len)) {
    return true;
  }
  if (!nfc_ctap_apdu_command(apdu, apdu_len, &ctap_cmd)) {
    return false;
  }
  return (ctap_cmd == NFC_CTAP_CMD_MAKE_CREDENTIAL) ||
         (ctap_cmd == NFC_CTAP_CMD_GET_ASSERTION) ||
         (ctap_cmd == NFC_CTAP_CMD_CLIENT_PIN);
}

nfc_ctap_relay_disposition_t nfc_ctap_relay_response_disposition(
    const uint8_t* raw, uint16_t raw_len) {
  uint16_t sw;

  /* [CTAP2.3] §11.3.5.2 — a complete token response always ends in an ISO7816
   * status word. A response without one is malformed; fail closed (the relay
   * must never synthesize a success status word). */
  if ((raw == NERO_NFC_NULL) || (raw_len < NFC_ISO7816_SW_STATUS_WORD_LEN)) {
    return NFC_CTAP_RELAY_FAIL_CLOSED;
  }
  sw = (uint16_t)(((uint16_t)raw[raw_len - NFC_ISO7816_SW_STATUS_WORD_LEN]
                   << NFC_BYTE_SHIFT_8) |
                  raw[raw_len - NFC_CTAP_CBOR_HDR_INLINE]);

  /* 9000 success is relayed verbatim. */
  if (sw == NFC_ISO7816_SW_SUCCESS) {
    return NFC_CTAP_RELAY_PASSTHROUGH;
  }
  /* 61xx / 91xx status-update is relayed verbatim — the host owns GET RESPONSE
   * / NFCCTAP_GETRESPONSE polling (§11.3.7.2). */
  if (((sw & NFC_ISO7816_SW1_HIGH_BYTE_MASK) ==
       NFC_ISO7816_SW1_MORE_DATA_PATTERN) ||
      ((sw & NFC_ISO7816_SW1_HIGH_BYTE_MASK) ==
       NFC_ISO7816_SW1_MORE_DATA_VENDOR_PATTERN)) {
    return NFC_CTAP_RELAY_PASSTHROUGH;
  }
  /* ISO7816 warning/error status words (62xx..6Fxx). */
  if ((sw >= NFC_ISO7816_SW_WARNING_MIN) &&
      (sw <= NFC_ISO7816_SW_WARNING_MAX)) {
    /* A CTAP success status byte (0x00) paired with an ISO7816 warning/error SW
     * is contradictory framing; fail closed rather than relay it as success. */
    if ((raw_len >= NFC_CTAP_MIN_RESPONSE_BODY_LEN) &&
        (raw[0] == NFC_CTAP_STATUS_SUCCESS)) {
      return NFC_CTAP_RELAY_FAIL_CLOSED;
    }
    return NFC_CTAP_RELAY_PASSTHROUGH;
  }
  /* Any other trailing word is not a valid ISO7816 status word (e.g. a CBOR
   * body byte misread as a status word): the response is malformed — fail
   * closed. */
  return NFC_CTAP_RELAY_FAIL_CLOSED;
}

bool nfc_ctap_dissect_response(const uint8_t* raw, uint16_t raw_len,
                               uint8_t* inner_out, uint16_t inner_cap,
                               uint16_t* inner_len) {
  uint16_t inner_len_local;

  if (inner_len != NERO_NFC_NULL) {
    *inner_len = 0u;
  }
  if ((raw == NERO_NFC_NULL) || (raw_len < NFC_ISO7816_SW_STATUS_WORD_LEN) ||
      (inner_len == NERO_NFC_NULL)) {
    return false;
  }

  if (((uint16_t)(raw[raw_len - NFC_ISO7816_SW_STATUS_WORD_LEN]
                  << NFC_BYTE_SHIFT_8) |
       raw[raw_len - NFC_CTAP_CBOR_HDR_INLINE]) != NFC_ISO7816_SW_SUCCESS) {
    return false;
  }
  if (raw_len < NFC_CTAP_MIN_RESPONSE_BODY_LEN) {
    return false;
  }
  if (raw[0] != NFC_CTAP_STATUS_SUCCESS) {
    return false;
  }

  inner_len_local = (uint16_t)(raw_len - NFC_CTAP_RESPONSE_STATUS_PREFIX_LEN);
  if (inner_out != NERO_NFC_NULL) {
    if (inner_len_local > inner_cap) {
      return false;
    }
    if ((inner_len_local > 0u) &&
        !nero_nfc_copy_bytes(inner_out, inner_cap, 0u,
                             raw + NFC_CTAP_CBOR_HDR_INLINE, inner_len_local)) {
      return false;
    }
  }
  *inner_len = inner_len_local;
  return true;
}
