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

#pragma once

#include "nero_nfc_attrs.h"
#include "nero_nfc_null.h"
#include "nfc_tag_geometry_limits.h"

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CTAP NFC transport command bytes and buffer sizes: nfc_tag_geometry_limits.h
 * ([CTAP2.3]; normative values in docs/spec-traceability.yaml). */
enum {
  NFC_CTAP_FIDO_APP_SELECT_VARIANT_COUNT = 4u,
  NFC_CTAP_FIDO_WEBAUTHN_SELECT_STEP_COUNT = 4u,
};

static const uint8_t NFC_CTAP_FIDO_AID[NFC_CTAP_FIDO_AID_LEN] = {
    0xA0u, 0x00u, 0x00u, 0x06u, 0x47u, 0x2Fu, 0x00u, 0x01u,
};

NERO_NFC_STATIC_ASSERT(NFC_CTAP_FIDO_AID_LEN == 8u,
                       "FIDO AID is 8 bytes per [CTAP2.3] section 11.3.3");
NERO_NFC_STATIC_ASSERT(NFC_CTAP_RP_ID_MAX <= 253u,
                       "RP ID cap fits CTAP text-string limits");
NERO_NFC_STATIC_ASSERT(
    NFC_ISO_DEP_IBLOCK_TX_BUF_LEN == 832u,
    "ISO-DEP I-block TX buffer fits CTAP APDU + framing overhead");

NERO_NFC_NODISCARD bool nfc_ctap_encode_get_assertion(
    const uint8_t* client_hash32, const char* rp_id, const uint8_t* allow_cred,
    uint16_t allow_cred_len, uint8_t* out, uint16_t out_max, uint16_t* out_len);

NERO_NFC_NODISCARD bool nfc_ctap_pack_cbor_apdu(
    uint8_t ctap_cmd, const uint8_t* cbor, uint16_t cbor_len,
    bool force_extended, uint8_t* apdu, uint16_t apdu_cap, uint16_t* apdu_len);

NERO_NFC_NODISCARD bool nfc_ctap_pack_select_fido_apdu(bool add_le_00,
                                                       uint8_t* apdu,
                                                       uint16_t apdu_cap,
                                                       uint16_t* apdu_len);

#ifdef __cplusplus
struct nfc_ctap_fido_app_select_variant_t {
#else
typedef struct {
#endif
  const uint8_t* aid;
  uint8_t aid_len;
  uint8_t p2;
  bool add_le_00;
#ifdef __cplusplus
};
#else
} nfc_ctap_fido_app_select_variant_t;
#endif

#ifdef __cplusplus
enum nfc_ctap_fido_select_prep_t {
#else
typedef enum {
#endif
  NFC_CTAP_FIDO_SELECT_PREP_NONE = 0,
  NFC_CTAP_FIDO_SELECT_PREP_RECOVER = 1,
  NFC_CTAP_FIDO_SELECT_PREP_SETTLE = 2,
#ifdef __cplusplus
};
#else
} nfc_ctap_fido_select_prep_t;
#endif

#ifdef __cplusplus
enum nfc_ctap_fido_select_log_t {
#else
typedef enum {
#endif
  NFC_CTAP_FIDO_SELECT_LOG_NONE = 0,
  NFC_CTAP_FIDO_SELECT_LOG_REOPEN = 1,
  NFC_CTAP_FIDO_SELECT_LOG_LAST_CHANCE = 2,
#ifdef __cplusplus
};
#else
} nfc_ctap_fido_select_log_t;
#endif

#ifdef __cplusplus
struct nfc_ctap_fido_webauthn_select_step_t {
#else
typedef struct {
#endif
  uint8_t variant_index;
  nfc_ctap_fido_select_prep_t prep;
  uint8_t log_before_prep;
#ifdef __cplusplus
};
#else
} nfc_ctap_fido_webauthn_select_step_t;
#endif

NERO_NFC_NODISCARD static inline bool nfc_ctap_fido_app_select_variant(
    uint8_t index, nfc_ctap_fido_app_select_variant_t* out) {
  static const struct {
    uint8_t p2;
    bool add_le_00;
  } K_VARIANTS[NFC_CTAP_FIDO_APP_SELECT_VARIANT_COUNT] = {
      {0x00u, false},
      {0x00u, true},
      {0x0Cu, false},
      {0x0Cu, true},
  };

  if (out != NERO_NFC_NULL) {
    out->aid = NERO_NFC_NULL;
    out->aid_len = 0u;
    out->p2 = 0u;
    out->add_le_00 = false;
  }
  if ((out == NERO_NFC_NULL) ||
      (index >= (uint8_t)NFC_CTAP_FIDO_APP_SELECT_VARIANT_COUNT)) {
    return false;
  }
  out->aid = NFC_CTAP_FIDO_AID;
  out->aid_len = (uint8_t)NFC_CTAP_FIDO_AID_LEN;
  out->p2 = K_VARIANTS[index].p2;
  out->add_le_00 = K_VARIANTS[index].add_le_00;
  return true;
}

NERO_NFC_NODISCARD static inline bool nfc_ctap_fido_app_select_variant_match(
    uint8_t p2, bool add_le_00, nfc_ctap_fido_app_select_variant_t* out) {
  if (out != NERO_NFC_NULL) {
    out->aid = NERO_NFC_NULL;
    out->aid_len = 0u;
    out->p2 = 0u;
    out->add_le_00 = false;
  }
  for (uint8_t i = 0u; i < (uint8_t)NFC_CTAP_FIDO_APP_SELECT_VARIANT_COUNT;
       ++i) {
    nfc_ctap_fido_app_select_variant_t variant;

    if (!nfc_ctap_fido_app_select_variant(i, &variant)) {
      break;
    }
    if ((variant.p2 == p2) && (variant.add_le_00 == add_le_00)) {
      if (out != NERO_NFC_NULL) {
        *out = variant;
      }
      return true;
    }
  }
  return false;
}

NERO_NFC_NODISCARD bool nfc_ctap_fido_webauthn_select_step(
    uint8_t step, nfc_ctap_fido_webauthn_select_step_t* out);

NERO_NFC_NODISCARD bool nfc_ctap_apdu_is_select_fido_aid(const uint8_t* apdu,
                                                         uint16_t apdu_len,
                                                         bool* add_le_00_out);

NERO_NFC_NODISCARD bool nfc_ctap_apdu_command(const uint8_t* apdu,
                                              uint16_t apdu_len,
                                              uint8_t* cmd_out);

NERO_NFC_NODISCARD bool nfc_ctap_response_more_data(const uint8_t* resp,
                                                    int rlen);

NERO_NFC_NODISCARD bool nfc_ctap_apdu_is_getresponse(const uint8_t* apdu,
                                                     uint16_t apdu_len);

NERO_NFC_NODISCARD bool nfc_ctap_apdu_is_control_end(const uint8_t* apdu,
                                                     uint16_t apdu_len);

NERO_NFC_NODISCARD bool nfc_ctap_apdu_needs_ccid_time_extension(
    const uint8_t* apdu, uint16_t apdu_len);

/*
 * [CTAP2.3] §11.3.5.2 — a transparent relay never synthesizes or rewrites the
 * token's ISO7816 status word. This classifier inspects a token response and
 * tells the relay whether to forward the bytes verbatim or fail closed; it does
 * not mutate the buffer.
 */
#ifdef __cplusplus
enum nfc_ctap_relay_disposition_t {
#else
typedef enum {
#endif
  NFC_CTAP_RELAY_PASSTHROUGH = 0, /* relay the token bytes verbatim */
  NFC_CTAP_RELAY_FAIL_CLOSED =
      1, /* malformed/contradictory/error: return ISO7816 error */
#ifdef __cplusplus
};
#else
} nfc_ctap_relay_disposition_t;
#endif

NERO_NFC_NODISCARD nfc_ctap_relay_disposition_t
nfc_ctap_relay_response_disposition(const uint8_t* raw, uint16_t raw_len);

NERO_NFC_NODISCARD bool nfc_ctap_dissect_response(const uint8_t* raw,
                                                  uint16_t raw_len,
                                                  uint8_t* inner_out,
                                                  uint16_t inner_cap,
                                                  uint16_t* inner_len);

#ifdef __cplusplus
}
#endif
