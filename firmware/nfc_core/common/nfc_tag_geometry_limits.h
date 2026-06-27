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

/*
 * Spec-cited Type 2 / 4 / 5 tag geometry, identity, and protocol-timing
 * constants. Centralizes values that were previously duplicated as raw literals
 * across the reader and writer tag paths (NTAG21x, ST25TN, ST25TV, ST25DV).
 *
 * Citation key (used in per-macro comments below):
 *   [T2T-ISO14443-A]   NFC Forum Type 2 Tag Technical Specification 1.0
 *   [T4T-ISO14443-4]   NFC Forum Type 4 Tag Technical Specification 1.0
 *   [T5T-ISO15693]   NFC Forum Type 5 Tag Technical Specification 1.0 over ISO/IEC 15693 (vicinity)
 *   [ISO14443-3] ISO/IEC 14443-3 (RFID — identification cards — contactless)
 *   [ISO14443-4] ISO/IEC 14443-4 (RFID — transmission protocol)
 *   [ISO7816-6]  ISO/IEC 7816-6 (IC manufacturer registration / RID)
 *   [T2T-ISO14443-A-NTAG21x]    NXP NTAG213/215/216 data sheet Rev. 3.2 (265332)
 *   [T2T-ISO14443-A-ST25TN]  STMicroelectronics ST25TN512/01K data sheet DS13433
 *   [T5T-ISO15693-ST25TV]  STMicroelectronics ST25TV02KC data sheet DS13304
 *   [T5T-ISO15693-ST25DV]  STMicroelectronics ST25DVxxKC data sheet DS13519
 *   [CTAP2.3] FIDO Client to Authenticator Protocol 2.3 PS 20260226 (NFC transport §11.3;
 *             includes GETRESPONSE cancel P1=0x11 and 100 ms/500 ms poll timing in §11.3.7.2)
 *   [WebAuthn] W3C Web Authentication Level 3 (browser/platform API paired with [CTAP2.3])
 *   [T4T-ISO14443-4-NT4H424] NXP NTAG 424 DNA data sheet Rev. 3.0 (465430)
 *   [CCID1.10]    USB CCID Rev 1.10
 *   [PCSC-P1] PC/SC Part 1 Release 2.01 (host API)
 *   [PCSC-P3] PC/SC Part 3 Release 2.01 (contactless storage)
 *   [ISO7816-3]  ISO/IEC 7816-3 (ATR / historical bytes)
 *   [ISO7816-4]  ISO/IEC 7816-4:2005 (APDU command set; Tables 5–6 SW1/SW2)
 *   [RFC8949-CBOR-CTAP2] IETF RFC 8949 CBOR encoding for CTAP2 canonical form
 *   [RFC6350] IETF RFC 6350 (vCard Format Specification)
 *   [WSC]     Wi-Fi Alliance Wi-Fi Simple Configuration (WPS)
 *   [PN532]   NXP PN532 User Manual UM0701-02 (PN532/C106 firmware V1.6)
 *   [ACR122U API] ACS ACR122U Application Programming Interface V2.02 (pseudo-APDUs)
 *   [NDEF]    NFC Forum NDEF specification
 *
 * Public spec URLs live in docs/ (TUTORIAL_WEBAUTHN_CCID.md, TUTORIAL_TAGS.md, CCID.md).
 *
 * Normative numeric literals defined here are mirrored in docs/spec-traceability.yaml.
 * make lint (helper-spec-traceability-check.py) fails when a manifest symbol is missing from
 * this file or when spec_value drifts from the live #define.
 *
 * Implementation tuning (retry budgets, buffer headroom, settle ms) uses
 * [IMPL-POLICY] in docs/spec-traceability.yaml unless a value is normative.
 *
 * Defined as object-like macros (not enums) so constants mix freely with
 * uint8_t/uint16_t operands without -Wextra enum/non-enum diagnostics.
 */

/* ---- IC manufacturer codes ([ISO7816-6] registered RID in UID) ---- */
#define NFC_TAG_MFR_CODE_ST 0x02u  /* [ISO7816-6] STMicroelectronics */
#define NFC_TAG_MFR_CODE_NXP 0x04u /* [ISO7816-6] NXP Semiconductors */

/* [T5T-ISO15693] addressed command: flags + opcode (+ optional param) + 8-byte UID. */
#define NFC_TAG_T5T_ISO15693_CMD_BUF_MAX 12u
/* [T5T-ISO15693] section 10.2 / ST25 Table 97–98 — addressed request flags (high data rate + UID).
 */
#define NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED 0x22u
/* [T5T-ISO15693] section 10.2 — Protocol_extension_flag bit (OR with 0x22 → 0x2A on wire). */
#define NFC_TAG_T5T_ISO15693_FLAG_PROTOCOL_EXTENSION 0x08u
/* [T5T-ISO15693] section 10.3 — block read/write opcodes (short vs extended block addr). */
#define NFC_TAG_T5T_ISO15693_CMD_READ_SINGLE 0x20u
#define NFC_TAG_T5T_ISO15693_CMD_WRITE_SINGLE 0x21u
#define NFC_TAG_T5T_ISO15693_CMD_READ_MULTIPLE 0x23u
#define NFC_TAG_T5T_ISO15693_CMD_EXT_READ_SINGLE 0x30u
#define NFC_TAG_T5T_ISO15693_CMD_EXT_WRITE_SINGLE 0x31u
#define NFC_TAG_T5T_ISO15693_CMD_EXT_READ_MULTIPLE 0x33u
/* Implementation cap: ST25R3916 ISO15693 stream buffer fits flags + 31 four-byte blocks + CRC. */
#define NFC_TAG_T5T_ISO15693_READ_MULTIPLE_BLOCKS_MAX 31u
/* [T5T-ISO15693] section 10.3.4 — Get System Info (0x2B) / Extended Get System Info (0x3B). */
#define NFC_TAG_T5T_ISO15693_CMD_GET_SYS_INFO 0x2Bu
#define NFC_TAG_T5T_ISO15693_CMD_EXT_GET_SYS_INFO 0x3Bu
/*
 * [T5T-ISO15693] one-byte block addressing (commands 0x20/0x21) covers blocks
 * 0..0xFF; extended addressing (commands 0x30/0x31) is required above that range.
 */
#define NFC_TAG_T5T_ISO15693_BLOCK_ADDR_1BYTE_MAX 0xFFu
/* [T5T-ISO15693] ISO15693 UID byte 1 (index 1) carries manufacturer code on Type 5. */
#define NFC_TAG_T5T_ISO15693_UID_MFR_MIN_LEN 2u

/* [ISO14443-3] ATQA field width on Type A tags. */
#define NFC_TAG_ATQA_LEN 2u

/* ---- NFC Forum Type 2 Tag ([T2T-ISO14443-A] structural geometry) ---- */
/* [T2T-ISO14443-A] section 5.1 — Type 2 page (block) size. */
#define NFC_TAG_T2T_PAGE_SIZE_BYTES 4u
/* [T2T-ISO14443-A] section 5.1 — READ returns four consecutive pages (16 bytes). */
#define NFC_TAG_T2T_READ_RESP_BYTES 16u
#define NFC_TAG_T2T_READ_RESP_PAGES 4u
/* [T2T-ISO14443-A] section 4.4 — CC byte 2 (MLEN) counts the data area in 8-byte units. */
#define NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES 8u
/* [T2T-ISO14443-A] section 4.4 — Capability Container page index is 3 (not page 0). */
#define NFC_TAG_T2T_CC_PAGE_INDEX 3u
/* [T2T-ISO14443-A] section 5.1/5.2 — READ frame: opcode + page address. */
#define NFC_TAG_T2T_READ_CMD_LEN 2u
/* [T2T-ISO14443-A-NTAG21x] FAST_READ frame: opcode + start page + end page. */
#define NFC_TAG_T2T_FAST_READ_CMD_LEN 3u
/* [T2T-ISO14443-A] section 5.2 — WRITE frame: opcode + page + four data bytes. */
#define NFC_TAG_T2T_WRITE_CMD_LEN 6u
/* [T2T-ISO14443-A-NTAG21x] GET_VERSION (0x60) command is a single-byte opcode on the RF wire. */
#define NFC_TAG_T2T_GET_VERSION_CMD_LEN 1u
/* [T2T-ISO14443-A] section 4.4 — CC page (4 B) plus ≥1 user page (4 B each) before NDEF TLV scan.
 */
#define NFC_TAG_T2T_MIN_NDEF_USER_PAGES 1u
#define NFC_TAG_T2T_MIN_NDEF_DUMP_BYTES                                                            \
  (NFC_TAG_T2T_PAGE_SIZE_BYTES + (NFC_TAG_T2T_MIN_NDEF_USER_PAGES * NFC_TAG_T2T_PAGE_SIZE_BYTES))
/* [T2T-ISO14443-A] section 5.2 — WRITE 4-bit ACK nibble is 1010b (0Ah). */
#define NFC_TAG_T2T_ACK_NIBBLE 0x0Au
#define NFC_TAG_T2T_ACK_NIBBLE_MASK 0x0Fu
/*
 * [T2T-ISO14443-A] section 4.5 — static-memory fallback when CC/IC fingerprint is unknown
 * (baseline Type 2 tags expose pages 0..44).
 */
#define NFC_TAG_T2T_FALLBACK_LAST_PAGE 44u

/* ---- NXP NTAG213 / NTAG215 / NTAG216 ([T2T-ISO14443-A-NTAG21x] memory organization) ---- */
/* [T2T-ISO14443-A-NTAG21x] last user page index per density tier. */
#define NFC_TAG_NTAG213_LAST_PAGE 39u
#define NFC_TAG_NTAG215_LAST_PAGE 129u
#define NFC_TAG_NTAG216_LAST_PAGE 225u

/* [T2T-ISO14443-A-NTAG21x] Table 28 byte 6 — storage-size ID (213=0Fh, 215=11h, 216=13h). */
#define NFC_TAG_NTAG213_SIZE_ID 0x0Fu
#define NFC_TAG_NTAG215_SIZE_ID 0x11u
#define NFC_TAG_NTAG216_SIZE_ID 0x13u

/* [T2T-ISO14443-A-NTAG21x] factory CC byte 2 (MLEN) per density tier. */
#define NFC_TAG_NTAG213_CC_MLEN 0x12u
#define NFC_TAG_NTAG215_CC_MLEN 0x3Eu
#define NFC_TAG_NTAG216_CC_MLEN 0x6Du

/* [T2T-ISO14443-A-NTAG21x] GET_VERSION 8-byte reply fingerprint (bytes 0,1,2,3,7). */
#define NFC_TAG_NTAG_VER_FIXED_HEADER 0x00u /* byte 0 */
#define NFC_TAG_NTAG_VER_VENDOR_NXP 0x04u   /* byte 1 */
#define NFC_TAG_NTAG_VER_PRODUCT_NTAG 0x04u /* byte 2 (NTAG product type) */
#define NFC_TAG_NTAG_VER_SUBTYPE 0x02u      /* byte 3 (50 pF) */
#define NFC_TAG_NTAG_VER_PROTO_14443 0x03u  /* byte 7 ([ISO14443-3]) */
/* [T2T-ISO14443-A-NTAG21x] GET_VERSION reply is eight bytes before optional CRC-A. */
#define NFC_TAG_NTAG_VER_REPLY_LEN 8u
/* [T2T-ISO14443-A-NTAG21x] GET_VERSION FIFO buffer (version + CRC-A headroom). */
#define NFC_TAG_NTAG_GET_VERSION_RX_BUF_MAX 12u
#define NFC_TAG_NTAG_VER_SIZE_BYTE_INDEX 6u
#define NFC_TAG_NTAG_VER_PROTO_BYTE_INDEX 7u
/* [T2T-ISO14443-A-NTAG21x] READ_SIG returns 32-byte ECDSA signature payload. */
#define NFC_TAG_NTAG_SIG_REPLY_LEN 32u
/* [T2T-ISO14443-A-NTAG21x] configuration: AUTH0 is two pages after the last user page. */
#define NFC_TAG_NTAG_AUTH0_PAGE_OFFSET 2u
/* [T2T-ISO14443-A-NTAG21x] AUTH0 byte value FFh disables password protection. */
#define NFC_TAG_NTAG_AUTH0_DISABLED 0xFFu

/* ---- STMicroelectronics ST25TN512 / ST25TN01K ([T2T-ISO14443-A-ST25TN]) ---- */
#define NFC_TAG_ST25TN512_DATA_BYTES 64u
#define NFC_TAG_ST25TN01K_DATA_BYTES 160u
#define NFC_TAG_ST25TN_MAX_USER_PAGE 43u
#define NFC_TAG_ST25TN_FALLBACK_LAST_PAGE 19u
/* [T2T-ISO14443-A-ST25TN] Table 28 — factory CC byte 2 (MLEN) at delivery. */
#define NFC_TAG_ST25TN512_CC_MLEN 0x08u
#define NFC_TAG_ST25TN01K_CC_MLEN 0x14u
#define NFC_TAG_ST25TN_CC_MLEN_DEFAULT NFC_TAG_ST25TN512_CC_MLEN

/* ---- NFC Forum Type 4 Tag ([T4T-ISO14443-4] + [ISO14443-4]) ---- */
/* [ISO14443-3] section 6.5.3.4 — SAK bit 6 (0x20) set means the PICC supports
 * ISO-DEP ([ISO14443-4]); bit numbering is ISO 14443-3's 1-indexed convention. */
#define NFC_TAG_T4T_SAK_ISO14443_4_BIT 0x20u
/* [T4T-ISO14443-4] section 7.2.1.7 — minimum CC file length (15 bytes). */
#define NFC_TAG_T4T_CC_MIN_LEN 15u
/* [T4T-ISO14443-4] section 7.2.1.7 — NDEF file-control TLV: T=04h, L=06h. */
#define NFC_TAG_T4T_NDEF_TLV_TYPE 0x04u
#define NFC_TAG_T4T_NDEF_TLV_LEN 0x06u
/* [T4T-ISO14443-4] section 7.2.1.7 — valid MLe/MLc lower bounds. */
#define NFC_TAG_T4T_MLE_MIN 0x000Fu
#define NFC_TAG_T4T_MLC_MIN 0x000Du
/* [ISO14443-4] section 5.1 — RATS PDU start byte (E0h). */
#define NFC_TAG_T4T_RATS_START_BYTE 0xE0u
/* [ISO14443-4] section 5.1 — RATS PARAM byte: FSDI=7, CID=0 → 70h. */
#define NFC_TAG_T4T_RATS_PARAM_FSDI7 0x70u
/* [ISO14443-4] section 5.1 — RATS command frame length (start byte + PARAM, 2 bytes). */
#define NFC_TAG_T4T_RATS_CMD_LEN 2u
/*
 * Implementation policy: ISO-DEP transceive / deselect windows for Type 4 writes
 * on Arduino-class hosts (milliseconds).
 */
#define NFC_TAG_T4T_ISO_DEP_TRANSCEIVE_TIMEOUT_MS 300u
#define NFC_TAG_T4T_DESELECT_TRANSCEIVE_TIMEOUT_MS 50u
#define NFC_TAG_T4T_DESELECT_SETTLE_MS 52u
/* [T4T-ISO14443-4] section 7.2 — CC file identifier (E103h; same on [T4T-ISO14443-4-NT4H424]). */
#define NFC_TAG_T4T_CC_FILE_ID 0xE103u
/* [T4T-ISO14443-4] section 5.3 / [T4T-ISO14443-4-NT4H424] section 8.2.3 — NDEF Tag Application AID
 * length. */
#define NFC_TAG_T4T_NDEF_APP_AID_LEN 7u

/* ---- NXP NTAG 424 DNA ([T4T-ISO14443-4-NT4H424] Rev 3.0) ---- */
/* [T4T-ISO14443-4-NT4H424] section 1 — 416-byte user-visible file system (T4T certified). */
#define NFC_TAG_NT4H424_USER_MEMORY_BYTES 416u
/* [T4T-ISO14443-4-NT4H424] section 8.2.3 — CC / NDEF / proprietary StandardData file IDs. */
#define NFC_TAG_NT4H424_CC_FILE_ID NFC_TAG_T4T_CC_FILE_ID
#define NFC_TAG_NT4H424_CC_FILE_STORAGE_BYTES 32u
#define NFC_TAG_NT4H424_CC_FILE_LEN 23u /* CCLEN 0017h at delivery (includes proprietary TLV). */
#define NFC_TAG_NT4H424_NDEF_FILE_ID 0xE104u
#define NFC_TAG_NT4H424_NDEF_FILE_SIZE 256u /* 0100h NDEF file size at delivery. */
#define NFC_TAG_NT4H424_PROP_FILE_ID 0xE105u
/* [T4T-ISO14443-4-NT4H424] section 8.2.3.2 — E105h proprietary file size 0080h at delivery. */
#define NFC_TAG_NT4H424_PROP_FILE_SIZE 128u
/* [T4T-ISO14443-4-NT4H424] section 8.2.4 — five application AES-128 keys (key numbers 0..4). */
#define NFC_TAG_NT4H424_AES_KEY_COUNT 5u
/* [T4T-ISO14443-4-NT4H424] section 8.2.3.2 — factory CC MLe/MLc (mapping version 2.0); CC
 * bytes 3..6 big-endian.
 */
#define NFC_TAG_NT4H424_DEFAULT_MLE_MSB 0x01u
#define NFC_TAG_NT4H424_DEFAULT_MLE_LSB 0x00u
#define NFC_TAG_NT4H424_DEFAULT_MLC_MSB 0x00u
#define NFC_TAG_NT4H424_DEFAULT_MLC_LSB 0xFFu
#define NFC_TAG_NT4H424_DEFAULT_MLE                                                                \
  ((uint16_t)(((uint16_t)NFC_TAG_NT4H424_DEFAULT_MLE_MSB << NFC_BYTE_SHIFT_8) |                    \
              NFC_TAG_NT4H424_DEFAULT_MLE_LSB))
#define NFC_TAG_NT4H424_DEFAULT_MLC                                                                \
  ((uint16_t)(((uint16_t)NFC_TAG_NT4H424_DEFAULT_MLC_MSB << NFC_BYTE_SHIFT_8) |                    \
              NFC_TAG_NT4H424_DEFAULT_MLC_LSB))
/*
 * SUN/SDM/AES secure messaging ([T4T-ISO14443-4-NT4H424] sections 9–10) is intentionally out of
 * scope for the plain-NDEF reader/writer paths; only file IDs and CC geometry above
 * are referenced here.
 */

/* ---- FIDO CTAP 2.3 NFC transport ([CTAP2.3] section 11.3) ---- */
/* [CTAP2.3] section 11.3.3 — FIDO2 application identifier (RID + PIX). */
#define NFC_CTAP_FIDO_AID_LEN 8u
#define NFC_CTAP_INS_MSG 0x10u                  /* [CTAP2.3] section 11.3.7.1 NFCCTAP_MSG */
#define NFC_CTAP_INS_GETRESPONSE 0x11u          /* [CTAP2.3] section 11.3.7.2 NFCCTAP_GETRESPONSE */
#define NFC_CTAP_INS_CONTROL 0x12u              /* [CTAP2.3] section 11.3.4 NFCCTAP_CONTROL */
#define NFC_CTAP_P1_CONTROL_END 0x01u           /* [CTAP2.3] section 11.3.4 END CTAP_MSG */
#define NFC_CTAP_P1_GETRESPONSE_SUPPORTED 0x80u /* [CTAP2.3] section 11.3.7.1 P1 bit 7 */
#define NFC_CTAP_P1_GETRESPONSE_CANCEL 0x11u    /* [CTAP2.3] §11.3.7.2 cancel poll P1 */
#define NFC_CTAP_CMD_MAKE_CREDENTIAL 0x01u
#define NFC_CTAP_CMD_GET_ASSERTION 0x02u
#define NFC_CTAP_CMD_GET_INFO 0x04u
#define NFC_CTAP_CMD_CLIENT_PIN 0x06u
#define NFC_CTAP_RP_ID_HEADROOM 2u /* [CTAP2.3] CBOR text-string type + length bytes */
#define NFC_CTAP_RP_ID_MAX (NFC_CBOR_ONE_BYTE_LEN_MAX - NFC_CTAP_RP_ID_HEADROOM)
/* [CTAP2.3] CBOR text-string headroom cap for RP ID encoding. */
/* [CTAP2.3] recommended ISO-DEP APDU buffer for CTAP over NFC. */
#define NFC_CTAP_APDU_BUF_RECOMMENDED 820u
/* [ISO14443-4] ISO-DEP I-block PCB (+ optional CID/NAD) before CTAP APDU body. */
#define NFC_ISO_DEP_IBLOCK_TX_OVERHEAD 12u
#define NFC_ISO_DEP_IBLOCK_TX_BUF_LEN                                                              \
  (NFC_CTAP_APDU_BUF_RECOMMENDED + NFC_ISO_DEP_IBLOCK_TX_OVERHEAD)
/* [ISO14443-4] section 7.2 — RATS/ATS exchange timeout (FWT headroom). */
#define NFC_ISO_DEP_RATS_TIMEOUT_MS 400u
/* [CTAP2.3] section 11.3.5.1 — NFCCTAP command class byte (proprietary short CLA). */
#define NFC_CTAP_CLA 0x80u
/* [CTAP2.3] section 6.1 / [WebAuthn] — clientDataHash is a 32-byte SHA-256 digest. */
#define NFC_CTAP_CLIENT_HASH_LEN 32u
/* [CTAP2.3] section 6.4 — authenticatorGetInfo AAGUID field width (16 bytes). */
#define NFC_CTAP_AAGUID_LEN 16u
/* [CTAP2.3] section 8.1 — CTAP2 status byte 0 means success in response payload. */
#define NFC_CTAP_STATUS_SUCCESS 0x00u
/* [CTAP2.3] section 6.3 — CTAP2 error codes surfaced in NFC response bodies. */
#define NFC_CTAP_ERR_INVALID_COMMAND 0x01u
#define NFC_CTAP_ERR_INVALID_PARAMETER 0x02u
#define NFC_CTAP_ERR_CBOR_UNEXPECTED_TYPE 0x11u
#define NFC_CTAP_ERR_INVALID_CBOR 0x12u
#define NFC_CTAP_ERR_MISSING_PARAMETER 0x14u
#define NFC_CTAP_ERR_NO_CREDENTIALS 0x2Eu
#define NFC_CTAP_ERR_KEEPALIVE_CANCEL 0x2Du    /* [CTAP2.3] §8.2 CTAP2_ERR_KEEPALIVE_CANCEL */
#define NFC_CTAP_ERR_USER_ACTION_TIMEOUT 0x2Fu /* [CTAP2.3] §8.2 CTAP2_ERR_USER_ACTION_TIMEOUT */
#define NFC_CTAP_ERR_PIN_INVALID 0x31u         /* [CTAP2.3] §8.2 CTAP2_ERR_PIN_INVALID */
#define NFC_CTAP_ERR_PIN_BLOCKED 0x32u         /* [CTAP2.3] §8.2 CTAP2_ERR_PIN_BLOCKED */
#define NFC_CTAP_ERR_PIN_AUTH_INVALID 0x33u    /* [CTAP2.3] §8.2 CTAP2_ERR_PIN_AUTH_INVALID */
#define NFC_CTAP_ERR_PUAT_REQUIRED 0x36u       /* [CTAP2.3] §8.2 CTAP2_ERR_PUAT_REQUIRED */
#define NFC_CTAP_ERR_INVALID_CHANNEL 0x0Bu     /* [CTAP2.3] §8.2 CTAP1_ERR_INVALID_CHANNEL */
#define NFC_CTAP_ERR_UNAUTHORIZED_PERMISSION 0x40u /* [CTAP2.3] §8.2 */
#define NFC_CTAP_ERR_OTHER 0x7Fu
/* [CTAP2.3] section 6.2 — authenticatorGetAssertion CBOR map keys (unsigned integer
 * keys): rpId 0x01, clientDataHash 0x02, allowList 0x03, extensions 0x04,
 * options 0x05. The serial demo request carries the "up"/"uv" options map, so
 * it uses the options key (0x05), not the extensions key (0x04). */
#define NFC_CTAP_CBOR_KEY_RP_ID 0x01u
#define NFC_CTAP_CBOR_KEY_CLIENT_DATA_HASH 0x02u
#define NFC_CTAP_CBOR_KEY_ALLOW_LIST 0x03u
#define NFC_CTAP_CBOR_KEY_OPTIONS 0x05u
/* [CTAP2.3] authenticatorGetInfo map keys. */
#define NFC_CTAP_GET_INFO_KEY_VERSIONS 0x01u
#define NFC_CTAP_GET_INFO_KEY_AAGUID 0x03u
#define NFC_CTAP_GET_INFO_KEY_OPTIONS 0x04u
/* [RFC8949-CBOR-CTAP2] RFC 8949 — major types and inline-length limits for CTAP CBOR builders. */
#define NFC_CBOR_MAJOR_UNSIGNED 0u
#define NFC_CBOR_MAJOR_NEGATIVE 1u
#define NFC_CBOR_MAJOR_BYTES 2u
#define NFC_CBOR_MAJOR_TEXT 3u
#define NFC_CBOR_MAJOR_ARRAY 4u
#define NFC_CBOR_MAJOR_MAP 5u
#define NFC_CBOR_MAJOR_FLOAT_SIMPLE 7u
#define NFC_CBOR_AI_INLINE_MAX 23u
#define NFC_CBOR_ONE_BYTE_LEN_MAX 255u
#define NFC_CBOR_HEADER_ONE_BYTE_BYTES 0x58u
#define NFC_CBOR_HEADER_TWO_BYTE_BYTES 0x59u
#define NFC_CBOR_HEADER_ONE_BYTE_TEXT 0x78u
#define NFC_CBOR_INLINE_TEXT_BASE 0x60u
#define NFC_CBOR_INLINE_BYTES_BASE 0x40u
#define NFC_CBOR_BOOL_TRUE 0xF5u
#define NFC_CBOR_BOOL_FALSE 0xF4u
#define NFC_CBOR_SIMPLE_TRUE 21u
#define NFC_CBOR_HDR_INLINE 1u
#define NFC_CBOR_HDR_UINT8 2u
#define NFC_CBOR_HDR_UINT16 3u
/* [CTAP2.3] getAssertion CBOR container headers (map/array arity). */
#define NFC_CTAP_CBOR_MAP_PK_CRED 0xA2u
/* [CTAP2.3] section 6.2 — options is a 2-entry map ({"up", "uv"}); CBOR map(2). */
#define NFC_CTAP_CBOR_MAP_OPTIONS 0xA2u
#define NFC_CTAP_CBOR_MAP_GET_ASSERTION_NO_ALLOW 0xA3u
#define NFC_CTAP_CBOR_MAP_GET_ASSERTION_WITH_ALLOW 0xA4u
#define NFC_CTAP_CBOR_ARRAY_ONE 0x81u
/* [CTAP2.3] fixed CBOR segment sizes in getAssertion encoder. */
#define NFC_CTAP_GET_ASSERTION_CDH_PREFIX_LEN 3u
/* options segment = key (0x05) + map(2) header (0xA2). */
#define NFC_CTAP_GET_ASSERTION_OPTIONS_PREFIX_LEN 2u
/* options body = {"up": true} (4 B) + {"uv": false} (4 B). */
#define NFC_CTAP_GET_ASSERTION_OPTIONS_BODY_LEN 8u
#define NFC_CTAP_GET_ASSERTION_RP_KEY_LEN 1u
#define NFC_CTAP_GET_ASSERTION_MAP_HDR_LEN 1u
#define NFC_CTAP_PK_CRED_DESCRIPTOR_HDR_LEN 20u
#define NFC_CTAP_PK_CRED_DESCRIPTOR_EXTRA 50u
/* [CTAP2.3] section 11.3.7 / [ISO7816-4] §7 — short vs extended C-APDU layout (bytes). */
#define NFC_CTAP_APDU_SHORT_HDR_LEN 6u
#define NFC_CTAP_APDU_EXTENDED_HDR_LEN 8u
#define NFC_CTAP_APDU_EXTENDED_LC_MSB_OFFSET 5u
#define NFC_CTAP_APDU_EXTENDED_LC_LSB_OFFSET 6u
#define NFC_CTAP_APDU_EXTENDED_CMD_OFFSET 7u
#define NFC_CTAP_APDU_EXTENDED_LC_HDR_OFFSET 7u
#define NFC_CTAP_APDU_EXTENDED_TAIL_LEN 2u
#define NFC_CTAP_APDU_SHORT_CMD_OFFSET 5u
#define NFC_CTAP_APDU_SHORT_TAIL_LEN 1u
#define NFC_CTAP_APDU_PAYLOAD_HDR_SHORT 6u
#define NFC_CTAP_APDU_PAYLOAD_HDR_EXTENDED 9u
#define NFC_CTAP_RESPONSE_STATUS_PREFIX_LEN 3u
/* [CTAP2.3] §11.3.5.2 — CTAP status byte + CBOR body + trailing ISO7816 SW1/SW2 (3-byte tail). */
#define NFC_CTAP_CBOR_HDR_INLINE 1u /* first CBOR byte offset after CTAP status byte */
#define NFC_CTAP_MIN_RESPONSE_BODY_LEN NFC_CTAP_RESPONSE_STATUS_PREFIX_LEN
#define NFC_BYTE_SHIFT_8 8u
/* Maximum value of an 8-bit byte; use as the low-byte mask (x & 0xFF). */
#define NFC_BYTE_VALUE_MAX 0xFFu

/* ---- RFC 6350 vCard field constraints ---- */
/*
 * [RFC6350] ASCII control characters are code points below space; reject them in property values.
 */
#define NFC_RFC6350_ASCII_FIRST_PRINTABLE 0x20u
/* [RFC6350] section 3.3 — vCard 4.0 VERSION property value. */
#define NFC_RFC6350_VCARD_VERSION_MAJOR 4u

/* ---- PC/SC / CCID / ISO7816 reader-emulation geometry ---- */
/* [ISO7816-3] section 8.2 — historical bytes field width cap in PC/SC ATR. */
#define NFC_ISO7816_HISTORICAL_BYTES_MAX 15u

/* ---- NFC Forum Type 5 Tag ([T5T-ISO15693] + ST25 datasheets) ---- */
/* [T5T-ISO15693-ST25DV] Table 169 — IC ref: 50h (ST25DV04KC), 51h (ST25DV16KC / ST25DV64KC). */
#define NFC_TAG_ST25DV_IC_REF 0x51u
#define NFC_TAG_ST25DV04KC_IC_REF 0x50u
/* [T5T-ISO15693] Get System Info — max block count with one-byte block-count field (256). */
#define NFC_TAG_T5T_ISO15693_BLOCK_COUNT_1BYTE_MAX 256u
/* [T5T-ISO15693-ST25TV] DS13304 §4.2 — ST25TV02KC silicon: 80 blocks (0..4Fh), not 256. */
#define NFC_TAG_ST25TV02KC_BLOCK_COUNT 80u
/* [T5T-ISO15693] section 4.3.1 — CC MLEN counts the T5T_Area in 8-byte units. */
#define NFC_TAG_T5T_AREA_SIZE_UNIT_BYTES 8u
/* [T5T-ISO15693] section 4.3.1 / 4.3.1.17 — CC lengths and MLEN-overflow markers. */
#define NFC_TAG_T5T_CC_LEN_SHORT 4u
#define NFC_TAG_T5T_CC_LEN_EXTENDED 8u
#define NFC_TAG_T5T_CC_MLEN_OVERFLOW 0xFFu
/* [T5T-ISO15693] section 4.3.1.17 — CC byte 3 bit 2 (Android MLEN-overflow flag). */
#define NFC_TAG_T5T_CC_MLEN_OVERFLOW_CC3_FLAG 0x04u

/* [T5T-ISO15693] section 10.3.4 — Get System Info command header before UID. */
#define NFC_TAG_T5T_ISO15693_SYS_INFO_CMD_HEADER_LEN 2u
/* [T5T-ISO15693-ST25DV] section 7.6.23 — Extended Get System Info adds request-fields byte. */
#define NFC_TAG_ST25DV_EXT_SYS_INFO_CMD_HEADER_LEN 3u
/* [T5T-ISO15693-ST25DV] section 7.6.23 Table 164 — request DSFID+AFI+memory+IC ref (0Fh). */
#define NFC_TAG_ST25DV_EXT_SYS_INFO_REQUEST_FIELDS 0x0Fu

/* [T5T-ISO15693] section 10.3.4 — minimum Get System Info reply (flags+info+UID). */
#define NFC_TAG_T5T_ISO15693_SYS_INFO_MIN_REPLY_LEN 11u
/*
 * [T5T-ISO15693-ST25DV] section 7.6.23 — Extended Get System Info minimum-accept guard:
 * 10-byte preamble (response flags + info flags + 8-byte UID) plus the 2 low
 * bytes of the block-count field needed to resolve a short-CC MLEN overflow. The
 * extended parser bounds-checks each optional field against the real reply length,
 * so a full all-fields reply (DSFID+AFI+memory+IC ref) is 16 B before CRC.
 */
#define NFC_TAG_ST25DV_EXT_SYS_INFO_MIN_REPLY_LEN 12u
/* [T5T-ISO15693] Extended Get System Info — preamble before optional fields (10 B). */
#define NFC_TAG_T5T_ISO15693_SYS_INFO_EXT_MIN_REPLY_LEN 10u
/* [T5T-ISO15693] section 10.3.4 — UID field length in System Info responses. */
#define NFC_TAG_T5T_ISO15693_SYS_INFO_UID_FIELD_LEN 8u
/* [DERIVED] Zero-based last-byte index from the 8-byte UID length; not a standalone SPEC entry. */
#define NFC_TAG_T5T_ISO15693_UID_MSB_BYTE_INDEX 7u
/* [T5T-ISO15693] raw Get System Info field storage in nfc_tag_type5_info_t::raw. */
#define NFC_TAG_T5T_SYS_INFO_RAW_FIELD_MAX 16u
/* [T5T-ISO15693] section 10.3.4 — response flags bit 0 (error flag). */
#define NFC_TAG_T5T_ISO15693_RESP_FLAG_ERROR 0x01u
/* [T5T-ISO15693] section 10.3.4 — info flags: DSFID / AFI / memory / IC reference. */
#define NFC_TAG_T5T_ISO15693_INFO_FLAG_DSFID 0x01u
#define NFC_TAG_T5T_ISO15693_INFO_FLAG_AFI 0x02u
#define NFC_TAG_T5T_ISO15693_INFO_FLAG_MEMORY_SIZE 0x04u
#define NFC_TAG_T5T_ISO15693_INFO_FLAG_IC_REF 0x08u
/* [T5T-ISO15693] info-flag preamble: response flags + info flags (2 bytes). */
#define NFC_TAG_T5T_ISO15693_SYS_INFO_PREAMBLE_LEN 2u
/* [T5T-ISO15693] memory-size field width in standard Get System Info (2 bytes). */
#define NFC_TAG_T5T_ISO15693_MEMORY_SIZE_FIELD_LEN 2u
/* [T5T-ISO15693-ST25DV] section 7.6.23 — extended memory-size field width (3 bytes). */
#define NFC_TAG_ST25DV_EXT_MEMORY_SIZE_FIELD_LEN 3u
/* [T5T-ISO15693] scratch buffer for Extended Get System Info replies. */
#define NFC_TAG_T5T_ISO15693_SYS_INFO_RAW_BUF_MAX 20u

/*
 * Implementation policy: generic Type 5 RF write tuning. Typical RF EEPROM programming time is
 * ~5 ms per block (ST25TV DS13304 / ST25DV DS13519 section 7.6); host settle is
 * rounded up for margin.
 */
#define NFC_TAG_T5T_RF_WRITE_SETTLE_MS 8u

/* ---- Type 2 / Type 5 write-verify implementation policy ---- */
/* Settle after Type 2 EEPROM program before read-back verify. */
#define NFC_TAG_T2T_WRITE_VERIFY_SETTLE_MS 5u
#define NFC_TAG_T2T_WRITE_FAIL_SETTLE_MS NFC_TAG_T5T_RF_WRITE_SETTLE_MS
/* Reader-path Type 2 retry budget after a missed write ACK or failed read-back verify. */
#define NFC_TAG_READER_TYPE2_WRITE_ATTEMPTS 3u
/*
 * [T2T-ISO14443-A-NTAG21x] Type 2 NDEF scan cap: NTAG216 user area (888 B) plus
 * margin; CC MLEN and per-IC page caps still bound real tag access.
 */
#define NFC_TAG_T2T_HOST_NDEF_SCAN_MAX 912u

/* ---- RF transceive timeouts (milliseconds) ---- */
/* [T2T-ISO14443-A-NTAG21x] READ / GET_VERSION transceive window on ISO14443-A link. */
#define NFC_TAG_T2T_READ_TIMEOUT_MS 20u
/* [T2T-ISO14443-A-NTAG21x] READ_SIG — longer reply than GET_VERSION. */
#define NFC_TAG_T2T_READ_SIG_TIMEOUT_MS 30u
/* [T2T-ISO14443-A-NTAG21x] section 10.4 Table 34 — WRITE TTimeOut for 4-bit ACK/NAK. */
#define NFC_TAG_T2T_WRITE_ACK_TIMEOUT_MS 10u
/* [T5T-ISO15693] single-block read/write transceive window. */
#define NFC_TAG_T5T_ISO15693_TRANSCEIVE_TIMEOUT_MS 30u
