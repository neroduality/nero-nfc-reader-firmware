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

#include <stdint.h>

/*
 * Wi-Fi Simple Configuration (WSC) constants for the NDEF MIME type
 * "application/vnd.wfa.wsc" Out-Of-Band connection handover record.
 * Reference: Wi-Fi Alliance "Wi-Fi Simple Configuration Technical
 * Specification" (data element / attribute IDs, WSC section 12).
 *
 * Single source of truth shared by the firmware writer (writer_payload.c) and
 * the host writer (nero_nfc_writer_payload.cpp) so both binaries emit
 * byte-for-byte identical credentials and cannot drift apart.
 */
enum {
  NFC_WSC_ATTR_AUTH_TYPE = 0x1003u,
  NFC_WSC_ATTR_MAC_ADDRESS = 0x1020u,
  NFC_WSC_ATTR_NETWORK_INDEX = 0x1026u,
  NFC_WSC_ATTR_NETWORK_KEY = 0x1027u,
  NFC_WSC_ATTR_SSID = 0x1045u,
  NFC_WSC_ATTR_CREDENTIAL = 0x100Eu,
  NFC_WSC_ATTR_ENCR_TYPE = 0x100Fu,

  /* Network-key (WPA2-PSK passphrase) length bounds. */
  NFC_WSC_PSK_MIN_LEN = 8u,
  NFC_WSC_PSK_MAX_LEN = 63u,
};

/* Authentication Type = WPA2-Personal (0x0020), big-endian 2-byte value. */
#define NFC_WSC_AUTH_WPA2_PSK_INIT {0x00u, 0x20u}
/* Encryption Type = AES (0x0008), big-endian 2-byte value. */
#define NFC_WSC_ENCR_AES_INIT {0x00u, 0x08u}
/* WSC Version attribute (0x104A), length 1, value 0x10 = Version 1.0. */
#define NFC_WSC_VERSION_HEADER_INIT {0x10u, 0x4Au, 0x00u, 0x01u, 0x10u}

/* NDEF MIME (TNF 0x02) media-type string for the WSC OOB record. */
#define NFC_NDEF_MIME_WSC "application/vnd.wfa.wsc"
