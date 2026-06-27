<!-- SPDX-License-Identifier: Apache-2.0 -->
<!--
Copyright (C) 2026 Nero Duality, LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Tutorial: WebAuthn with USB CCID firmware

Flash CCID firmware on [supported hardware](../README.md#supported-hardware),
then tap an NFC FIDO key or card to authenticate with WebAuthn on Linux. This
firmware relays APDUs; credentials stay on the token.

The CCID firmware treats the host PC/SC stack as untrusted: once a Type 4 card is
identified as a FIDO/security key, WebAuthn APDU relay stays separate from plain
NDEF tag access. This keeps the security boundary in firmware even if a different
userspace binary talks to the reader.

## 1. Flash USB CCID firmware

Default `TARGET=arduino_uno_r4wifi`. Alternate: `# TARGET=nucleo_wba65ri …`.

```bash
make flash
```

## 2. Linux host

Set up PC/SC using [CCID.md § Linux setup](CCID.md#linux-setup). For the
WebAuthn browser bridge, see [CCID.md § WebAuthn middleware](CCID.md#webauthn-middleware).

## 3. Authenticate

1. Open [webauthn.io](https://webauthn.io).
2. Place the NFC FIDO key or card on the reader before you start registration or sign-in, and keep it there until the ceremony completes (enter a PIN or touch the key if required).

Use a resettable development token for repeated tests — many keys and cards
limit stored passkeys, so re-registering on sites like webauthn.io eventually
fills storage.

## 4. Troubleshooting

If authentication fails:

```bash
sudo systemctl restart pcscd.socket pcsc-fido
sudo systemctl status pcscd.socket pcsc-fido
pcsc-fido --list-readers
journalctl -u pcsc-fido -u pcscd -e
```

Remove the card, then tap again by holding it steady against the antenna or
placing it directly on the reader.

Recheck [§ 2. Linux host](#2-linux-host) for PC/SC and WebAuthn middleware setup.
You can also retry with a commercial USB CCID NFC reader—for example the
[HID Global OMNIKEY 5022](https://www.hidglobal.com/products/omnikey-5022-reader)
or [ACS ACR1252U](https://www.acs.com.hk/en/products/342/acr1252u-usb-nfc-reader-iii-nfc-forum-certified-reader/)—to
isolate board-specific issues.

## Authoritative sources

The following external references apply.

### Spec traceability

| Area | SPEC Prefix | Public source |
| ---- | ----------- | ------------- |
| USB CCID device class | `[CCID1.10]` | [USB-IF CCID 1.10](https://www.usb.org/sites/default/files/DWG_Smart-Card_CCID_Rev110.pdf) |
| FIDO CTAP 2.3 | `[CTAP2.3]` | [FIDO CTAP 2.3 PS 20260226 PDF](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.pdf) (NFC transport §11.3, including cancel `NFCCTAP_GETRESPONSE` `P1=0x11` and poll timing in §11.3.7.2) |
| ISO/IEC 14443-4 (ISO-DEP / CTAP transport) | `[ISO14443-4]` | [ISO/IEC 14443-4:2018](https://www.iso.org/standard/73599.html) (RATS/ATS, I/R/S blocks; CTAP over NFC) |
| ISO/IEC 7816-3 (ATR / historical bytes) | `[ISO7816-3]` | [ISO/IEC 7816-3:2006](https://www.iso.org/standard/38770.html) (PC/SC ATR synthesis) |
| ISO/IEC 7816-4 (APDU / status words) | `[ISO7816-4]` | [ISO/IEC 7816-4:2020](https://www.iso.org/standard/77180.html) (Tables 5–6 SW1/SW2; CTAP/CCID relay framing) |
| PC/SC host model (Part 1) | `[PCSC-P1]` | [PC/SC Part 1 v2.01.01](https://pcscworkgroup.com/Download/Specifications/pcsc1_v2.01.01.pdf) |
| PC/SC contactless storage (Part 3) | `[PCSC-P3]` | [PC/SC Part 3 v2.01.09](https://pcscworkgroup.com/Download/Specifications/pcsc3_v2.01.09.pdf) |
| NXP PN532 reader command compatibility | `[PN532]` | [PN532 User Manual UM0701-02](https://www.nxp.com/docs/en/user-guide/141520.pdf) (PN53x/ACR122-style direct APDU compatibility path) |
| ACS ACR122U pseudo-APDUs | `[ACR122U API]` | [ACR122U Application Programming Interface v2.02](https://downloads.acs.com.hk/drivers/en/API-ACR122U-2.02.pdf) (`FF 00 48 00 00` firmware-version pseudo-APDU) |
| IETF RFC 8949 (CBOR) | `[RFC8949-CBOR-CTAP2]` | [RFC 8949](https://datatracker.ietf.org/doc/html/rfc8949) (CTAP2 canonical CBOR encoding) |
| W3C WebAuthn | `[WebAuthn]` | [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) |

### Hardware and tooling

| Area | SPEC Prefix | Public source |
| ---- | ----------- | ------------- |
| Arduino UNO R4 WiFi | NA | [Arduino UNO R4 WiFi docs](https://docs.arduino.cc/hardware/uno-r4-wifi) |
| NUCLEO-WBA65RI | NA | [NUCLEO-WBA65RI ST product page](https://www.st.com/en/evaluation-tools/nucleo-wba65ri.html) |
| Build/upload tool | NA | [Arduino CLI](https://arduino.github.io/arduino-cli/latest/) |
| TinyUSB | NA | [hathach/tinyusb](https://github.com/hathach/tinyusb) |
| Cryptnox NFC FIDO cards | NA | [Cryptnox FIDO2 NFC card product page](https://cryptnox.com/fido2-security-key-nfc-compatible-passwordless-key/) |
| YubiKey NFC security keys | NA | [YubiKey 5C NFC product page](https://www.yubico.com/us/product/yubikey-5-series/yubikey-5c-nfc/) |
| Linux browser middleware | NA | [pcsc-fido releases](https://github.com/neroduality/pcsc-fido/releases) and [install docs](https://github.com/neroduality/pcsc-fido/blob/main/INSTALLATION.md) |

PDFs for FIDO Device Onboard and Credential Exchange Format are not required
for WebAuthn NFC-authenticator transport in this firmware.
