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

# Tutorial: Read and write NFC tags

Flash firmware on [supported hardware](../README.md#supported-hardware), write NDEF records, and read tag details from Type 2, Type 4, and Type 5 tags.

## 1. Flash firmware

Default `TARGET=arduino_uno_r4wifi`. Alternate: `# TARGET=nucleo_wba65ri …`.

Option 1: Serial reader/writer (simplest):

```bash
make flash-cdc
```

Option 2: USB smart-card reader (PC/SC):

```bash
make flash
```

## 2. Host setup

From the repo root:

```bash
make userspace
make install-userspace
export PATH="${HOME}/.local/bin:${PATH}"
```

Serial reader/writer (simplest):

```bash
sudo make install-udev
```

Replug the board after `install-udev`.

USB smart-card reader (PC/SC):

See [CCID.md § Linux setup](CCID.md#linux-setup) to install distro packages, then run:

```bash
sudo make install-pcsc-driver
```

### CCID vs CDC performance

The CDC serial shell talks to the firmware directly. CCID goes through `pcscd`
and one bulk `XfrBlock` per host APDU, so CDC is usually faster for the same
operation.

On CCID, Type 4 is the quickest tag family: plain ISO-DEP `SELECT`, then
chunked `READ BINARY` / `UPDATE BINARY` on the NDEF file. Type 2 and Type 5 use
PC/SC Part 3 storage instead—page- or block-sized `READ`/`UPDATE BINARY` (Type
5 can fall back to transparent ISO15693)—which means more round trips. Reads
fetch NDEF first; optional `GET DATA` adds tag metadata but not Type 2 `AUTH0`.

## 3. Write NDEF

Use the same flags over serial or PC/SC. Remove the tag before the next write.

```bash
writer --text='hello NFC'
writer --uri=https://example.test/one --uri=https://example.test/two
writer --wifi='SSID|passphrase'
writer --contact='Ada Lovelace|+15551234567|ada@example.test'
writer --ndef-hex=0311D1010D55036578616D706C652E74657374FE
```

**Hold card over or place directly on the antenna until message `*** SUCCESS - Wrote NDEF message ***` appears**.

USB CCID / PC/SC firmware mode: It may take a bit — see
[CCID vs CDC performance](#ccid-vs-cdc-performance).

## 4. Read tags

```bash
reader   # or `reader --no-open-url`
```

**Hold card over or place directly on the antenna until metadata appears**.

USB CCID / PC/SC firmware mode: It may take a bit — see
[CCID vs CDC performance](#ccid-vs-cdc-performance).

## Capabilities and limitations

The firmware reads and writes **plain NDEF** on NFC Forum Type 2, Type 4, and
Type 5 tags. The limits below are intentional.

- **Type 2 — password-protected tags are read-only for writes.** When a tag
  advertises `AUTH0`/`PWD` protection, the firmware detects it. If the data area
  is readable without authentication, NDEF is parsed normally. Writes **fail
  closed** because the firmware does not send `PWD_AUTH`; it will not modify a
  protected tag.
- **Type 4 — plain NDEF only.** Access uses the standard Type 4 flow in plain
  communication mode: `SELECT` the NDEF application → `SELECT`/read the
  Capability Container (CC) → `ReadBinary`/`UpdateBinary` on the NDEF file. A
  factory-default **NTAG424 DNA** allows plain read and write of its NDEF file
  (mapping version 2.0, 23-byte CC, NDEF file at `E104h`) and is handled like any
  other Type 4 tag. **Secure Messaging** is not supported—authenticated/encrypted
  file access, SDM/SUN mirroring, and LRP. If access conditions require secure
  messaging, reads report restricted access and writes **fail closed**.
  [YubiKey NFC security keys](https://www.yubico.com/us/product/yubikey-5-series/yubikey-5c-nfc/)
  and [Cryptnox NFC FIDO cards](https://cryptnox.com/fido2-security-key-nfc-compatible-passwordless-key/)
  are also Type 4 ISO-DEP devices, but WebAuthn requires CCID firmware and APDU
  relay rather than plain NDEF read/write—see
  [Tutorial: WebAuthn with CCID firmware](TUTORIAL_WEBAUTHN_CCID.md).
- **Type 5 — block addressing.** **Writes** accept NDEF payloads up to 880
  bytes, which fit within single-byte ISO/IEC 15693 block addressing (blocks
  0–255). **Reads** also use extended (two-byte) block addressing when needed
  for larger dynamic ST25DV tags.

## Authoritative sources

The following external references apply.

### Spec traceability

| Area | SPEC Prefix | Public source |
| ---- | ----------- | ------------- |
| Bluetooth Secure Simple Pairing OOB over NFC | `[BT-OOB]` | [NFC Forum Bluetooth Secure Simple Pairing Using NFC 1.3](https://nfc-forum.org/uploads/specifications/NFCForum-AD-BTSSP-1.3.pdf) (`--bt` OOB pairing record) |
| USB CCID device class | `[CCID1.10]` | [USB-IF CCID 1.10](https://www.usb.org/sites/default/files/DWG_Smart-Card_CCID_Rev110.pdf) |
| ISO/IEC 14443-3 (Type A activation / UID) | `[ISO14443-3]` | [ISO/IEC 14443-3:2018](https://www.iso.org/standard/73598.html) |
| ISO/IEC 14443-4 (ISO-DEP) | `[ISO14443-4]` | [ISO/IEC 14443-4:2018](https://www.iso.org/standard/73599.html) |
| ISO/IEC 7816-3 (ATR / historical bytes) | `[ISO7816-3]` | [ISO/IEC 7816-3:2006](https://www.iso.org/standard/38770.html) |
| ISO/IEC 7816-4 (APDU / status words) | `[ISO7816-4]` | [ISO/IEC 7816-4:2020](https://www.iso.org/standard/77180.html) (SELECT / READ BINARY / UPDATE BINARY; Tables 5–6 SW1/SW2) |
| ISO/IEC 7816-6 (application identifiers / RID) | `[ISO7816-6]` | [ISO/IEC 7816-6:2023](https://www.iso.org/standard/77181.html) |
| ISO/IEC JTC 1/SC 17 IC manufacturer register | `[SC17-ICM]` | [SC 17 Standing Document 5 — Register of IC Manufacturers](https://www.aimglobal.org/wp-content/uploads/2022/04/ISO_IEC_JTC1_SC17_Standing_Document_5_Register_of_IC_Manufacturers.pdf) (UID manufacturer codes such as ST `02h`, NXP `04h`) |
| PC/SC host model (Part 1) | `[PCSC-P1]` | [PC/SC Part 1 v2.01.01](https://pcscworkgroup.com/Download/Specifications/pcsc1_v2.01.01.pdf) (host `SCard*` API; reader selection) |
| PC/SC contactless storage (Part 3) | `[PCSC-P3]` | [PC/SC Part 3 v2.01.09](https://pcscworkgroup.com/Download/Specifications/pcsc3_v2.01.09.pdf) (storage ATR, GET DATA, Type 2/4/5 tag access over PC/SC) |
| NFC Forum tag operations | `[NDEF]` | [NFC Forum specifications](https://nfc-forum.org/build/specifications) |
| IETF RFC 3986 (URI generic syntax) | `[RFC3986]` | [RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986) (`--uri`, `--mail`, and `--sms` percent encoding) |
| IETF RFC 6350 (vCard) | `[RFC6350]` | [RFC 6350](https://datatracker.ietf.org/doc/html/rfc6350) (`--contact` field encoding) |
| NXP PN532 reader command compatibility | `[PN532]` | [PN532 User Manual UM0701-02](https://www.nxp.com/docs/en/user-guide/141520.pdf) (PN53x/ACR122-style direct APDU compatibility path) |
| ACS ACR122U pseudo-APDUs | `[ACR122U API]` | [ACR122U Application Programming Interface v2.02](https://downloads.acs.com.hk/drivers/en/API-ACR122U-2.02.pdf) (`FF 00 48 00 00` firmware-version pseudo-APDU) |
| NFC Forum Type 2 | `[T2T-ISO14443-A]` | [Type 2 Tag Specification](https://nfc-forum.org/build/specifications/type-2-tag-specification/) |
| NXP Type 2 tags | `[T2T-ISO14443-A-NTAG21x]` | [NTAG213/215/216 datasheet](https://www.nxp.com/docs/en/data-sheet/NTAG213_215_216.pdf) |
| ST Type 2 tags | `[T2T-ISO14443-A-ST25TN]` | [ST25TN512/ST25TN01K datasheet](https://www.st.com/resource/en/datasheet/st25tn512.pdf) |
| NFC Forum Type 4 | `[T4T-ISO14443-4]` | [Type 4 Tag Specification](https://nfc-forum.org/build/specifications/type-4-tag-specification/) |
| NXP NTAG424 DNA | `[T4T-ISO14443-4-NT4H424]` | [NT4H2421Gx datasheet](https://www.nxp.com/docs/en/data-sheet/NT4H2421Gx.pdf) (plain NDEF only; Secure Messaging not supported) |
| ISO/IEC 15693 (Type 5 vicinity RF) | `[T5T-ISO15693]` | [ISO/IEC 15693-3:2026](https://www.iso.org/standard/90286.html) |
| NFC Forum Type 5 | `[T5T-NFCFORUM]` | [Type 5 Tag Specification](https://nfc-forum.org/build/specifications/type-5-tag-specification/) |
| ST dynamic Type 5 tags | `[T5T-ISO15693-ST25DV]` | [ST25DV04KC/16KC/64KC datasheet](https://www.st.com/resource/en/datasheet/st25dv04kc.pdf) |
| ST Type 5 tags | `[T5T-ISO15693-ST25TV]` | [ST25TV02KC datasheet](https://www.st.com/resource/en/datasheet/st25tv02kc.pdf) |
| Wi‑Fi Simple Configuration (WSC) | `[WSC]` | [Wi‑Fi Protected Setup / WSC specification](https://www.wi-fi.org/file/wi-fi-protected-setup-specification) (`--wifi` credential TLV) |

### Hardware and tooling

| Area | SPEC Prefix | Public source |
| ---- | ----------- | ------------- |
| Arduino UNO R4 WiFi | NA | [Arduino UNO R4 WiFi docs](https://docs.arduino.cc/hardware/uno-r4-wifi) |
| NUCLEO-WBA65RI | NA | [NUCLEO-WBA65RI ST product page](https://www.st.com/en/evaluation-tools/nucleo-wba65ri.html) |
| Build/upload tool | NA | [Arduino CLI](https://arduino.github.io/arduino-cli/latest/) |
| ST reader libraries | NA | [stm32duino/ST25R3916](https://github.com/stm32duino/ST25R3916) and [stm32duino/NFC-RFAL](https://github.com/stm32duino/NFC-RFAL) |
| TinyUSB | NA | [hathach/tinyusb](https://github.com/hathach/tinyusb) |
| X-NUCLEO-NFC08A1 reader shield | NA | [X-NUCLEO-NFC08A1](https://www.st.com/en/evaluation-tools/x-nucleo-nfc08a1.html), [ST25R3916B](https://www.st.com/en/nfc/st25r3916b.html) ([UM3007](https://www.st.com/resource/en/user_manual/um3007-getting-started-with-the-nfc-card-reader-expansion-board-based-on-st25r3916b-for-stm32-and-stm8-nucleos-stmicroelectronics.pdf)) |
| ST Type 4 tags | NA | [ST25TA02K datasheet](https://www.st.com/resource/en/datasheet/st25ta02kb.pdf) |
| NXP NTAG I2C Plus | NA | [NT3H2111/2211 datasheet](https://www.nxp.com/docs/en/data-sheet/NT3H2111_2211.pdf) |
| X-NUCLEO-NFC07A1 tag dev board | NA | [X-NUCLEO-NFC07A1](https://www.st.com/en/evaluation-tools/x-nucleo-nfc07a1.html), [ST25DV64KC](https://www.st.com/en/nfc/st25dv64kc.html) ([UM2960](https://www.st.com/resource/en/user_manual/um2960-getting-started-with-the-xnucleonfc07a1-nfcrfid-tag-ic-expansion-board-based-on-st25dv64kc-for-stm32-nucleo-stmicroelectronics.pdf)) |

PDFs for FIDO Device Onboard, Credential Exchange Format, ICAO eMRTD, and BSI
eID/eSign are not required for tag read/write in this tutorial.
