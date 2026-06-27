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

<!-- Upstream: https://github.com/neroduality/nero-nfc-reader-firmware -->

# nero-nfc-reader-firmware

[![Main CI](https://img.shields.io/github/actions/workflow/status/neroduality/nero-nfc-reader-firmware/main-ci.yml?branch=main&label=Main%20CI)](https://github.com/neroduality/nero-nfc-reader-firmware/actions/workflows/main-ci.yml)
[![Release](https://img.shields.io/github/v/release/neroduality/nero-nfc-reader-firmware?label=Release&color=939C9E)](https://github.com/neroduality/nero-nfc-reader-firmware/releases)
[![Documentation](https://img.shields.io/badge/docs-read-38D868.svg)](docs/)

<p align="left">
  <img src="docs/img/nero-nfc.png" alt="Nero NFC" width="120">
</p>

**Open Desktop NFC Reader**: firmware and Linux host CLI tools for turning a
supported MCU board with an ST25R3916B RF reader frontend into an NFC reader/writer
/ USB CCID smart-card reader.

**Development is supported on Linux hosts only** (build, flash, host CLIs, and
tests).

This is **source-build only**: no supported release bundles or prebuilt firmware
images.

## What it does

It is reader firmware, not a FIDO authenticator. The tapped security key/card
keeps the credentials and private keys.

- Reads NFC Forum Type 2, Type 4, and Type 5 tags (Type 5 when RF hardware supports ISO15693).
- Writes NDEF records.
- Plain NDEF storage tags only—no Secure Messaging or password-protected writes.
- Two USB firmware modes: CDC serial shell or USB CCID; PC/SC uses USB CCID.
- Optionally lets PC/SC hosts use a tapped NFC FIDO security key/card for
  WebAuthn passwordless sign-in by relaying CTAP APDUs over Type 4 ISO-DEP.

## Quick start

You need a supported board, [X-NUCLEO-NFC08A1](https://www.st.com/en/evaluation-tools/x-nucleo-nfc08a1.html) shield, USB data cable, and NFC tags — see [Supported hardware](#supported-hardware).

**1. Build and flash firmware** ([firmware](INSTALLATION.md#firmware)) — serial shell (simplest quick start):

Default `TARGET=arduino_uno_r4wifi`. Alternate: `# TARGET=nucleo_wba65ri …`.

```sh
make deps
make flash-cdc
```

USB CCID reader (PC/SC): `make flash` instead — [CCID host setup](docs/CCID.md#linux-setup).

**2. Install host userspace CLIs** ([host](INSTALLATION.md#host)):

```sh
make userspace
make install-userspace
export PATH="${HOME}/.local/bin:${PATH}"
```

**3. One-time Linux setup** ([host](INSTALLATION.md#host)) — after serial flash:

```sh
sudo make install-udev
```

Replug the board. After `make flash` (PC/SC), use [CCID.md § Linux setup](docs/CCID.md#linux-setup) instead.

**4. Read or write tags** — tap a tag when prompted ([TUTORIAL_TAGS.md](docs/TUTORIAL_TAGS.md)):

```sh
reader --no-open-url
writer --uri=https://example.test/ --uri=https://example2.test/
```

**Optional — WebAuthn** with an NFC FIDO security key: follow [TUTORIAL_WEBAUTHN_CCID.md](docs/TUTORIAL_WEBAUTHN_CCID.md). Not required for tag read/write.

Developers: `make help`.

## Documentation

See [docs/](docs/) for tutorials, [CCID host setup](docs/CCID.md), and
[spec traceability](docs/spec-traceability.yaml) (compliance, coverage, and drift checks).

## Supported hardware

<table>
<thead>
<tr>
<th align="left">Layer</th>
<th align="left">Hardware</th>
<th align="left">Notes</th>
</tr>
</thead>
<tbody>
<tr>
<td>MCU board</td>
<td>Option 1: <a href="https://docs.arduino.cc/hardware/uno-r4-wifi">Arduino UNO R4 WiFi</a></td>
<td><ul>
<li>Default <code>TARGET=arduino_uno_r4wifi</code></li>
<li>Built and uploaded with Arduino CLI over USB</li>
<li>CCID USB (<code>0x2341:0x006D</code>)</li>
<li>CCID USB: Arduino core's bundled TinyUSB, patched via <code>patches/arduino/renesas_uno/</code></li>
</ul></td>
</tr>
<tr>
<td>MCU board</td>
<td>Option 2: <a href="https://www.st.com/en/evaluation-tools/nucleo-wba65ri.html">NUCLEO-WBA65RI</a></td>
<td><ul>
<li><code>TARGET=nucleo_wba65ri</code></li>
<li>Flash via on-board ST-Link (project OpenOCD)</li>
<li>CCID USB on CN9 (<code>0x2341:0x006E</code>)</li>
<li>CCID USB: vendored upstream <a href="https://github.com/hathach/tinyusb">TinyUSB</a> (unpatched); board support in <code>patches/arduino/stm32/wba65/</code></li>
</ul></td>
</tr>
<tr>
<td style="border-top: 2px solid #888">RF reader shield</td>
<td style="border-top: 2px solid #888"><a href="https://www.st.com/en/evaluation-tools/x-nucleo-nfc08a1.html">X-NUCLEO-NFC08A1</a></td>
<td style="border-top: 2px solid #888"><a href="https://www.st.com/en/nfc/st25r3916b.html">ST25R3916B</a> NFC reader shield (<a href="https://www.st.com/resource/en/user_manual/um3007-getting-started-with-the-nfc-card-reader-expansion-board-based-on-st25r3916b-for-stm32-and-stm8-nucleos-stmicroelectronics.pdf">UM3007</a>).</td>
</tr>
<tr>
<td style="border-top: 2px solid #888">NFC Forum tag</td>
<td style="border-top: 2px solid #888"><a href="https://nfc-forum.org/build/specifications/type-2-tag-specification/">Type 2 tags</a></td>
<td style="border-top: 2px solid #888"><a href="https://www.nxp.com/docs/en/data-sheet/NTAG213_215_216.pdf">NTAG213/215/216</a>, <a href="https://www.st.com/resource/en/datasheet/st25tn512.pdf">ST25TN01K/ST25TN512</a>.</td>
</tr>
<tr>
<td>NFC Forum tag</td>
<td>(Optional) <a href="https://nfc-forum.org/build/specifications/type-4-tag-specification/">Type 4 tags</a></td>
<td><a href="https://www.st.com/resource/en/datasheet/st25ta02kb.pdf">ST25TA02K</a>, <a href="https://www.nxp.com/docs/en/data-sheet/NT3H2111_2211.pdf">NTAG I2C Plus</a>, <a href="https://www.nxp.com/docs/en/data-sheet/NT4H2421Gx.pdf">NTAG424 DNA</a> (plain NDEF only), <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.pdf">NFC FIDO security keys/cards</a> (e.g. <a href="https://www.yubico.com/us/product/yubikey-5-series/yubikey-5c-nfc/">YubiKey</a>, <a href="https://cryptnox.com/fido2-security-key-nfc-compatible-passwordless-key/">Cryptnox</a>).</td>
</tr>
<tr>
<td>NFC Forum tag</td>
<td>(Optional) <a href="https://nfc-forum.org/build/specifications/type-5-tag-specification/">Type 5 tags</a></td>
<td><a href="https://www.st.com/resource/en/datasheet/st25tv02kc.pdf">ST25TV02KC</a>, <a href="https://www.st.com/resource/en/datasheet/st25dv04kc.pdf">ST25DV04KC/16KC/64KC</a>, <a href="https://www.st.com/resource/en/user_manual/um2960-getting-started-with-the-xnucleonfc07a1-nfcrfid-tag-ic-expansion-board-based-on-st25dv64kc-for-stm32-nucleo-stmicroelectronics.pdf">X-NUCLEO-NFC07A1</a>.</td>
</tr>
</tbody>
</table>

## License

| Part | Terms |
| ---- | ----- |
| This project source | Apache-2.0; see [LICENSE](LICENSE) and SPDX headers. |
| Fetched ST libraries under `third-party/` | ST license terms from each upstream tree; this firmware targets ST25R-series reader hardware. |
