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

# USB CCID — PC/SC setup

Supported MCU boards with CCID firmware may need `install-pcsc-driver` when their
VID:PID pairs are not in upstream `libccid` — unlike commercial CCID readers,
which usually are.

| Board | `ifdVendorID` | `ifdProductID` | `ifdFriendlyName` (PC/SC reader label) |
| ----- | ------------- | -------------- | -------------------------------------- |
| Arduino UNO R4 WiFi CCID | `0x2341` | `0x006D` | `Nero NFC Arduino UNO R4 WiFi CCID` |
| NUCLEO-WBA65RI CCID | `0x2341` | `0x006E` | `Nero NFC NUCLEO-WBA65RI CCID` |

## Linux

### Linux setup

Fedora/RHEL:

```bash
sudo dnf install pcsc-lite pcsc-lite-ccid pcsc-tools
```

Debian/Ubuntu:

```bash
sudo apt install pcscd libccid pcsc-tools
```

Then (all distros) — CCID board on USB; replug if `pcsc_scan` does not list it:

```bash
sudo systemctl enable --now pcscd.socket
sudo make install-pcsc-driver
sudo systemctl restart pcscd.socket
pcsc_scan
```

`sudo make install-pcsc-driver` patches the system `ifd-ccid.bundle` plist (backup kept).
No standalone bundle — shared `libccid.so` would collide with other readers.

Remove:

```bash
sudo bash scripts/install-pcsc-driver.sh --remove
sudo systemctl restart pcscd.socket
```

### WebAuthn middleware

Linux browsers expect FIDO keys on hidraw. Use [pcsc-fido](https://github.com/neroduality/pcsc-fido)
([releases](https://github.com/neroduality/pcsc-fido/releases),
[install guide](https://github.com/neroduality/pcsc-fido/blob/main/INSTALLATION.md)) until the
platform exposes NFC FIDO cards through PC/SC directly.

The on-air path follows [FIDO CTAP 2.3 §11.3 (NFC transport)](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.pdf)—that
framing is relayed unchanged over PC/SC; the browser side is
[WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/). For setup,
troubleshooting, and the full spec list, see
[TUTORIAL_WEBAUTHN_CCID.md](TUTORIAL_WEBAUTHN_CCID.md).

Fedora/RHEL:

```bash
sudo dnf install ./pcsc-fido-*.rpm
```

Debian/Ubuntu:

```bash
sudo dpkg -i ./pcsc-fido_*.deb && sudo apt-get install -f
```

Then (all distros):

```bash
sudo systemctl enable --now pcscd.socket pcsc-fido.service
```

Verify: `pcsc_scan` or `pcsc-fido --list-readers`. Hold the token on the coil through
the browser ceremony.

## Commercial readers

Off-the-shelf CCID NFC readers are usually recognized by upstream `libccid` without
`install-pcsc-driver`. Examples include the [HID Global OMNIKEY 5022](https://www.hidglobal.com/products/omnikey-5022-reader)
and [ACS ACR1252U](https://www.acs.com.hk/en/products/342/acr1252u-usb-nfc-reader-iii-nfc-forum-certified-reader/).
Use `pcsc_scan` or `pcsc-fido --list-readers` to confirm the reader appears.
