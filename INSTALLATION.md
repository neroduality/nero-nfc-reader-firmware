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

# Installation (Linux)

**Build from source only.** Hardware: [README § Supported hardware](README.md#supported-hardware).
Walkthroughs: [TUTORIAL_TAGS.md](docs/TUTORIAL_TAGS.md) and [TUTORIAL_WEBAUTHN_CCID.md](docs/TUTORIAL_WEBAUTHN_CCID.md).

Run from the repo root unless noted.

Two firmware modes: **serial reader/writer (CDC)** or **USB smart-card reader
(CCID / PC/SC)**. Pick one path below.

## Host

Install host dependencies and CLIs (reader, writer, and `nero_nfc_uart`).

```bash
make deps
make userspace
make install-userspace
export PATH="${HOME}/.local/bin:${PATH}"
```

Plain `make` builds CCID firmware **and** userspace.

## Firmware: Serial reader/writer (CDC)

Default `TARGET=arduino_uno_r4wifi`. Alternate: `# TARGET=nucleo_wba65ri …`.

Simplest path for tag read/write over the serial shell.

```bash
make flash-cdc              # build and upload
make nfc-cdc                # compile only
```

First-time setup: configure serial permissions and ModemManager. Replug the board.

```bash
sudo make install-udev
```

## Firmware: USB smart-card reader (CCID / PC/SC)

Default `TARGET=arduino_uno_r4wifi`. Alternate: `# TARGET=nucleo_wba65ri …`.

PC/SC CCID reader for tag tools over PC/SC and optional WebAuthn. Enable
**`pcscd.socket`**, not `pcscd.service`.

```bash
make flash                  # build and upload
make nfc                    # compile only
```

See [CCID.md § Linux setup](docs/CCID.md#linux-setup) for distro packages, then run:

```bash
sudo systemctl enable --now pcscd.socket
sudo make install-pcsc-driver
sudo systemctl restart pcscd.socket
pcsc_scan
```

Replug the board if the reader does not appear.

WebAuthn (optional): see [CCID.md § WebAuthn middleware](docs/CCID.md#webauthn-middleware)
for `pcsc-fido` install, then run:

```bash
sudo systemctl enable --now pcscd.socket pcsc-fido.service
```

## Verify

```bash
make test
make lint
make verify
make ci-local
```

See `make help` for command descriptions.

## Tutorials

Step-by-step walkthroughs after install:

- [TUTORIAL_TAGS.md](docs/TUTORIAL_TAGS.md) — read and write NDEF on Type 2, Type 4, and
  Type 5 tags (serial or PC/SC)
- [TUTORIAL_WEBAUTHN_CCID.md](docs/TUTORIAL_WEBAUTHN_CCID.md) — WebAuthn with CCID
  firmware and NFC FIDO security keys/cards
