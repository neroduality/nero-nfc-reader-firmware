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

# nero-nfc-reader-firmware @TAG@

NFC reader/writer and USB CCID firmware for supported Arduino and Nucleo boards,
plus Linux host CLIs for PC/SC and CDC serial workflows.

## Changelog

<!-- Optional per-release notes below. CI publishes this template as-is when no release-specific notes are added. -->

Git history contains detailed changes. Includes general improvements and capability updates.

**Notice:** AI-assisted, human-reviewed, and hardware-tested. Source-only development firmware.

<!-- Per-release changes (optional):

- ...
-->

## Assets

- **Source:** `nero-nfc-reader-firmware-@VERSION@.tar.gz` (git archive at tag)
- **Integrity:** `SHA256SUMS` (GNU `sha256sum` format)
- **Tests:** release requires a successful **Main CI** run on the tagged commit

Verify downloads: `sha256sum -c SHA256SUMS`.

## Notes

| Item | Detail |
| ------ | -------- |
| Repository | `nero-nfc-reader-firmware` |
| Firmware targets | Arduino UNO R4 WiFi, NUCLEO-WBA65RI (+ X-NUCLEO-NFC08A1) |
| Host tools | `userspace/` CLIs (PC/SC reader/writer, CDC bridge) |
| WebAuthn posture | USB CCID reader + CTAP APDU relay — not a FIDO authenticator |
| Security reports | [SECURITY.md](https://github.com/neroduality/.github/blob/main/SECURITY.md) |
| License | Apache-2.0 |
