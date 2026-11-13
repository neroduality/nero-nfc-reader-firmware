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

# Wipe a security key and set a new PIN

Requires the reader on **CCID** firmware (`make flash-ccid`) with
[PC/SC set up](CCID.md#linux-setup). CDC firmware will not work.

Install (to `~/.local/bin`):

```bash
make deps
make userspace
make install-userspace
```

Wipe and set a new PIN:

```bash
fido_token -R -S
```

1. Type `yes` to confirm the wipe.
2. Enter the new PIN twice (4–63 characters).
3. Tap the key and hold it on the reader until the command finishes.

This erases **all** passkeys on the key and replaces its PIN. It cannot be
undone. Use `fido_token -R` to wipe without setting a PIN.

Keys accept a reset only within a few seconds of the tap; if refused,
`fido_token` asks you to tap again.
