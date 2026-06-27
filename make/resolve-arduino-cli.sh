#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2026 Nero Duality, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Print the repo-pinned arduino-cli path (never a system install).
#
# Bootstrap first: make third-party-host-tools
#
# Usage: bash make/resolve-arduino-cli.sh [FIRMWARE_ROOT]
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat <<'EOF'
Usage: bash make/resolve-arduino-cli.sh [FIRMWARE_ROOT]

Prints third-party/arduino-cli/arduino-cli. Run `make third-party-host-tools` first.
EOF
  exit 0
fi

# shellcheck source=lib-firmware-root.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib-firmware-root.sh"
root="$(nero_resolve_firmware_root "${1:-}")"

cli="${root}/third-party/arduino-cli/arduino-cli"
if [[ ! -x "${cli}" ]]; then
  echo "ERROR: pinned arduino-cli not found at ${cli}" >&2
  echo "  Run: make -C \"${root}\" third-party-host-tools" >&2
  exit 1
fi

printf '%s\n' "${cli}"
