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

# Print the repo-isolated Arduino data root (directories.data + directories.user).
# Never ~/.arduino15.
#
# Usage: bash make/resolve-arduino-user-dir.sh [FIRMWARE_ROOT]
set -euo pipefail

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  cat <<'EOF'
Usage: bash make/resolve-arduino-user-dir.sh [FIRMWARE_ROOT]

Prints third-party/arduino-user (isolated Board Manager cores, tools, libraries).
EOF
  exit 0
fi

# shellcheck source=lib-firmware-root.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib-firmware-root.sh"
root="$(nero_resolve_firmware_root "${1:-}")"

if [[ -n ${ARDUINO_DIRECTORIES_DATA:-} ]]; then
  printf '%s\n' "${ARDUINO_DIRECTORIES_DATA}"
elif [[ -n ${ARDUINO_DIRECTORIES_USER:-} ]]; then
  printf '%s\n' "${ARDUINO_DIRECTORIES_USER}"
else
  printf '%s\n' "${root}/third-party/arduino-user"
fi
