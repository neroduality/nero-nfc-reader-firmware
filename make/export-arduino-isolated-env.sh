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

# Export isolated Arduino CLI data + user directories (never ~/.arduino15).
#
# Board Manager cores install under directories.data; sketchbook/manual hardware
# under directories.user. Both point at third-party/arduino-user in this repo.
#
# Usage: eval "$(bash make/export-arduino-isolated-env.sh [FIRMWARE_ROOT])"
set -euo pipefail

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  cat <<'EOF'
Usage: eval "$(bash make/export-arduino-isolated-env.sh [FIRMWARE_ROOT])"

Exports ARDUINO_DIRECTORIES_DATA and ARDUINO_DIRECTORIES_USER to
third-party/arduino-user under the firmware repo.
EOF
  exit 0
fi

dir="$(bash "$(dirname "${BASH_SOURCE[0]}")/resolve-arduino-user-dir.sh" "${1:-}")"
printf 'export ARDUINO_DIRECTORIES_DATA=%q\n' "${dir}"
printf 'export ARDUINO_DIRECTORIES_USER=%q\n' "${dir}"
