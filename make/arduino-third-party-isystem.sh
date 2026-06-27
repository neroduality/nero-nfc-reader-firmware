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

# Emit GCC -isystem flags for vendor trees (GCC "system headers" — see gcc Directory Options).
#
# Used with Makefile / ci-lint strict Arduino builds (SUPPRESS_ARDUINO_3P_WARNINGS=0,
# --warnings all, full -W* in compiler.*.extra_flags).
#
# Usage: bash make/arduino-third-party-isystem.sh REPO_ROOT [PROFILE]
#   PROFILE: uno (default) | wba65
set -euo pipefail

if [[ ${1:-} == -h || ${1:-} == --help ]]; then
  cat <<'EOF'
Usage: bash make/arduino-third-party-isystem.sh REPO_ROOT [PROFILE]

Print -isystem flags (one per line) for vendor Arduino compile inputs.
PROFILE is uno (default) or wba65.

Includes repo third-party/ library trees and installed Board Manager cores under
the isolated arduino-user data directory (see make/resolve-arduino-user-dir.sh).
ST25R3916 and NFC-RFAL stay -I on UNO — see ci-lint.sh arduino_vendor_st25_rfal_inc.
EOF
  exit 0
fi

if [[ $# -lt 1 ]]; then
  echo "error: REPO_ROOT required" >&2
  exit 2
fi

repo_root="$(cd "$1" && pwd)"
profile="${2:-uno}"
third_party="${repo_root}/third-party"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
arduino_user_dir="$(bash "${script_dir}/resolve-arduino-user-dir.sh" "${repo_root}")"

emit_isystem() {
  local dir="$1"
  [[ -d ${dir} ]] || return 0
  printf -- '-isystem %s\n' "${dir}"
}

emit_board_manager_isystems() {
  local packages_root="$1/packages"
  local vendor_dir hw_dir
  [[ -d ${packages_root} ]] || return 0
  for vendor_dir in "${packages_root}"/*/hardware/; do
    [[ -d ${vendor_dir} ]] || continue
    for hw_dir in "${vendor_dir}"*/*; do
      [[ -d ${hw_dir} ]] || continue
      emit_isystem "${hw_dir}"
    done
  done
}

skip_names='arduino-cli|openocd-wba65|openocd-wba65-src|arduino-user'
isystem_skip_uno='ST25R3916|NFC-RFAL'

for top in "${third_party}"/*/; do
  [[ -d ${top} ]] || continue
  base="$(basename "${top}")"
  if [[ ${base} =~ ^(${skip_names})$ ]]; then
    continue
  fi
  if [[ ${base} == tinyusb && ${profile} != wba65 ]]; then
    continue
  fi
  if [[ ${profile} == uno && ${base} =~ ^(${isystem_skip_uno})$ ]]; then
    continue
  fi
  emit_isystem "${top}src"
  emit_isystem "${top}include"
  emit_isystem "${top}"
done

emit_board_manager_isystems "${arduino_user_dir}"
