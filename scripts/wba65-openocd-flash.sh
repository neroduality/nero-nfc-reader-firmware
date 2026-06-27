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

# Flash NUCLEO-WBA65RI via project-local OpenOCD (stm32wba6x target).
#
# Usage: wba65-openocd-flash.sh --build-dir DIR [--elf PATH]
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

BUILD_DIR=""
ELF=""

usage() {
  cat <<'EOF' >&2
Usage: bash scripts/wba65-openocd-flash.sh --build-dir DIR [--elf PATH]
EOF
}

while (($# > 0)); do
  case "$1" in
    --build-dir)
      shift
      BUILD_DIR="${1:-}"
      ;;
    --elf)
      shift
      ELF="${1:-}"
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
  shift
done

[[ -n "${BUILD_DIR}" ]] || {
  echo "ERROR: --build-dir is required" >&2
  exit 1
}

OPENOCD_BIN="${WBA65_OPENOCD_BIN:-${repo_root}/third-party/openocd-wba65/bin/openocd}"
OPENOCD_SCRIPTS="${WBA65_OPENOCD_SCRIPTS:-${repo_root}/third-party/openocd-wba65/share/openocd/scripts}"

[[ -x "${OPENOCD_BIN}" ]] || {
  echo "ERROR: WBA65 OpenOCD not found at ${OPENOCD_BIN}" >&2
  echo "  Run: TARGET=nucleo_wba65ri make" >&2
  exit 1
}

if [[ -z "${ELF}" ]]; then
  ELF="${BUILD_DIR}/nfc.ino.elf"
fi
[[ -f "${ELF}" ]] || {
  echo "ERROR: firmware ELF not found: ${ELF}" >&2
  exit 1
}

echo "── Flashing ${ELF} via OpenOCD (stm32wba6x / ST-Link SWD) ──"
exec "${OPENOCD_BIN}" -s "${OPENOCD_SCRIPTS}" -d0 \
  -f interface/stlink.cfg \
  -f target/stm32wba6x.cfg \
  -c "transport select swd" \
  -c "reset_config srst_only srst_nogate connect_assert_srst" \
  -c "program ${ELF} verify reset exit"
