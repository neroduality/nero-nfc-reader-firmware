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

# Bootstrap STMicroelectronics:stm32 core + NUCLEO-WBA65RI board patch for arduino-cli.
#
# Usage: ensure-wba65-stm32-core.sh <repo-root> <arduino-cli> <stamp> <force-external>
set -euo pipefail

die() {
  echo "ERROR: $*" >&2
  exit 1
}

[[ $# -ge 4 ]] || die "usage: ensure-wba65-stm32-core.sh <repo-root> <arduino-cli> <stamp> <force-external>"

REPO_ROOT="$1"
ARDUINO_CLI="$2"
STAMP="$3"
FORCE_EXTERNAL="$4"

[[ -x "${ARDUINO_CLI}" ]] || die "arduino-cli missing at ${ARDUINO_CLI}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENSURE_CORE="${SCRIPT_DIR}/ensure-arduino-core.sh"
SYNC_BOARD="${REPO_ROOT}/scripts/stm32-sync-wba65-board.sh"
PATCH_DIR="${REPO_ROOT}/patches/arduino/stm32/wba65"
REPO_ARDUINO_USER_DIR="${REPO_ROOT}/third-party/arduino-user"
ARDUINO_USER_DIR="${ARDUINO_USER_DIR:-${ARDUINO_DIRECTORIES_DATA:-${ARDUINO_DIRECTORIES_USER:-${REPO_ARDUINO_USER_DIR}}}}"
if [[ "${ARDUINO_USER_DIR}" == "${REPO_ARDUINO_USER_DIR}" ]]; then
  WBA65_STAMP="${REPO_ROOT}/third-party/.wba65-board-patch-version"
else
  WBA65_STAMP="${ARDUINO_USER_DIR}/.wba65-board-patch-version"
fi

CORE_PACKAGE="${WBA65_STM32_CORE_PACKAGE:-STMicroelectronics:stm32}"
CORE_VERSION="${WBA65_STM32_CORE_VERSION:-2.12.0}"
BOARD_MANAGER_URLS="${WBA65_STM32_BOARD_MANAGER_URLS:-https://github.com/stm32duino/BoardManagerFiles/raw/main/package_stmicroelectronics_index.json}"

patch_signature() {
  if [[ -d "${PATCH_DIR}" ]]; then
    sha256sum "${PATCH_DIR}"/* 2>/dev/null | sha256sum | awk '{print $1}'
  else
    echo "none"
  fi
}

vendor="${CORE_PACKAGE%%:*}"
arch="${CORE_PACKAGE#*:}"
CORE_TREE="${ARDUINO_USER_DIR}/packages/${vendor}/hardware/${arch}/${CORE_VERSION}"
BOARDS_TXT="${CORE_TREE}/boards.txt"

want_wba65="${CORE_PACKAGE}@${CORE_VERSION}|wba65-board-patch|$(patch_signature)"

wba65_board_ok() {
  [[ -f "${BOARDS_TXT}" ]] && grep -q 'NUCLEO_WBA65RI' "${BOARDS_TXT}"
}

if [[ "${FORCE_EXTERNAL}" != "1" ]] &&
   [[ -f "${WBA65_STAMP}" ]] &&
   [[ "$(cat "${WBA65_STAMP}")" == "${want_wba65}" ]] &&
   wba65_board_ok; then
  bash "${ENSURE_CORE}" "${REPO_ROOT}" "${ARDUINO_CLI}" "${STAMP}" \
    "${CORE_PACKAGE}" "${CORE_VERSION}" "${BOARD_MANAGER_URLS}" \
    "${FORCE_EXTERNAL}" "${ARDUINO_USER_DIR}"
  exit 0
fi

bash "${ENSURE_CORE}" "${REPO_ROOT}" "${ARDUINO_CLI}" "${STAMP}" \
  "${CORE_PACKAGE}" "${CORE_VERSION}" "${BOARD_MANAGER_URLS}" \
  "${FORCE_EXTERNAL}" "${ARDUINO_USER_DIR}"

bash "${SYNC_BOARD}" "${REPO_ROOT}" "${CORE_TREE}"

printf '%s' "${want_wba65}" >"${WBA65_STAMP}"
echo "── WBA65 STM32 core + board patch ready ──"
