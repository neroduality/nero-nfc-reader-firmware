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

# Apply NUCLEO-WBA65RI board entries + variant files to an installed stm32duino core.
#
# Usage: stm32-sync-wba65-board.sh <repo-root> <core-tree-dir>
set -euo pipefail

REPO="$1"
CORE_TREE="$2"
PATCH_DIR="${REPO}/patches/arduino/stm32/wba65"
FRAG="${PATCH_DIR}/nucleo_wba65ri_boards.fragment"
BOARDS_TXT="${CORE_TREE}/boards.txt"
VARIANT_DIR="${CORE_TREE}/variants/STM32WBAxx/WBA65R(G-I)V"

die() {
  echo "stm32-sync-wba65: ERROR: $*" >&2
  exit 1
}

[[ -f "${FRAG}" ]] || die "missing fragment ${FRAG}"
[[ -f "${BOARDS_TXT}" ]] || die "missing boards.txt under ${CORE_TREE}"
[[ -d "${VARIANT_DIR}" ]] || die "missing variant dir ${VARIANT_DIR} (need stm32 core >= 2.12.0)"

if ! grep -q 'NUCLEO_WBA65RI' "${BOARDS_TXT}"; then
  echo "stm32-sync-wba65: appending NUCLEO_WBA65RI to boards.txt" >&2
  printf '\n%s\n' "$(cat "${FRAG}")" >>"${BOARDS_TXT}"
else
  echo "stm32-sync-wba65: NUCLEO_WBA65RI already in boards.txt" >&2
fi

if grep -q 'Nucleo_64.menu.pnum.NUCLEO_WBA65RI.openocd.target=stm32wbax' "${BOARDS_TXT}"; then
  echo "stm32-sync-wba65: fixing openocd.target stm32wbax -> stm32wba6x (WBA65 silicon)" >&2
  sed -i 's/Nucleo_64.menu.pnum.NUCLEO_WBA65RI.openocd.target=stm32wbax/Nucleo_64.menu.pnum.NUCLEO_WBA65RI.openocd.target=stm32wba6x/' "${BOARDS_TXT}"
fi

install -m 0644 "${PATCH_DIR}/variant_NUCLEO_WBA65RI.h" "${VARIANT_DIR}/"
install -m 0644 "${PATCH_DIR}/variant_NUCLEO_WBA65RI.cpp" "${VARIANT_DIR}/"
install -m 0644 "${PATCH_DIR}/ldscript.ld" "${VARIANT_DIR}/"

CMAKE="${VARIANT_DIR}/CMakeLists.txt"
if [[ -f "${CMAKE}" ]] && ! grep -q 'variant_NUCLEO_WBA65RI.cpp' "${CMAKE}"; then
  echo "stm32-sync-wba65: adding variant_NUCLEO_WBA65RI.cpp to CMakeLists.txt" >&2
  sed -i 's/variant_generic.cpp/variant_generic.cpp\n  variant_NUCLEO_WBA65RI.cpp/' "${CMAKE}"
fi
echo "stm32-sync-wba65: variant files installed under ${VARIANT_DIR}" >&2
