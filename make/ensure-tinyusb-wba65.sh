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

# Bootstrap upstream TinyUSB (STM32WBA65 / OPT_MCU_STM32WBA) for WBA65 CCID builds.
#
# Usage: ensure-tinyusb-wba65.sh <repo-root> <stamp> [force-external]
set -euo pipefail

die() {
  echo "ERROR: $*" >&2
  exit 1
}

[[ $# -ge 2 ]] || die "usage: ensure-tinyusb-wba65.sh <repo-root> <stamp> [force-external]"

REPO_ROOT="$1"
STAMP="$2"
FORCE_EXTERNAL="${3:-0}"

TINYUSB_DIR="${REPO_ROOT}/third-party/tinyusb"
TINYUSB_REV="${WBA65_TINYUSB_REV:-9f055f113c38b6fbd898231bc1636448712adf14}"
TINYUSB_WANT="tinyusb-wba65|${TINYUSB_REV}"

tinyusb_ok() {
  [[ -f "${TINYUSB_DIR}/src/tusb.h" ]] &&
    [[ -f "${TINYUSB_DIR}/src/tusb_option.h" ]] &&
    grep -qF 'OPT_MCU_STM32WBA' "${TINYUSB_DIR}/src/tusb_option.h" 2>/dev/null
}

write_stamp() {
  printf '%s' "${TINYUSB_WANT}" >"${STAMP}"
}

if [[ ${FORCE_EXTERNAL} != "1" ]] &&
  [[ -f ${STAMP} ]] &&
  [[ "$(cat "${STAMP}")" == "${TINYUSB_WANT}" ]] &&
  tinyusb_ok; then
  exit 0
fi

command -v git >/dev/null 2>&1 || die "missing git"

checkout_tinyusb_rev() {
  git -C "${TINYUSB_DIR}" fetch --depth 1 origin "${TINYUSB_REV}" 2>/dev/null ||
    git -C "${TINYUSB_DIR}" fetch --depth 1 origin \
      "refs/tags/${TINYUSB_REV}:refs/tags/${TINYUSB_REV}"
  git -C "${TINYUSB_DIR}" checkout --detach FETCH_HEAD >/dev/null
}

if [[ ${FORCE_EXTERNAL} == "1" ]] || [[ ! -d "${TINYUSB_DIR}/.git" ]]; then
  echo "── Cloning TinyUSB (${TINYUSB_REV}) for WBA65 CCID ──" >&2
  rm -rf "${TINYUSB_DIR}"
  git clone --filter=blob:none --no-checkout https://github.com/hathach/tinyusb.git \
    "${TINYUSB_DIR}"
fi
checkout_tinyusb_rev

tinyusb_ok || die "TinyUSB tree missing STM32WBA support (need recent upstream)"
write_stamp
echo "── TinyUSB ready for WBA65 CCID: ${TINYUSB_DIR} ──"
