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

# Discover the installed Arduino Renesas core and apply the repo's CCID patch
# series before ``arduino-cli compile`` with NFC_USB_MODE=ccid.
#
# Invoke from the firmware repo Makefile as:
#   bash scripts/ccid-sync-arduino-usb-cpp.sh <repo-root> <arduino-cli> [expected semver]
#
# Opt-out:
#   CCID_SKIP_ARDUINO_USB_SYNC=1
set -euo pipefail

if [[ ${CCID_SKIP_ARDUINO_USB_SYNC:-} == "1" ]]; then
  echo "ccid-sync: skipping (CCID_SKIP_ARDUINO_USB_SYNC=1)" >&2
  exit 0
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
if [[ ${1:-} != "" ]]; then
  REPO="$(cd "${1}" && pwd)"
fi
CANON_CLI="${REPO}/third-party/arduino-cli/arduino-cli"
CANON_DATA="$(bash "${REPO}/make/resolve-arduino-user-dir.sh" "${REPO}")"
CLI="${2:-${CANON_CLI}}"
EXPECT_VER="${3:-1.6.0}"

abs_path() {
  if command -v realpath >/dev/null 2>&1; then
    realpath "$1"
  elif command -v readlink >/dev/null 2>&1; then
    readlink -f "$1"
  else
    local d b
    d="$(cd "$(dirname "$1")" && pwd)"
    b="$(basename "$1")"
    printf '%s/%s\n' "$d" "$b"
  fi
}

if [[ ! -x ${CLI} ]]; then
  echo "ccid-sync: ERROR: pinned arduino-cli not executable: ${CLI}" >&2
  echo "  Run: make -C \"${REPO}\" third-party-host-tools" >&2
  exit 1
fi

if [[ "$(abs_path "${CLI}")" != "$(abs_path "${CANON_CLI}")" ]]; then
  echo "ccid-sync: ERROR: must use repo third-party arduino-cli: ${CANON_CLI}" >&2
  echo "  (refusing foreign binary: ${CLI})" >&2
  exit 1
fi

DATA_DIR="$(abs_path "${ARDUINO_DIRECTORIES_DATA:-${ARDUINO_DIRECTORIES_USER:-${CANON_DATA}}}")"
if [[ ${DATA_DIR} != "$(abs_path "${CANON_DATA}")" ]]; then
  echo "ccid-sync: ERROR: must use isolated arduino-user dir: ${CANON_DATA}" >&2
  echo "  (refusing foreign data dir: ${DATA_DIR})" >&2
  exit 1
fi

case "${DATA_DIR}" in
  "${HOME}/.arduino15" | "${HOME}/.arduino15"/*)
    echo "ccid-sync: ERROR: refusing system Arduino data dir ${DATA_DIR}" >&2
    exit 1
    ;;
esac

VERS_ROOT="${DATA_DIR%/}/packages/arduino/hardware/renesas_uno"
if [[ ! -d ${VERS_ROOT} ]]; then
  echo "ccid-sync: ERROR: Arduino Renesas core not found under '${VERS_ROOT}'." >&2
  echo "  Install with: make -C \"${REPO}\" third-party-host-tools" >&2
  exit 1
fi

PICK=""
if [[ -d "${VERS_ROOT}/${EXPECT_VER}" ]]; then
  PICK="${VERS_ROOT}/${EXPECT_VER}"
else
  vers=()
  for cand in "${VERS_ROOT}"/*/; do
    if [[ -d ${cand} ]]; then
      vers+=("$(basename "${cand}")")
    fi
  done
  if [[ ${#vers[@]} -eq 0 ]]; then
    echo "ccid-sync: ERROR: no semver directories under ${VERS_ROOT}." >&2
    exit 1
  fi
  if [[ ${#vers[@]} -eq 1 ]]; then
    PICK="${VERS_ROOT}/${vers[0]}"
    echo "ccid-sync: WARN: semver ${EXPECT_VER} not installed; using only installed version ${vers[0]}." >&2
  else
    cat >&2 <<-EOF
ccid-sync: ERROR: pinned core ${EXPECT_VER} is not installed under:
  ${VERS_ROOT}
Installed candidates: ${vers[*]}
Fix:
  make -C "${REPO}" third-party-host-tools
(or set NFC_USB_MODE=ccid with CCID_SKIP_ARDUINO_USB_SYNC=1 for manual sketch builds.)
EOF
    exit 1
  fi
fi

HAVE_VER="$(basename "${PICK}")"
if [[ ${HAVE_VER} != "${EXPECT_VER}" ]]; then
  echo "ccid-sync: WARN: repo patch series targets stock ${EXPECT_VER}; you have ${HAVE_VER}. Patch apply may fail until the series is rebased upstream." >&2
fi

bash "${REPO}/scripts/ccid-patch-arduino-usb.sh" "${PICK}" --patch-version "${EXPECT_VER}"
