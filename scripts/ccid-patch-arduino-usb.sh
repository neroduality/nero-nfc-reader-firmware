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

# Apply or verify the CCID patch series for the Arduino Renesas core USB stack.
# Firmware must be compiled with NFC_USB_MODE=ccid.
#
# Typical workflow: rely on ``make nfc-ccid`` / ``make flash`` — those run
# ``scripts/ccid-sync-arduino-usb-cpp.sh`` first.
#
# Usage:
#   bash scripts/ccid-patch-arduino-usb.sh /path/to/packages/arduino/hardware/renesas_uno/VERSION [--dry-run] [--patch-version VERSION]
#
# Example:
#   bash scripts/ccid-patch-arduino-usb.sh third-party/arduino-user/packages/arduino/hardware/renesas_uno/1.6.0
set -euo pipefail

usage() {
  cat <<'EOF' >&2
Usage: bash scripts/ccid-patch-arduino-usb.sh <arduino-renesas_uno-package-root> [--dry-run] [--patch-version VERSION]

Apply or verify the CCID patch series stored under:
  patches/arduino/renesas_uno/<VERSION>/
EOF
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
PATCH_ROOT="${ROOT}/patches/arduino/renesas_uno"

CORE_ARG=""
DRY_RUN=0
PATCH_VER=""

while (($# > 0)); do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      ;;
    --patch-version)
      shift
      PATCH_VER="${1:-}"
      if [[ -z ${PATCH_VER} ]]; then
        echo "ERROR: --patch-version requires a value." >&2
        usage
        exit 64
      fi
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    --*)
      echo "ERROR: unknown option: $1" >&2
      usage
      exit 64
      ;;
    *)
      if [[ -n ${CORE_ARG} ]]; then
        echo "ERROR: only one Arduino Renesas core path may be provided." >&2
        usage
        exit 64
      fi
      CORE_ARG="$1"
      ;;
  esac
  shift
done

if [[ -z ${CORE_ARG} ]] || [[ ! -d ${CORE_ARG} ]]; then
  usage
  echo "  e.g. <repo>/third-party/arduino-user/packages/arduino/hardware/renesas_uno/1.6.0" >&2
  exit 64
fi

CORE_ROOT="$(cd "${CORE_ARG}" && pwd)"
CORE_VER="$(basename "${CORE_ROOT}")"
if [[ -z ${PATCH_VER} ]]; then
  PATCH_VER="${CORE_VER}"
fi

PATCH_DIR="${PATCH_ROOT}/${PATCH_VER}"
SERIES_FILE="${PATCH_DIR}/series"
CORE_DATA_DIR="$(cd "${CORE_ROOT}/../../../../.." && pwd)"
STAGING_ARCHIVE="${CORE_DATA_DIR}/staging/packages/ArduinoCore-renesas_uno-${PATCH_VER}.tar.bz2"
RESTORED_STOCK=0

if [[ ! -f ${SERIES_FILE} ]]; then
  echo "ERROR: patch series not found for arduino:renesas_uno ${PATCH_VER}" >&2
  if [[ -d ${PATCH_ROOT} ]]; then
    echo "  Available patch versions: $(find "${PATCH_ROOT}" -mindepth 1 -maxdepth 1 -type d -printf '%f ' | sed 's/[[:space:]]*$//')" >&2
  fi
  exit 1
fi

for target in \
  "${CORE_ROOT}/cores/arduino/usb/USB.cpp" \
  "${CORE_ROOT}/cores/arduino/tinyusb/rusb2/dcd_rusb2.c"; do
  if [[ ! -f ${target} ]]; then
    echo "ERROR: Missing ${target}" >&2
    exit 1
  fi
done

if [[ ${PATCH_VER} != "${CORE_VER}" ]]; then
  echo "ccid-patch: using patch series ${PATCH_VER} against installed core ${CORE_VER}" >&2
fi

restore_stock_core_files() {
  local tmpdir=""
  local rel=""
  local archive_member=""

  if [[ ! -f ${STAGING_ARCHIVE} ]]; then
    echo "ERROR: stale patched core detected, but stock archive is unavailable:" >&2
    echo "  ${STAGING_ARCHIVE}" >&2
    echo "Reinstall arduino:renesas_uno@${PATCH_VER} or restore the stock core, then retry." >&2
    return 1
  fi

  if [[ ${DRY_RUN} -eq 1 ]]; then
    echo "ERROR: installed core looks stale relative to the current patch series." >&2
    echo "  Re-run without --dry-run so the script can restore stock files from:" >&2
    echo "  ${STAGING_ARCHIVE}" >&2
    return 1
  fi

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "${tmpdir}"' RETURN

  for rel in \
    "cores/arduino/usb/USB.cpp" \
    "cores/arduino/tinyusb/rusb2/dcd_rusb2.c"; do
    archive_member="ArduinoCore-renesas/${rel}"
    tar -xf "${STAGING_ARCHIVE}" -C "${tmpdir}" "${archive_member}"
    install -m 0644 "${tmpdir}/${archive_member}" "${CORE_ROOT}/${rel}"
  done

  rm -rf "${tmpdir}"
  trap - RETURN
  RESTORED_STOCK=1
  echo "Restored stock Renesas USB core files from ${STAGING_ARCHIVE}" >&2
}

apply_one() {
  local patch_rel="$1"
  local patch_src="${PATCH_DIR}/${patch_rel}"

  if [[ ! -f ${patch_src} ]]; then
    echo "ERROR: patch file not found at ${patch_src}" >&2
    return 1
  fi

  if patch --batch -p1 -N --dry-run <"${patch_src}" >/dev/null 2>&1; then
    if [[ ${DRY_RUN} -eq 1 ]]; then
      echo "OK: ${patch_rel} applies cleanly (--dry-run only)."
    else
      patch --batch -p1 -N <"${patch_src}" >/dev/null
      echo "Applied ${patch_rel}"
    fi
    return 0
  fi

  if patch --batch -R -p1 --dry-run <"${patch_src}" >/dev/null 2>&1; then
    echo "OK: ${patch_rel} already applied."
    return 0
  fi

  if [[ ${RESTORED_STOCK} -eq 0 ]] && restore_stock_core_files; then
    if patch --batch -p1 -N --dry-run <"${patch_src}" >/dev/null 2>&1; then
      if [[ ${DRY_RUN} -eq 1 ]]; then
        echo "OK: ${patch_rel} applies cleanly after restoring stock files (--dry-run only)."
      else
        patch --batch -p1 -N <"${patch_src}" >/dev/null
        echo "Applied ${patch_rel}"
      fi
      return 0
    fi

    if patch --batch -R -p1 --dry-run <"${patch_src}" >/dev/null 2>&1; then
      echo "OK: ${patch_rel} already applied."
      return 0
    fi
  fi

  echo "ERROR: ${patch_rel} failed patch dry-run (already mismatched or upstream core version drifted)." >&2
  echo "  Patch series: ${PATCH_DIR}" >&2
  return 1
}

cd "${CORE_ROOT}"

while IFS= read -r patch_rel || [[ -n ${patch_rel} ]]; do
  [[ -z ${patch_rel} ]] && continue
  [[ ${patch_rel} =~ ^# ]] && continue
  apply_one "${patch_rel}"
done <"${SERIES_FILE}"
