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

# MCU build tooling: minimal OS packages (make, unzip) plus third-party fetch via Make.
# After this, flash from the repo root with `make flash` or `make flash-cdc`.
#
#   bash scripts/flash-toolchain/install-linux.sh
#
# For the full lint/test toolchain, use `make deps` or `INSTALL_DEPS=1 make` from the repo root.

set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This installer is Linux-only." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -n ${NERO_NFC_FW_ROOT:-} ]]; then
  REPO_ROOT="$(cd "${NERO_NFC_FW_ROOT}" && pwd)"
else
  REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
fi

: "${ARDUINO_MIN_CLI_VERSION:=${MIN_ARDUINO_CLI:-1.5.1}}"
: "${ARDUINO_CLI_VERSION:=${ARDUINO_MIN_CLI_VERSION}}"
: "${ARDUINO_MIN_RENESAS_CORE:=${MIN_RENESAS_CORE:-1.6.0}}"
eval "$(bash "${REPO_ROOT}/make/export-arduino-isolated-env.sh" "${REPO_ROOT}")"
: "${ARDUINO_MIN_BOARD_CORE_VERSION:=${MIN_BOARD_CORE_VERSION:-${ARDUINO_MIN_RENESAS_CORE}}}"
: "${ARDUINO_CORE_PACKAGE:=${BOARD_ARDUINO_CORE_PACKAGE:-arduino:renesas_uno}}"
: "${ARDUINO_BOARD_MANAGER_URLS:=}"

for _arg in "$@"; do
  case "${_arg}" in
    --skip-symlink) ;; # deprecated; no-op (nfc-* wrappers removed)
    -h | --help)
      echo "Usage: bash scripts/flash-toolchain/install-linux.sh"
      echo "Env: NERO_NFC_FW_ROOT  ARDUINO_CORE_PACKAGE  ARDUINO_MIN_BOARD_CORE_VERSION ..."
      echo "     ARDUINO_BOARD_MANAGER_URLS for non-default Arduino cores"
      echo "Then from repo root: make   and   make flash  (or make flash-cdc)"
      exit 0
      ;;
    *)
      echo "Unknown option: ${_arg} (try --help)" >&2
      exit 2
      ;;
  esac
done

have() { command -v "$1" >/dev/null 2>&1; }

priv() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  elif have sudo; then
    sudo -E "$@"
  else
    echo "ERROR: need root or sudo for: $*" >&2
    return 1
  fi
}

echo "── nero-nfc flash toolchain — repo: ${REPO_ROOT} ──"

need_os=false
have make || need_os=true

if [[ ${need_os} == true ]]; then
  echo "── OS packages (make — plus unzip recommended for STM ZIP fetch speed) ──" >&2
  if have apt-get; then
    priv apt-get update -qq
    priv DEBIAN_FRONTEND=noninteractive apt-get install -y make unzip ca-certificates bash
  elif have dnf; then
    priv dnf install -y make unzip ca-certificates bash
  elif have microdnf; then
    priv microdnf install -y make unzip ca-certificates bash
  elif have yum; then
    priv yum install -y make unzip ca-certificates bash
  elif have zypper; then
    priv zypper refresh
    priv zypper install -y make unzip ca-certificates bash
  elif have pacman; then
    priv pacman -Sy --noconfirm make unzip ca-certificates bash
  elif have apk; then
    priv apk add make unzip ca-certificates bash
  else
    echo "ERROR: install GNU make manually, then re-run." >&2
    exit 1
  fi
fi

have make || {
  echo "ERROR: make is required" >&2
  exit 1
}

echo "── arduino-cli + core (see third-party/arduino-cli/) ──" >&2
make -C "${REPO_ROOT}" third-party-host-tools \
  ARDUINO_CORE_PACKAGE="${ARDUINO_CORE_PACKAGE}" \
  ARDUINO_BOARD_MANAGER_URLS="${ARDUINO_BOARD_MANAGER_URLS}" \
  ARDUINO_MIN_BOARD_CORE_VERSION="${ARDUINO_MIN_BOARD_CORE_VERSION}" \
  ARDUINO_MIN_CLI_VERSION="${ARDUINO_MIN_CLI_VERSION}" \
  ARDUINO_CLI_VERSION="${ARDUINO_CLI_VERSION}"

ARDUINO_CLI_BIN="$(bash "${REPO_ROOT}/make/resolve-arduino-cli.sh" "${REPO_ROOT}")"
arduino_cli_dir="$(dirname "${ARDUINO_CLI_BIN}")"
export PATH="${arduino_cli_dir}:${PATH}"
cd "${REPO_ROOT}"
echo "── make (smoke build combined firmware) ──" >&2
make

echo ""
echo "Flash firmware (default boot NFC_MODE=reader):"
echo "  make flash"
echo "Writer default at boot:"
echo "  NFC_MODE=writer make flash-cdc"
echo "Host CLIs (after make userspace && make install-userspace):"
echo "  reader"
echo ""
echo "Ensure PATH and isolated Arduino data dir when running make outside this script:"
echo "  export PATH=\"${REPO_ROOT}/third-party/arduino-cli:\${PATH}\""
echo "  eval \"\$(bash ${REPO_ROOT}/make/export-arduino-isolated-env.sh ${REPO_ROOT})\""
