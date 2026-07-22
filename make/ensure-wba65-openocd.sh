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

# Bootstrap upstream OpenOCD with STM32WBA6x flash support (bundled xpack lacks it).
#
# Usage: ensure-wba65-openocd.sh <repo-root> <stamp> [force-external]
set -euo pipefail

die() {
  echo "ERROR: $*" >&2
  exit 1
}

[[ $# -ge 2 ]] || die "usage: ensure-wba65-openocd.sh <repo-root> <stamp> [force-external]"

REPO_ROOT="$1"
STAMP="$2"
FORCE_EXTERNAL="${3:-0}"

# shellcheck source=make/cli-spinner.sh
source "${REPO_ROOT}/make/cli-spinner.sh"

OPENOCD_PREFIX="${REPO_ROOT}/third-party/openocd-wba65"
OPENOCD_BIN="${OPENOCD_PREFIX}/bin/openocd"
OPENOCD_SRC="${REPO_ROOT}/third-party/openocd-wba65-src"
OPENOCD_REV="${WBA65_OPENOCD_REV:-df14f586629a70878636d138ec3bffd9148aaf1b}"
PATCH_DIR="${REPO_ROOT}/patches/openocd"
IDCODE_SRC="${OPENOCD_SRC}/src/flash/nor/stm32l4x.c"
IDCODE_PATCH_MARKER='DBGMCU_IDCODE_L4_G4, DBGMCU_IDCODE_L5, DBGMCU_IDCODE_G0'
OPENOCD_JOBS="$(bash "$(dirname "${BASH_SOURCE[0]}")/cpu-jobs.sh")"
# NUCLEO-WBA65RI flash uses ST-Link only; disable other adapters (auto=yes with libusb).
OPENOCD_CONFIGURE_PROFILE='stlink-only-v1'
OPENOCD_DISABLE_ADAPTERS=(
  --disable-ftdi --disable-ftdi-cjtag --disable-ch347 --disable-cklink
  --disable-ti-icdi --disable-ulink --disable-angie --disable-usb-blaster-2
  --disable-ft232r --disable-vsllink --disable-xds110 --disable-osbdm
  --disable-opendous --disable-armjtagew --disable-rlink --disable-usbprog
  --disable-esp-usb-jtag --disable-cmsis-dap-v2 --disable-cmsis-dap
  --disable-nulink --disable-kitprog --disable-usb-blaster --disable-presto
  --disable-openjtag --disable-linuxgpiod --disable-dmem --disable-sysfsgpio
  --disable-remote-bitbang --disable-linuxspidev --disable-buspirate
  --disable-dummy --disable-vdebug --disable-jtag-dpi --disable-jtag-vpi
  --disable-rshim --disable-xlnx-xvc --disable-jlink --disable-cmsis-dap-tcp
  --disable-xvc --disable-parport --disable-amtjtagaccel --disable-ep93xx
  --disable-at91rm9200 --disable-bcm2835gpio --disable-imx-gpio --disable-am335xgpio
)

OPENOCD_SPINNER_ACTIVE=0
OPENOCD_ROTATE_PID=""

openocd_spinner_stop_rotate() {
  if [[ -n ${OPENOCD_ROTATE_PID} ]]; then
    kill "${OPENOCD_ROTATE_PID}" 2>/dev/null || true
    wait "${OPENOCD_ROTATE_PID}" 2>/dev/null || true
    OPENOCD_ROTATE_PID=""
  fi
}

openocd_spinner_rotate() {
  local started="${1}"
  local phase="${2:-build}"
  while [[ ${OPENOCD_SPINNER_ACTIVE} -eq 1 ]]; do
    sleep 5
    local elapsed=$((SECONDS - started))
    if [[ ${phase} == "clone" ]]; then
      if ((elapsed < 60)); then
        cli_spinner_set_message "Processing — cloning OpenOCD source"
      else
        cli_spinner_set_message "Processing — still cloning OpenOCD (${elapsed}s)"
      fi
    elif ((elapsed < 20)); then
      cli_spinner_set_message "Processing — initializing jimtcl submodule and applying patches"
    elif ((elapsed < 90)); then
      cli_spinner_set_message "Processing — bootstrapping and configuring OpenOCD (${elapsed}s)"
    elif ((elapsed < 240)); then
      cli_spinner_set_message "Processing — compiling OpenOCD (${elapsed}s) — first build may take a few min"
    else
      cli_spinner_set_message "Processing — still compiling OpenOCD (${elapsed}s)"
    fi
  done
}

run_openocd_step_with_spinner() {
  local message="$1"
  local phase="${2:-build}"
  shift 2

  local log=""
  log="$(mktemp "${TMPDIR:-/tmp}/openocd-step.XXXXXX.log")"

  local started="${SECONDS}"
  OPENOCD_SPINNER_ACTIVE=1
  cli_spinner_start "${message}"
  openocd_spinner_rotate "${started}" "${phase}" &
  OPENOCD_ROTATE_PID=$!

  local step_status=0
  set +e
  "$@" >"${log}" 2>&1
  step_status=$?
  set -e

  OPENOCD_SPINNER_ACTIVE=0
  openocd_spinner_stop_rotate
  cli_spinner_finish

  if [[ -s ${log} ]]; then
    cat "${log}"
  fi
  rm -f "${log}"
  return "${step_status}"
}

clone_openocd_source() {
  rm -rf "${OPENOCD_SRC}"
  git clone --filter=blob:none --no-checkout https://github.com/openocd-org/openocd.git \
    "${OPENOCD_SRC}"
}

checkout_openocd_rev() {
  git -C "${OPENOCD_SRC}" fetch --depth 1 origin "${OPENOCD_REV}" 2>/dev/null ||
    git -C "${OPENOCD_SRC}" fetch --depth 1 origin \
      "refs/tags/${OPENOCD_REV}:refs/tags/${OPENOCD_REV}"
  # Patches modify tracked files (e.g. stm32l4x.c); reset so FETCH_HEAD checkout never aborts.
  git -C "${OPENOCD_SRC}" reset --hard FETCH_HEAD >/dev/null
  # Drop autotools/build products from a previous checkout so bootstrap re-runs cleanly.
  git -C "${OPENOCD_SRC}" clean -fdX >/dev/null
}

build_openocd_tree() {
  (
    cd "${OPENOCD_SRC}"
    git submodule update --init --recursive jimtcl
    apply_openocd_patches

    if [[ -x ${OPENOCD_BIN} ]] &&
      [[ -f ${IDCODE_SRC} ]] &&
      [[ ${OPENOCD_BIN} -nt ${IDCODE_SRC} ]] &&
      openocd_config_matches; then
      echo "── WBA65 OpenOCD binary up to date, skipping compile ──" >&2
      exit 0
    fi

    [[ -f configure ]] || ./bootstrap
    if ! openocd_config_matches; then
      ./configure \
        --prefix="${OPENOCD_PREFIX}" \
        --enable-stlink \
        --disable-werror \
        --disable-doxygen-html \
        "${USE_INTERNAL_JIMTCL}" \
        "${OPENOCD_DISABLE_ADAPTERS[@]}"
    fi
    make -j"${OPENOCD_JOBS}"
    make install
  )
}

patch_signature() {
  if [[ -d ${PATCH_DIR} ]]; then
    sha256sum "${PATCH_DIR}"/*.patch 2>/dev/null | sha256sum | awk '{print $1}'
  else
    echo "none"
  fi
}

OPENOCD_WANT="$(printf 'openocd-wba65|%s|%s|%s' "${OPENOCD_CONFIGURE_PROFILE}" "${OPENOCD_REV}" "$(patch_signature)")"

openocd_config_matches() {
  local cfg=""
  [[ -f "${OPENOCD_SRC}/config.status" ]] || return 1
  cfg="$(grep -m1 '^ac_cs_config=' "${OPENOCD_SRC}/config.status" | sed "s/^ac_cs_config='//; s/'$//")"
  [[ ${cfg} == *"--prefix=${OPENOCD_PREFIX}"* ]] || return 1
  [[ ${cfg} == *"--enable-stlink"* ]] || return 1
  [[ ${cfg} == *"--disable-ftdi"* ]] || return 1
  [[ ${cfg} == *"--disable-jlink"* ]] || return 1
}

openocd_has_wba6() {
  [[ -x ${OPENOCD_BIN} ]] &&
    [[ -f "${OPENOCD_PREFIX}/share/openocd/scripts/target/stm32wba6x.cfg" ]] &&
    grep -aqF 'STM32WBA6x' "${OPENOCD_BIN}" 2>/dev/null
}

openocd_idcode_patch_applied() {
  [[ -f ${IDCODE_SRC} ]] &&
    grep -qF "${IDCODE_PATCH_MARKER}" "${IDCODE_SRC}"
}

apply_openocd_patches() {
  if openocd_idcode_patch_applied; then
    echo "stm32-openocd: idcode probe-order patch already applied" >&2
    return 0
  fi
  [[ -d ${PATCH_DIR} ]] || return 0
  local patch name
  shopt -s nullglob
  for patch in "${PATCH_DIR}"/*.patch; do
    name="$(basename "${patch}")"
    echo "stm32-openocd: applying ${name}" >&2
    # GNU patch 2.8 hangs with -d/-s and a positional patch file when stdout is redirected.
    patch -d "${OPENOCD_SRC}" -p1 -N --forward -f -i "${patch}" </dev/null
  done
  shopt -u nullglob
  openocd_idcode_patch_applied || die "stm32-openocd: patch apply failed (${IDCODE_SRC})"
}

write_stamp() {
  printf '%s' "${OPENOCD_WANT}" >"${STAMP}"
}

# Fast path: installed binary matches current patch set.
if [[ ${FORCE_EXTERNAL} != "1" ]] &&
  [[ -f ${STAMP} ]] &&
  [[ "$(cat "${STAMP}")" == "${OPENOCD_WANT}" ]] &&
  openocd_has_wba6; then
  exit 0
fi

wba65_openocd_build_tools_ok() {
  # Debian: package "libtool" ships libtoolize; "libtool-bin" ships /usr/bin/libtool.
  # OpenOCD bootstrap uses autoreconf/libtoolize; either libtool or libtoolize is enough.
  # GNU patch applies patches/openocd/*.patch (sid-slim does not ship it by default).
  for tool in git make pkg-config autoreconf automake patch; do
    command -v "${tool}" >/dev/null 2>&1 || return 1
  done
  { command -v gcc >/dev/null 2>&1 || command -v g++ >/dev/null 2>&1; } || return 1
  { command -v libtool >/dev/null 2>&1 || command -v libtoolize >/dev/null 2>&1; } || return 1
  pkg-config --exists libusb-1.0
}

if ! wba65_openocd_build_tools_ok; then
  if [[ ${INSTALL_DEPS:-0} == "1" ]]; then
    INSTALL_DEPS=1 AUTO_INSTALL_LINUX_DEPS=1 FIRMWARE_ROOT="${REPO_ROOT}" \
      bash "${REPO_ROOT}/make/install-linux-deps.sh"
  else
    die "missing WBA65 OpenOCD build tools (autoconf/automake/libtool/patch/libusb). Run: make deps  (or INSTALL_DEPS=1 TARGET=nucleo_wba65ri make)"
  fi
fi
wba65_openocd_build_tools_ok || die "WBA65 OpenOCD build tools still missing after install"

USE_INTERNAL_JIMTCL=--enable-internal-jimtcl
if pkg-config --exists jimtcl 2>/dev/null; then
  USE_INTERNAL_JIMTCL=--disable-internal-jimtcl
fi

if [[ ! -d "${OPENOCD_SRC}/.git" ]]; then
  echo "── Cloning OpenOCD (${OPENOCD_REV}) for WBA65 flash ──" >&2
  run_openocd_step_with_spinner "Processing — cloning OpenOCD source" clone clone_openocd_source
fi
checkout_openocd_rev

echo "── Building OpenOCD for NUCLEO-WBA65RI (STM32WBA6x, ${OPENOCD_JOBS} jobs) ──" >&2
run_openocd_step_with_spinner \
  "Processing — initializing jimtcl submodule and applying patches" \
  build \
  build_openocd_tree

openocd_has_wba6 || die "OpenOCD build missing STM32WBA6x support"
write_stamp
echo "── WBA65 OpenOCD ready: ${OPENOCD_BIN} ──"
