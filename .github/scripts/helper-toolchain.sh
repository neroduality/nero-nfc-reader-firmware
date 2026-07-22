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

# GCC 15+ for userspace builds (firmware uses arduino-cli / STM32 toolchains).
#
# API: nero_nfc_toolchain_{system_ok,effective_ok,ok,ensure_symlinks,activate,verify}
# Usage: bash helper-toolchain.sh [verify|activate]

[[ -n ${NERO_NFC_TOOLCHAIN_HELPERS_LOADED:-} ]] && return 0
NERO_NFC_TOOLCHAIN_HELPERS_LOADED=1

NERO_NFC_GXX_MIN_VERSION="${NERO_NFC_GXX_MIN_VERSION:-15.0}"
NERO_NFC_GXX_MIN_MAJOR="${NERO_NFC_GXX_MIN_MAJOR:-15}"
NERO_NFC_TOOLCHAIN_PREFIX="${NERO_NFC_TOOLCHAIN_PREFIX:-/usr/local/bin}"
NERO_NFC_TOOLCHAIN_NAMES=(gcc g++ cc c++)

nero_nfc_ht_have() { command -v "$1" >/dev/null 2>&1; }

nero_nfc_ht_priv() {
  if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    "$@"
  elif nero_nfc_ht_have sudo; then
    sudo -E "$@"
  else
    printf 'error: need root or sudo for toolchain install\n' >&2
    return 1
  fi
}

nero_nfc_ht_version_normalize() {
  local v="$1"
  if [[ ${v} =~ ^[0-9]+$ ]]; then
    printf '%s.0' "${v}"
  else
    printf '%s' "${v}"
  fi
}

nero_nfc_ht_version_ge() {
  local have want
  have="$(nero_nfc_ht_version_normalize "$1")"
  want="$(nero_nfc_ht_version_normalize "$2")"
  [[ -n ${have} && -n ${want} ]] || return 1
  printf '%s\n%s\n' "${want}" "${have}" | sort -V -C
}

nero_nfc_ht_version_raw() {
  local bin="$1"
  local v
  [[ -n ${bin} ]] || return 1
  v="$("${bin}" -dumpfullversion 2>/dev/null | head -n1 | sed 's/-.*$//')" || true
  [[ -n ${v} ]] || v="$("${bin}" -dumpversion 2>/dev/null | head -n1 | sed 's/-.*$//')"
  [[ -n ${v} ]] || return 1
  printf '%s' "$(nero_nfc_ht_version_normalize "${v}")"
}

nero_nfc_ht_version_major() {
  local v
  v="$(nero_nfc_ht_version_raw "$1")" || return 1
  printf '%s' "${v%%.*}"
}

nero_nfc_ht_tools_ok_on_path() {
  local name v
  for name in "${NERO_NFC_TOOLCHAIN_NAMES[@]}"; do
    nero_nfc_ht_have "${name}" || return 1
    v="$(nero_nfc_ht_version_raw "${name}")" || return 1
    nero_nfc_ht_version_ge "${v}" "${NERO_NFC_GXX_MIN_VERSION}" || return 1
  done
  return 0
}

nero_nfc_ht_path_without_prefix() {
  local p="${1:-${PATH:-}}"
  p="${p#"${NERO_NFC_TOOLCHAIN_PREFIX}:"}"
  printf '%s' "${p}"
}

# Distro defaults on PATH (no /usr/local/bin preference).
nero_nfc_toolchain_system_ok() {
  local saved_path="${PATH:-}" stripped rc
  stripped="$(nero_nfc_ht_path_without_prefix "${saved_path}")"
  PATH="${stripped}"
  nero_nfc_ht_tools_ok_on_path
  rc=$?
  PATH="${saved_path}"
  return "${rc}"
}

# Effective toolchain after optional /usr/local/bin symlinks.
nero_nfc_toolchain_effective_ok() {
  local saved_path="${PATH:-}" rc
  PATH="${NERO_NFC_TOOLCHAIN_PREFIX}:$(nero_nfc_ht_path_without_prefix "${saved_path}")"
  nero_nfc_ht_tools_ok_on_path
  rc=$?
  PATH="${saved_path}"
  return "${rc}"
}

nero_nfc_toolchain_ok() {
  nero_nfc_toolchain_system_ok || nero_nfc_toolchain_effective_ok
}

nero_nfc_toolchain_best_versioned_gxx() {
  local bin ver
  for bin in g++-15 g++-16 g++-17 g++-14 g++-13; do
    nero_nfc_ht_have "${bin}" || continue
    ver="$(nero_nfc_ht_version_raw "${bin}")" || continue
    nero_nfc_ht_version_ge "${ver}" "${NERO_NFC_GXX_MIN_VERSION}" || continue
    printf '%s' "${bin}"
    return 0
  done
  return 1
}

nero_nfc_toolchain_ensure_symlinks() {
  local best_gxx gcc_bin name dest_dir="${NERO_NFC_TOOLCHAIN_PREFIX}"

  if nero_nfc_toolchain_system_ok; then
    return 0
  fi

  best_gxx="$(nero_nfc_toolchain_best_versioned_gxx || true)"
  if [[ -z ${best_gxx} ]]; then
    printf 'error: no g++-%s+ found to symlink\n' "${NERO_NFC_GXX_MIN_MAJOR}" >&2
    return 1
  fi

  gcc_bin="${best_gxx/g++/gcc}"
  nero_nfc_ht_have "${gcc_bin}" || {
    printf 'error: missing companion %s for %s\n' "${gcc_bin}" "${best_gxx}" >&2
    return 1
  }

  nero_nfc_ht_priv mkdir -p "${dest_dir}"
  for name in "${NERO_NFC_TOOLCHAIN_NAMES[@]}"; do
    case "${name}" in
      g++ | c++) nero_nfc_ht_priv ln -sf "$(command -v "${best_gxx}")" "${dest_dir}/${name}" ;;
      gcc | cc) nero_nfc_ht_priv ln -sf "$(command -v "${gcc_bin}")" "${dest_dir}/${name}" ;;
    esac
  done

  nero_nfc_toolchain_effective_ok
}

nero_nfc_toolchain_activate() {
  if nero_nfc_toolchain_system_ok; then
    export CC="${CC:-gcc}"
    export CXX="${CXX:-g++}"
    return 0
  fi
  if nero_nfc_toolchain_effective_ok; then
    local stripped
    stripped="$(nero_nfc_ht_path_without_prefix "${PATH:-}")"
    export PATH="${NERO_NFC_TOOLCHAIN_PREFIX}:${stripped}"
    export CC=gcc
    export CXX=g++
    return 0
  fi
  printf 'error: toolchain below GCC %s (run INSTALL_DEPS=1 bash make/install-linux-deps.sh)\n' \
    "${NERO_NFC_GXX_MIN_VERSION}" >&2
  return 1
}

nero_nfc_toolchain_verify() {
  local name path major target

  nero_nfc_toolchain_activate || return 1

  printf '── Toolchain smoke (GCC %s+ for userspace; firmware uses arduino-cli) ──\n' \
    "${NERO_NFC_GXX_MIN_MAJOR}"
  for name in "${NERO_NFC_TOOLCHAIN_NAMES[@]}"; do
    path="$(command -v "${name}")"
    major="$(nero_nfc_ht_version_major "${name}")"
    if [[ ${path} == "${NERO_NFC_TOOLCHAIN_PREFIX}/"* && -L ${path} ]]; then
      target="$(readlink -f "${path}")"
      printf '  %s -> %s (GCC %s)\n' "${name}" "${target}" "${major}"
    else
      printf '  %s -> %s (GCC %s, distro default)\n' "${name}" "${path}" "${major}"
    fi
  done
  printf '── Toolchain: OK ──\n'
}

if [[ ${BASH_SOURCE[0]} == "${0}" ]]; then
  set -euo pipefail
  case "${1:-verify}" in
    verify) nero_nfc_toolchain_verify ;;
    activate) nero_nfc_toolchain_activate ;;
    *)
      printf 'usage: %s [verify|activate]\n' "${BASH_SOURCE[0]}" >&2
      exit 2
      ;;
  esac
fi
