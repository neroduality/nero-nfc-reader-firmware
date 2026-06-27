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

# Resolve cppcheck >= 2.19.1 for lint parity with current Fedora.
# Ubuntu 24.04 apt ships 2.13.x, which mis-parses _Generic macros and emits
# extra variableScope noise; build the upstream release when the distro package
# is too old.
#
# Sourceable helpers (install-linux-deps.sh):
#   nero_nfc_ensure_cppcheck
set -euo pipefail

NERO_NFC_CPPCHECK_MIN_VERSION=2.19.1
NERO_NFC_CPPCHECK_SOURCE_VERSION=2.19.1

nero_nfc_cppcheck_hint() {
  printf '%s\n' \
    'hint: INSTALL_DEPS=1 bash make/install-linux-deps.sh' \
    "      or: install g++/make/curl, then build cppcheck ${NERO_NFC_CPPCHECK_SOURCE_VERSION} from source" >&2
}

nero_nfc_cppcheck_version_raw() {
  command -v cppcheck >/dev/null 2>&1 || return 1
  cppcheck --version 2>/dev/null | sed -n 's/^Cppcheck \([0-9][0-9.]*\).*/\1/p' | head -n1
}

nero_nfc_cppcheck_version_ge() {
  local want="$1"
  local have
  have="$(nero_nfc_cppcheck_version_raw)" || return 1
  [[ -n ${have} ]] || return 1
  [[ "$(printf '%s\n%s\n' "$want" "$have" | sort -V | head -n1)" == "$want" ]]
}

nero_nfc_cppcheck_install_dir() {
  if [[ ${EUID} -eq 0 ]]; then
    printf '/usr/local/bin\n'
  else
    printf '%s\n' "${HOME}/.local/bin"
  fi
}

nero_nfc_cppcheck_store_root() {
  if [[ ${EUID} -eq 0 ]]; then
    printf '/var/lib/nero-nfc\n'
  else
    printf '%s\n' "${XDG_CACHE_HOME:-${HOME}/.cache}/nero-nfc"
  fi
}

nero_nfc_ensure_cppcheck() {
  if nero_nfc_cppcheck_version_ge "$NERO_NFC_CPPCHECK_MIN_VERSION"; then
    return 0
  fi
  if ! command -v curl >/dev/null 2>&1; then
    return 1
  fi
  if ! command -v make >/dev/null 2>&1 || ! command -v g++ >/dev/null 2>&1; then
    return 1
  fi

  local ver="${NERO_NFC_CPPCHECK_SOURCE_VERSION}"
  local cache_root
  cache_root="$(nero_nfc_cppcheck_store_root)"
  local build_root="${cache_root}/cppcheck-${ver}-build"
  local prefix="${cache_root}/cppcheck-${ver}"
  local staged="${prefix}/cppcheck"
  local cfg_dir="${prefix}/cfg"
  local install_dir dest tmp needs_build=0
  install_dir="$(nero_nfc_cppcheck_install_dir)"
  dest="${install_dir}/cppcheck"

  if [[ ! -x ${staged} ]] || ! "${staged}" --version 2>/dev/null | grep -qF "${ver}"; then
    needs_build=1
  fi
  if [[ ! -f ${cfg_dir}/std.cfg ]]; then
    needs_build=1
  fi

  if ((needs_build == 1)); then
    tmp="$(mktemp -d)"
    curl -fsSL "https://github.com/cppcheck-opensource/cppcheck/archive/refs/tags/${ver}.tar.gz" \
      -o "${tmp}/cppcheck.tgz"
    rm -rf "${build_root}" "${prefix}"
    mkdir -p "${build_root}" "${prefix}"
    tar -xzf "${tmp}/cppcheck.tgz" -C "${build_root}" --strip-components=1
    rm -rf "${tmp}"
    make -C "${build_root}" MATCHCOMPILER=yes CXX=g++ -j"$(bash "$(dirname "${BASH_SOURCE[0]}")/../../make/cpu-jobs.sh")" >/dev/null
    install -m755 "${build_root}/cppcheck" "${staged}"
    rm -rf "${cfg_dir}"
    cp -a "${build_root}/cfg" "${cfg_dir}"
  fi

  if [[ ${EUID} -eq 0 ]]; then
    chmod -R a+rX "${prefix}" 2>/dev/null || true
  fi

  mkdir -p "${install_dir}"
  ln -sf "${staged}" "${dest}"
  export PATH="${install_dir}:${PATH}"

  [[ -f ${cfg_dir}/std.cfg ]] || return 1
  nero_nfc_cppcheck_version_ge "$NERO_NFC_CPPCHECK_MIN_VERSION"
}
