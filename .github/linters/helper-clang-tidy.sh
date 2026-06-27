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

# Resolve clang-tidy >= 21.0.0 and clang-format >= 20.0.0 for lint parity (overlay checks,
# ExcludeHeaderFilterRegex, and consistent -i formatting vs Lima / GitHub ubuntu-24.04).
# Ubuntu 24.04 / Debian: install-linux-deps uses apt.llvm.org when distro packages are unavailable.
# Container test jobs set INSTALL_LINT_DEPS=0 (see ci-run-tests.sh); lint runs on the host/VM only.
#
# Sourceable helpers (install-linux-deps.sh, ci-lint.sh):
#   nero_nfc_ensure_clang_tidy
#   nero_nfc_ensure_clang_format
set -euo pipefail

NERO_NFC_CLANG_TIDY_MIN_VERSION=21.0.0
NERO_NFC_CLANG_TIDY_PREFERRED_MAJOR=21
NERO_NFC_CLANG_FORMAT_MIN_VERSION=20.0.0

nero_nfc_clang_tidy_hint() {
  printf '%s\n' \
    'hint: INSTALL_DEPS=1 bash make/install-linux-deps.sh' \
    "      or: apt install clang-tidy-${NERO_NFC_CLANG_TIDY_PREFERRED_MAJOR} clang-tools-${NERO_NFC_CLANG_TIDY_PREFERRED_MAJOR}" \
    '      or: install clang-tools-extra (Fedora)' >&2
}

nero_nfc_clang_format_hint() {
  printf '%s\n' \
    'hint: INSTALL_DEPS=1 bash make/install-linux-deps.sh' \
    "      or: apt install clang-format-${NERO_NFC_CLANG_TIDY_PREFERRED_MAJOR} clang-format-20" \
    '      or: install clang-tools-extra (Fedora ≥43)' >&2
}

nero_nfc_clang_tidy_install_dir() {
  if [[ ${EUID} -eq 0 ]]; then
    printf '/usr/local/bin\n'
  else
    printf '%s\n' "${HOME}/.local/bin"
  fi
}

nero_nfc_export_tool_shim_dir() {
  local install_dir="$1"

  export PATH="${install_dir}:${PATH}"
  if [[ -n ${GITHUB_PATH:-} ]] &&
    { [[ ! -f ${GITHUB_PATH} ]] || ! grep -Fxq "${install_dir}" "${GITHUB_PATH}" 2>/dev/null; }; then
    printf '%s\n' "${install_dir}" >>"${GITHUB_PATH}"
  fi
}

nero_nfc_clang_tidy_version_raw() {
  local bin="${1:-}"
  if [[ -z ${bin} ]]; then
    command -v clang-tidy >/dev/null 2>&1 || return 1
    bin="$(command -v clang-tidy)"
  fi
  [[ -x ${bin} ]] || return 1
  "${bin}" --version 2>/dev/null |
    sed -n \
      -e 's/.*LLVM version \([0-9][0-9.]*\).*/\1/p' \
      -e 's/.*clang-tidy version \([0-9][0-9.]*\).*/\1/p' |
    head -n1
}

nero_nfc_clang_tidy_version_ge() {
  local want="$1"
  local have="${2:-}"
  if [[ -z ${have} ]]; then
    have="$(nero_nfc_clang_tidy_version_raw)" || return 1
  fi
  [[ -n ${have} ]] || return 1
  [[ "$(printf '%s\n%s\n' "$want" "$have" | sort -V | head -n1)" == "$want" ]]
}

nero_nfc_clang_tidy_candidate_bins() {
  local name
  for name in clang-tidy-21 clang-tidy-20 clang-tidy-19 clang-tidy-18 clang-tidy; do
    command -v "${name}" 2>/dev/null || true
  done
}

nero_nfc_find_clang_tidy() {
  local candidate ver best="" best_ver=""
  while IFS= read -r candidate; do
    [[ -n ${candidate} && -x ${candidate} ]] || continue
    ver="$(nero_nfc_clang_tidy_version_raw "${candidate}")" || continue
    nero_nfc_clang_tidy_version_ge "$NERO_NFC_CLANG_TIDY_MIN_VERSION" "$ver" || continue
    if [[ -z ${best_ver} ]] ||
      [[ "$(printf '%s\n%s\n' "$best_ver" "$ver" | sort -V | tail -n1)" == "$ver" ]]; then
      best="${candidate}"
      best_ver="${ver}"
    fi
  done < <(nero_nfc_clang_tidy_candidate_bins)
  [[ -n ${best} ]] || return 1
  printf '%s\n' "${best}"
}

nero_nfc_find_run_clang_tidy() {
  local tidy_bin="$1"
  local base="${tidy_bin##*/}"
  local candidate

  case "${base}" in
    clang-tidy-[0-9][0-9])
      for candidate in "run-${base}" "run-${base}.py"; do
        command -v "${candidate}" >/dev/null 2>&1 && {
          command -v "${candidate}"
          return 0
        }
      done
      ;;
  esac

  for candidate in run-clang-tidy run-clang-tidy.py; do
    command -v "${candidate}" >/dev/null 2>&1 && {
      command -v "${candidate}"
      return 0
    }
  done
  return 1
}

nero_nfc_ensure_clang_tidy() {
  local tidy_bin run_bin install_dir
  tidy_bin="$(nero_nfc_find_clang_tidy)" || return 1

  install_dir="$(nero_nfc_clang_tidy_install_dir)"
  mkdir -p "${install_dir}"
  if [[ ${tidy_bin} != "${install_dir}/clang-tidy" ]]; then
    ln -sf "${tidy_bin}" "${install_dir}/clang-tidy"
  fi

  if run_bin="$(nero_nfc_find_run_clang_tidy "${tidy_bin}")"; then
    if [[ ${run_bin} != "${install_dir}/run-clang-tidy" ]]; then
      ln -sf "${run_bin}" "${install_dir}/run-clang-tidy"
    fi
  fi

  nero_nfc_export_tool_shim_dir "${install_dir}"

  nero_nfc_clang_tidy_version_ge "$NERO_NFC_CLANG_TIDY_MIN_VERSION"
}

nero_nfc_clang_format_version_raw() {
  local bin="${1:-}"
  if [[ -z ${bin} ]]; then
    command -v clang-format >/dev/null 2>&1 || return 1
    bin="$(command -v clang-format)"
  fi
  [[ -x ${bin} ]] || return 1
  "${bin}" --version 2>/dev/null |
    sed -n \
      -e 's/.*LLVM version \([0-9][0-9.]*\).*/\1/p' \
      -e 's/.*clang-format version \([0-9][0-9.]*\).*/\1/p' |
    head -n1
}

nero_nfc_clang_format_version_ge() {
  local want="$1"
  local have="${2:-}"
  if [[ -z ${have} ]]; then
    have="$(nero_nfc_clang_format_version_raw)" || return 1
  fi
  [[ -n ${have} ]] || return 1
  [[ "$(printf '%s\n%s\n' "$want" "$have" | sort -V | head -n1)" == "$want" ]]
}

nero_nfc_clang_format_candidate_bins() {
  local name
  for name in clang-format-21 clang-format-20 clang-format; do
    command -v "${name}" 2>/dev/null || true
  done
}

nero_nfc_find_clang_format() {
  local candidate ver best="" best_ver=""
  while IFS= read -r candidate; do
    [[ -n ${candidate} && -x ${candidate} ]] || continue
    ver="$(nero_nfc_clang_format_version_raw "${candidate}")" || continue
    nero_nfc_clang_format_version_ge "$NERO_NFC_CLANG_FORMAT_MIN_VERSION" "$ver" || continue
    if [[ -z ${best_ver} ]] ||
      [[ "$(printf '%s\n%s\n' "$best_ver" "$ver" | sort -V | tail -n1)" == "$ver" ]]; then
      best="${candidate}"
      best_ver="${ver}"
    fi
  done < <(nero_nfc_clang_format_candidate_bins)
  [[ -n ${best} ]] || return 1
  printf '%s\n' "${best}"
}

nero_nfc_ensure_clang_format() {
  local format_bin install_dir
  format_bin="$(nero_nfc_find_clang_format)" || return 1

  install_dir="$(nero_nfc_clang_tidy_install_dir)"
  mkdir -p "${install_dir}"
  if [[ ${format_bin} != "${install_dir}/clang-format" ]]; then
    ln -sf "${format_bin}" "${install_dir}/clang-format"
  fi

  nero_nfc_export_tool_shim_dir "${install_dir}"

  nero_nfc_clang_format_version_ge "$NERO_NFC_CLANG_FORMAT_MIN_VERSION"
}
