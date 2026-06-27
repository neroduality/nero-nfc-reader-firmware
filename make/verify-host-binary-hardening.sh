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

# Release host CLI hardening verification (PIE, RELRO, BIND_NOW, stack, nodlopen).
#
# Usage (from firmware root):
#   bash make/verify-host-binary-hardening.sh
#   NERO_HOST_BIN_DIR=build/userspace/bin bash make/verify-host-binary-hardening.sh
#
# Run automatically at the end of ``make verify`` after a Release userspace build.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="${NERO_HOST_BIN_DIR:-${repo_root}/build/userspace/bin}"

if ! command -v readelf >/dev/null 2>&1; then
  printf 'error: readelf not found (install binutils)\n' >&2
  exit 1
fi

expected_bins=(reader writer nero_nfc_uart)
fail=0

check_pie() {
  local bin="$1"
  local ty
  ty="$(readelf -h "${bin}" | awk '/Type:/ { print $2; exit }')"
  if [[ ${ty} != "DYN" ]]; then
    printf 'error: %s: ELF Type is %s (expected DYN / PIE)\n' "${bin}" "${ty}" >&2
    fail=1
  fi
}

check_bind_now() {
  local bin="$1"
  if ! readelf -d "${bin}" 2>/dev/null | grep -q 'BIND_NOW'; then
    printf 'error: %s: missing BIND_NOW (full RELRO)\n' "${bin}" >&2
    fail=1
  fi
}

check_relro() {
  local bin="$1"
  if ! readelf -l "${bin}" 2>/dev/null | grep -q 'GNU_RELRO'; then
    printf 'error: %s: missing GNU_RELRO program header\n' "${bin}" >&2
    fail=1
  fi
}

check_noexecstack() {
  local bin="$1"
  local flags
  flags="$(readelf -W -l "${bin}" | awk '/GNU_STACK/ { print $7; exit }')"
  if [[ -z ${flags} ]]; then
    printf 'error: %s: missing GNU_STACK program header\n' "${bin}" >&2
    fail=1
    return
  fi
  if [[ ${flags} == *E* ]]; then
    printf 'error: %s: GNU_STACK is executable (expected noexecstack)\n' "${bin}" >&2
    fail=1
  fi
}

check_nodlopen() {
  local bin="$1"
  if readelf -d "${bin}" 2>/dev/null | grep -Eq 'NOOPEN|0x[0-9]+ \(FLAGS_1\).*NOOPEN'; then
    return 0
  fi
  # Some toolchains (e.g. Fedora binutils) accept -Wl,-z,nodlopen but omit DF_1_NOOPEN in readelf.
  # Fall back to the recorded link line from the userspace CMake build.
  local name
  name="$(basename "${bin}")"
  local link_txt="${bin_dir}/../cli/CMakeFiles/${name}.dir/link.txt"
  if [[ -f ${link_txt} ]] && grep -q 'nodlopen' "${link_txt}"; then
    return 0
  fi
  printf 'error: %s: missing -Wl,-z,nodlopen (readelf NOOPEN or link.txt nodlopen)\n' "${bin}" >&2
  fail=1
}

printf '── Host binary hardening (readelf) ──\n'
printf 'Directory: %s\n' "${bin_dir}"

for name in "${expected_bins[@]}"; do
  bin="${bin_dir}/${name}"
  if [[ ! -f ${bin} ]]; then
    printf 'error: missing host binary %s (build userspace Release first)\n' "${bin}" >&2
    fail=1
    continue
  fi
  printf 'Checking %s\n' "${name}"
  check_pie "${bin}"
  check_bind_now "${bin}"
  check_relro "${bin}"
  check_noexecstack "${bin}"
  check_nodlopen "${bin}"
done

if ((fail != 0)); then
  exit 1
fi

printf 'host binary hardening: OK\n'
