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

# Clang static analyzer on the host unit-test tree (project sources + tests only when
# NERO_USE_SYSTEM_GTEST=ON — avoids analyzing a FetchContent googletest build).
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${repo_root}/tests/build-scan"
report_dir="${repo_root}/tests/scan-build-report"

resolve_scan_build() {
  local c v
  if command -v scan-build >/dev/null 2>&1; then printf '%s' "scan-build"; return 0; fi
  for v in 21 20 19 18 17 16; do
    c="scan-build-${v}"
    if command -v "$c" >/dev/null 2>&1; then printf '%s' "$c"; return 0; fi
  done
  return 1
}

usage() {
  cat <<'EOF'
Usage: make/scan-build-tests.sh

Requires: cmake, Ninja or Make, clang scan-build (clang-tools / llvm packages).

Uses a fresh build tree under tests/build-scan/ with -DNERO_USE_SYSTEM_GTEST=ON so the
analyzer does not compile vendored googletest sources. Install on Debian/Ubuntu:

  sudo apt-get install -y cmake ninja-build libgtest-dev clang-tools

Environment:
  INSTALL_DEPS=1            Run make/install-linux-deps.sh before scan-build (default: 0)
  AUTO_INSTALL_LINUX_DEPS=1 Alias for INSTALL_DEPS when invoking this script directly
  NERO_SCAN_BUILD_CMD   Override analyzer driver (default: first of scan-build, scan-build-18, …)
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "$(uname -s)" == "Linux" ]]; then
  : "${AUTO_INSTALL_LINUX_DEPS:=${INSTALL_DEPS:-0}}"
  if [[ "${AUTO_INSTALL_LINUX_DEPS}" != "0" ]]; then
    FIRMWARE_ROOT="${repo_root}" \
      INSTALL_DEPS="${INSTALL_DEPS:-1}" \
      AUTO_INSTALL_LINUX_DEPS="${AUTO_INSTALL_LINUX_DEPS}" \
      bash "${repo_root}/make/install-linux-deps.sh"
  fi
fi

if ! command -v cmake >/dev/null 2>&1; then
  printf 'error: cmake not found (install via: make deps or INSTALL_DEPS=1 bash make/scan-build-tests.sh)\n' >&2
  exit 1
fi

scan_build="${NERO_SCAN_BUILD_CMD:-}"
if [[ -z "$scan_build" ]]; then
  if ! scan_build="$(resolve_scan_build)"; then
    printf 'error: scan-build not found (install clang-tools / llvm — e.g. apt install clang-tools)\n' >&2
    exit 1
  fi
fi

generator="Unix Makefiles"
if command -v ninja >/dev/null 2>&1; then
  generator="Ninja"
fi

rm -rf "${build_dir}" "${report_dir}"
mkdir -p "${report_dir}"

# Configure without scan-build (CMake feature tests expect a real compiler).
cmake \
  -S "${repo_root}/tests" \
  -B "${build_dir}" \
  -G "${generator}" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DNERO_USE_SYSTEM_GTEST=ON \
  -DNERO_ENABLE_COVERAGE=OFF \
  -DNERO_ENABLE_SANITIZER_ADDRESS=OFF \
  -DNERO_ENABLE_SANITIZER_UNDEFINED=OFF

procs="$(bash "${repo_root}/make/cpu-jobs.sh")"

if [[ "${generator}" == "Ninja" ]]; then
  "${scan_build}" --status-bugs -o "${report_dir}" ninja -C "${build_dir}" -j "${procs}"
else
  env -u MAKEFLAGS "${scan_build}" --status-bugs -o "${report_dir}" cmake --build "${build_dir}" -j "${procs}"
fi

printf 'scan-build HTML (if emitted): %s/index.html\n' "${report_dir}"
