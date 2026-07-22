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

# Traced build for CodeQL: CMake host tests + userspace, then Arduino combined NFC
# firmware (`make nfc`) for each supported board.
#
# Mirrors .github/scripts/ci-run-tests.sh for CMake (without coverage / sanitizers / scan-build).
#
# Requires: cmake ≥ 3.20, C++23 toolchain, ninja or make; network for googletest FetchContent (CMake)
# and `make third-party-nfc-libs` (ST25R3916 + NFC-RFAL headers for host firmware tests).
# With CODEQL_INCLUDE_FIRMWARE=1 (default): arduino-cli and per-board Arduino cores via
# `make third-party-host-tools`, then traced `make nfc`.
#
# Environment:
#   FIRMWARE_ROOT               Repo root (default: pwd)
#   CODEQL_INSTALL_LINUX_DEPS   If 1 on Linux, run make/install-linux-deps.sh before CMake builds (default: 0).
#   CODEQL_INCLUDE_FIRMWARE     If 1 (default), run traced \`make nfc\` after CMake builds.
#   CODEQL_FIRMWARE_TARGETS     Space-separated TARGET list (default: both boards).
set -euo pipefail

repo_root="${FIRMWARE_ROOT:-$(pwd)}"
if [[ ! -f "${repo_root}/tests/CMakeLists.txt" ]]; then
  printf 'error: FIRMWARE_ROOT must point at firmware repo root (missing tests/CMakeLists.txt)\n' >&2
  exit 1
fi

if [[ "$(uname -s)" == "Linux" && ${CODEQL_INSTALL_LINUX_DEPS:-0} == "1" ]]; then
  export FIRMWARE_ROOT="${repo_root}"
  INSTALL_DEPS=1 AUTO_INSTALL_LINUX_DEPS=1 INSTALL_LINT_DEPS=0 \
    bash "${repo_root}/make/install-linux-deps.sh"
fi

build_dir_tests="${repo_root}/tests/build-codeql"
build_dir_userspace="${repo_root}/build/userspace-codeql"

rm -rf "${build_dir_tests}" "${build_dir_userspace}"

generator="Unix Makefiles"
if command -v ninja >/dev/null 2>&1; then
  generator="Ninja"
fi

jobs="$(bash "${repo_root}/make/cpu-jobs.sh")"

# Host tests compile ST25 frontend TUs; headers live under third-party/.
make -C "${repo_root}" third-party-nfc-libs

cmake -S "${repo_root}/tests" -B "${build_dir_tests}" \
  -DCMAKE_BUILD_TYPE=Release \
  -G "${generator}" \
  -DNERO_ENABLE_COVERAGE=OFF \
  -DNERO_ENABLE_SANITIZER_ADDRESS=OFF \
  -DNERO_ENABLE_SANITIZER_UNDEFINED=OFF \
  -DNERO_USE_SYSTEM_GTEST=OFF

cmake --build "${build_dir_tests}" --parallel "${jobs}"

cmake -S "${repo_root}/userspace" -B "${build_dir_userspace}" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_RUNTIME_OUTPUT_DIRECTORY="${build_dir_userspace}/bin"

cmake --build "${build_dir_userspace}" --parallel "${jobs}"

if [[ ${CODEQL_INCLUDE_FIRMWARE:-1} == "1" ]]; then
  printf '\n── CodeQL traced Arduino firmware (make nfc, both boards) ──\n'
  eval "$(bash "${repo_root}/make/export-arduino-isolated-env.sh" "${repo_root}")"
  # Isolate under build/nfc-codeql (FIRMWARE_BUILD_DIR = $(BUILD_DIR)/firmware/$(TARGET)/...).
  # NFC_BUILD_DIR is not a Make variable — do not pass it.
  # shellcheck disable=SC2086 # intentional word-split of space-separated TARGET list
  for target in ${CODEQL_FIRMWARE_TARGETS:-arduino_uno_r4wifi nucleo_wba65ri}; do
    printf '\n── CodeQL traced make nfc TARGET=%s ──\n' "${target}"
    # Host tools must land before resolve-arduino-cli (fresh CI has no third-party/).
    make -C "${repo_root}" third-party-host-tools TARGET="${target}"
    arduino_cli="$(bash "${repo_root}/make/resolve-arduino-cli.sh" "${repo_root}")"
    PATH="$(dirname "${arduino_cli}"):${PATH}"
    export PATH
    make -C "${repo_root}" nfc \
      TARGET="${target}" \
      BUILD_DIR="${repo_root}/build/nfc-codeql"
  done
fi

printf '── CodeQL traced build complete (CMake + optional firmware) ──\n'
