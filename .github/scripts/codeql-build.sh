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

# Traced build for CodeQL: CMake host tests + userspace (project code only; the host
# tests compile the NeroNfc firmware library sources).
#
# Mirrors .github/scripts/ci-run-tests.sh for CMake (without coverage / sanitizers / scan-build).
#
# Layout (disjoint from CLI/DB — GitHub database-create: build must not wipe tools/DB):
#   tests/build-codeql/     — host unit-test CMake tree (this script may rm -rf)
#   build/userspace-codeql/ — userspace CMake tree (this script may rm -rf)
#   build/codeql-cli/       — local CLI (ci-run-codeql.sh; not touched here)
#   build/codeql/           — database + SARIF (ci-run-codeql.sh; not touched here)
#
# Requires: cmake >= 3.20, C++23 toolchain, ninja or make, system GoogleTest (libgtest-dev),
# and `make third-party-nfc-libs` (ST25R3916 + NFC-RFAL headers for host firmware tests).
#
# Environment:
#   FIRMWARE_ROOT               Repo root (default: pwd)
#   CODEQL_INSTALL_LINUX_DEPS   If 1 on Linux, run make/install-linux-deps.sh before CMake builds (default: 0).
set -euo pipefail

repo_root="${FIRMWARE_ROOT:-$(pwd)}"
if [[ ! -f "${repo_root}/tests/CMakeLists.txt" ]]; then
  printf 'error: FIRMWARE_ROOT must point at firmware repo root (missing tests/CMakeLists.txt)\n' >&2
  exit 1
fi

# codeql.yml cannot source the pin helper, so assert here -- inside the CodeQL
# job itself, not only from `make codeql-local` -- that the workflow's container
# image and bundle URL match helper-codeql-pins.sh.
# shellcheck source=helper-codeql-pins.sh
source "${repo_root}/.github/scripts/helper-codeql-pins.sh"
codeql_pins_check_workflow "${repo_root}/.github/workflows/codeql.yml"

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
  -DNERO_USE_SYSTEM_GTEST=ON

cmake --build "${build_dir_tests}" --parallel "${jobs}"

cmake -S "${repo_root}/userspace" -B "${build_dir_userspace}" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_RUNTIME_OUTPUT_DIRECTORY="${build_dir_userspace}/bin"

cmake --build "${build_dir_userspace}" --parallel "${jobs}"

printf '── CodeQL traced build complete ──\n'
