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

# Remove stale host CMake trees so lint/test/verify always compile current sources.
#
# Usage: bash make/wipe-host-build-trees.sh {test|lint|verify|ci}
#
# Opt out (incremental dev rebuilds): NERO_KEEP_HOST_BUILDS=1 make test|lint|verify
# The ``ci`` scope always wipes (Main CI / ci-run-tests); NERO_KEEP_HOST_BUILDS is ignored.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: bash make/wipe-host-build-trees.sh {test|lint|verify|ci}

Scopes:
  test   — tests/build
  lint   — build/lint/tests, build/lint/userspace, build/clang-tidy-compile-db
  verify — tests/build, tests/build-scan, tests/scan-build-report
  ci     — all CMake trees Main CI may configure (always wipes; no opt-out)

Set NERO_KEEP_HOST_BUILDS=1 to skip wiping for test/lint/verify only (faster local iteration).
EOF
}

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
scope="${1:-}"

wipe_dir() {
  local dir="$1"
  if [[ -d ${dir} ]]; then
    printf '── wiping %s ──\n' "${dir#"${repo_root}/"}" >&2
    rm -rf "${dir}"
  fi
}

wipe_ci_build_trees() {
  wipe_dir "${repo_root}/tests/build"
  wipe_dir "${repo_root}/tests/build-scan"
  wipe_dir "${repo_root}/tests/scan-build-report"
  wipe_dir "${repo_root}/build/lint/tests"
  wipe_dir "${repo_root}/build/lint/userspace"
  wipe_dir "${repo_root}/build/clang-tidy-compile-db"
  wipe_dir "${repo_root}/build/userspace"
}

if [[ "${NERO_KEEP_HOST_BUILDS:-0}" == "1" && ${scope} != ci ]]; then
  exit 0
fi

case "${scope}" in
  test)
    wipe_dir "${repo_root}/tests/build"
    ;;
  lint)
    wipe_dir "${repo_root}/build/lint/tests"
    wipe_dir "${repo_root}/build/lint/userspace"
    wipe_dir "${repo_root}/build/clang-tidy-compile-db"
    ;;
  verify)
    wipe_dir "${repo_root}/tests/build"
    wipe_dir "${repo_root}/tests/build-scan"
    wipe_dir "${repo_root}/tests/scan-build-report"
    ;;
  ci)
    wipe_ci_build_trees
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    printf 'error: unknown wipe scope: %s\n' "${scope}" >&2
    usage >&2
    exit 2
    ;;
esac
