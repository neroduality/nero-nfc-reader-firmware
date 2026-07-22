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

# Reproduce GitHub Actions CodeQL locally (same pattern as make ci-local):
#   isolated work tree + debian:sid-slim + ci-run-codeql.sh
#
# Mirrors .github/workflows/codeql.yml (install-linux-deps INSTALL_LINT_DEPS=0,
# traced CMake + make nfc on both boards, then analyze).
#
# Usage:
#   bash .github/scripts/run-codeql-locally.sh
#   bash .github/scripts/run-codeql-locally.sh --db-only
#   make codeql-local
#
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=helper-container-engine.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/helper-container-engine.sh"
# shellcheck source=helper-container-bind-mount.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/helper-container-bind-mount.sh"

usage() {
  cat <<'EOF'
Reproduce CodeQL locally (mirrors .github/workflows/codeql.yml).

Same shape as make ci-local: fresh isolated work tree + debian:sid-slim.
No host CodeQL CLI/pack caches are mounted — CLI and packs download inside
the container each run (GHA-cold). Live checkout build/ and third-party/ are
untouched. SARIF is copied to build/codeql/results.sarif on success.

Usage:
  bash .github/scripts/run-codeql-locally.sh [options]
  make codeql-local

Options:
  --db-only       Create the CodeQL database only (skip analyze)
  --no-summary    Do not print SARIF summary after analyze
  --open          Open SARIF on the host after the container exits
  --verify-gate   Exit non-zero on CodeQL error-level findings
  -h, --help      Help

Environment:
  CONTAINER_ENGINE         docker (default) or podman
  CODEQL_IMAGE             Container image (default: digest-pinned debian:sid-slim)
  CI_PLATFORM              Container platform (default: linux/amd64)
  CODEQL_INCLUDE_FIRMWARE  Set to 0 to skip traced make nfc (default: 1)
  NERO_CI_LOCAL_WORK_ROOT  Isolated work tree (default: ~/.cache/nero-nfc-ci-local/work-codeql)
  NERO_CI_LOCAL_KEEP_WORK  Set to 1 to keep the work tree after exit

EOF
}

VERIFY_GATE=0
SUMMARIZE_SARIF="${CODEQL_SUMMARIZE_SARIF:-1}"
OPEN_SARIF="${CODEQL_OPEN_SARIF:-0}"
FORWARD_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --db-only)
      FORWARD_ARGS+=("$1")
      shift
      ;;
    --verify-gate)
      VERIFY_GATE=1
      FORWARD_ARGS+=("$1")
      shift
      ;;
    --no-summary)
      SUMMARIZE_SARIF=0
      FORWARD_ARGS+=("$1")
      shift
      ;;
    --open)
      OPEN_SARIF=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      printf 'error: unknown option %q\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

SOURCE_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
FIRMWARE_ROOT="${SOURCE_ROOT}"

if [[ ! -f "${SOURCE_ROOT}/tests/CMakeLists.txt" ]]; then
  printf 'error: unexpected layout (missing tests/CMakeLists.txt under %s)\n' "${SOURCE_ROOT}" >&2
  exit 1
fi

if ! nero_require_container_engine >/dev/null; then
  exit 1
fi

if ! [[ -v CI_PLATFORM ]]; then
  export CI_PLATFORM=linux/amd64
fi
PLATFORM_ARGS=()
nero_nfc_load_ci_platform_args

_CI_LOCAL_WORK_ROOT_TO_CLEAN=""
_codeql_local_cleanup_worktree() {
  local root="${_CI_LOCAL_WORK_ROOT_TO_CLEAN}"
  [[ -n ${root} ]] || return 0
  if [[ ${NERO_CI_LOCAL_KEEP_WORK:-0} == 1 ]]; then
    printf '── codeql-local: keeping work tree %s (NERO_CI_LOCAL_KEEP_WORK=1) ──\n' "${root}" >&2
    return 0
  fi
  if [[ ! -d ${root} || ${root} == "${SOURCE_ROOT}" ]]; then
    return 0
  fi
  printf '── codeql-local: removing work tree %s ──\n' "${root}" >&2
  rm -rf "${root}"
}

_default_work="${XDG_CACHE_HOME:-${HOME}/.cache}/nero-nfc-ci-local/work-codeql"
WORK_ROOT="${NERO_CI_LOCAL_WORK_ROOT:-${_default_work}}"
# Fresh tree every run (rsync --exclude leaves prior third-party/ in place otherwise).
rm -rf "${WORK_ROOT}"
bash "${SCRIPT_DIR}/prepare-ci-worktree.sh" "${SOURCE_ROOT}" "${WORK_ROOT}"
FIRMWARE_ROOT="${WORK_ROOT}"
export FIRMWARE_ROOT
_CI_LOCAL_WORK_ROOT_TO_CLEAN="${WORK_ROOT}"
trap '_codeql_local_cleanup_worktree' EXIT
printf '── codeql-local: fresh isolated work tree %s (live repo %s untouched) ──\n' \
  "${FIRMWARE_ROOT}" "${SOURCE_ROOT}"

CODEQL_IMAGE="${CODEQL_IMAGE:-debian:sid-slim@sha256:54f7a23f03be1e9fe2849c61a7455588ea29b84c1659440f8ece2aea4c9871af}"
mkdir -p "${SOURCE_ROOT}/build/codeql"

printf '\n── CodeQL: container %s (cold; no host CodeQL caches) ──\n' "${CODEQL_IMAGE}"
# Only the isolated work tree is bind-mounted. CodeQL CLI + packs download inside
# the container (ephemeral), matching a clean GHA runner.
# shellcheck disable=SC2016
nero_nfc_run_bind_mount_container \
  -- \
  "${PLATFORM_ARGS[@]}" \
  -v "${FIRMWARE_ROOT}:/src" \
  -w /src \
  -e "FIRMWARE_ROOT=/src" \
  -e "HOST_UID=$(id -u)" \
  -e "HOST_GID=$(id -g)" \
  -e "CODEQL_CACHE=/tmp/nero-nfc-codeql-cli" \
  -e "CODEQL_INCLUDE_FIRMWARE=${CODEQL_INCLUDE_FIRMWARE:-1}" \
  -e "CODEQL_FIRMWARE_TARGETS=${CODEQL_FIRMWARE_TARGETS:-}" \
  -e "CODEQL_CLI_VERSION=${CODEQL_CLI_VERSION:-}" \
  -e "CODEQL_SUITE_FILE=${CODEQL_SUITE_FILE:-}" \
  -e "CODEQL_PACK_SCOPE=${CODEQL_PACK_SCOPE:-}" \
  -e "CODEQL_SUMMARIZE_SARIF=${SUMMARIZE_SARIF}" \
  -e "CODEQL_OPEN_SARIF=0" \
  -e "CODEQL_SARIF_LIST_LIMIT=${CODEQL_SARIF_LIST_LIMIT:-}" \
  -e "CODEQL_VERIFY_FAIL_LEVEL=${CODEQL_VERIFY_FAIL_LEVEL:-}" \
  "${CODEQL_IMAGE}" \
  bash -ceu 'bash /src/.github/scripts/ci-run-codeql.sh "$@"' \
  bash \
  "${FORWARD_ARGS[@]}"

# Preserve SARIF (and db metadata) on the live checkout before work-tree cleanup.
if [[ -d ${FIRMWARE_ROOT}/build/codeql ]]; then
  mkdir -p "${SOURCE_ROOT}/build/codeql"
  cp -a "${FIRMWARE_ROOT}/build/codeql/." "${SOURCE_ROOT}/build/codeql/"
  printf '── codeql-local: copied results → %s/build/codeql/ ──\n' "${SOURCE_ROOT}" >&2
fi

SARIF_PATH="${SOURCE_ROOT}/build/codeql/results.sarif"
if [[ ${OPEN_SARIF} == "1" && -s ${SARIF_PATH} ]]; then
  case "$(uname -s)" in
    Linux)
      if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "${SARIF_PATH}" >/dev/null 2>&1 &
      fi
      ;;
    Darwin)
      if command -v open >/dev/null 2>&1; then
        open "${SARIF_PATH}"
      fi
      ;;
  esac
fi

if [[ ${VERIFY_GATE} -eq 1 ]]; then
  if [[ ! -s ${SARIF_PATH} ]]; then
    printf 'error: CodeQL verify gate: empty SARIF at %s\n' "${SARIF_PATH}" >&2
    exit 1
  fi
  if ! command -v jq >/dev/null 2>&1; then
    printf 'error: CodeQL verify gate requires jq on the host\n' >&2
    exit 1
  fi
  fail_level="${CODEQL_VERIFY_FAIL_LEVEL:-error}"
  count="$(jq --arg lvl "${fail_level}" \
    '[.runs[].results[] | select((.level // "warning") == $lvl)] | length' "${SARIF_PATH}")"
  if [[ ${count} != "0" ]]; then
    printf 'error: CodeQL verify gate: %s %s-level finding(s) in %s\n' \
      "${count}" "${fail_level}" "${SARIF_PATH}" >&2
    exit 1
  fi
  printf 'CodeQL verify gate: OK (0 %s-level findings)\n' "${fail_level}"
fi

printf '\n── CodeQL local finished ──\n'
