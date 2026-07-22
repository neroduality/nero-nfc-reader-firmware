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

# Reproduce GitHub Actions Main CI locally (container lint + container test matrix).
#
# Same order as .github/workflows/main-ci.yml:
#   1. Debian slim lint container + make lint (spec-traceability gate, cppcheck/clang-tidy mins, …)
#   2. Debian trixie + Fedora 43 via ci-run-tests.sh (linux/amd64, fresh CMake)
#
# Requirements: docker or podman, bash
#
# Usage:
#   bash .github/scripts/run-ci-locally.sh
#   bash .github/scripts/run-ci-locally.sh --containers-only
#   bash .github/scripts/run-ci-locally.sh --debian-only
#   make ci-local
#   make lima
#
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=helper-container-engine.sh
source "${SCRIPT_DIR}/helper-container-engine.sh"

# --lima on the host delegates to a Lima ubuntu-24.04 VM; inside the VM NERO_CI_LOCAL_IN_VM=1.
LIMA=0
_parsed_args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --lima) LIMA=1 ;;
    *) _parsed_args+=("$1") ;;
  esac
  shift
done
set -- "${_parsed_args[@]}"

if [[ ${LIMA} -eq 1 && ${NERO_CI_LOCAL_IN_VM:-0} != 1 ]]; then
  exec bash "${SCRIPT_DIR}/run-ci-locally-lima.sh" "$@"
fi

usage() {
  cat <<'EOF'
Reproduce Main CI locally (mirrors .github/workflows/main-ci.yml).

Default: Debian slim strict lint container, then container test matrix.

Lint container (same as GitHub lint job):
  debian:sid-slim, lint kit at .lint-kit-org/lint-c-cpp, ci-run-lint.sh

Test matrix (same as GitHub test job):
  debian:sid-slim + fedora:43, ci-run-test-container.sh

Usage:
  bash .github/scripts/run-ci-locally.sh [options]

Presets:
  --main              Lint container + test matrix (default)
  --containers-only   Skip lint container; run test matrix only
  --lint-only         Lint container only (alias for --skip-containers)

Matrix:
  --all               Debian then Fedora (default when containers run)
  --debian-only       debian:sid-slim only
  --fedora-only       fedora:43 only

Skip flags:
  --skip-lint         Skip lint container
  --skip-containers   Skip test matrix (lint container only)

Lima (host only):
  --lima              Run inside a fresh Lima ubuntu-24.04 VM (see also: make lima)
                      Requires limactl; destroys/recreates VM each run.
                      Host /src is read-only; CI uses a VM-local work tree
                      (no host build/ or third-party/ reuse).

Other:
  -h, --help          Help

Environment:
  CONTAINER_ENGINE    docker (default) or podman
  LINT_KIT            Host path to org lint-c-cpp (Lima: mounted at /opt/lint-kit;
                      lint container: /opt/lint-kit when outside repo clone path)
  LINT_KIT_REF        Override lint kit git ref/tag (e.g. v0.1.0)
  LINT_IMAGE          Lint container image (default: digest-pinned debian:sid-slim; same as Main CI)
  CI_PLATFORM         Container platform (default: linux/amd64; set empty for native arch on ARM hosts)
  NERO_LIMA_INSTANCE  Lima VM name for --lima (default: nero-nfc-ci)
  NERO_LIMA_START_TIMEOUT  limactl start timeout (default: 15m)
  NERO_LIMA_KEEP_ON_FAILURE  Set to 1 to keep the VM when startup/CI fails
  NERO_LIMA_VERBOSE   Set to 1 to show limactl delete output on teardown
  NERO_LIMA_WORK_ROOT Lima guest work tree (default: ~/nero-nfc-ci-work)
  NERO_CI_LOCAL_WORK_ROOT  Host ci-local work tree (default: ~/.cache/nero-nfc-ci-local/work)
  NERO_CI_LOCAL_KEEP_WORK  Set to 1 to keep the host work tree after exit (default: delete)

Note: make lint runs on the native host checkout for fast iteration. make ci-local
and make lima run container CI in an isolated work tree so the live repo's
build/ and third-party/ are not reused or written. Host ci-local deletes its
work tree on exit (success or failure).

EOF
}

FIRMWARE_ROOT="${FIRMWARE_ROOT:-$(cd -- "${SCRIPT_DIR}/../.." && pwd)}"
# On the host this is the live checkout. Lima guest already points FIRMWARE_ROOT at
# its VM-local work tree and sets NERO_CI_LOCAL_IN_VM=1 before exec'ing this script.
SOURCE_ROOT="${FIRMWARE_ROOT}"

# shellcheck source=helper-container-bind-mount.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/helper-container-bind-mount.sh"

resolve_lint_kit_root() {
  if [[ -n ${LINT_KIT:-} ]]; then
    candidate="$(cd "${LINT_KIT}" && pwd)" || {
      printf 'error: lint kit not found: %s\n' "${LINT_KIT}" >&2
      exit 1
    }
    printf '%s\n' "${candidate}"
    return 0
  fi
  # shellcheck source=lint-kit-config.sh
  # shellcheck disable=SC1091
  source "${SCRIPT_DIR}/lint-kit-config.sh"
  lint_kit_ensure_cloned "${SOURCE_ROOT}"
  lint_kit_root "${SOURCE_ROOT}"
}

RUN_LINT=1
RUN_CONTAINERS=1
RUN_DEBIAN=1
RUN_FEDORA=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --main)
      RUN_LINT=1
      RUN_CONTAINERS=1
      ;;
    --containers-only)
      RUN_LINT=0
      RUN_CONTAINERS=1
      ;;
    --lint-only)
      RUN_LINT=1
      RUN_CONTAINERS=0
      ;;
    --all)
      RUN_DEBIAN=1
      RUN_FEDORA=1
      ;;
    --debian-only)
      RUN_DEBIAN=1
      RUN_FEDORA=0
      ;;
    --fedora-only)
      RUN_DEBIAN=0
      RUN_FEDORA=1
      ;;
    --skip-lint) RUN_LINT=0 ;;
    --skip-containers) RUN_CONTAINERS=0 ;;
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
  shift
done

# Isolate container CI from the live workspace unless the Lima guest already did.
# Native `make lint` keeps using the live checkout; ci-local writes only under WORK_ROOT.
# Host work trees are always removed on EXIT (success or failure) unless
# NERO_CI_LOCAL_KEEP_WORK=1. Lima guest trees go away with VM teardown.
_CI_LOCAL_WORK_ROOT_TO_CLEAN=""
_ci_local_cleanup_worktree() {
  local root="${_CI_LOCAL_WORK_ROOT_TO_CLEAN}"
  [[ -n ${root} ]] || return 0
  if [[ ${NERO_CI_LOCAL_KEEP_WORK:-0} == 1 ]]; then
    printf '── ci-local: keeping work tree %s (NERO_CI_LOCAL_KEEP_WORK=1) ──\n' "${root}" >&2
    return 0
  fi
  if [[ ! -d ${root} ]]; then
    return 0
  fi
  # Refuse to delete the live checkout if misconfigured.
  if [[ ${root} == "${SOURCE_ROOT}" ]]; then
    printf '── ci-local: refusing to delete SOURCE_ROOT %s ──\n' "${root}" >&2
    return 0
  fi
  printf '── ci-local: removing work tree %s ──\n' "${root}" >&2
  rm -rf "${root}"
}

if [[ ${NERO_CI_LOCAL_IN_VM:-0} == 1 ]]; then
  printf '── ci-local: FIRMWARE_ROOT=%s (Lima guest work tree) ──\n' "${FIRMWARE_ROOT}"
else
  _default_ci_work="${XDG_CACHE_HOME:-${HOME}/.cache}/nero-nfc-ci-local/work"
  WORK_ROOT="${NERO_CI_LOCAL_WORK_ROOT:-${_default_ci_work}}"
  # Pin lint kit to the live checkout clone before switching FIRMWARE_ROOT.
  if [[ -z ${LINT_KIT:-} ]]; then
    export LINT_KIT
    LINT_KIT="$(resolve_lint_kit_root)"
  fi
  bash "${SCRIPT_DIR}/prepare-ci-worktree.sh" "${SOURCE_ROOT}" "${WORK_ROOT}"
  FIRMWARE_ROOT="${WORK_ROOT}"
  export FIRMWARE_ROOT
  _CI_LOCAL_WORK_ROOT_TO_CLEAN="${WORK_ROOT}"
  trap '_ci_local_cleanup_worktree' EXIT
  printf '── ci-local: isolated work tree %s (live repo %s untouched; removed on exit) ──\n' \
    "${FIRMWARE_ROOT}" "${SOURCE_ROOT}"
fi

_ci_local_plan() {
  local lint=off containers=off debian=off fedora=off
  [[ ${RUN_LINT} -eq 1 ]] && lint=on
  [[ ${RUN_CONTAINERS} -eq 1 ]] && containers=on
  [[ ${RUN_DEBIAN} -eq 1 ]] && debian=on
  [[ ${RUN_FEDORA} -eq 1 ]] && fedora=on
  if [[ ${RUN_CONTAINERS} -eq 1 ]]; then
    printf '── local Main CI plan: lint=%s test_matrix=%s (debian=%s fedora=%s) ──\n' \
      "${lint}" "${containers}" "${debian}" "${fedora}"
  else
    printf '── local Main CI plan: lint=%s test_matrix=%s ──\n' "${lint}" "${containers}"
  fi
}

run_lint_container() {
  local lint_kit lint_image default_kit container_lint_kit mount_args=()
  lint_kit="$(resolve_lint_kit_root)"
  if [[ ! -x ${lint_kit}/lint-c-cpp.sh ]]; then
    printf 'error: lint kit missing lint-c-cpp.sh: %s\n' "${lint_kit}" >&2
    exit 1
  fi
  lint_image="${LINT_IMAGE:-debian:sid-slim@sha256:54f7a23f03be1e9fe2849c61a7455588ea29b84c1659440f8ece2aea4c9871af}"
  default_kit="${FIRMWARE_ROOT}/.lint-kit-org/lint-c-cpp"
  container_lint_kit="/src/.lint-kit-org/lint-c-cpp"
  # External LINT_KIT (host path): mount at /opt/lint-kit inside the container.
  if [[ ${lint_kit} != "$(cd "${default_kit}" 2>/dev/null && pwd || true)" ]]; then
    mount_args=(-v "${lint_kit}:/opt/lint-kit:ro")
    container_lint_kit="/opt/lint-kit"
  fi
  printf '\n── Main CI: lint container (%s) ──\n' "${lint_image}"
  printf '── lint kit: %s → %s ──\n' "${lint_kit}" "${container_lint_kit}"
  # Bind-mount isolated FIRMWARE_ROOT at /src (never the live make lint workspace).
  # shellcheck disable=SC2016
  nero_nfc_run_bind_mount_container \
    -- \
    "${PLATFORM_ARGS[@]}" \
    -v "${FIRMWARE_ROOT}:/src" \
    "${mount_args[@]}" \
    -w /src \
    -e "FIRMWARE_ROOT=/src" \
    -e "LINT_KIT=${container_lint_kit}" \
    -e "HOST_UID=$(id -u)" \
    -e "HOST_GID=$(id -g)" \
    -e "NERO_CI_LOCAL_IN_VM=${NERO_CI_LOCAL_IN_VM:-0}" \
    "${lint_image}" \
    bash -ceu 'bash /src/.github/scripts/ci-run-lint.sh'
}

if ! [[ -v CI_PLATFORM ]]; then
  export CI_PLATFORM=linux/amd64
fi

PLATFORM_ARGS=()
nero_nfc_load_ci_platform_args
_resolved_platform="$(nero_nfc_resolve_ci_platform)"
case "$(uname -m)" in
  x86_64 | amd64) ;;
  *)
    if [[ -n ${_resolved_platform} ]]; then
      printf 'note: container platform %s (host %s); needs QEMU for amd64 on non-x86 hosts\n' \
        "${_resolved_platform}" "$(uname -m)"
    else
      printf 'note: container platform native (host %s); differs from GitHub linux/amd64\n' "$(uname -m)"
    fi
    ;;
esac

if [[ ${RUN_LINT} -eq 1 || ${RUN_CONTAINERS} -eq 1 ]]; then
  # Fail early if docker/podman is missing; nero_nfc_run_bind_mount_container uses CONTAINER_ENGINE.
  if ! nero_require_container_engine >/dev/null; then
    exit 1
  fi
fi

_ci_local_plan

if [[ ${RUN_LINT} -eq 1 ]]; then
  run_lint_container
fi

if [[ ${RUN_CONTAINERS} -eq 0 ]]; then
  printf '\n── local Main CI finished (lint container only) ──\n'
  exit 0
fi

run_in_image() {
  local image="$1"
  local label="$2"
  printf '\n── Main CI: test matrix %s (%s) ──\n' "${label}" "${image}"
  # Bind-mount isolated FIRMWARE_ROOT at /src (never the live make lint workspace).
  # shellcheck disable=SC2016
  nero_nfc_run_bind_mount_container \
    -- \
    "${PLATFORM_ARGS[@]}" \
    -v "${FIRMWARE_ROOT}:/src" \
    -w /src \
    -e "FIRMWARE_ROOT=/src" \
    -e "HOST_UID=$(id -u)" \
    -e "HOST_GID=$(id -g)" \
    -e "NERO_CI_LOCAL_IN_VM=${NERO_CI_LOCAL_IN_VM:-0}" \
    -e "AUTO_INSTALL_LINUX_DEPS=1" \
    -e "INSTALL_DEPS=1" \
    -e "INSTALL_LINT_DEPS=0" \
    "${image}" \
    bash -ceu 'bash /src/.github/scripts/ci-run-test-container.sh'
}

if [[ ${RUN_DEBIAN} -eq 1 ]]; then
  run_in_image \
    debian:sid-slim@sha256:54f7a23f03be1e9fe2849c61a7455588ea29b84c1659440f8ece2aea4c9871af \
    "Debian sid"
fi
if [[ ${RUN_FEDORA} -eq 1 ]]; then
  run_in_image \
    fedora:43@sha256:762d73ba1c455232b0272c5d445a34f36c4b9f421cbc05ce8102552325b6a222 \
    "Fedora 43"
fi

printf '\n── local Main CI completed successfully ──\n'
