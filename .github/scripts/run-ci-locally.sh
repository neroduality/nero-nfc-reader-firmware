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

# Reproduce GitHub Actions Main CI locally (host lint + container test matrix).
#
# Same order as .github/workflows/main-ci.yml:
#   1. install-linux-deps + make lint (CI=true; spec-traceability gate, cppcheck/clang-tidy mins, …)
#   2. Debian trixie + Fedora 43 via ci-run-tests.sh (linux/amd64, fresh CMake)
#
# Requirements: docker or podman, bash; sudo for host INSTALL_DEPS=1 when packages are missing
#
# Usage:
#   bash .github/scripts/run-ci-locally.sh
#   bash .github/scripts/run-ci-locally.sh --containers-only
#   bash .github/scripts/run-ci-locally.sh --debian-only
#   make ci-local CI_LOCAL_FLAGS=--lima   # ubuntu-24.04 Lima VM (GHA parity)
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

Default: host strict lint, then container test matrix.

Host lint (same as GitHub lint job):
  bash make/install-linux-deps.sh
  CI=true make lint INSTALL_DEPS=0

Containers: debian:sid-slim + fedora:43, linux/amd64, ci-run-tests.sh (wipes CMake trees first).
  Container deps use INSTALL_LINT_DEPS=0 (unit tests only; clang-tidy runs on the lint host/VM).

Usage:
  bash .github/scripts/run-ci-locally.sh [options]

Presets:
  --main              Lint + containers (default)
  --containers-only   Skip host lint; run containers only

Matrix:
  --all               Debian then Fedora (default when containers run)
  --debian-only       debian:sid-slim only
  --fedora-only       fedora:43 only

Skip flags:
  --skip-lint         Skip host install-linux-deps + make lint
  --skip-containers   Skip container matrix

Lima (optional; host only):
  --lima              Run host lint + containers inside a fresh Lima ubuntu-24.04 VM
                      each time (destroy → create → CI → teardown; requires limactl).
                      Default is native host.

Other:
  -h, --help          Help

Environment:
  CONTAINER_ENGINE    docker (default) or podman
  CI_PLATFORM         Default for containers: linux/amd64 (same as GitHub).
                      Set empty (CI_PLATFORM=) for native arch on ARM hosts.
  NERO_LIMA_INSTANCE  Lima VM name for --lima (default: nero-nfc-ci)
  NERO_LIMA_START_TIMEOUT  limactl start timeout (default: 15m; Docker SocketUser boot)
  NERO_LIMA_KEEP_ON_FAILURE  Set to 1 to keep the VM when startup/CI fails
  NERO_LIMA_VERBOSE   Set to 1 to show limactl delete output on teardown

EOF
}

FIRMWARE_ROOT="${FIRMWARE_ROOT:-$(cd -- "${SCRIPT_DIR}/../.." && pwd)}"
_IN_VM=0
if [[ ${NERO_CI_LOCAL_IN_VM:-0} == 1 ]]; then
  _IN_VM=1
  FIRMWARE_ROOT="${FIRMWARE_ROOT:-/src}"
fi

# shellcheck source=helper-container-bind-mount.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/helper-container-bind-mount.sh"

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

run_host_lint() {
  if [[ ${_IN_VM} -eq 1 ]]; then
    printf '\n── Main CI: lint (Lima VM; deps installed in guest entry) ──\n'
    (cd "${FIRMWARE_ROOT}" && CI=true make lint INSTALL_DEPS=0)
    return
  fi
  printf '\n── Main CI: install lint dependencies (host) ──\n'
  (cd "${FIRMWARE_ROOT}" && INSTALL_DEPS=1 bash make/install-linux-deps.sh)
  printf '\n── Main CI: lint (host) ──\n'
  (cd "${FIRMWARE_ROOT}" && CI=true make lint INSTALL_DEPS=0)
}

if [[ ${RUN_LINT} -eq 1 ]]; then
  run_host_lint
fi

if [[ ${RUN_CONTAINERS} -eq 0 ]]; then
  printf '\n── local Main CI finished (host lint only) ──\n'
  exit 0
fi

ENGINE="$(nero_require_container_engine)" || exit 1

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

run_in_image() {
  local image="$1"
  local label="$2"
  printf '\n── Main CI: test matrix %s (%s) ──\n' "${label}" "${image}"
  if [[ ${_IN_VM} -eq 1 ]]; then
    # GHA-style: root container entry, no HOST_UID / bind-mount ownership restore.
    # shellcheck disable=SC2016
    "${ENGINE}" run --rm \
      "${PLATFORM_ARGS[@]}" \
      -v "${FIRMWARE_ROOT}:/src" \
      -w /src \
      -e "AUTO_INSTALL_LINUX_DEPS=1" \
      -e "INSTALL_DEPS=1" \
      -e "INSTALL_LINT_DEPS=0" \
      "${image}" \
      bash -ceu '
        bash /src/.github/scripts/ci-bootstrap-container.sh
        cd /src
        bash .github/scripts/ci-run-tests.sh
      '
  else
    # shellcheck disable=SC2016
    nero_nfc_run_bind_mount_container \
      -- \
      "${PLATFORM_ARGS[@]}" \
      -v "${FIRMWARE_ROOT}:/src" \
      -w /src \
      -e "HOST_UID=$(id -u)" \
      -e "HOST_GID=$(id -g)" \
      -e "AUTO_INSTALL_LINUX_DEPS=1" \
      -e "INSTALL_DEPS=1" \
      -e "INSTALL_LINT_DEPS=0" \
      "${image}" \
      bash -ceu '
        bash /src/.github/scripts/ci-bootstrap-container.sh
        cd /src
        bash .github/scripts/ci-run-tests.sh
      '
  fi
}

if [[ ${RUN_DEBIAN} -eq 1 ]]; then
  run_in_image debian:sid-slim "Debian sid"
fi
if [[ ${RUN_FEDORA} -eq 1 ]]; then
  run_in_image fedora:43 "Fedora 43"
fi

printf '\n── local Main CI completed successfully ──\n'
