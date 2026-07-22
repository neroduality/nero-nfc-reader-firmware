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

# Guest entry for Lima Main CI. Invoked by run-ci-locally-lima.sh via limactl shell.
#
# Host bind mount (/src) is read-only source. CI runs on a VM-local work tree so
# host build/ and third-party/ are neither reused nor written.
set -euo pipefail

HOST_SRC="${NERO_LIMA_HOST_SRC:-/src}"
WORK_ROOT="${NERO_LIMA_WORK_ROOT:-${HOME}/nero-nfc-ci-work}"

if [[ ! -d ${HOST_SRC} || ! -f ${HOST_SRC}/Makefile ]]; then
  printf 'error: repo not mounted at %s\n' "${HOST_SRC}" >&2
  exit 1
fi

if [[ $(id -un) != lima ]]; then
  printf 'error: expected guest user lima, got %s\n' "$(id -un)" >&2
  exit 1
fi

export LINT_KIT="${LINT_KIT:-/opt/lint-kit}"
if [[ ! -x ${LINT_KIT}/lint-c-cpp.sh ]]; then
  printf 'error: lint kit missing lint-c-cpp.sh: %s\n' "${LINT_KIT}" >&2
  exit 1
fi

printf '── Lima guest: lint kit %s ──\n' "${LINT_KIT}"
printf '── Lima guest: docker smoke test (docker info + docker run) ──\n'
if ! LIMA_DOCKER_SMOKE_MODE=full DOCKER_INFO_TIMEOUT=60s DOCKER_RUN_TIMEOUT=300s \
  bash "${HOST_SRC}/.github/scripts/lima-docker-smoke.sh"; then
  printf 'error: docker smoke test failed for %s\n' "$(id -un)" >&2
  docker info 2>&1 | head -10 >&2 || true
  exit 1
fi

bash "${HOST_SRC}/.github/scripts/prepare-ci-worktree.sh" "${HOST_SRC}" "${WORK_ROOT}"
export FIRMWARE_ROOT="${WORK_ROOT}"

printf '── Lima guest: installing CI host deps (docker runner; lint in container) ──\n'
sudo env LINT_KIT="${LINT_KIT}" bash "${FIRMWARE_ROOT}/.github/scripts/lima-install-deps.sh" "${FIRMWARE_ROOT}"

export NERO_CI_LOCAL_IN_VM=1
export CONTAINER_ENGINE="${CONTAINER_ENGINE:-docker}"
export CI_PLATFORM="${CI_PLATFORM:-linux/amd64}"
export FIRMWARE_ROOT

# Prefer scripts from the work tree after seed (same content; avoids /src writes).
# shellcheck source=helper-toolchain.sh
source "${FIRMWARE_ROOT}/.github/scripts/helper-toolchain.sh"
nero_nfc_toolchain_activate || true

printf '── Lima guest: Main CI via docker (lint debian:sid-slim + test matrix) ──\n'
printf '── Lima guest: FIRMWARE_ROOT=%s (VM-local; host /src is source-only) ──\n' "${FIRMWARE_ROOT}"
exec bash "${FIRMWARE_ROOT}/.github/scripts/run-ci-locally.sh" "$@"
