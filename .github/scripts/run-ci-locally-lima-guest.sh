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
set -euo pipefail

FIRMWARE_ROOT="${FIRMWARE_ROOT:-/src}"

if [[ ! -d ${FIRMWARE_ROOT} || ! -f ${FIRMWARE_ROOT}/Makefile ]]; then
  printf 'error: repo not mounted at %s\n' "${FIRMWARE_ROOT}" >&2
  exit 1
fi

if [[ $(id -un) != lima ]]; then
  printf 'error: expected guest user lima, got %s\n' "$(id -un)" >&2
  exit 1
fi

printf '── Lima guest: docker smoke test (docker info + docker run) ──\n'
if ! LIMA_DOCKER_SMOKE_MODE=full DOCKER_INFO_TIMEOUT=60s DOCKER_RUN_TIMEOUT=300s \
  bash "${FIRMWARE_ROOT}/.github/scripts/lima-docker-smoke.sh"; then
  printf 'error: docker smoke test failed for %s\n' "$(id -un)" >&2
  docker info 2>&1 | head -10 >&2 || true
  exit 1
fi

printf '── Lima guest: installing CI deps ──\n'
sudo bash "${FIRMWARE_ROOT}/.github/scripts/lima-install-deps.sh" "${FIRMWARE_ROOT}"

export NERO_CI_LOCAL_IN_VM=1
export CI=true
export CONTAINER_ENGINE="${CONTAINER_ENGINE:-docker}"
export CI_PLATFORM="${CI_PLATFORM:-linux/amd64}"
export FIRMWARE_ROOT

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=helper-host-toolchain.sh
source "${script_dir}/helper-host-toolchain.sh"
nero_nfc_host_toolchain_activate

printf '── Lima guest: host toolchain smoke test ──\n'
nero_nfc_host_toolchain_verify

printf '── Lima guest: Main CI (lint + containers) ──\n'
exec bash "${FIRMWARE_ROOT}/.github/scripts/run-ci-locally.sh" "$@"
