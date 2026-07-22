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

# Test matrix container entry (after repo checkout). Mirrors main-ci.yml test job.
#
# GHA: run after actions/checkout with job env AUTO_INSTALL_LINUX_DEPS/INSTALL_DEPS/
# INSTALL_LINT_DEPS already set.
# ci-local: bind-mounts the repo and sets the same env vars before invoking this script.
set -euo pipefail

repo_root="${FIRMWARE_ROOT:-$(pwd)}"
if [[ ! -f ${repo_root}/Makefile ]]; then
  printf 'error: FIRMWARE_ROOT must point at firmware repo root (missing Makefile)\n' >&2
  exit 1
fi

# shellcheck source=helper-container-bind-mount.sh
# shellcheck disable=SC1091
source "${repo_root}/.github/scripts/helper-container-bind-mount.sh"

export FIRMWARE_ROOT="${repo_root}"

if [[ $(id -u) -eq 0 && -n ${HOST_UID:-} && ${NERO_NFC_CI_AS_USER:-0} != 1 ]]; then
  if [[ ${CI_SKIP_CHECKOUT_PREREQUISITES:-0} != 1 ]]; then
    bash "${repo_root}/.github/scripts/ci-install-checkout-prerequisites.sh"
  fi
  bash "${repo_root}/.github/scripts/ci-bootstrap-container.sh"
  AUTO_INSTALL_LINUX_DEPS=1 INSTALL_DEPS=1 INSTALL_LINT_DEPS=0 \
    bash "${repo_root}/make/install-linux-deps.sh"
  nero_nfc_prepare_bind_mount_paths "${repo_root}"
  nero_nfc_require_drop_to_host_user bash "${repo_root}/.github/scripts/ci-run-test-container.sh"
fi

nero_nfc_refuse_root_bind_mount_writes

if [[ ${CI_SKIP_CHECKOUT_PREREQUISITES:-0} != 1 && $(id -u) -eq 0 ]]; then
  bash "${repo_root}/.github/scripts/ci-install-checkout-prerequisites.sh"
fi
if [[ $(id -u) -eq 0 ]]; then
  bash "${repo_root}/.github/scripts/ci-bootstrap-container.sh"
fi

cd "${repo_root}"
bash .github/scripts/ci-run-tests.sh
