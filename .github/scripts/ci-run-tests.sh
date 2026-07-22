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

# Shared CI entry: Release unit tests (same as ``make test``) in container matrix jobs.
# Always wipes CMake trees first (``make/wipe-host-build-trees.sh ci``) — no cache reuse.
# Usage (from firmware root):
#   AUTO_INSTALL_LINUX_DEPS=1 bash .github/scripts/ci-run-tests.sh
set -euo pipefail

repo_root="$(pwd)"
if [[ ! -f "${repo_root}/Makefile" ]]; then
  printf 'error: run from firmware root (missing Makefile)\n' >&2
  exit 1
fi

# shellcheck source=helper-container-bind-mount.sh
source "${repo_root}/.github/scripts/helper-container-bind-mount.sh"

if [[ $(id -u) -eq 0 && -n ${HOST_UID:-} && ${NERO_NFC_CI_AS_USER:-0} != 1 ]]; then
  AUTO_INSTALL_LINUX_DEPS=1 INSTALL_DEPS=1 INSTALL_LINT_DEPS=0 \
    bash "${repo_root}/make/install-linux-deps.sh"
  nero_nfc_prepare_bind_mount_paths "${repo_root}"
  nero_nfc_require_drop_to_host_user bash "${repo_root}/.github/scripts/ci-run-tests.sh"
fi

nero_nfc_refuse_root_bind_mount_writes

if [[ "$(uname -s)" == "Linux" && $(id -u) -eq 0 ]]; then
  auto_install_linux_deps="${AUTO_INSTALL_LINUX_DEPS:-}"
  if [[ -z ${auto_install_linux_deps} ]]; then
    if [[ ${GITHUB_ACTIONS:-false} == true ]]; then
      auto_install_linux_deps=1
    else
      auto_install_linux_deps=0
    fi
  fi
  if [[ ${auto_install_linux_deps} != "0" ]]; then
    AUTO_INSTALL_LINUX_DEPS="${auto_install_linux_deps}" \
      INSTALL_DEPS="${INSTALL_DEPS:-${auto_install_linux_deps}}" \
      INSTALL_LINT_DEPS="${INSTALL_LINT_DEPS:-0}" \
      bash "${repo_root}/make/install-linux-deps.sh"
  fi
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=helper-toolchain.sh
source "${script_dir}/helper-toolchain.sh"
nero_nfc_toolchain_activate

bash "${repo_root}/make/wipe-host-build-trees.sh" ci

SANITIZE_ADDRESS=0 SANITIZE_UNDEFINED=0 NERO_TESTS_BUILD_TYPE=Release \
  bash "${repo_root}/make/run-unit-tests.sh"
