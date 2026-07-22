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

# Lint job container entry (after repo + .lint-kit-org checkout). Mirrors main-ci.yml lint job.
#
# GHA: run after checkouts with CI_SKIP_CHECKOUT_PREREQUISITES=1.
# ci-local: bind-mounts repo + lint kit at .lint-kit-org/lint-c-cpp and runs full entry.
set -euo pipefail

repo_root="${FIRMWARE_ROOT:-$(pwd)}"
lint_kit="${LINT_KIT:-${repo_root}/.lint-kit-org/lint-c-cpp}"

if [[ ! -f ${repo_root}/Makefile ]]; then
  printf 'error: FIRMWARE_ROOT must point at firmware repo root (missing Makefile)\n' >&2
  exit 1
fi
if [[ ! -x ${lint_kit}/lint-c-cpp.sh ]]; then
  printf 'error: lint kit missing lint-c-cpp.sh: %s\n' "${lint_kit}" >&2
  printf 'hint: GHA checks out neroduality/.github to .lint-kit-org; ci-local mounts or clones it\n' >&2
  exit 1
fi

# shellcheck source=helper-container-bind-mount.sh
# shellcheck disable=SC1091
source "${repo_root}/.github/scripts/helper-container-bind-mount.sh"

export FIRMWARE_ROOT="${repo_root}"
export LINT_KIT="${lint_kit}"

if [[ $(id -u) -eq 0 && -n ${HOST_UID:-} && ${NERO_NFC_CI_AS_USER:-0} != 1 ]]; then
  INSTALL_DEPS=1 bash "${repo_root}/make/install-linux-deps.sh"
  if [[ ${CI_SKIP_CHECKOUT_PREREQUISITES:-0} != 1 ]]; then
    bash "${repo_root}/.github/scripts/ci-install-checkout-prerequisites.sh"
  fi
  nero_nfc_prepare_bind_mount_paths "${repo_root}"
  nero_nfc_require_drop_to_host_user bash "${repo_root}/.github/scripts/ci-run-lint.sh"
fi

nero_nfc_refuse_root_bind_mount_writes

if [[ ${CI_SKIP_CHECKOUT_PREREQUISITES:-0} != 1 && $(id -u) -eq 0 ]]; then
  bash "${repo_root}/.github/scripts/ci-install-checkout-prerequisites.sh"
fi

if [[ $(id -u) -eq 0 ]]; then
  INSTALL_DEPS=1 bash "${repo_root}/make/install-linux-deps.sh"
fi
make -C "${repo_root}" lint INSTALL_DEPS=0 "LINT_KIT=${lint_kit}"
