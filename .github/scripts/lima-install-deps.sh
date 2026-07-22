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

# CI deps install inside the Lima guest (root via sudo).
# Lint runs in debian:sid-slim via run-ci-locally.sh — do not install lint tools on the VM host.
set -euo pipefail

FIRMWARE_ROOT="${1:-/src}"

[[ -f ${FIRMWARE_ROOT}/make/install-linux-deps.sh ]] || {
  printf 'error: %s/make/install-linux-deps.sh missing\n' "${FIRMWARE_ROOT}" >&2
  exit 1
}

: "${LINT_KIT:=/opt/lint-kit}"
export LINT_KIT
if [[ ! -x ${LINT_KIT}/lint-c-cpp.sh ]]; then
  printf 'error: lint kit missing lint-c-cpp.sh: %s\n' "${LINT_KIT}" >&2
  exit 1
fi

export HOME=/root DEBIAN_FRONTEND=noninteractive
apt-get install -y --no-install-recommends make
export INSTALL_DEPS=1
export INSTALL_LINT_DEPS=0
export AUTO_INSTALL_LINUX_DEPS=1
bash "${FIRMWARE_ROOT}/make/install-linux-deps.sh"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=helper-toolchain.sh
source "${script_dir}/helper-toolchain.sh"
nero_nfc_toolchain_activate
cat >/etc/profile.d/nero-nfc-ci-path.sh <<EOF
export PATH="${PATH}"
export CC="${CC:-gcc}"
export CXX="${CXX:-g++}"
export LINT_KIT="${LINT_KIT}"
EOF
