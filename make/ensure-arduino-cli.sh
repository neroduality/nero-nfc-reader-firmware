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

set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  exit 0
fi

SETUP_ROOT="$1"
DEP_DIR="$2"
STAMP="$3"
VERSION="$4"
FETCH_SCRIPT="$5"
FORCE_EXTERNAL="${6:-}"

if [[ "${FORCE_EXTERNAL}" == "1" ]]; then
  echo "-- FORCE_EXTERNAL: clearing ${DEP_DIR}" >&2
  rm -rf "${DEP_DIR}"
  rm -f "${STAMP}"
fi

want="${VERSION}"
marker="${DEP_DIR}/arduino-cli"
tree_ok() { [[ -x "${marker}" ]]; }

if [[ -f "${STAMP}" ]] && [[ "$(cat "${STAMP}")" == "${want}" ]] && tree_ok; then
  echo "── arduino-cli ${VERSION} already present ──"
  touch "${STAMP}"
  exit 0
fi

if [[ -f "${STAMP}" ]] && ! tree_ok; then
  echo "── stale arduino-cli stamp; re-fetching ──" >&2
  rm -f "${STAMP}"
  rm -rf "${DEP_DIR}"
fi

mkdir -p "${SETUP_ROOT}/third-party"
echo "── Fetching arduino-cli ${VERSION} (release tarball + SHA256) ──"
bash "${FETCH_SCRIPT}" "${VERSION}" "${DEP_DIR}"
printf '%s' "${want}" >"${STAMP}"
test -x "${marker}"
echo "── arduino-cli ready ──"
