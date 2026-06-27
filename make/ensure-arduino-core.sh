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
CLI_BIN="$2"
STAMP="$3"
CORE_PACKAGE="$4"
CORE_VERSION="$5"
BOARD_MANAGER_URLS="${6:-}"
FORCE_EXTERNAL="${7:-}"
ARDUINO_USER_DIR="${8:-${ARDUINO_DIRECTORIES_DATA:-${ARDUINO_DIRECTORIES_USER:-${SETUP_ROOT}/third-party/arduino-user}}}"

[[ -x "${CLI_BIN}" ]] || {
  echo "ERROR: arduino-cli missing at ${CLI_BIN}" >&2
  exit 1
}

case "${ARDUINO_USER_DIR}" in
  "${HOME}/.arduino15"|"${HOME}/.arduino15"/*)
    echo "ERROR: refusing system Arduino data dir ${ARDUINO_USER_DIR}" >&2
    echo "  Board Manager cores must install under ${SETUP_ROOT}/third-party/arduino-user" >&2
    exit 1
    ;;
esac

export ARDUINO_DIRECTORIES_DATA="${ARDUINO_USER_DIR}"
export ARDUINO_DIRECTORIES_USER="${ARDUINO_USER_DIR}"
mkdir -p "${ARDUINO_USER_DIR}"

want="${CORE_PACKAGE}@${CORE_VERSION}"
lock="${STAMP}.lock"

core_tree() {
  local vendor arch
  vendor="${CORE_PACKAGE%%:*}"
  arch="${CORE_PACKAGE#*:}"
  printf '%s/packages/%s/hardware/%s/%s\n' \
    "${ARDUINO_USER_DIR}" "${vendor}" "${arch}" "${CORE_VERSION}"
}

core_ok() {
  local v tree
  tree="$(core_tree)"
  v="$("${CLI_BIN}" core list 2>/dev/null | awk -v pkg="${CORE_PACKAGE}" '$1 == pkg { print $2; exit }')"
  [[ "${v}" == "${CORE_VERSION}" ]] && [[ -d "${tree}" ]]
}

do_core() {
  if [[ "${FORCE_EXTERNAL}" == "1" ]]; then
    rm -f "${STAMP}"
  fi

  if [[ -f "${STAMP}" ]] && [[ "$(cat "${STAMP}")" == "${want}" ]] && core_ok; then
    echo "── Arduino core ${CORE_PACKAGE}@${CORE_VERSION} already present (${ARDUINO_USER_DIR}) ──"
    touch "${STAMP}"
    return 0
  fi

  if [[ -f "${STAMP}" ]] && ! core_ok; then
    echo "── stale Arduino core stamp; refreshing ──" >&2
    rm -f "${STAMP}"
  fi

  mkdir -p "${SETUP_ROOT}/third-party"
  arduino_url_args=()
  if [[ -n "${BOARD_MANAGER_URLS}" ]]; then
    arduino_url_args=(--additional-urls "${BOARD_MANAGER_URLS}")
  fi

  if ! core_ok; then
    echo "── arduino-cli core update-index ──" >&2
    "${CLI_BIN}" core update-index "${arduino_url_args[@]}"
    echo "── arduino-cli core install ${CORE_PACKAGE}@${CORE_VERSION} (→ ${ARDUINO_USER_DIR}) ──" >&2
    "${CLI_BIN}" core install "${CORE_PACKAGE}@${CORE_VERSION}" "${arduino_url_args[@]}"
  fi

  if ! core_ok; then
    echo "ERROR: Arduino core bootstrap incomplete" >&2
    echo "  expected tree: $(core_tree)" >&2
    exit 1
  fi

  printf '%s' "${want}" >"${STAMP}"
  echo "── Arduino core ready (${ARDUINO_USER_DIR}) ──"
}

if command -v flock >/dev/null 2>&1; then
  ( flock 200 || exit 1; do_core ) 200>"${lock}"
else
  do_core
fi
