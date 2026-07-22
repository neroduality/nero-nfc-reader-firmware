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

# Generic stamp handler: writes <stamp> when a third-party archive dependency is
# present at DEP_DIR. Calls fetch-archive.sh when missing or stale.
# Invoked from Make with a marker path inside DEP_DIR (e.g. library.properties)
# as the rule’s target so deleting the extracted tree re-runs the recipe.

set -euo pipefail

SETUP_ROOT="$1"
DEP_DIR="$2"
STAMP="$3"
VERSION="$4"
EXPECT_SHA_HEX="$5"
ARCHIVE_URL="$6"
FETCH_SCRIPT="$7"
CHECK_FILE="${8:-}" # relative path inside DEP_DIR to validate presence
FORCE_EXTERNAL="${9:-}"

if [ "${#EXPECT_SHA_HEX}" -ne 64 ]; then
  echo 'ERROR: bad SHA256 pin (want 64 hex chars)' >&2
  exit 1
fi

lock="${STAMP}.lock"
mkdir -p "${SETUP_ROOT}/third-party"

want="${VERSION}|${EXPECT_SHA_HEX}"

do_stamp() {
  tree_ok() {
    if [ -n "${CHECK_FILE}" ]; then
      [ -e "${DEP_DIR}/${CHECK_FILE}" ]
    else
      [ -d "${DEP_DIR}" ] && [ -n "$(ls -A "${DEP_DIR}" 2>/dev/null)" ]
    fi
  }

  if [ "${FORCE_EXTERNAL}" = 1 ]; then
    echo "-- FORCE_EXTERNAL: clearing ${DEP_DIR}"
    rm -rf "${DEP_DIR}"
    rm -f "${STAMP}"
  fi

  # Stamp says OK but tree is gone (manual delete, partial clean) — clear and re-fetch.
  if [ "${FORCE_EXTERNAL}" != 1 ] && [ -f "${STAMP}" ] && [ "$(cat "${STAMP}")" = "${want}" ] && ! tree_ok; then
    echo "-- Stale stamp ${STAMP##*/} (tree missing or incomplete); re-fetching $(basename "${DEP_DIR}")" >&2
    rm -f "${STAMP}"
  fi

  if [ "${FORCE_EXTERNAL}" != 1 ] && tree_ok && [ -f "${STAMP}" ] && [ "$(cat "${STAMP}")" = "${want}" ]; then
    echo "── $(basename "${DEP_DIR}") ${VERSION} already present ──"
    touch "${STAMP}"
    return 0
  fi

  if [ "${FORCE_EXTERNAL}" != 1 ] && tree_ok && [ ! -f "${STAMP}" ]; then
    printf '%s' "${want}" >"${STAMP}"
    echo "── $(basename "${DEP_DIR}") ${VERSION} present (wrote stamp) ──"
    return 0
  fi

  test -f "${FETCH_SCRIPT}"

  echo "── Fetching $(basename "${DEP_DIR}") ${VERSION} (release ZIP + SHA256) ──"
  bash "${FETCH_SCRIPT}" "${ARCHIVE_URL}" "${EXPECT_SHA_HEX}" "${DEP_DIR}" "${CHECK_FILE}"

  printf '%s' "${want}" >"${STAMP}"
  if [ -n "${CHECK_FILE}" ]; then
    test -e "${DEP_DIR}/${CHECK_FILE}"
  fi
  echo "── $(basename "${DEP_DIR}") ready ──"
}

if command -v flock >/dev/null 2>&1; then
  (
    flock 200 || exit 1
    do_stamp
  ) 200>"${lock}"
else
  do_stamp
fi
