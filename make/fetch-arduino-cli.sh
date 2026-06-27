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

# Usage: fetch-arduino-cli.sh <version> <dest_dir_abs>
set -eu

die() { echo "ERROR: $*" >&2; exit 1; }

[[ "${#}" -ge 2 ]] || die "need: VERSION DEST_DIR_ABS"
VERSION="$1"
DEST_DIR="$2"
MEMBER="arduino-cli"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FETCH_TAR="${SCRIPT_DIR}/fetch-tarball.sh"
[[ -x "${FETCH_TAR}" ]] || die "missing ${FETCH_TAR}"

case "$(uname -m)" in
  x86_64 | amd64) cli_arch="64bit" ;;
  i386 | i686) cli_arch="32bit" ;;
  aarch64 | arm64) cli_arch="ARM64" ;;
  armv7l | armv7*) cli_arch="ARMv7" ;;
  armv6l | armv6*) cli_arch="ARMv6" ;;
  *) die "unsupported arduino-cli host architecture: $(uname -m)" ;;
esac

sha_file="${SCRIPT_DIR}/arduino-cli-${VERSION}-Linux_${cli_arch}.sha256"
[[ -s "${sha_file}" ]] || die "missing SHA256 pin ${sha_file}"
expect_sha="$(tr -cd '[:xdigit:]' <"${sha_file}")"
[[ "${#expect_sha}" -eq 64 ]] || die "bad arduino-cli SHA256 pin in ${sha_file}"

cli_asset="arduino-cli_${VERSION}_Linux_${cli_arch}.tar.gz"
cli_url="https://github.com/arduino/arduino-cli/releases/download/v${VERSION}/${cli_asset}"

mkdir -p "${DEST_DIR}"
bash "${FETCH_TAR}" "${cli_url}" "${expect_sha}" "${DEST_DIR}/${MEMBER}" "${MEMBER}"
test -x "${DEST_DIR}/${MEMBER}" || die "arduino-cli not executable after fetch"
