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

# Download a release tarball, verify SHA256, extract one member to DEST.
#
# Usage: fetch-tarball.sh <url> <expected_sha256_hex> <dest_abs_path> <member_path>
set -eu

die() { echo "ERROR: $*" >&2; exit 1; }

[ "${#}" -ge 4 ] || die "need: URL SHA256_HEX DEST_ABS MEMBER_PATH"
DL_URL="$1"
EXPECT_SHA="$2"
DEST="$3"
MEMBER="$4"

command -v sha256sum >/dev/null 2>&1 || die "sha256sum required (coreutils)"
command -v tar >/dev/null 2>&1 || die "tar required"
if ! [ "${#EXPECT_SHA}" -eq 64 ]; then
  die "SHA256 must be exactly 64 characters (got ${#EXPECT_SHA})"
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/tarball-dl.XXXXXX")"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT

arc="$tmp/archive.tar.gz"

echo "-- Download ${DL_URL##*/} ..."
if command -v curl >/dev/null 2>&1; then
  curl -fL --progress-bar --retry 3 --retry-connrefused --connect-timeout 20 \
    --max-time 0 -o "$arc" "$DL_URL" || die "download failed ($DL_URL)"
elif command -v wget >/dev/null 2>&1; then
  wget -q --show-progress -O "$arc" "$DL_URL" || die "download failed ($DL_URL)"
else
  die "need curl or wget"
fi

echo "-- Verify SHA256 ..."
got="$(sha256sum "$arc" | awk '{print $1}')"
[ "${got}" = "${EXPECT_SHA}" ] || die "checksum mismatch expected=${EXPECT_SHA} actual=${got}"

echo "-- Extract ${MEMBER} ..."
tar -xzf "$arc" -C "$tmp" "$MEMBER"
test -e "${tmp}/${MEMBER}" || die "archive missing ${MEMBER}"

mkdir -p "$(dirname "$DEST")"
install -m 0755 "${tmp}/${MEMBER}" "$DEST"
echo "-- Installed at ${DEST}"
