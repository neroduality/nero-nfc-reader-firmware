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

# Download a release ZIP, verify SHA256, extract into DEST.
#
# Usage: fetch-archive.sh <url> <expected_sha256_hex> <dest_abs_path> [<check_file_rel>]
#
#   check_file_rel  optional relative path inside the extracted tree to validate
#                   (e.g. "library.properties" for Arduino/ST libs)
set -eu

die() {
  echo "ERROR: $*" >&2
  exit 1
}

[ "${#}" -ge 3 ] || die "need: URL SHA256_HEX DEST_ABS [CHECK_FILE_REL]"
DL_URL="$1"
EXPECT_SHA="$2"
DEST="$3"
CHECK_FILE="${4:-}"

command -v sha256sum >/dev/null 2>&1 || die "sha256sum required (coreutils)"
command -v unzip >/dev/null 2>&1 || die "unzip required"
if ! [ "${#EXPECT_SHA}" -eq 64 ]; then
  die "SHA256 must be exactly 64 characters (got ${#EXPECT_SHA})"
fi
if ! printf '%s\n' "${EXPECT_SHA}" | LC_ALL=C grep -qxE '[0-9A-Fa-f]{64}'; then
  die "SHA256 contains non-hexadecimal characters"
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/archive-dl.XXXXXX")"
cleanup() {
  rm -rf "$tmp"
}
trap cleanup EXIT

arc="$tmp/archive.zip"

echo "-- Download ${DL_URL##*/} ..."
if command -v curl >/dev/null 2>&1; then
  curl -fL --progress-bar --retry 3 --retry-connrefused --connect-timeout 20 \
    --max-time 0 \
    -o "$arc" "$DL_URL" ||
    die "download failed ($DL_URL)"
elif command -v wget >/dev/null 2>&1; then
  wget -q --show-progress -O "$arc" "$DL_URL" ||
    die "download failed ($DL_URL)"
else
  die "need curl or wget"
fi

echo "-- Verify SHA256 ..."
got="$(sha256sum "$arc" | awk '{print $1}')"

if ! [ "${got}" = "${EXPECT_SHA}" ]; then
  die "checksum mismatch expected=${EXPECT_SHA} actual=${got}"
fi

staging="$tmp/staged"
mkdir -p "$staging"

echo "-- Extract (to scratch) ..."
unzip -q "$arc" -d "$staging"

shopt -s nullglob
subs=("$staging"/*)
shopt -u nullglob
case "${#subs[@]}" in
  1) ;;
  *) die "expected one top-level dir in ZIP, got: ${subs[*]}" ;;
esac

src="${subs[0]}"
if [ -n "${CHECK_FILE}" ]; then
  test -e "${src}/${CHECK_FILE}" ||
    die "extract tree missing ${CHECK_FILE} (wrong archive?)"
fi

mkdir -p "$(dirname "$DEST")"

if [[ -e $DEST ]] || [[ -L $DEST ]]; then
  rm -rf "$DEST"
fi

mv "$src" "$DEST"
echo "-- Installed at ${DEST}"
