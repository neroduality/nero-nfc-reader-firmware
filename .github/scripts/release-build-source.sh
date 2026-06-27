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

# Build source-only release assets: git-archive tarball + SHA256SUMS (+ self-check).
#
# Usage:
#   TAG=v0.1.0 bash .github/scripts/release-build-source.sh
#   bash .github/scripts/release-build-source.sh --tag v0.1.0
#
# Writes (default under repo-root dist/):
#   nero-nfc-reader-firmware-VERSION.tar.gz
#   SHA256SUMS

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

TAG=""
OUTPUT_DIR="${RELEASE_OUTPUT_DIR:-${ROOT}/dist}"

usage() {
  cat <<'EOF'
Usage: release-build-source.sh [--tag TAG] [--output-dir DIR]

Build source-only release assets for an annotated git tag.

Options:
  --tag TAG          Release tag (e.g. v0.1.0)
  --output-dir DIR   Output directory (default: repo-root dist/)

Environment:
  TAG                 Same as --tag (fallback: GITHUB_REF_NAME)
  RELEASE_OUTPUT_DIR  Same as --output-dir

Outputs:
  nero-nfc-reader-firmware-VERSION.tar.gz
  SHA256SUMS
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)
      TAG="${2:-}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:-}"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      printf 'error: unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

TAG="${TAG:-${GITHUB_REF_NAME:-}}"
if [[ -z ${TAG} ]]; then
  printf 'error: release tag required (--tag or TAG / GITHUB_REF_NAME)\n' >&2
  exit 2
fi

VERSION="${TAG#v}"
if [[ -z ${VERSION} || ${VERSION} == "${TAG}" ]]; then
  printf 'error: release tag must start with v (got %s)\n' "${TAG}" >&2
  exit 2
fi

archive_name="nero-nfc-reader-firmware-${VERSION}.tar.gz"
archive_path="${OUTPUT_DIR}/${archive_name}"
checksum_path="${OUTPUT_DIR}/SHA256SUMS"

mkdir -p "${OUTPUT_DIR}"
rm -f "${archive_path}" "${checksum_path}"

git -C "${ROOT}" archive \
  --format=tar.gz \
  --prefix="nero-nfc-reader-firmware-${VERSION}/" \
  -o "${archive_path}" \
  "${TAG}"

(
  cd "${OUTPUT_DIR}"
  sha256sum "${archive_name}" >SHA256SUMS
)

if ! (cd "${OUTPUT_DIR}" && sha256sum -c SHA256SUMS >/dev/null); then
  printf 'error: SHA256SUMS self-check failed under %s\n' "${OUTPUT_DIR}" >&2
  exit 1
fi

mapfile -t output_files < <(find "${OUTPUT_DIR}" -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort)
if ((${#output_files[@]} != 2)) || [[ ${output_files[0]} != "${archive_name}" || ${output_files[1]} != SHA256SUMS ]]; then
  printf 'error: expected exactly %s and SHA256SUMS in %s\n' "${archive_name}" "${OUTPUT_DIR}" >&2
  printf 'found:\n' >&2
  printf '  %s\n' "${output_files[@]:-<none>}" >&2
  exit 1
fi

printf '── release-build-source: %s ──\n' "${archive_path}"
printf '── release-build-source: %s ──\n' "${checksum_path}"
printf '── release-build-source: ready to publish from %s ──\n' "${OUTPUT_DIR}"
