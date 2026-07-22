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

# Seed an isolated CI work tree from a source checkout.
#
# Used by:
#   - make ci-local (host): keep native make lint / make workspaces unpolluted
#   - make lima (guest): keep the host bind mount source-only
#
# Source build/ and third-party/ are never copied. The work tree is removed when
# ci-local exits (see run-ci-locally.sh EXIT trap) unless NERO_CI_LOCAL_KEEP_WORK=1.
#
# Usage: bash prepare-ci-worktree.sh <source-root> <work-root>
set -euo pipefail

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

[[ $# -ge 2 ]] || die "usage: prepare-ci-worktree.sh <source-root> <work-root>"

source_root="$(cd -- "$1" && pwd)" || die "source root not found: $1"
work_root="$2"

[[ -f ${source_root}/Makefile ]] || die "source root missing Makefile: ${source_root}"

if ! command -v rsync >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    printf '── ci-worktree: installing rsync ──\n' >&2
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends rsync >/dev/null
  elif command -v dnf >/dev/null 2>&1; then
    printf '── ci-worktree: installing rsync ──\n' >&2
    sudo dnf install -y --setopt=install_weak_deps=False rsync >/dev/null
  else
    die "rsync required to seed CI work tree"
  fi
fi

mkdir -p "${work_root}"
printf '── ci-worktree: seeding isolated tree (excluding source build/third-party) ──\n' >&2
printf '   source: %s\n' "${source_root}" >&2
printf '   work:   %s\n' "${work_root}" >&2

# --delete refreshes tracked sources. Excluded paths (build/, third-party/, …) are
# not deleted in dest, so a prior work-tree third-party cache can remain.
rsync -a --delete \
  --exclude '/build/' \
  --exclude '/build-*/' \
  --exclude '/third-party/' \
  --exclude '/.lint-kit-org/' \
  --exclude '/tests/build/' \
  --exclude '/tests/build-*/' \
  --exclude '/tests/build-scan/' \
  --exclude '/tests/scan-build-report/' \
  --exclude '/.cursor/' \
  "${source_root}/" "${work_root}/"

[[ -f ${work_root}/Makefile ]] || die "work tree missing Makefile after rsync: ${work_root}"
printf '── ci-worktree: ready (CI writes only under work tree) ──\n' >&2
