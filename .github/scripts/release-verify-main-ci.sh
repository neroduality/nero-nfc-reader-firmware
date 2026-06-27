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

# Release gate: require a successful Main CI run on the tagged commit.
#
# Usage:
#   TAG=v0.1.0 bash .github/scripts/release-verify-main-ci.sh
#
# CI sets GITHUB_REPOSITORY and uses gh with github.token (actions: read).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

TAG="${TAG:-${GITHUB_REF_NAME:-}}"
WORKFLOW_FILE="${RELEASE_MAIN_CI_WORKFLOW:-main-ci.yml}"

usage() {
  cat <<'EOF'
Usage: release-verify-main-ci.sh [--tag TAG]

Require a completed, successful Main CI workflow run for the tagged commit.

Environment:
  TAG                         Release tag (fallback: GITHUB_REF_NAME)
  GITHUB_REPOSITORY           owner/repo (required unless gh repo view works)
  RELEASE_MAIN_CI_WORKFLOW    Workflow file name (default: main-ci.yml)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)
      TAG="${2:-}"
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

if [[ -z ${TAG} ]]; then
  printf 'error: release tag required (--tag or TAG / GITHUB_REF_NAME)\n' >&2
  exit 2
fi

if [[ ${TAG} != v* ]]; then
  printf 'error: release tags must start with v (got %s)\n' "${TAG}" >&2
  exit 1
fi

if [[ "$(git -C "${ROOT}" cat-file -t "${TAG}")" != tag ]]; then
  printf 'error: release ref %s must be an annotated tag\n' "${TAG}" >&2
  exit 1
fi

commit="$(git -C "${ROOT}" rev-parse "${TAG}^{commit}")"

repo="${GITHUB_REPOSITORY:-}"
if [[ -z ${repo} ]]; then
  if ! command -v gh >/dev/null 2>&1; then
    printf 'error: GITHUB_REPOSITORY unset and gh not available\n' >&2
    exit 2
  fi
  repo="$(gh repo view "${ROOT}" --json nameWithOwner --jq .nameWithOwner)"
fi

if ! command -v gh >/dev/null 2>&1; then
  printf 'error: gh CLI required to query workflow runs\n' >&2
  exit 2
fi

success_count="$(
  gh api \
    "/repos/${repo}/actions/workflows/${WORKFLOW_FILE}/runs?head_sha=${commit}&status=completed&per_page=30" \
    --jq '[.workflow_runs[] | select(.conclusion == "success")] | length'
)"

if [[ ${success_count} -lt 1 ]]; then
  printf 'error: no successful Main CI run for %s (%s)\n' "${TAG}" "${commit}" >&2
  printf 'hint: wait for Main CI to finish on that commit before pushing the tag\n' >&2
  exit 1
fi

latest_url="$(
  gh api \
    "/repos/${repo}/actions/workflows/${WORKFLOW_FILE}/runs?head_sha=${commit}&status=completed&per_page=30" \
    --jq '[.workflow_runs[] | select(.conclusion == "success")][0].html_url // empty'
)"

printf 'ok: Main CI succeeded for %s (%s)\n' "${TAG}" "${commit}"
if [[ -n ${latest_url} ]]; then
  printf '    %s\n' "${latest_url}"
fi
