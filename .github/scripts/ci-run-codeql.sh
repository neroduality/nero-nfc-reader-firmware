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

# CodeQL job container entry. Mirrors .github/workflows/codeql.yml on debian:sid-slim
# (same pattern as ci-run-lint.sh / ci-run-test-container.sh):
#   root → install-linux-deps (INSTALL_LINT_DEPS=0) → drop to HOST_UID → CodeQL CLI
#
# Invoked by run-codeql-locally.sh (make codeql-local).
set -euo pipefail

repo_root="${FIRMWARE_ROOT:-$(pwd)}"
if [[ ! -f "${repo_root}/Makefile" ]]; then
  printf 'error: FIRMWARE_ROOT must point at firmware repo root (missing Makefile)\n' >&2
  exit 1
fi

# shellcheck source=helper-container-bind-mount.sh
# shellcheck disable=SC1091
source "${repo_root}/.github/scripts/helper-container-bind-mount.sh"

export FIRMWARE_ROOT="${repo_root}"
SCRIPT_DIR="${repo_root}/.github/scripts"

if [[ $(id -u) -eq 0 && -n ${HOST_UID:-} && ${NERO_NFC_CI_AS_USER:-0} != 1 ]]; then
  bash "${repo_root}/.github/scripts/ci-bootstrap-container.sh"
  AUTO_INSTALL_LINUX_DEPS=1 INSTALL_DEPS=1 INSTALL_LINT_DEPS=0 \
    bash "${repo_root}/make/install-linux-deps.sh"
  nero_nfc_prepare_bind_mount_paths "${repo_root}"
  ci_home="${NERO_NFC_CI_HOME:-/tmp/nero-nfc-ci}"
  # Ephemeral CodeQL CLI + pack dirs inside the container only (no host mounts).
  codeql_cache="${CODEQL_CACHE:-/tmp/nero-nfc-codeql-cli}"
  mkdir -p "${ci_home}" "${codeql_cache}"
  chown -R "${HOST_UID}:${HOST_GID:-${HOST_UID}}" "${ci_home}" "${codeql_cache}"
  export CODEQL_CACHE="${codeql_cache}"
  nero_nfc_require_drop_to_host_user \
    bash "${repo_root}/.github/scripts/ci-run-codeql.sh" "$@"
fi

nero_nfc_refuse_root_bind_mount_writes

# ── Worker (unprivileged; deps already installed) ───────────────────────────

print_codeql_sarif_summary() {
  local sarif="$1"
  printf '\n── Results (SARIF) ──\n'
  printf 'File: %s\n' "${sarif}"
  if [[ ! -s ${sarif} ]]; then
    printf 'warning: SARIF missing or empty\n' >&2
    return 0
  fi
  if ! command -v jq >/dev/null 2>&1; then
    printf 'hint: install jq for an alert summary (counts + listing).\n' >&2
    return 0
  fi
  local total limit
  total="$(jq '[.runs[].results[]] | length' "${sarif}")"
  printf 'Total findings: %s\n' "${total}"
  if [[ ${total} != "0" ]]; then
    printf '\nBy severity:\n'
    jq -r '[.runs[].results[] | (.level // "warning")] | group_by(.) | map("  \(.[0]): \(length)") | .[]' "${sarif}"
    printf '\nBy rule (top 25):\n'
    jq -r '[.runs[].results[] | .ruleId // "(no ruleId)"] | group_by(.) | map({id: .[0], n: length}) | sort_by(-.n) | .[:25] | .[] | "  \(.n)\t\(.id)"' "${sarif}"
    limit="${CODEQL_SARIF_LIST_LIMIT:-40}"
    [[ ${limit} =~ ^[0-9]+$ ]] || limit="40"
    printf '\nFindings (first %s):\n' "${limit}"
    jq -r --argjson lim "${limit}" '
      [.runs[].results[] | . as $r | {
        rule: ($r.ruleId // "?"),
        msg: (($r.message.text // "") | gsub("\\s+"; " ") | if length > 160 then .[0:157] + "..." else . end),
        uri: (($r.locations[0].physicalLocation.artifactLocation.uri // "?")),
        line: ($r.locations[0].physicalLocation.region.startLine // empty)
      }]
      | .[:$lim][]
      | "[\(.rule)] \(.uri)" + (if .line != null and .line != "" then ":\(.line)" else "" end) + "\n  \(.msg)\n"
    ' "${sarif}"
  fi
}

DB_ONLY=0
VERIFY_GATE=0
SUMMARIZE_SARIF="${CODEQL_SUMMARIZE_SARIF:-1}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --db-only) DB_ONLY=1 ;;
    --verify-gate) VERIFY_GATE=1 ;;
    --no-summary) SUMMARIZE_SARIF=0 ;;
    --open) ;; # host launcher opens SARIF
    -h | --help)
      printf 'ci-run-codeql.sh: container worker (see run-codeql-locally.sh --help)\n'
      exit 0
      ;;
    *)
      printf 'error: unknown option %q\n' "$1" >&2
      exit 1
      ;;
  esac
  shift
done

CODEQL_CLI_VERSION="${CODEQL_CLI_VERSION:-v2.26.0}"
# Always ephemeral inside the container (launcher must not mount host caches).
CODEQL_CACHE="${CODEQL_CACHE:-/tmp/nero-nfc-codeql-cli}"
# Matches .github/codeql/codeql-config.yml queries: security-extended
CODEQL_SUITE_FILE="${CODEQL_SUITE_FILE:-cpp-security-extended.qls}"
CODEQL_PACK_SCOPE="${CODEQL_PACK_SCOPE:-codeql/cpp-queries}"
DB_PATH="${CODEQL_DB_PATH:-${FIRMWARE_ROOT}/build/codeql/cpp-db}"
SARIF_PATH="${CODEQL_SARIF_PATH:-${FIRMWARE_ROOT}/build/codeql/results.sarif}"

resolve_codeql() {
  # Refuse host-injected CODEQL_DIST — local must download like a cold GHA runner.
  if [[ -n ${CODEQL_DIST:-} ]]; then
    printf 'error: CODEQL_DIST is not allowed in ci-run-codeql (cold container only)\n' >&2
    exit 1
  fi
  if command -v codeql >/dev/null 2>&1; then
    command -v codeql
    return 0
  fi

  local os arch asset extract_root zip_path expected_hash actual_hash
  os="$(uname -s)"
  arch="$(uname -m)"
  case "${os}:${arch}" in
    Linux:x86_64) asset="codeql-linux64.zip" ;;
    *)
      printf 'error: unsupported OS/arch %s/%s inside CodeQL container\n' "${os}" "${arch}" >&2
      exit 1
      ;;
  esac

  zip_path="${CODEQL_CACHE}/${CODEQL_CLI_VERSION}/${asset}"
  mkdir -p "$(dirname "${zip_path}")"
  if [[ ! -f ${zip_path} ]]; then
    printf '\n── Downloading CodeQL CLI %s (%s) ──\n' "${CODEQL_CLI_VERSION}" "${asset}" >&2
    curl -fsSL --retry 3 --retry-delay 2 \
      -o "${zip_path}.part" \
      "https://github.com/github/codeql-cli-binaries/releases/download/${CODEQL_CLI_VERSION}/${asset}"
    curl -fsSL --retry 3 --retry-delay 2 \
      -o "${zip_path}.checksum.txt" \
      "https://github.com/github/codeql-cli-binaries/releases/download/${CODEQL_CLI_VERSION}/${asset}.checksum.txt"
    expected_hash="$(awk '{print $1}' "${zip_path}.checksum.txt")"
    actual_hash="$(sha256sum "${zip_path}.part" | awk '{print $1}')"
    if [[ ${actual_hash} != "${expected_hash}" ]]; then
      rm -f "${zip_path}.part" "${zip_path}.checksum.txt"
      printf 'error: SHA256 mismatch for %s\n' "${asset}" >&2
      exit 1
    fi
    mv -f "${zip_path}.part" "${zip_path}"
  fi

  extract_root="${CODEQL_CACHE}/${CODEQL_CLI_VERSION}/extract-${asset%.zip}"
  if [[ ! -x "${extract_root}/codeql/codeql" ]]; then
    printf '\n── Extracting CodeQL bundle ──\n' >&2
    rm -rf "${extract_root}"
    mkdir -p "${extract_root}"
    unzip -q "${zip_path}" -d "${extract_root}"
  fi
  printf '%s\n' "${extract_root}/codeql/codeql"
}

CODEQL_BIN="$(resolve_codeql)"

ensure_cpp_query_packs() {
  # Always fetch packs inside the container (no host ~/.codeql mount).
  printf '\n── CodeQL pack download (%s) ──\n' "${CODEQL_PACK_SCOPE}" >&2
  "${CODEQL_BIN}" pack download "${CODEQL_PACK_SCOPE}" >&2
}

resolve_query_suite() {
  if [[ -n ${CODEQL_QUERY_SUITE:-} ]]; then
    if [[ -f ${CODEQL_QUERY_SUITE} ]]; then
      printf '%s\n' "${CODEQL_QUERY_SUITE}"
      return 0
    fi
    printf 'error: CODEQL_QUERY_SUITE=%s is not a readable file\n' "${CODEQL_QUERY_SUITE}" >&2
    exit 1
  fi
  local hits hit
  hits="$(find "${HOME}/.codeql/packages/codeql/cpp-queries" -path "*/codeql-suites/${CODEQL_SUITE_FILE}" 2>/dev/null | sort -V)"
  hit="$(printf '%s\n' "${hits}" | tail -n1)"
  if [[ -z ${hit} || ! -f ${hit} ]]; then
    printf 'error: could not find codeql-suites/%s under ~/.codeql/packages\n' "${CODEQL_SUITE_FILE}" >&2
    exit 1
  fi
  printf '%s\n' "${hit}"
}

# Fail closed if OpenOCD deps (incl. patch) were not installed — same gate as ensure-wba65.
if [[ " ${CODEQL_FIRMWARE_TARGETS:-arduino_uno_r4wifi nucleo_wba65ri} " == *" nucleo_wba65ri "* ]] &&
  [[ ${CODEQL_INCLUDE_FIRMWARE:-1} == "1" ]]; then
  command -v patch >/dev/null 2>&1 || {
    printf 'error: GNU patch missing (required for WBA65 OpenOCD). install-linux-deps.sh must install it.\n' >&2
    exit 1
  }
fi

rm -rf "${DB_PATH}"
mkdir -p "$(dirname "${DB_PATH}")" "$(dirname "${SARIF_PATH}")"

build_cmd="env FIRMWARE_ROOT=${FIRMWARE_ROOT} CODEQL_INSTALL_LINUX_DEPS=0 CODEQL_INCLUDE_FIRMWARE=${CODEQL_INCLUDE_FIRMWARE:-1} bash ${SCRIPT_DIR}/codeql-build.sh"

printf '\n── CodeQL database create → %s ──\n' "${DB_PATH}"
"${CODEQL_BIN}" database create "${DB_PATH}" \
  --language=cpp \
  --overwrite \
  --source-root="${FIRMWARE_ROOT}" \
  --command="${build_cmd}"

if [[ ${DB_ONLY} -eq 1 ]]; then
  printf '\n── Database ready (--db-only); skipping analyze ──\n'
  exit 0
fi

ensure_cpp_query_packs
QUERY_SUITE_PATH="$(resolve_query_suite)"

printf '\n── CodeQL analyze → %s ──\n' "${SARIF_PATH}"
"${CODEQL_BIN}" database analyze "${DB_PATH}" \
  --threads=0 \
  --sarif-category=cpp \
  --format=sarif-latest \
  --output="${SARIF_PATH}" \
  "${QUERY_SUITE_PATH}"

if [[ ${SUMMARIZE_SARIF} == "1" ]]; then
  print_codeql_sarif_summary "${SARIF_PATH}"
fi

if [[ ${VERIFY_GATE} -eq 1 ]]; then
  fail_level="${CODEQL_VERIFY_FAIL_LEVEL:-error}"
  if [[ ! -s ${SARIF_PATH} ]]; then
    printf 'error: CodeQL verify gate: empty SARIF at %s\n' "${SARIF_PATH}" >&2
    exit 1
  fi
  if ! command -v jq >/dev/null 2>&1; then
    printf 'error: CodeQL verify gate requires jq\n' >&2
    exit 1
  fi
  count="$(jq --arg lvl "${fail_level}" \
    '[.runs[].results[] | select((.level // "warning") == $lvl)] | length' "${SARIF_PATH}")"
  if [[ ${count} != "0" ]]; then
    printf 'error: CodeQL verify gate: %s %s-level finding(s)\n' "${count}" "${fail_level}" >&2
    exit 1
  fi
  printf 'CodeQL verify gate: OK (0 %s-level findings)\n' "${fail_level}"
fi

printf '\n── CodeQL container worker finished ──\n'
