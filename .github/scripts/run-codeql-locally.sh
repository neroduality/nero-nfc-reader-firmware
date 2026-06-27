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

# Run CodeQL database create + analyze against this checkout (same traced build as CI).
#
# Uses the official CodeQL CLI bundle from github/codeql-cli-binaries (pinned version),
# or an existing install when CODEQL_DIST / `codeql` on PATH is set.
#
# Usage (from anywhere):
#   bash /path/to/nero-nfc-reader-firmware/.github/scripts/run-codeql-locally.sh
#   bash .../run-codeql-locally.sh --db-only
#   bash .../run-codeql-locally.sh --open
#   CODEQL_BOOTSTRAP_LINUX_DEPS=0 bash .../run-codeql-locally.sh
#
set -euo pipefail

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

maybe_open_sarif() {
  local sarif="$1"
  [[ ${OPEN_SARIF} == "1" ]] || return 0
  printf '\n── Opening SARIF (desktop default application) ──\n' >&2
  case "$(uname -s)" in
    Linux)
      if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "${sarif}" >/dev/null 2>&1 &
        return 0
      fi
      ;;
    Darwin)
      if command -v open >/dev/null 2>&1; then
        open "${sarif}"
        return 0
      fi
      ;;
  esac
  printf 'warning: could not open SARIF (install xdg-open on Linux or use OPEN_SARIF=0)\n' >&2
}

usage() {
  cat <<'EOF'
Run CodeQL locally — creates build/codeql/cpp-db and SARIF under build/codeql/.

Requires: bash, curl, unzip, sha256sum; C/C++ build deps (cmake, ninja or make, C++23).
On Linux, installs distro packages via make/install-linux-deps.sh unless disabled.

Usage:
  bash /path/to/nero-nfc-reader-firmware/.github/scripts/run-codeql-locally.sh [options]

Options:
  --db-only              Only create the CodeQL database (skip analyze)
  --no-summary           Do not print SARIF summary after analyze
  --open                 Open SARIF with xdg-open (Linux) or open (macOS)
  --verify-gate          Exit non-zero on CodeQL error-level findings
  -h, --help             Help

Environment:
  CODEQL_DIST            Path to extracted bundle root (directory containing ./codeql binary)
  CODEQL_CLI_VERSION     github/codeql-cli-binaries tag (default: v2.25.6)
  CODEQL_CACHE           Download/extract cache (default: ~/.cache/nero-nfc-codeql)
  CODEQL_QUERY_SUITE     Absolute path to a .qls suite file (optional). When unset, uses the
                         newest ~/.codeql/packages/.../codeql-suites/$CODEQL_SUITE_FILE
  CODEQL_SUITE_FILE      Suite filename when CODEQL_QUERY_SUITE unset (default: cpp-security-and-quality.qls)
  CODEQL_PACK_SCOPE      Pack passed to \`codeql pack download\` (default: codeql/cpp-queries)
  CODEQL_SKIP_PACK_DOWNLOAD    Set to 1 to skip registry pack fetch (you must have suites in ~/.codeql/packages)
  CODEQL_BOOTSTRAP_LINUX_DEPS  On Linux, run install-linux-deps.sh first (default: 1)
  CODEQL_INCLUDE_ARDUINO       Set to 0 to skip traced \`make nfc\` (default: 1)
  CODEQL_SUMMARIZE_SARIF       Set to 0 to skip post-run SARIF summary (default: 1; overridden by --no-summary)
  CODEQL_OPEN_SARIF            Set to 1 to open SARIF after analyze (default: 0; overridden by --open)
  CODEQL_SARIF_LIST_LIMIT      Max findings listed in detail (default: 40)

Defaults mirror .github/workflows/codeql.yml (CMake tests + userspace + traced Arduino \`make nfc\`).

The standalone CLI zip does not ship query packs; this script runs \`codeql pack download\` first.

After analyze, a text summary is printed when jq is installed; use --no-summary to skip.

EOF
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
FIRMWARE_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

DB_ONLY=0
VERIFY_GATE=0
SUMMARIZE_SARIF="${CODEQL_SUMMARIZE_SARIF:-1}"
OPEN_SARIF="${CODEQL_OPEN_SARIF:-0}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --db-only)
      DB_ONLY=1
      shift
      ;;
    --verify-gate)
      VERIFY_GATE=1
      shift
      ;;
    --no-summary)
      SUMMARIZE_SARIF=0
      shift
      ;;
    --open)
      OPEN_SARIF=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      printf 'error: unknown option %q\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ ! -f "${FIRMWARE_ROOT}/tests/CMakeLists.txt" ]]; then
  printf 'error: unexpected layout (missing tests/CMakeLists.txt under %s)\n' "${FIRMWARE_ROOT}" >&2
  exit 1
fi

CODEQL_CLI_VERSION="${CODEQL_CLI_VERSION:-v2.25.6}"
CODEQL_CACHE="${CODEQL_CACHE:-${HOME}/.cache/nero-nfc-codeql}"
CODEQL_SUITE_FILE="${CODEQL_SUITE_FILE:-cpp-security-and-quality.qls}"
CODEQL_PACK_SCOPE="${CODEQL_PACK_SCOPE:-codeql/cpp-queries}"
DB_PATH="${CODEQL_DB_PATH:-${FIRMWARE_ROOT}/build/codeql/cpp-db}"
SARIF_PATH="${CODEQL_SARIF_PATH:-${FIRMWARE_ROOT}/build/codeql/results.sarif}"

resolve_codeql() {
  local bin=""
  if [[ -n ${CODEQL_DIST:-} ]]; then
    bin="${CODEQL_DIST%/}/codeql"
    if [[ -x ${bin} ]]; then
      printf '%s\n' "${bin}"
      return 0
    fi
    if [[ ${VERIFY_GATE:-0} -eq 1 ]]; then
      printf 'skip: CODEQL_DIST=%s has no executable codeql\n' "${CODEQL_DIST}" >&2
      return 2
    fi
    printf 'error: CODEQL_DIST=%s does not contain executable codeql\n' "${CODEQL_DIST}" >&2
    exit 1
  fi
  if command -v codeql >/dev/null 2>&1; then
    command -v codeql
    return 0
  fi

  local os arch asset extract_root zip_path
  os="$(uname -s)"
  arch="$(uname -m)"
  case "${os}:${arch}" in
    Linux:x86_64)
      asset="codeql-linux64.zip"
      ;;
    Darwin:x86_64 | Darwin:arm64)
      asset="codeql-osx64.zip"
      ;;
    *)
      if [[ ${VERIFY_GATE:-0} -eq 1 ]]; then
        printf 'skip: unsupported OS/arch %s/%s for CodeQL auto-download (install CLI manually)\n' "${os}" "${arch}" >&2
        return 2
      fi
      printf 'error: unsupported OS/arch %s/%s — install CodeQL CLI manually and set CODEQL_DIST\n' "${os}" "${arch}" >&2
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
      printf 'error: SHA256 mismatch for %s (expected %s got %s)\n' "${asset}" "${expected_hash}" "${actual_hash}" >&2
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

CODEQL_BIN="$(resolve_codeql)" || {
  rc=$?
  if [[ ${rc} -eq 2 && ${VERIFY_GATE} -eq 1 ]]; then
    exit 0
  fi
  exit "${rc}"
}

codeql_verify_gate() {
  local sarif="$1"
  local fail_level="${CODEQL_VERIFY_FAIL_LEVEL:-error}"
  if [[ ! -s ${sarif} ]]; then
    printf 'error: CodeQL verify gate: empty SARIF at %s\n' "${sarif}" >&2
    return 1
  fi
  if ! command -v jq >/dev/null 2>&1; then
    printf 'error: CodeQL verify gate requires jq\n' >&2
    return 1
  fi
  local count
  count="$(jq --arg lvl "${fail_level}" '[.runs[].results[] | select((.level // "warning") == $lvl)] | length' "${sarif}")"
  if [[ ${count} != "0" ]]; then
    printf 'error: CodeQL verify gate: %s %s-level finding(s) in %s\n' "${count}" "${fail_level}" "${sarif}" >&2
    return 1
  fi
  printf 'CodeQL verify gate: OK (0 %s-level findings)\n' "${fail_level}"
}

bootstrap_linux_deps() {
  if [[ "$(uname -s)" != "Linux" ]]; then
    return 0
  fi
  if [[ ${CODEQL_BOOTSTRAP_LINUX_DEPS:-1} != "1" ]]; then
    return 0
  fi
  printf '\n── Linux dependency bootstrap (make/install-linux-deps.sh) ──\n' >&2
  env FIRMWARE_ROOT="${FIRMWARE_ROOT}" INSTALL_DEPS=1 AUTO_INSTALL_LINUX_DEPS=1 \
    bash "${FIRMWARE_ROOT}/make/install-linux-deps.sh"
}

ensure_cpp_query_packs() {
  if [[ ${CODEQL_SKIP_PACK_DOWNLOAD:-0} == "1" ]]; then
    return 0
  fi
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
    printf 'error: could not find codeql-suites/%s under ~/.codeql/packages (pack download failed?)\n' "${CODEQL_SUITE_FILE}" >&2
    exit 1
  fi
  printf '%s\n' "${hit}"
}

bootstrap_linux_deps

rm -rf "${DB_PATH}"
mkdir -p "$(dirname "${DB_PATH}")" "$(dirname "${SARIF_PATH}")"

build_cmd="env FIRMWARE_ROOT=${FIRMWARE_ROOT} CODEQL_INSTALL_LINUX_DEPS=0 CODEQL_INCLUDE_ARDUINO=${CODEQL_INCLUDE_ARDUINO:-1} bash ${SCRIPT_DIR}/codeql-build.sh"

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
maybe_open_sarif "${SARIF_PATH}"

if [[ ${VERIFY_GATE} -eq 1 ]]; then
  codeql_verify_gate "${SARIF_PATH}"
fi

printf '\n── CodeQL finished ──\n'
