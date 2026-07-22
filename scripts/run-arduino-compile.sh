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

# Wrap arduino-cli compile with periodic progress on stderr (arduino-cli is often silent
# until the final "Sketch uses …" summary). Same heartbeat style as Lima guest / CI.
#
# With --repo-root: same contract as make lint — full -W on the command line, but only
# diagnostics under REPO_ROOT outside third-party/ fail the build. Vendor/Board Manager
# noise under third-party/ is ignored and not printed on success.
set -euo pipefail

BOARD_DESCRIPTION=""
COMPILE_LOG=""
REPO_ROOT=""
INTERNAL_COMPILE_LOG=0

usage() {
  cat <<'EOF' >&2
Usage: bash scripts/run-arduino-compile.sh --board "Board name" [OPTIONS] -- command...

Options:
  --repo-root PATH   Fail only on warnings/errors in repo sources outside third-party/
  --log FILE         Capture arduino-cli output (always used with --repo-root)

Example:
  bash scripts/run-arduino-compile.sh --board "Arduino UNO R4 WiFi" --repo-root /path/to/repo -- \
    third-party/arduino-cli/arduino-cli compile --fqbn arduino:renesas_uno:unor4wifi ...
EOF
}

compile_log_last_hint() {
  local log="$1"
  [[ -f ${log} ]] || return 0
  awk '
    /Sketch uses/ || /Global variables use/ || /Compiling/ || /Linking/ || /Building/ || /Downloading/ {
      line = $0
      sub(/\r$/, "", line)
      if (length(line) > 120) {
        line = substr(line, 1, 117) "..."
      }
      hint = line
    }
    END {
      if (hint != "") {
        print hint
      }
    }
  ' "${log}" 2>/dev/null || true
}

compile_log_print_summary() {
  local log="$1"
  [[ -f ${log} ]] || return 0
  awk '/Sketch uses/ || /Global variables use/ || /Used library/ || /Used platform/ { print }' "${log}" 2>/dev/null || true
}

arduino_repo_diagnostic_count() {
  local log="$1" severity="$2" root="$3"
  awk -v root="${root}/" -v sev=": ${severity}:" '
    match($0, /^[^:]+/) { p = substr($0, RSTART, RLENGTH) }
    index($0, sev) &&
      index(p, root) == 1 &&
      index(p, root "third-party/") == 0 {
      c++
    }
    END { print c + 0 }' \
    "${log}"
}

arduino_repo_fatal_error_count() {
  local log="$1" root="$2"
  awk -v root="${root}/" '
    match($0, /^[^:]+/) { p = substr($0, RSTART, RLENGTH) }
    index($0, ": fatal error:") &&
      index(p, root) == 1 &&
      index(p, root "third-party/") == 0 {
      c++
    }
    END { print c + 0 }' \
    "${log}"
}

print_arduino_repo_diagnostics() {
  local log="$1" root="$2"
  awk -v root="${root}/" '
    match($0, /^[^:]+/) { p = substr($0, RSTART, RLENGTH) }
    index(p, root) == 1 &&
      index(p, root "third-party/") == 0 &&
      ($0 ~ /: (warning|error|fatal error|note):/) {
      print
    }' \
    "${log}" >&2
}

assert_arduino_repo_clean() {
  local log="$1" label="$2" root="$3"
  local repo_warnings repo_errors repo_fatals
  repo_warnings=$(arduino_repo_diagnostic_count "$log" warning "$root")
  repo_errors=$(arduino_repo_diagnostic_count "$log" error "$root")
  repo_fatals=$(arduino_repo_fatal_error_count "$log" "$root")
  if ((repo_warnings > 0 || repo_errors > 0 || repo_fatals > 0)); then
    print_arduino_repo_diagnostics "${log}" "${root}"
    printf 'error: repo-owned Arduino diagnostics for %s: %u warning(s), %u error(s), %u fatal error(s)\n' \
      "${label}" "${repo_warnings}" "${repo_errors}" "${repo_fatals}" >&2
    exit 1
  fi
}

run_compile_with_log_heartbeat() {
  local started="${SECONDS}"
  local compile_pid compile_ec=0 last_size=0 hint=""

  printf '── Compiling firmware for %s ──\n' "${BOARD_DESCRIPTION}" >&2
  if [[ ${NERO_CI_LOCAL_IN_VM:-0} == 1 ]]; then
    printf '── note: Lima uses a VM-local work tree (not the host mount); first third-party fetch + STM32/WBA65 compile can take several minutes ──\n' >&2
  fi

  : >"${COMPILE_LOG}"
  "$@" >>"${COMPILE_LOG}" 2>&1 &
  compile_pid=$!

  while kill -0 "${compile_pid}" 2>/dev/null; do
    sleep 20
    local elapsed=$((SECONDS - started))
    local size
    size="$(wc -c <"${COMPILE_LOG}" 2>/dev/null || echo 0)"
    hint="$(compile_log_last_hint "${COMPILE_LOG}")"
    if [[ -n ${hint} ]]; then
      printf '── compiling %s (%ss, log %s bytes): %s ──\n' \
        "${BOARD_DESCRIPTION}" "${elapsed}" "${size}" "${hint}" >&2
    elif [[ ${size} -gt ${last_size} ]]; then
      printf '── compiling %s (%ss, log %s bytes) ──\n' \
        "${BOARD_DESCRIPTION}" "${elapsed}" "${size}" >&2
      last_size=${size}
    else
      printf '── compiling %s (%ss, waiting for arduino-cli output…) ──\n' \
        "${BOARD_DESCRIPTION}" "${elapsed}" >&2
    fi
  done

  wait "${compile_pid}" || compile_ec=$?
  return "${compile_ec}"
}

while (($# > 0)); do
  case "$1" in
    --board)
      shift
      BOARD_DESCRIPTION="${1:-}"
      ;;
    --log)
      shift
      COMPILE_LOG="${1:-}"
      ;;
    --repo-root)
      shift
      REPO_ROOT="${1:-}"
      ;;
    --)
      shift
      break
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
  shift
done

if [[ -z ${BOARD_DESCRIPTION} || $# -eq 0 ]]; then
  echo "ERROR: --board and compile command are required" >&2
  usage
  exit 2
fi

if [[ -n ${REPO_ROOT} ]]; then
  REPO_ROOT="$(cd -- "${REPO_ROOT}" && pwd)"
fi

if [[ -z ${COMPILE_LOG} ]]; then
  COMPILE_LOG="$(mktemp)"
  INTERNAL_COMPILE_LOG=1
fi

compile_ec=0
run_compile_with_log_heartbeat "$@" || compile_ec=$?

if [[ -n ${REPO_ROOT} ]]; then
  if ((compile_ec != 0)); then
    repo_warnings=$(arduino_repo_diagnostic_count "${COMPILE_LOG}" warning "${REPO_ROOT}")
    repo_errors=$(arduino_repo_diagnostic_count "${COMPILE_LOG}" error "${REPO_ROOT}")
    repo_fatals=$(arduino_repo_fatal_error_count "${COMPILE_LOG}" "${REPO_ROOT}")
    if ((repo_warnings > 0 || repo_errors > 0 || repo_fatals > 0)); then
      print_arduino_repo_diagnostics "${COMPILE_LOG}" "${REPO_ROOT}"
      printf 'error: repo-owned Arduino diagnostics for %s: %u warning(s), %u error(s), %u fatal error(s)\n' \
        "${BOARD_DESCRIPTION}" "${repo_warnings}" "${repo_errors}" "${repo_fatals}" >&2
      exit 1
    fi
    cat "${COMPILE_LOG}" >&2
    printf 'error: Arduino compile failed for %s (third-party/toolchain only; repo sources clean)\n' \
      "${BOARD_DESCRIPTION}" >&2
    exit 1
  fi
  assert_arduino_repo_clean "${COMPILE_LOG}" "${BOARD_DESCRIPTION}" "${REPO_ROOT}"
  compile_log_print_summary "${COMPILE_LOG}"
elif ((compile_ec != 0)); then
  cat "${COMPILE_LOG}" >&2
elif ((INTERNAL_COMPILE_LOG == 1)); then
  compile_log_print_summary "${COMPILE_LOG}"
fi

if ((INTERNAL_COMPILE_LOG == 1)); then
  rm -f "${COMPILE_LOG}"
fi

exit "${compile_ec}"
