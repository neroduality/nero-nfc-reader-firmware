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

# Board upload driver with a spinner between the prep prompt and the ready prompt.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
# shellcheck source=make/cli-spinner.sh
source "${repo_root}/make/cli-spinner.sh"

ARDUINO_CLI=""
FQBN=""
INPUT_DIR=""
BUILD_DIR=""
PORT=""
PSEUDO_PORT=""
NEEDS_PORT=1
DISCOVERY_TIMEOUT="10s"
PORT_WAIT_SECONDS=6
READY_MARKER=""
WAIT_MESSAGE="Processing — wait"
READY_BANNER=""

usage() {
  cat <<'EOF' >&2
Usage: bash scripts/run-board-upload.sh --arduino-cli PATH --fqbn FQBN --input-dir DIR [options]

Options:
  --build-dir DIR
  --port DEV
  --pseudo-port NAME
  --needs-port 0|1
  --discovery-timeout DURATION
  --port-wait-seconds N
  --ready-marker TEXT     Stop spinner when this substring appears on stderr
  --ready-banner TEXT     Emit this banner when port discovery succeeds (ported boards)
  --wait-message TEXT     Spinner label (default: Processing — wait)
EOF
}

while (($# > 0)); do
  case "$1" in
    --arduino-cli)
      shift
      ARDUINO_CLI="${1:-}"
      ;;
    --fqbn)
      shift
      FQBN="${1:-}"
      ;;
    --input-dir)
      shift
      INPUT_DIR="${1:-}"
      ;;
    --build-dir)
      shift
      BUILD_DIR="${1:-}"
      ;;
    --port)
      shift
      PORT="${1:-}"
      ;;
    --pseudo-port)
      shift
      PSEUDO_PORT="${1:-}"
      ;;
    --needs-port)
      shift
      NEEDS_PORT="${1:-}"
      ;;
    --discovery-timeout)
      shift
      DISCOVERY_TIMEOUT="${1:-}"
      ;;
    --port-wait-seconds)
      shift
      PORT_WAIT_SECONDS="${1:-}"
      ;;
    --ready-marker)
      shift
      READY_MARKER="${1:-}"
      ;;
    --ready-banner)
      shift
      READY_BANNER="${1:-}"
      ;;
    --wait-message)
      shift
      WAIT_MESSAGE="${1:-}"
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

[[ -x "${ARDUINO_CLI}" ]] || {
  echo "ERROR: arduino-cli not executable: ${ARDUINO_CLI}" >&2
  exit 1
}
[[ -n "${FQBN}" ]] || {
  echo "ERROR: --fqbn is required" >&2
  exit 1
}
[[ -d "${INPUT_DIR}" ]] || {
  echo "ERROR: input dir not found: ${INPUT_DIR}" >&2
  exit 1
}

normalize_port() {
  local candidate="$1"
  if [[ -n "${candidate}" && ! -e "${candidate}" && -e "/dev/${candidate}" ]]; then
    printf '/dev/%s\n' "${candidate}"
    return 0
  fi
  printf '%s\n' "${candidate}"
}

discover_port_once() {
  local found=""
  if command -v timeout >/dev/null 2>&1; then
    found="$(timeout 2 "${ARDUINO_CLI}" board list 2>/dev/null | awk 'NR > 1 && $1 ~ /^\/dev\// { print $1; exit }')"
  else
    found="$("${ARDUINO_CLI}" board list 2>/dev/null | awk 'NR > 1 && $1 ~ /^\/dev\// { print $1; exit }')"
  fi
  if [[ -z "${found}" ]]; then
    found="$(ls /dev/ttyACM* /dev/ttyUSB* 2>/dev/null | head -1 || true)"
  fi
  printf '%s\n' "${found}"
}

UPLOAD_SPINNER_DURING_CLI=1

emit_ready_banner() {
  if [[ -n "${READY_BANNER}" ]]; then
    echo "── ${READY_BANNER} ──" >&2
    UPLOAD_SPINNER_DURING_CLI=0
  fi
}

resolve_upload_port() {
  local saved_port=""
  PORT="$(normalize_port "${PORT}")"

  if [[ -n "${PSEUDO_PORT}" ]]; then
    PORT="${PSEUDO_PORT}"
    return 0
  fi

  if [[ "${NEEDS_PORT}" != "1" ]]; then
    return 0
  fi

  if [[ -n "${PORT}" ]]; then
    emit_ready_banner
    return 0
  fi

  if [[ -n "${BUILD_DIR}" && -f "${BUILD_DIR}/.port" ]]; then
    saved_port="$(<"${BUILD_DIR}/.port")"
    if [[ -e "${saved_port}" ]]; then
      PORT="${saved_port}"
      emit_ready_banner
      return 0
    fi
    if [[ -e "/dev/${saved_port}" ]]; then
      PORT="/dev/${saved_port}"
      emit_ready_banner
      return 0
    fi
  fi

  cli_spinner_start "${WAIT_MESSAGE}"
  local waited=0
  while [[ -z "${PORT}" && "${waited}" -lt "${PORT_WAIT_SECONDS}" ]]; do
    PORT="$(discover_port_once)"
    if [[ -z "${PORT}" ]]; then
      waited=$((waited + 1))
      remaining=$((PORT_WAIT_SECONDS - waited))
      cli_spinner_set_message "${WAIT_MESSAGE} (${remaining}s left)"
      sleep 1
    fi
  done
  cli_spinner_finish

  if [[ -z "${PORT}" ]]; then
    echo "ERROR: No board found" >&2
    exit 1
  fi
  if [[ ! -e "${PORT}" ]]; then
    echo "ERROR: Port ${PORT} not found" >&2
    exit 1
  fi

  emit_ready_banner
}

run_upload_with_spinner() {
  local upload_port="$1"
  local spinner_active=0
  local line=""
  local -a upload_args=(upload --fqbn "${FQBN}" --input-dir "${INPUT_DIR}" --discovery-timeout "${DISCOVERY_TIMEOUT}")

  if [[ "${UPLOAD_SPINNER_DURING_CLI}" -eq 1 && -n "${READY_MARKER}" ]]; then
    cli_spinner_start "${WAIT_MESSAGE}"
    spinner_active=1
  fi

  if [[ -n "${upload_port}" ]]; then
    upload_args+=(-p "${upload_port}")
  fi

  # Upload tools that draw \r spinners on stderr need a real TTY.
  if [[ -z "${READY_MARKER}" ]]; then
    timeout 120 "${ARDUINO_CLI}" "${upload_args[@]}"
  else
    timeout 120 "${ARDUINO_CLI}" "${upload_args[@]}" 2> >(
      while IFS= read -r line || [[ -n "${line}" ]]; do
        if [[ "${spinner_active}" -eq 1 && "${line}" == *"${READY_MARKER}"* ]]; then
          cli_spinner_finish
          spinner_active=0
        fi
        printf '%s\n' "${line}" >&2
      done
    )
  fi

  if [[ "${spinner_active}" -eq 1 ]]; then
    cli_spinner_finish
  fi
}

remember_port() {
  local live_port=""
  [[ "${NEEDS_PORT}" == "1" ]] || return 0
  [[ -n "${BUILD_DIR}" ]] || return 0
  live_port="$("${ARDUINO_CLI}" board list 2>/dev/null | awk 'NR > 1 && $1 ~ /^\/dev\// { print $1; exit }')"
  if [[ -n "${live_port}" ]]; then
    PORT="${live_port}"
  fi
  mkdir -p "${BUILD_DIR}"
  printf '%s\n' "${PORT}" >"${BUILD_DIR}/.port"
}

resolve_upload_port

UPLOAD_PORT="${PORT}"
UPLOAD_OK=0
for ATTEMPT in 1 2 3 4; do
  if run_upload_with_spinner "${UPLOAD_PORT}"; then
    PORT="${UPLOAD_PORT}"
    UPLOAD_OK=1
    break
  fi
  NEXT_PORT="$("${ARDUINO_CLI}" board list 2>/dev/null | awk 'NR > 1 && $1 ~ /^\/dev\// { print $1; exit }')"
  if [[ -z "${NEXT_PORT}" ]]; then
    NEXT_PORT="$(ls /dev/ttyACM* /dev/ttyUSB* 2>/dev/null | head -1 || true)"
  fi
  if [[ -z "${NEXT_PORT}" ]]; then
    break
  fi
  echo "── Retrying upload on ${NEXT_PORT} (attempt ${ATTEMPT}) ──" >&2
  UPLOAD_PORT="${NEXT_PORT}"
  sleep 1
done

if [[ "${UPLOAD_OK}" -ne 1 ]]; then
  exit 1
fi

remember_port
