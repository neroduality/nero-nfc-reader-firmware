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

# Braille spinner for long-running upload/bootstrap steps (Cursor-style CLI wait).
#
# Source from bash:
#   source make/cli-spinner.sh
#   cli_spinner_start "Processing — wait"   # blank line, spinner row, reserved blank line below
#   cli_spinner_set_message "Processing — updated detail"
#   cli_spinner_finish                      # clear spinner row; blank line before next output
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "Source this file; do not execute directly." >&2
  exit 1
fi

CLI_SPINNER_PID=""
CLI_SPINNER_MSG_FILE=""
CLI_SPINNER_FRAMES=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)

cli_spinner_start() {
  local message="${1:-Processing — wait}"
  cli_spinner_stop
  # Blank line, then spinner row (avoid \r drawing on the same line as a single leading \n).
  printf '\n\n' >&2
  CLI_SPINNER_MSG_FILE="$(mktemp "${TMPDIR:-/tmp}/cli-spinner-msg.XXXXXX")"
  printf '%s' "${message}" >"${CLI_SPINNER_MSG_FILE}"
  (
    local i=0
    local frame_count="${#CLI_SPINNER_FRAMES[@]}"
    local msg=""
    while [[ -f "${CLI_SPINNER_MSG_FILE}" ]]; do
      msg="$(<"${CLI_SPINNER_MSG_FILE}")"
      printf '\r%s %s  ' "${CLI_SPINNER_FRAMES[$i]}" "${msg}" >&2
      i=$(( (i + 1) % frame_count ))
      sleep 0.12
    done
  ) &
  CLI_SPINNER_PID=$!
}

cli_spinner_set_message() {
  if [[ -n "${CLI_SPINNER_MSG_FILE}" && -f "${CLI_SPINNER_MSG_FILE}" ]]; then
    printf '%s' "$1" >"${CLI_SPINNER_MSG_FILE}"
  fi
}

cli_spinner_stop() {
  if [[ -n "${CLI_SPINNER_PID}" ]]; then
    kill "${CLI_SPINNER_PID}" 2>/dev/null || true
    wait "${CLI_SPINNER_PID}" 2>/dev/null || true
    CLI_SPINNER_PID=""
  fi
  if [[ -n "${CLI_SPINNER_MSG_FILE}" ]]; then
    rm -f "${CLI_SPINNER_MSG_FILE}"
    CLI_SPINNER_MSG_FILE=""
  fi
  printf '\r\033[K' >&2
}

cli_spinner_finish() {
  cli_spinner_stop
  # Leave one fully empty line after the cleared spinner row.
  printf '\n\n' >&2
}
