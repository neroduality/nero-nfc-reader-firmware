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

# Run Main CI inside a Lima Ubuntu 24.04 VM (1:1 with GitHub Actions ubuntu-24.04).
# Invoked by run-ci-locally.sh when --lima is passed on the host.
#
# Flow: destroy old VM → create → start (Docker + smoke test) → full CI in guest → destroy.
#
# Usage (normally via make ci-local CI_LOCAL_FLAGS=--lima):
#   bash .github/scripts/run-ci-locally-lima.sh [--main] [--skip-lint] ...
#
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
FIRMWARE_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
LIMA_TEMPLATE="${FIRMWARE_ROOT}/.github/lima/ubuntu-24.04-ci.yaml"
INSTANCE="${NERO_LIMA_INSTANCE:-nero-nfc-ci}"
LIMA_DIR="${HOME}/.lima/${INSTANCE}"
START_TIMEOUT="${NERO_LIMA_START_TIMEOUT:-15m}"
# Non-interactive: skip limactl's post-create YAML editor when stdout is a TTY.
LIMA_YES=(-y)
_LIMA_PHASE=init

if ! command -v limactl >/dev/null 2>&1; then
  printf 'error: limactl not found — Lima is required for --lima CI.\n' >&2
  printf '  GitHub: https://github.com/lima-vm/lima\n' >&2
  printf '  Install: https://lima-vm.io/docs/installation/\n' >&2
  exit 1
fi

if [[ ! -f ${LIMA_TEMPLATE} ]]; then
  printf 'error: Lima template missing: %s\n' "${LIMA_TEMPLATE}" >&2
  exit 1
fi

if [[ -z ${FIRMWARE_ROOT} || ! -f ${FIRMWARE_ROOT}/Makefile ]]; then
  printf 'error: firmware root missing Makefile: %s\n' "${FIRMWARE_ROOT}" >&2
  exit 1
fi

# yq expression for limactl --set (double-quoted path for yq lexer).
_lima_repo_set() {
  local escaped="${FIRMWARE_ROOT//\"/\\\"}"
  printf '.param.repoRoot = "%s"' "${escaped}"
}

_lima_instance_exists() {
  limactl list "${INSTANCE}" --format '{{.Name}}' 2>/dev/null | grep -qx "${INSTANCE}"
}

_lima_close_ssh() {
  local sock="${LIMA_DIR}/ssh.sock"
  if [[ -S ${sock} ]]; then
    ssh -F /dev/null -o ControlPath="${sock}" -O exit 127.0.0.1 2>/dev/null || true
  fi
}

_lima_kill_orphan_qemu() {
  local qemu_pid=""
  if [[ -f ${LIMA_DIR}/qemu.pid ]]; then
    qemu_pid="$(cat "${LIMA_DIR}/qemu.pid" 2>/dev/null || true)"
  fi
  if [[ -n ${qemu_pid} ]] && ps -p "${qemu_pid}" >/dev/null 2>&1; then
    printf '── Lima: killing orphaned QEMU (pid %s) ──\n' "${qemu_pid}" >&2
    if [[ ${NERO_LIMA_VERBOSE:-0} == 1 ]]; then
      ps -p "${qemu_pid}" -o pid,cmd= >&2 || true
    fi
    if ! timeout 5s bash -c "kill '${qemu_pid}' 2>/dev/null; while ps -p '${qemu_pid}' >/dev/null 2>&1; do sleep 0.2; done"; then
      printf '── Lima: SIGKILL orphaned QEMU (pid %s) ──\n' "${qemu_pid}" >&2
      timeout 5s bash -c "kill -9 '${qemu_pid}' 2>/dev/null; while ps -p '${qemu_pid}' >/dev/null 2>&1; do sleep 0.2; done" || true
    fi
  fi
  pkill -f "qemu-system-.*${INSTANCE}" 2>/dev/null || true
}

_lima_force_delete() {
  local delete_timeout="${NERO_LIMA_DELETE_TIMEOUT:-2m}"
  printf '── Lima: limactl delete --force %s ──\n' "${INSTANCE}" >&2
  _lima_close_ssh
  if _lima_instance_exists; then
    local status=""
    status="$(limactl list "${INSTANCE}" --format '{{.Status}}' 2>/dev/null || true)"
    case "${status}" in
      Running | Broken)
        if [[ ${NERO_LIMA_VERBOSE:-0} == 1 ]]; then
          timeout "${delete_timeout}" limactl stop "${INSTANCE}" || _lima_kill_orphan_qemu
        else
          timeout "${delete_timeout}" limactl stop "${INSTANCE}" >/dev/null 2>&1 ||
            _lima_kill_orphan_qemu
        fi
        ;;
    esac
  elif [[ -d ${LIMA_DIR} ]]; then
    _lima_kill_orphan_qemu
  fi
  if [[ ${NERO_LIMA_VERBOSE:-0} == 1 ]]; then
    if ! timeout "${delete_timeout}" limactl "${LIMA_YES[@]}" delete --force "${INSTANCE}"; then
      printf '── Lima: delete timed out; removing %s ──\n' "${LIMA_DIR}" >&2
      rm -rf "${LIMA_DIR}"
    fi
  else
    if ! timeout "${delete_timeout}" limactl "${LIMA_YES[@]}" delete --force "${INSTANCE}" 2>&1 |
      grep -v 'Ignoring non-existent instance' >&2; then
      printf '── Lima: delete timed out; removing %s ──\n' "${LIMA_DIR}" >&2
      rm -rf "${LIMA_DIR}"
    fi
  fi
}

_lima_destroy_instance() {
  _lima_force_delete
}

_lima_print_failure_diagnostics() {
  local rc=$1
  [[ ${rc} -eq 0 ]] && return 0

  printf '\n── Lima: failed during phase %s (exit %s) ──\n' "${_LIMA_PHASE}" "${rc}" >&2
  case "${_LIMA_PHASE}" in
    boot)
      printf '── hint: boot = Docker install + SocketUser restart (no VM reboot) ──\n' >&2
      if [[ -f ${LIMA_DIR}/serial.log ]]; then
        printf '── serial.log (last 80 lines) ──\n' >&2
        tail -80 "${LIMA_DIR}/serial.log" >&2 || true
      fi
      if [[ -f ${LIMA_DIR}/start.stderr.log ]]; then
        printf '── limactl start stderr (last 40 lines) ──\n' >&2
        tail -40 "${LIMA_DIR}/start.stderr.log" >&2 || true
      fi
      if _lima_instance_exists; then
        printf '── provision log (last 60 lines) ──\n' >&2
        limactl shell "${INSTANCE}" -- sudo tail -60 /var/log/cloud-init-output.log >&2 || true
        limactl shell "${INSTANCE}" -- sudo systemctl is-active docker.service >&2 || true
      fi
      ;;
    ci)
      printf '── hint: CI error output should appear above this block ──\n' >&2
      if _lima_instance_exists; then
        limactl shell "${INSTANCE}" -- bash -ce '
          printf "user=%s\n" "$(id -un)"
          command -v clang-tidy >/dev/null && clang-tidy --version | head -1 || echo clang-tidy=missing
          docker info >/dev/null 2>&1 && echo docker=ok || echo docker=broken
        ' >&2 || true
      fi
      ;;
    *)
      printf '── hint: see logs under %s ──\n' "${LIMA_DIR}" >&2
      ;;
  esac
  if [[ -f ${LIMA_DIR}/ha.stderr.log ]]; then
    printf '── hostagent stderr (last 40 lines) ──\n' >&2
    tail -40 "${LIMA_DIR}/ha.stderr.log" >&2 || true
  fi
  printf '── logs: %s ──\n' "${LIMA_DIR}" >&2
  printf '── keep VM for inspection: NERO_LIMA_KEEP_ON_FAILURE=1 make ci-local CI_LOCAL_FLAGS=--lima ──\n' >&2
}

_lima_create_args() {
  local -a args=()
  local host_cpus host_mem_gb
  host_cpus="$(nproc 2>/dev/null || echo 4)"
  host_mem_gb="$(awk '/MemTotal/ { printf "%d", $2/1024/1024 }' /proc/meminfo 2>/dev/null || echo 8)"
  # Cap VM size so limactl start does not hang on hosts that cannot allocate 12c/16GiB.
  if [[ ${host_cpus} -gt 4 ]]; then
    args+=(--cpus "$((host_cpus > 8 ? 8 : host_cpus))")
  fi
  if [[ ${host_mem_gb} -gt 8 ]]; then
    args+=(--memory "$((host_mem_gb > 12 ? 12 : host_mem_gb))")
  fi
  printf '%s\n' "${args[@]}"
}

_lima_start_instance() {
  local start_log="${LIMA_DIR}/start.stderr.log"
  if [[ ${NERO_LIMA_VERBOSE:-0} == 1 ]]; then
    limactl "${LIMA_YES[@]}" start --progress --timeout "${START_TIMEOUT}" "${INSTANCE}"
    return $?
  fi
  printf '── Lima: booting VM (Docker install + probe; usually 2–5 min) ──\n' >&2
  printf '── tip: NERO_LIMA_VERBOSE=1 shows cloud-init tail ──\n' >&2
  limactl "${LIMA_YES[@]}" start --timeout "${START_TIMEOUT}" "${INSTANCE}" 2>"${start_log}" &
  local start_pid=$!
  local t0=$SECONDS
  while kill -0 "${start_pid}" 2>/dev/null; do
    sleep 20
    local elapsed=$((SECONDS - t0))
    local status="starting"
    if _lima_instance_exists; then
      status="$(limactl list "${INSTANCE}" --format '{{.Status}}' 2>/dev/null || echo unknown)"
    fi
    local phase="hostagent boot"
    if [[ -f ${LIMA_DIR}/serial.log ]]; then
      phase="$(tail -20 "${LIMA_DIR}/serial.log" 2>/dev/null | awk '
        /Executing .*provision\.system/ { p = $0; sub(/^.*Executing /, "", p); next }
        /Lima provision: Docker ready/ { p = "docker ready"; next }
        /Creating .*docker\.socket/ { p = "docker socket override"; next }
        END { if (p != "") print p; else print "hostagent boot" }
      ')"
    fi
    printf '── Lima boot %ss: status=%s (%s) ──\n' "${elapsed}" "${status}" "${phase}" >&2
  done
  wait "${start_pid}"
}

_lima_teardown() {
  local rc=$?
  set +e
  if [[ ${rc} -eq 130 || ${rc} -eq 143 ]]; then
    printf '\n── Lima Main CI interrupted (signal) ──\n' >&2
  elif [[ ${rc} -ne 0 ]]; then
    _lima_print_failure_diagnostics "${rc}"
  else
    printf '\n── Lima Main CI passed; tearing down %s ──\n' "${INSTANCE}"
  fi
  if [[ ${rc} -ne 0 && ${NERO_LIMA_KEEP_ON_FAILURE:-0} == 1 ]]; then
    printf '── Lima: keeping %s (NERO_LIMA_KEEP_ON_FAILURE=1) ──\n' "${INSTANCE}" >&2
    trap - EXIT
    exit "${rc}"
  fi
  if [[ ${rc} -eq 0 ]]; then
    if ! _lima_destroy_instance; then
      printf '── Lima: destroy failed (try: limactl delete --force %s) ──\n' "${INSTANCE}" >&2
    fi
  elif [[ ${NERO_LIMA_KEEP_ON_FAILURE:-0} != 1 ]]; then
    _lima_destroy_instance || true
  fi
  trap - EXIT
  exit "${rc}"
}

printf '── Lima Main CI: fresh ubuntu-24.04 VM %s ──\n' "${INSTANCE}"
printf '   repo: %s → /src\n' "${FIRMWARE_ROOT}"
printf '   start timeout: %s (override: NERO_LIMA_START_TIMEOUT)\n' "${START_TIMEOUT}"

_LIMA_PHASE=boot
_lima_force_delete
trap _lima_teardown EXIT

printf '── Lima: creating %s ──\n' "${INSTANCE}"
_lima_create_size=()
while IFS= read -r _lima_opt; do
  [[ -n ${_lima_opt} ]] && _lima_create_size+=("${_lima_opt}")
done < <(_lima_create_args)
limactl "${LIMA_YES[@]}" create "${LIMA_TEMPLATE}" --name "${INSTANCE}" --set "$(_lima_repo_set)" \
  "${_lima_create_size[@]}"

printf '── Lima: starting %s ──\n' "${INSTANCE}"
_lima_start_instance
printf '── Lima: boot complete (dockerd probe passed) ──\n'

_LIMA_PHASE=ci
printf '── Lima: running full Main CI inside %s (deps + lint + containers) ──\n' "${INSTANCE}"
limactl shell "${INSTANCE}" -- bash /src/.github/scripts/run-ci-locally-lima-guest.sh "$@"
