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

# Shared helpers for local container CI on bind-mounted repo trees.
# Source this file; do not execute directly.

if [[ ${BASH_SOURCE[0]} == "${0}" ]]; then
  printf '%s\n' "error: source helper-container-bind-mount.sh instead of executing it" >&2
  exit 1
fi

_NERO_NFC_BIND_MOUNT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_NERO_NFC_BIND_MOUNT_RESTORE_DONE=0

# Relative repo paths bind-mounted local container CI may write (restored on exit).
_NERO_NFC_BIND_MOUNT_RESTORE_PATHS=(
  .lint-kit-org
  build
  third-party
  tests/build
  tests/build-scan
  tests/scan-build-report
)

# Subtrees created before drop so host UID owns them from the first write.
# mkdir -p as root leaves intermediate dirs (e.g. build/lint) root-owned; always
# chown the top-level trees below after all mkdirs — never only the leaf path.
_NERO_NFC_BIND_MOUNT_PREPARE_PATHS=(
  .lint-kit-org
  build
  build/lint
  build/lint/firmware
  build/lint/tests
  build/lint/userspace
  build/lint/openssf-probe-verify
  build/lint-overrides
  build/clang-tidy-compile-db
  build/codeql
  build/userspace
  third-party
  tests/build
  tests/build-scan
  tests/scan-build-report
)

# Top-level bind-mount trees to chown -R after prepare mkdirs (covers intermediates).
_NERO_NFC_BIND_MOUNT_CHOWN_ROOTS=(
  .lint-kit-org
  build
  third-party
  tests/build
  tests/build-scan
  tests/scan-build-report
)

nero_nfc_restore_bind_mount_ownership() {
  local paths=("$@")
  if [[ ${#paths[@]} -eq 0 ]]; then
    paths=("${_NERO_NFC_BIND_MOUNT_RESTORE_PATHS[@]}")
  fi
  bash "${_NERO_NFC_BIND_MOUNT_DIR}/helper-restore-bind-mount-ownership.sh" "${paths[@]}"
}

nero_nfc_prepare_bind_mount_paths() {
  local repo_root="${1:-.}"
  if [[ $(id -u) -ne 0 || -z ${HOST_UID:-} ]]; then
    return 0
  fi
  local uid="${HOST_UID}"
  local gid="${HOST_GID:-${uid}}"
  local rel
  for rel in "${_NERO_NFC_BIND_MOUNT_PREPARE_PATHS[@]}"; do
    mkdir -p "${repo_root}/${rel}"
  done
  # Chown top-level trees only after every mkdir -p so intermediates are not left root-owned.
  for rel in "${_NERO_NFC_BIND_MOUNT_CHOWN_ROOTS[@]}"; do
    if [[ -e ${repo_root}/${rel} ]]; then
      chown -R "${uid}:${gid}" "${repo_root}/${rel}"
    fi
  done
}

nero_nfc_ensure_runuser() {
  if command -v runuser >/dev/null 2>&1; then
    return 0
  fi
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y --no-install-recommends util-linux
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y --setopt=install_weak_deps=False util-linux
    dnf clean all
  fi
}

nero_nfc_ensure_host_user() {
  local uid="${HOST_UID:?HOST_UID required}"
  local gid="${HOST_GID:-${uid}}"

  if id -u "${uid}" >/dev/null 2>&1; then
    return 0
  fi
  if ! getent group "${gid}" >/dev/null 2>&1; then
    groupadd -o -g "${gid}" nero_nfc_ci 2>/dev/null || groupadd -g "${gid}" nero_nfc_ci
  fi
  useradd -o -u "${uid}" -g "${gid}" -M -s /bin/bash nero_nfc_ci
}

# In a root container entry, re-exec the same script as the unprivileged host
# user. Dependencies are installed by the caller while still root; this re-exec
# runs with INSTALL_DEPS=0.
nero_nfc_drop_to_host_user() {
  if [[ $(id -u) -ne 0 || -z ${HOST_UID:-} || ${NERO_NFC_CI_AS_USER:-0} == 1 ]]; then
    return 1
  fi
  nero_nfc_ensure_runuser
  if ! command -v runuser >/dev/null 2>&1; then
    printf 'error: runuser missing; cannot run bind-mount builds without root-owned output\n' >&2
    return 1
  fi
  nero_nfc_ensure_host_user
  local -a drop_env=(
    NERO_NFC_CI_AS_USER=1
    AUTO_INSTALL_LINUX_DEPS=0
    INSTALL_DEPS=0
    HOST_UID="${HOST_UID}"
    HOST_GID="${HOST_GID:-${HOST_UID}}"
    HOME="${NERO_NFC_CI_HOME:-/tmp/nero-nfc-ci}"
  )
  if [[ -n ${FIRMWARE_ROOT:-} ]]; then
    drop_env+=(FIRMWARE_ROOT="${FIRMWARE_ROOT}")
  fi
  if [[ -n ${LINT_KIT:-} ]]; then
    drop_env+=(LINT_KIT="${LINT_KIT}")
  fi
  if [[ -n ${CI_SKIP_CHECKOUT_PREREQUISITES:-} ]]; then
    drop_env+=(CI_SKIP_CHECKOUT_PREREQUISITES="${CI_SKIP_CHECKOUT_PREREQUISITES}")
  fi
  if [[ -n ${NERO_CI_LOCAL_IN_VM:-} ]]; then
    drop_env+=(NERO_CI_LOCAL_IN_VM="${NERO_CI_LOCAL_IN_VM}")
  fi
  # Forward CodeQL local/CI knobs into the dropped-user re-exec.
  local _k
  for _k in $(compgen -e CODEQL_ || true); do
    drop_env+=("${_k}=${!_k}")
  done
  exec runuser -u nero_nfc_ci -- env "${drop_env[@]}" "$@"
}

nero_nfc_require_drop_to_host_user() {
  if ! nero_nfc_drop_to_host_user "$@"; then
    printf 'error: failed to re-exec as host UID %s (install util-linux / runuser?)\n' \
      "${HOST_UID}" >&2
    exit 1
  fi
}

nero_nfc_refuse_root_bind_mount_writes() {
  if [[ $(id -u) -eq 0 && -n ${HOST_UID:-} && ${NERO_NFC_CI_AS_USER:-0} != 1 ]]; then
    printf 'error: refusing bind-mount writes as root (HOST_UID=%s); drop to host user failed\n' \
      "${HOST_UID}" >&2
    exit 1
  fi
}

# Run a container command on a bind-mounted repo; restore ownership even on failure.
nero_nfc_run_bind_mount_container() {
  local engine="${CONTAINER_ENGINE:-docker}"
  local -a restore_paths=()
  local -a docker_args=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --restore)
        shift
        while [[ $# -gt 0 && $1 != -- ]]; do
          restore_paths+=("$1")
          shift
        done
        ;;
      --)
        shift
        docker_args=("$@")
        break
        ;;
      *)
        printf 'error: nero_nfc_run_bind_mount_container: unexpected argument %q (use --restore ... -- docker-args...)\n' \
          "$1" >&2
        return 2
        ;;
    esac
  done

  if [[ ${#restore_paths[@]} -eq 0 ]]; then
    restore_paths=("${_NERO_NFC_BIND_MOUNT_RESTORE_PATHS[@]}")
  fi
  if [[ ${#docker_args[@]} -eq 0 ]]; then
    printf 'error: nero_nfc_run_bind_mount_container needs docker run arguments after --\n' >&2
    return 2
  fi

  _NERO_NFC_BIND_MOUNT_RESTORE_DONE=0
  _nero_nfc_restore_bind_mount_on_exit() {
    if [[ ${_NERO_NFC_BIND_MOUNT_RESTORE_DONE:-0} -eq 0 ]]; then
      _NERO_NFC_BIND_MOUNT_RESTORE_DONE=1
      nero_nfc_restore_bind_mount_ownership "${restore_paths[@]}"
    fi
  }
  trap _nero_nfc_restore_bind_mount_on_exit EXIT

  "${engine}" run --rm "${docker_args[@]}"
  local ec=$?

  _NERO_NFC_BIND_MOUNT_RESTORE_DONE=1
  trap - EXIT
  nero_nfc_restore_bind_mount_ownership "${restore_paths[@]}"
  return "${ec}"
}

# Docker --platform for local CI container pulls.
# - CI_PLATFORM unset: linux/amd64 on x86_64, else linux/$host where known.
# - CI_PLATFORM empty: native pull (no --platform).
# - CI_PLATFORM set: use that value.
nero_nfc_default_ci_platform() {
  case "$(uname -m)" in
    x86_64 | amd64) printf '%s' 'linux/amd64' ;;
    aarch64 | arm64) printf '%s' 'linux/arm64' ;;
    armv7l | armv6l) printf '%s' 'linux/arm/v7' ;;
    riscv64) printf '%s' 'linux/riscv64' ;;
    ppc64le) printf '%s' 'linux/ppc64le' ;;
    s390x) printf '%s' 'linux/s390x' ;;
    *) printf '%s' '' ;;
  esac
}

nero_nfc_resolve_ci_platform() {
  if [[ -v CI_PLATFORM ]]; then
    printf '%s' "${CI_PLATFORM}"
    return 0
  fi
  nero_nfc_default_ci_platform
}

nero_nfc_ci_platform_docker_args() {
  local platform
  platform="$(nero_nfc_resolve_ci_platform)"
  if [[ -n ${platform} ]]; then
    printf '%s\n' "--platform" "${platform}"
  fi
}

# Populate the PLATFORM_ARGS bash array for docker/podman run.
nero_nfc_load_ci_platform_args() {
  PLATFORM_ARGS=()
  # shellcheck disable=SC2034 # caller consumes PLATFORM_ARGS after sourcing this helper
  mapfile -t PLATFORM_ARGS < <(nero_nfc_ci_platform_docker_args)
}
