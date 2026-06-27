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

# Linux system dependency installer — distro packages for build, test, and lint.
# Pinned third-party trees (arduino-cli, Arduino cores, NFC-RFAL, ST25R3916, …)
# are fetched by Make targets under third-party/ as needed.
#
# Usage: INSTALL_DEPS=1 bash make/install-linux-deps.sh
#        make deps   (sets INSTALL_DEPS=1)
#
# Installed tools:
#   Build:    cmake ≥ 3.20, g++ ≥ 15 (userspace/host; firmware uses arduino-cli toolchain), ninja, make, git, pkg-config, curl/wget, ca-certificates
#   WBA65:    autoconf, automake, libtool, libusb-1.0 (compile project-local OpenOCD on WBA65 build)
#   Runtime:  util-linux, psmisc (fuser), procps (timeout/pgrep), bash
#   PC/SC:    libpcsclite-dev (userspace lint/build with NERO_USERSPACE_HAVE_PCSC)
#   Fetch:    tar, unzip, coreutils (sha256sum)
#   Test:     lcov ≥ 2.0 / genhtml, valgrind, libgtest-dev, libasan, libubsan
#   Analysis: clang-tools (scan-build), clang-tidy (≥21.0.0), clang-format (≥20.0.0), cppcheck (≥2.19.1), perf
#   Lint:    shellcheck, shfmt, codespell (≥2.4.0), markdownlint-cli (≥0.48.0; Node.js ≥20)
#
# Environment (all optional):
#   AUTO_INSTALL_LINUX_DEPS=0   skip this script entirely (Makefile default via INSTALL_DEPS=0)
#   INSTALL_DEPS=0              alias for AUTO_INSTALL_LINUX_DEPS
#   INSTALL_LINT_DEPS=0         test/CI containers: build + unit-test tools only (no clang-tidy/cppcheck/…)
#   FIRMWARE_ROOT               repo root (default: parent of make/)
# Legacy skip aliases (any one =0 also disables install):
#   AUTO_INSTALL_LINUX_HOST_DEPS, AUTO_INSTALL_LINUX_UNIT_TEST_DEPS

set -euo pipefail

# ---------------------------------------------------------------------------
# Early exits
# ---------------------------------------------------------------------------
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "── install-linux-deps: not Linux; skipping ──" >&2
  exit 0
fi

: "${AUTO_INSTALL_LINUX_DEPS:=${INSTALL_DEPS:-0}}"
: "${INSTALL_LINT_DEPS:=1}"

lint_deps_enabled() {
  [[ ${INSTALL_LINT_DEPS} != "0" ]]
}

if [[ ${AUTO_INSTALL_LINUX_DEPS} == "0" ]] ||
  [[ ${AUTO_INSTALL_LINUX_HOST_DEPS:-1} == "0" ]] ||
  [[ ${AUTO_INSTALL_LINUX_UNIT_TEST_DEPS:-1} == "0" ]]; then
  echo "── install-linux-deps: auto-install disabled; skipping ──" >&2
  exit 0
fi

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${FIRMWARE_ROOT:=$(cd "${SCRIPT_DIR}/.." && pwd)}"

# shellcheck source=../.github/linters/helper-cppcheck.sh
source "${SCRIPT_DIR}/../.github/linters/helper-cppcheck.sh"
# shellcheck source=../.github/linters/helper-codespell.sh
source "${SCRIPT_DIR}/../.github/linters/helper-codespell.sh"
# shellcheck source=../.github/linters/helper-markdownlint.sh
source "${SCRIPT_DIR}/../.github/linters/helper-markdownlint.sh"
# shellcheck source=../.github/linters/helper-clang-tidy.sh
source "${SCRIPT_DIR}/../.github/linters/helper-clang-tidy.sh"

NERO_NFC_GXX_MIN_VERSION=15.0
NERO_NFC_LCOV_MIN_VERSION=2.0

# shellcheck source=../.github/scripts/helper-host-toolchain.sh
source "${SCRIPT_DIR}/../.github/scripts/helper-host-toolchain.sh"

# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

priv() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  elif have sudo; then
    sudo -E "$@"
  else
    echo "ERROR: need root or sudo to install OS packages: $*" >&2
    return 1
  fi
}

# fuser: Debian psmisc → /usr/bin/fuser; Fedora psmisc → /usr/sbin/fuser (not always on PATH).
have_fuser() {
  command -v fuser >/dev/null 2>&1 && return 0
  [[ -x /usr/sbin/fuser ]] && return 0
  [[ -x /sbin/fuser ]] && return 0
  return 1
}

version_normalize() {
  local v="$1"
  if [[ ${v} =~ ^[0-9]+$ ]]; then
    printf '%s.0' "${v}"
  else
    printf '%s' "${v}"
  fi
}

version_ge() {
  local have want
  have="$(version_normalize "$1")"
  want="$(version_normalize "$2")"
  [[ -n ${have} && -n ${want} ]] || return 1
  printf '%s\n%s\n' "${want}" "${have}" | sort -V -C
}

cmake_ok() {
  local v
  have cmake || return 1
  v="$(cmake --version 2>/dev/null | sed -n 's/cmake version \([0-9.]*\).*/\1/p' | head -n1)"
  [[ -n ${v} ]] && version_ge "${v}" "3.20"
}

gxx_ok() {
  nero_nfc_host_toolchain_ok
}

apt_install_gcc15() {
  apt_enable_universe
  if apt_pkg_installable g++-15 gcc-15; then
    priv apt-get install -y g++-15 gcc-15
    return 0
  fi
  apt_is_ubuntu || return 1
  priv apt-get install -y --no-install-recommends software-properties-common ca-certificates
  priv add-apt-repository -y -u ppa:ubuntu-toolchain-r/test
  priv apt-get update -qq
  priv apt-get install -y g++-15 gcc-15
}

lcov_version_raw() {
  have lcov || return 1
  lcov --version 2>/dev/null | sed -n 's/.*version \([0-9][0-9.]*\).*/\1/p' | head -n1
}

lcov_ok() {
  local v
  v="$(lcov_version_raw)" || return 1
  [[ -n ${v} ]] && version_ge "${v}" "${NERO_NFC_LCOV_MIN_VERSION}"
}

node_ok() {
  nero_nfc_node_ok
}

clang_format_ok() {
  nero_nfc_ensure_clang_format
}

fetch_tool_ok() { have curl || have wget; }
scan_build_ok() {
  local v
  if have scan-build; then return 0; fi
  for v in 21 20 19 18 17 16; do
    have "scan-build-${v}" && return 0
  done
  return 1
}

openocd_build_tools_ok() {
  (have gcc || gxx_ok) &&
    have autoreconf &&
    have automake &&
    (have libtool || have libtoolize) &&
    pkg-config --exists libusb-1.0
}

cppcheck_ok() {
  nero_nfc_cppcheck_version_ge "$NERO_NFC_CPPCHECK_MIN_VERSION"
}

codespell_ok() {
  nero_nfc_codespell_supports_multiline_regex
}

markdownlint_ok() {
  nero_nfc_markdownlint_version_ge "$NERO_NFC_MARKDOWNLINT_MIN_VERSION"
}

clang_tidy_ok() {
  nero_nfc_ensure_clang_tidy
}

lint_cli_ok() {
  have shellcheck &&
    have shfmt &&
    node_ok &&
    codespell_ok &&
    markdownlint_ok
}

build_packages_ok() {
  cmake_ok &&
    gxx_ok &&
    fetch_tool_ok &&
    have git &&
    have ninja &&
    have make &&
    have pkg-config &&
    have_fuser &&
    have timeout &&
    have tar &&
    have unzip &&
    have sha256sum &&
    lcov_ok &&
    have genhtml &&
    have valgrind &&
    have python3
}

lint_packages_ok() {
  scan_build_ok &&
    clang_tidy_ok &&
    clang_format_ok &&
    have cppcheck &&
    cppcheck_ok &&
    have perf &&
    openocd_build_tools_ok &&
    have shellcheck &&
    have shfmt &&
    node_ok &&
    codespell_ok &&
    markdownlint_ok
}

system_packages_ok() {
  build_packages_ok && { ! lint_deps_enabled || lint_packages_ok; }
}

install_cppcheck() {
  if nero_nfc_ensure_cppcheck; then
    if have apt-get && [[ -x /usr/local/bin/cppcheck ]] && dpkg -s cppcheck >/dev/null 2>&1; then
      priv apt-get remove -y cppcheck >/dev/null 2>&1 || true
    fi
    return 0
  fi
  if ! have cppcheck; then
    printf 'warning: cppcheck not installed\n' >&2
  else
    printf 'warning: cppcheck >= %s required; found %s\n' \
      "$NERO_NFC_CPPCHECK_MIN_VERSION" \
      "$(nero_nfc_cppcheck_version_raw 2>/dev/null || echo unknown)" >&2
  fi
  nero_nfc_cppcheck_hint
  return 1
}

install_codespell() {
  if nero_nfc_ensure_codespell; then
    return 0
  fi
  if ! have codespell; then
    printf 'warning: codespell not installed\n' >&2
  else
    printf 'warning: codespell >= %s required (--ignore-multiline-regex); found %s\n' \
      "$NERO_NFC_CODESPELL_MIN_VERSION" \
      "$(codespell --version 2>/dev/null | head -n1 || echo unknown)" >&2
  fi
  nero_nfc_codespell_hint
  return 1
}

install_markdownlint() {
  if nero_nfc_ensure_markdownlint; then
    return 0
  fi
  if ! have npm; then
    printf 'warning: markdownlint not installed (install nodejs npm, then re-run install-linux-deps.sh)\n' >&2
  else
    printf 'warning: markdownlint >= %s required; found %s\n' \
      "$NERO_NFC_MARKDOWNLINT_MIN_VERSION" \
      "$(nero_nfc_markdownlint_version_raw 2>/dev/null || echo unknown)" >&2
  fi
  nero_nfc_markdownlint_hint
  return 1
}

install_node() {
  if node_ok; then
    return 0
  fi
  if have apt-get; then
    echo "── apt-get: Node.js ${NERO_NFC_NODE_MIN_MAJOR} (markdownlint-cli) ──" >&2
    if [[ ! -f /etc/apt/sources.list.d/nodesource.list ]]; then
      curl -fsSL https://deb.nodesource.com/setup_20.x | priv bash -
    fi
    priv apt-get install -y nodejs
    nero_nfc_ensure_node_symlink || true
  fi
  if node_ok; then
    return 0
  fi
  printf 'warning: Node.js >= %s required; found %s\n' \
    "${NERO_NFC_NODE_MIN_MAJOR}" \
    "$(nero_nfc_node_version_major 2>/dev/null || echo unknown)" >&2
  nero_nfc_node_hint
  return 1
}

install_gxx() {
  if nero_nfc_host_toolchain_system_ok; then
    echo "── host toolchain: system GCC ${NERO_NFC_GXX_MIN_MAJOR}+ OK ──"
    return 0
  fi
  if have apt-get; then
    priv apt-get update -qq
    apt_install_gcc15 || return 1
    nero_nfc_host_toolchain_ensure_symlinks || return 1
    [[ -n ${GITHUB_PATH:-} ]] && printf '%s\n' "${NERO_NFC_HOST_TOOLCHAIN_PREFIX}" >>"${GITHUB_PATH}"
    nero_nfc_host_toolchain_activate || return 1
    return 0
  fi
  if have dnf || have microdnf || have yum; then
    if have dnf; then
      priv dnf install -y gcc-c++
    elif have microdnf; then
      priv microdnf install -y gcc-c++
    else
      priv yum install -y gcc-c++
    fi
  elif have zypper; then
    priv zypper install -y gcc-c++
  elif have pacman; then
    priv pacman -Sy --noconfirm gcc
  elif have apk; then
    priv apk add g++
  fi
  nero_nfc_host_toolchain_ok || {
    printf 'warning: g++ >= %s required\n' "${NERO_NFC_GXX_MIN_VERSION}" >&2
    return 1
  }
}

apt_is_ubuntu() {
  [[ -f /etc/os-release ]] && grep -qE '^ID=ubuntu' /etc/os-release
}

apt_enable_universe() {
  apt_is_ubuntu || return 0
  if grep -rqE ' universe' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
    return 0
  fi
  echo "── apt-get: enabling Ubuntu universe ──" >&2
  priv apt-get install -y --no-install-recommends software-properties-common ca-certificates
  priv add-apt-repository -y universe
  priv apt-get update -qq
}

apt_pkg_installable() {
  local pkg
  for pkg in "$@"; do
    if ! priv apt-get install -y --dry-run "${pkg}" >/dev/null 2>&1; then
      return 1
    fi
  done
}

apt_codename() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    if [[ -n ${VERSION_CODENAME:-} ]]; then
      printf '%s\n' "${VERSION_CODENAME}"
      return 0
    fi
  fi
  if have lsb_release; then
    lsb_release -sc 2>/dev/null
    return 0
  fi
  return 1
}

apt_is_debian() {
  [[ -f /etc/os-release ]] && grep -qE '^ID=debian' /etc/os-release
}

llvm_apt_codename_fallbacks() {
  local primary="$1"
  printf '%s\n' "${primary}"
  if apt_is_debian; then
    case "${primary}" in
      trixie | sid | unstable | testing)
        printf '%s\n' bookworm
        ;;
    esac
  fi
}

install_llvm_apt_repo_for_codename() {
  local ver="$1"
  local codename="$2"
  local repo_line key_file

  repo_line="deb https://apt.llvm.org/${codename}/ llvm-toolchain-${codename}-${ver} main"

  echo "── apt.llvm.org: LLVM ${ver} (${codename}) ──" >&2
  priv apt-get install -y --no-install-recommends \
    wget curl ca-certificates gnupg lsb-release software-properties-common

  key_file="/etc/apt/trusted.gpg.d/apt.llvm.org.asc"
  if [[ ! -f ${key_file} ]]; then
    curl -fsSL --retry 3 https://apt.llvm.org/llvm-snapshot.gpg.key | priv tee "${key_file}" >/dev/null
  fi

  if ! grep -rqF "llvm-toolchain-${codename}-${ver}" /etc/apt/sources.list.d/ 2>/dev/null; then
    priv add-apt-repository -y "${repo_line}"
  fi

  priv apt-get update
  apt_pkg_installable "clang-tidy-${ver}"
}

install_llvm_apt_repo() {
  local ver="$1"
  local codename candidate

  if apt_pkg_installable "clang-tidy-${ver}"; then
    return 0
  fi

  codename="$(apt_codename)" || return 1
  while IFS= read -r candidate; do
    [[ -n ${candidate} ]] || continue
    if install_llvm_apt_repo_for_codename "${ver}" "${candidate}"; then
      return 0
    fi
  done < <(llvm_apt_codename_fallbacks "${codename}")

  echo "ERROR: clang-tidy-${ver} unavailable after apt.llvm.org setup (network/DNS?)" >&2
  priv apt-cache policy "clang-tidy-${ver}" >&2 || true
  return 1
}

install_clang_tidy_via_distro() {
  local ver="${NERO_NFC_CLANG_TIDY_PREFERRED_MAJOR}"
  apt_enable_universe
  if ! apt_pkg_installable "clang-tidy-${ver}" "clang-tools-${ver}"; then
    return 1
  fi
  echo "── apt-get: clang-tidy-${ver} + clang-tools-${ver} ──" >&2
  priv apt-get install -y --no-install-recommends \
    "clang-tidy-${ver}" "clang-tools-${ver}"
}

install_clang_tidy_via_llvm_apt() {
  local ver="${NERO_NFC_CLANG_TIDY_PREFERRED_MAJOR}"
  install_llvm_apt_repo "${ver}" || return 1
  echo "── apt-get: clang-tidy-${ver} + clang-tools-${ver} (apt.llvm.org) ──" >&2
  priv apt-get install -y --no-install-recommends \
    "clang-tidy-${ver}" "clang-tools-${ver}"
}

install_clang_format_via_distro() {
  local ver
  apt_enable_universe
  for ver in "${NERO_NFC_CLANG_TIDY_PREFERRED_MAJOR}" 20; do
    if ! apt_pkg_installable "clang-format-${ver}"; then
      continue
    fi
    echo "── apt-get: clang-format-${ver} ──" >&2
    priv apt-get install -y --no-install-recommends "clang-format-${ver}"
    return 0
  done
  return 1
}

install_clang_format_via_llvm_apt() {
  local ver="${NERO_NFC_CLANG_TIDY_PREFERRED_MAJOR}"
  install_llvm_apt_repo "${ver}" || return 1
  if ! apt_pkg_installable "clang-format-${ver}"; then
    return 1
  fi
  echo "── apt-get: clang-format-${ver} (apt.llvm.org) ──" >&2
  priv apt-get install -y --no-install-recommends "clang-format-${ver}"
}

install_clang_format() {
  if nero_nfc_ensure_clang_format; then
    return 0
  fi
  if have apt-get; then
    install_clang_format_via_distro || true
    if nero_nfc_ensure_clang_format; then
      return 0
    fi
    install_clang_format_via_llvm_apt || true
  elif have dnf; then
    priv dnf install -y clang-tools-extra clang
  elif have microdnf; then
    priv microdnf install -y clang-tools-extra clang
  elif have yum; then
    priv yum install -y clang-tools-extra clang
  elif have zypper; then
    priv zypper install -y clang
  elif have pacman; then
    priv pacman -Sy --noconfirm clang
  elif have apk; then
    priv apk add clang-extra-tools || priv apk add clang
  fi
  if nero_nfc_ensure_clang_format; then
    return 0
  fi
  if ! have clang-format; then
    printf 'warning: clang-format not installed\n' >&2
  else
    printf 'warning: clang-format >= %s required; found %s\n' \
      "$NERO_NFC_CLANG_FORMAT_MIN_VERSION" \
      "$(nero_nfc_clang_format_version_raw 2>/dev/null || echo unknown)" >&2
  fi
  nero_nfc_clang_format_hint
  return 1
}

install_clang_tidy() {
  if nero_nfc_ensure_clang_tidy; then
    return 0
  fi
  if have apt-get; then
    install_clang_tidy_via_distro || true
    if nero_nfc_ensure_clang_tidy; then
      return 0
    fi
    install_clang_tidy_via_llvm_apt || return 1
  elif have dnf; then
    priv dnf install -y clang-tools-extra clang-tools
  fi
  if nero_nfc_ensure_clang_tidy; then
    return 0
  fi
  if ! have clang-tidy; then
    printf 'warning: clang-tidy not installed\n' >&2
  else
    printf 'warning: clang-tidy >= %s required; found %s\n' \
      "$NERO_NFC_CLANG_TIDY_MIN_VERSION" \
      "$(nero_nfc_clang_tidy_version_raw 2>/dev/null || echo unknown)" >&2
  fi
  nero_nfc_clang_tidy_hint
  return 1
}

install_github_actions_llvm_shims() {
  local install_dir tidy_bin format_bin run_bin

  [[ ${GITHUB_ACTIONS:-} == "true" ]] || return 0

  install_dir="/usr/local/bin"
  tidy_bin="$(nero_nfc_find_clang_tidy)" || return 1
  format_bin="$(nero_nfc_find_clang_format)" || return 1

  echo "── GitHub Actions: LLVM tool shims in ${install_dir} ──" >&2
  priv mkdir -p "${install_dir}"
  if [[ ${tidy_bin} != "${install_dir}/clang-tidy" ]]; then
    priv ln -sf "${tidy_bin}" "${install_dir}/clang-tidy"
  fi
  if [[ ${format_bin} != "${install_dir}/clang-format" ]]; then
    priv ln -sf "${format_bin}" "${install_dir}/clang-format"
  fi
  if run_bin="$(nero_nfc_find_run_clang_tidy "${tidy_bin}")"; then
    if [[ ${run_bin} != "${install_dir}/run-clang-tidy" ]]; then
      priv ln -sf "${run_bin}" "${install_dir}/run-clang-tidy"
    fi
  fi

  if [[ -n ${GITHUB_PATH:-} ]] &&
    { [[ ! -f ${GITHUB_PATH} ]] || ! grep -Fxq "${install_dir}" "${GITHUB_PATH}" 2>/dev/null; }; then
    printf '%s\n' "${install_dir}" >>"${GITHUB_PATH}"
  fi
}

if system_packages_ok; then
  if lint_deps_enabled; then
    install_github_actions_llvm_shims || {
      echo "ERROR: failed to install GitHub Actions LLVM tool shims." >&2
      exit 1
    }
  fi
  echo "── install-linux-deps: satisfied ──"
  exit 0
fi

if lint_deps_enabled; then
  echo "── install-linux-deps: resolving missing distro packages / lint tool versions ──" >&2
else
  echo "── install-linux-deps: resolving missing build/test packages (INSTALL_LINT_DEPS=0) ──" >&2
fi

if ! have sudo && [[ "$(id -u)" -ne 0 ]]; then
  echo "── sudo may be required once for OS packages ──" >&2
fi

# ---------------------------------------------------------------------------
# OS package install
# ---------------------------------------------------------------------------
install_packages() {
  if have apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    priv apt-get update -qq
    if lint_deps_enabled; then
      echo "── apt-get: build + lint dev tools ──" >&2
      local apt_perf_pkg=""
      for candidate in linux-perf perf linux-tools-generic; do
        if apt-get install -y --dry-run "${candidate}" >/dev/null 2>&1; then
          apt_perf_pkg="${candidate}"
          break
        fi
      done
      if [[ -z ${apt_perf_pkg} ]]; then
        echo "ERROR: no perf package found (tried linux-perf, perf, linux-tools-generic)." >&2
        return 1
      fi
      priv apt-get install -y \
        cmake ninja-build g++ make git pkg-config \
        autoconf automake libtool libusb-1.0-0-dev libpcsclite-dev \
        curl ca-certificates \
        util-linux psmisc procps bash tar unzip coreutils \
        lcov valgrind libgtest-dev \
        clang-tools cppcheck \
        shellcheck codespell shfmt nodejs npm python3 python3-pip python3-yaml \
        "${apt_perf_pkg}"
    else
      echo "── apt-get: build + unit-test dev tools ──" >&2
      priv apt-get install -y \
        cmake ninja-build g++ make git pkg-config \
        libpcsclite-dev curl ca-certificates \
        util-linux psmisc procps bash tar unzip coreutils \
        lcov valgrind libgtest-dev python3
    fi
    priv apt-get install -y libasan8 2>/dev/null ||
      priv apt-get install -y libasan6 2>/dev/null || true
    priv apt-get install -y libubsan2 2>/dev/null ||
      priv apt-get install -y libubsan1 2>/dev/null || true
    if lint_deps_enabled; then
      nero_nfc_ensure_node_symlink || true
    fi
  elif have dnf; then
    if lint_deps_enabled; then
      echo "── dnf: build + lint dev tools ──" >&2
      priv dnf install -y \
        cmake ninja-build gcc-c++ make git pkgconf-pkg-config \
        autoconf automake libtool libusb1-devel pcsc-lite-devel \
        curl ca-certificates \
        util-linux psmisc procps-ng bash tar unzip coreutils \
        lcov valgrind gtest-devel libasan libubsan \
        clang-analyzer clang-tools-extra clang clang-format cppcheck perf \
        ShellCheck codespell shfmt nodejs npm python3 python3-pip python3-pyyaml
    else
      echo "── dnf: build + unit-test dev tools ──" >&2
      priv dnf install -y \
        cmake ninja-build gcc-c++ make git pkgconf-pkg-config \
        pcsc-lite-devel curl ca-certificates \
        util-linux psmisc procps-ng bash tar unzip coreutils \
        lcov valgrind gtest-devel libasan libubsan python3
    fi
  elif have microdnf; then
    echo "── microdnf: all dev tools ──" >&2
    priv microdnf install -y \
      cmake ninja-build gcc-c++ make git pkgconf-pkg-config \
      autoconf automake libtool libusb1-devel \
      curl ca-certificates \
      util-linux psmisc procps-ng bash tar unzip coreutils \
      lcov valgrind gtest-devel libasan libubsan \
      clang-analyzer clang-tools-extra clang clang-format cppcheck perf
  elif have yum; then
    echo "── yum: all dev tools ──" >&2
    priv yum install -y \
      cmake ninja-build gcc-c++ make git pkgconfig \
      autoconf automake libtool libusb1-devel \
      curl ca-certificates \
      util-linux psmisc procps-ng bash tar unzip coreutils \
      lcov valgrind gtest-devel libasan libubsan \
      clang-analyzer clang-tools-extra clang clang-format cppcheck perf
  elif have zypper; then
    echo "── zypper: all dev tools ──" >&2
    priv zypper refresh
    priv zypper install -y \
      cmake ninja gcc-c++ make git pkg-config \
      autoconf automake libtool libusb-1_0-devel \
      curl ca-certificates \
      util-linux psmisc procps bash tar unzip coreutils \
      lcov valgrind gtest clang-tools clang clang-format cppcheck perf
  elif have pacman; then
    echo "── pacman: all dev tools ──" >&2
    priv pacman -Sy --noconfirm \
      cmake ninja gcc make git pkgconf \
      autoconf automake libtool libusb \
      curl ca-certificates \
      util-linux psmisc procps-ng bash tar unzip coreutils \
      lcov valgrind gtest clang llvm clang-format cppcheck perf
  elif have apk; then
    echo "── apk: all dev tools ──" >&2
    priv apk add \
      cmake ninja g++ make git pkgconf \
      autoconf automake libtool libusb-dev \
      curl ca-certificates \
      util-linux psmisc procps bash tar unzip coreutils \
      lcov valgrind gtest-dev clang clang-extra-tools clang-format cppcheck || true
  else
    echo "ERROR: No supported package manager (apt-get, dnf, microdnf, yum, zypper, pacman, apk)." >&2
    echo "Install manually: cmake ninja g++ make git pkg-config autoconf automake libtool libusb-1.0 curl ca-certificates util-linux psmisc procps bash" >&2
    echo "  tar unzip coreutils lcov valgrind clang-tools clang-tidy clang-format cppcheck perf libgtest-dev" >&2
    return 1
  fi
}

install_packages

# ---------------------------------------------------------------------------
# Post-install checks
# ---------------------------------------------------------------------------
cmake_ok || {
  echo "ERROR: cmake ≥ 3.20 required after install." >&2
  exit 1
}
install_gxx || {
  echo "ERROR: g++ ≥ ${NERO_NFC_GXX_MIN_VERSION} required after install." >&2
  exit 1
}
nero_nfc_host_toolchain_verify
fetch_tool_ok || {
  echo "ERROR: curl or wget required after install." >&2
  exit 1
}
have git || {
  echo "ERROR: git required after install." >&2
  exit 1
}
have ninja || {
  echo "ERROR: ninja required after install (ninja-build package)." >&2
  exit 1
}
have pkg-config || {
  echo "ERROR: pkg-config required after install." >&2
  exit 1
}
have_fuser || {
  echo "ERROR: fuser required after install (psmisc package on Debian/Fedora; not util-linux)." >&2
  exit 1
}
have unzip || {
  echo "ERROR: unzip required after install." >&2
  exit 1
}
have tar || {
  echo "ERROR: tar required after install." >&2
  exit 1
}
have sha256sum || {
  echo "ERROR: sha256sum required after install (coreutils package)." >&2
  exit 1
}
have lcov || {
  echo "ERROR: lcov required after install." >&2
  exit 1
}
lcov_ok || {
  echo "ERROR: lcov ≥ ${NERO_NFC_LCOV_MIN_VERSION} required after install (found $(lcov_version_raw 2>/dev/null || echo unknown))." >&2
  exit 1
}
have genhtml || {
  echo "ERROR: genhtml required after install (lcov package)." >&2
  exit 1
}
have valgrind || {
  echo "ERROR: valgrind required after install." >&2
  exit 1
}
if lint_deps_enabled; then
  scan_build_ok || {
    echo "ERROR: scan-build required after install (clang-tools package)." >&2
    exit 1
  }
  install_clang_tidy || {
    echo "ERROR: clang-tidy >= ${NERO_NFC_CLANG_TIDY_MIN_VERSION} required after install." >&2
    exit 1
  }
  install_clang_format || {
    echo "ERROR: clang-format >= ${NERO_NFC_CLANG_FORMAT_MIN_VERSION} required after install." >&2
    exit 1
  }
  install_github_actions_llvm_shims || {
    echo "ERROR: failed to install GitHub Actions LLVM tool shims." >&2
    exit 1
  }
  have cppcheck || {
    echo "ERROR: cppcheck required after install." >&2
    exit 1
  }
  install_cppcheck || {
    echo "ERROR: cppcheck >= ${NERO_NFC_CPPCHECK_MIN_VERSION} required after install." >&2
    exit 1
  }
  have shellcheck || {
    echo "ERROR: shellcheck required after install." >&2
    exit 1
  }
  have shfmt || {
    echo "ERROR: shfmt required after install." >&2
    exit 1
  }
  install_codespell || {
    echo "ERROR: codespell >= ${NERO_NFC_CODESPELL_MIN_VERSION} required after install." >&2
    exit 1
  }
  install_node || {
    echo "ERROR: Node.js >= ${NERO_NFC_NODE_MIN_MAJOR} required after install." >&2
    exit 1
  }
  install_markdownlint || {
    echo "ERROR: markdownlint required after install." >&2
    exit 1
  }
  have perf || {
    echo "ERROR: perf required after install." >&2
    exit 1
  }
  openocd_build_tools_ok || {
    echo "ERROR: autoconf/automake/libtool/libusb-1.0 required after install (WBA65 OpenOCD build)." >&2
    exit 1
  }
fi

echo "── install-linux-deps: ready ──"
