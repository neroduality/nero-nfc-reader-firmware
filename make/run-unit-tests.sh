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

set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
build_dir="${repo_root}/tests/build"

nero_pcsc_dev_available() {
  if command -v pkg-config >/dev/null 2>&1; then
    pkg-config --exists libpcsclite 2>/dev/null && return 0
    pkg-config --exists pcsclite 2>/dev/null && return 0
  fi
  if [[ $(uname -s) == Darwin ]]; then
    [[ -e /System/Library/Frameworks/PCSC.framework/PCSC ]] && return 0
  fi
  return 1
}

nero_resolve_tests_enable_pcsc() {
  if [[ -n ${NERO_TESTS_ENABLE_PCSC+x} ]]; then
    if [[ ${NERO_TESTS_ENABLE_PCSC} == 1 ]] && ! nero_pcsc_dev_available; then
      printf 'error: NERO_TESTS_ENABLE_PCSC=1 but libpcsclite dev library not found\n' >&2
      printf 'hint: make deps  (Debian: libpcsclite-dev; Fedora: pcsc-lite-devel)\n' >&2
      exit 1
    fi
    return 0
  fi
  if nero_pcsc_dev_available; then
    export NERO_TESTS_ENABLE_PCSC=1
    printf '── unit tests: libpcsclite found; linking PC/SC (NERO_TESTS_ENABLE_PCSC=1) ──\n' >&2
  else
    export NERO_TESTS_ENABLE_PCSC=0
  fi
}
build_lock_file="${build_dir}/.nero_unit_test.lock"
coverage_dir="${build_dir}/coverage-html"
lcov_info="${build_dir}/coverage.info"
profile_file="${build_dir}/.nero_unit_test_profile"

# Debug unit-test builds enable both ASan and UBSan by default. Coverage and Valgrind run without
# sanitizers because they either conflict or are intended to inspect an unsanitized binary.
sanitize_address_defaulted=0
sanitize_undefined_defaulted=0
debug_sanitizers_default=1
if [[ "${COVERAGE:-0}" == "1" || "${VALGRIND:-0}" == "1" ]]; then
  SANITIZE_ADDRESS=0
  SANITIZE_UNDEFINED=0
  SANITIZE_THREAD=0
  debug_sanitizers_default=0
else
  if [[ ! -v SANITIZE_ADDRESS ]]; then
    SANITIZE_ADDRESS=1
    sanitize_address_defaulted=1
  fi
  if [[ ! -v SANITIZE_UNDEFINED ]]; then
    SANITIZE_UNDEFINED=1
    sanitize_undefined_defaulted=1
  fi
  if [[ ! -v SANITIZE_THREAD ]]; then
    SANITIZE_THREAD=0
  fi
fi

if [[ "${SANITIZE_THREAD:-0}" == "1" ]]; then
  SANITIZE_ADDRESS=0
  SANITIZE_UNDEFINED=0
  debug_sanitizers_default=0
fi

if [[ "${COVERAGE:-0}" == "1" ]]; then
  build_type="Debug"
elif [[ -n "${NERO_TESTS_BUILD_TYPE:-}" ]]; then
  build_type="${NERO_TESTS_BUILD_TYPE}"
  debug_sanitizers_default=0
elif [[ "${sanitize_address_defaulted}" == "1" && "${sanitize_undefined_defaulted}" == "1" ]]; then
  build_type="Debug"
elif [[ "${SANITIZE_ADDRESS:-0}" == "1" || "${SANITIZE_UNDEFINED:-0}" == "1" || "${SANITIZE_THREAD:-0}" == "1" ]]; then
  build_type="RelWithDebInfo"
else
  build_type="Debug"
fi

nero_unit_test_profile() {
  printf '%s:%s:%s:%s:%s:%s:%s:%s:%s' \
    "${COVERAGE:-0}" \
    "${build_type}" \
    "${SANITIZE_ADDRESS:-0}" \
    "${SANITIZE_UNDEFINED:-0}" \
    "${SANITIZE_THREAD:-0}" \
    "${debug_sanitizers_default}" \
    "${NERO_USE_SYSTEM_GTEST:-0}" \
    "${NERO_ENABLE_EXTENDED_SANITIZERS:-1}" \
    "${NERO_TESTS_ENABLE_PCSC:-0}"
}

usage() {
  cat <<'EOF'
Usage: make/run-unit-tests.sh

Environment (optional):
  COVERAGE=1              Build with --coverage and write lcov HTML when lcov is available.
                          Uses --ignore-errors mismatch on lcov ≥ 2.0 only (GCC 15 / gtest .gcda quirks).
  COVERAGE_STRICT=1       Fail if COVERAGE=1 but lcov/genhtml are missing.
  COVERAGE_MIN_LINES=90   With COVERAGE=1, fail if total line coverage is below this percent.
  NERO_TESTS_ENABLE_PCSC=0 Force PC/SC stub (default: auto ON when pkg-config finds libpcsclite).
  NERO_TESTS_ENABLE_PCSC=1 Force PC/SC link (error if libpcsclite dev library missing).
  SKIP_CTEST=1            Configure and build only; skip ctest.
  VALGRIND=1              Run the GoogleTest binary under valgrind (must be installed).
  SANITIZE_ADDRESS=1      Force AddressSanitizer on.
  SANITIZE_UNDEFINED=1    Force UndefinedBehaviorSanitizer on.
  SANITIZE_THREAD=1       Force ThreadSanitizer on (mutually exclusive with ASan/UBSan).
  SANITIZE_ADDRESS=0      Force AddressSanitizer off (coverage / valgrind also force this).
  SANITIZE_UNDEFINED=0      Force UndefinedBehaviorSanitizer off (coverage / valgrind also force this).
  SANITIZE_THREAD=0         Force ThreadSanitizer off (default).
  NERO_TESTS_BUILD_TYPE     Override CMAKE_BUILD_TYPE (e.g. Release for ``make test``).
  NERO_ENABLE_EXTENDED_SANITIZERS=OFF   CMake: skip extra -fsanitize=* probes (default ON in CMake).
  PERF_RECORD=1           After tests, run `perf record -g` on the binary (Linux perf_events).
                          Non-fatal if perf is missing or lacks permission (try: sysctl kernel.perf_event_paranoid).
  NERO_USE_SYSTEM_GTEST=1 Pass -DNERO_USE_SYSTEM_GTEST=ON (requires distro libgtest-dev / gtest-devel).

On Linux, this script runs make/install-linux-deps.sh only when
AUTO_INSTALL_LINUX_DEPS=1 (or INSTALL_DEPS=1). Makefile targets default to
INSTALL_DEPS=0; use `make deps` or `INSTALL_DEPS=1 make test` on a fresh host.

Typical workflows:
  bash make/run-unit-tests.sh
  COVERAGE=1 bash make/run-unit-tests.sh
  bash make/scan-build-tests.sh                # Clang analyzer

This script targets cmake 3.20+, Ninja or Make, and a C++23 toolchain.
Direct invocation defaults to Debug with ASan+UBSan. ``make test`` uses Release without
sanitizers; explicit sanitizer overrides use CMAKE_BUILD_TYPE=RelWithDebInfo; coverage
uses Debug with sanitizers forced off.
Default ASAN_OPTIONS / LSAN_OPTIONS / UBSAN_OPTIONS favor strict abort-on-error behavior; override by exporting them before running.
EOF
}

nero_check_line_coverage_threshold() {
  [[ -n "${COVERAGE_MIN_LINES:-}" ]] || return 0
  if ! [[ "${COVERAGE_MIN_LINES}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    printf 'error: COVERAGE_MIN_LINES must be a numeric percentage, got: %s\n' "${COVERAGE_MIN_LINES}" >&2
    exit 2
  fi

  local actual
  actual="$(
    LC_ALL=C lcov --summary "${lcov_info}" 2>/dev/null |
      awk -F'[:%]' '/lines\.*:/ { gsub(/[[:space:]]/, "", $2); print $2; exit }'
  )"
  if [[ -z "${actual}" ]]; then
    printf 'error: unable to read line coverage from %s\n' "${lcov_info}" >&2
    exit 1
  fi

  printf 'Coverage lines: %s%% (minimum %s%%)\n' "${actual}" "${COVERAGE_MIN_LINES}"
  if ! awk -v actual="${actual}" -v minimum="${COVERAGE_MIN_LINES}" \
    'BEGIN { exit((actual + 0.0) >= (minimum + 0.0) ? 0 : 1) }'; then
    printf 'error: line coverage %s%% is below required %s%%\n' "${actual}" "${COVERAGE_MIN_LINES}" >&2
    exit 1
  fi
}

run_logged_or_fail() {
  local log_file="$1"
  shift
  if "$@" >"${log_file}" 2>&1; then
    return 0
  fi
  cat "${log_file}" >&2
  exit 1
}

nero_wipe_gcda_profiles() {
  # Stale .gcda from a prior coverage/sanitizer profile survives --clean-first and
  # triggers libgcov "different checksum" noise (or bad data) on the next ctest run.
  find "${build_dir}" -name '*.gcda' -delete 2>/dev/null || true
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

generator="Unix Makefiles"
if command -v ninja >/dev/null 2>&1; then
  generator="Ninja"
fi

cmake_args=(
  -S "${repo_root}/tests"
  -B "${build_dir}"
  -DCMAKE_BUILD_TYPE="${build_type}"
  -G "${generator}"
)

if [[ "${COVERAGE:-0}" == "1" ]]; then
  cmake_args+=(-DNERO_ENABLE_COVERAGE=ON)
else
  cmake_args+=(-DNERO_ENABLE_COVERAGE=OFF)
fi

if [[ "${NERO_USE_SYSTEM_GTEST:-0}" == "1" ]]; then
  cmake_args+=(-DNERO_USE_SYSTEM_GTEST=ON)
else
  cmake_args+=(-DNERO_USE_SYSTEM_GTEST=OFF)
fi

if [[ "${SANITIZE_ADDRESS:-0}" == "1" ]]; then
  cmake_args+=(-DNERO_ENABLE_SANITIZER_ADDRESS=ON)
else
  cmake_args+=(-DNERO_ENABLE_SANITIZER_ADDRESS=OFF)
fi
if [[ "${SANITIZE_UNDEFINED:-0}" == "1" ]]; then
  cmake_args+=(-DNERO_ENABLE_SANITIZER_UNDEFINED=ON)
else
  cmake_args+=(-DNERO_ENABLE_SANITIZER_UNDEFINED=OFF)
fi
if [[ "${SANITIZE_THREAD:-0}" == "1" ]]; then
  cmake_args+=(-DNERO_ENABLE_SANITIZER_THREAD=ON)
else
  cmake_args+=(-DNERO_ENABLE_SANITIZER_THREAD=OFF)
fi
if [[ "${NERO_ENABLE_EXTENDED_SANITIZERS:-1}" == "0" ]]; then
  cmake_args+=(-DNERO_ENABLE_EXTENDED_SANITIZERS=OFF)
fi
if [[ "${NERO_TESTS_ENABLE_PCSC:-0}" == "1" ]]; then
  cmake_args+=(-DNERO_TESTS_ENABLE_PCSC=ON)
else
  cmake_args+=(-DNERO_TESTS_ENABLE_PCSC=OFF)
fi
if [[ "${debug_sanitizers_default}" == "1" ]]; then
  cmake_args+=(-DNERO_TESTS_DEBUG_SANITIZERS=ON)
else
  cmake_args+=(-DNERO_TESTS_DEBUG_SANITIZERS=OFF)
fi

invoke_linux_unit_test_install() {
  if [[ "$(uname -s)" != "Linux" ]]; then
    return 0
  fi
  : "${AUTO_INSTALL_LINUX_DEPS:=${INSTALL_DEPS:-0}}"
  if [[ "${AUTO_INSTALL_LINUX_DEPS}" == "0" ]]; then
    return 0
  fi
  FIRMWARE_ROOT="${repo_root}" \
    INSTALL_DEPS="${INSTALL_DEPS:-1}" \
    AUTO_INSTALL_LINUX_DEPS="${AUTO_INSTALL_LINUX_DEPS}" \
    bash "${repo_root}/make/install-linux-deps.sh"
}

invoke_linux_unit_test_install
nero_resolve_tests_enable_pcsc

mkdir -p "${build_dir}"
if command -v flock >/dev/null 2>&1; then
  exec 9>"${build_lock_file}"
  flock 9
fi

# lcov 1.x (--ignore-errors gcov|source|graph only); 2.x adds mismatch/unused used for newer gcc/gcov.
nero_lcov_modern_ignore_flags() {
  local v
  v="$(lcov --version 2>/dev/null | head -n1 | sed -n 's/.*version \([0-9][0-9]*\.[0-9][0-9.]*\).*/\1/p' | head -n1)"
  [[ -n "${v}" ]] || return 1
  [[ "$(printf '%s\n2.0\n' "${v}" | sort -V | tail -n1)" == "${v}" ]]
}

if ! command -v cmake >/dev/null 2>&1; then
  printf 'error: cmake not found on PATH (install via: make deps or INSTALL_DEPS=1 make test)\n' >&2
  exit 1
fi

previous_profile=""
if [[ -f "${profile_file}" ]]; then
  IFS= read -r previous_profile <"${profile_file}" || previous_profile=""
fi
current_profile="$(nero_unit_test_profile)"
need_clean=""
if [[ -n "${previous_profile}" && "${previous_profile}" != "${current_profile}" ]]; then
  printf '── unit tests: CMake profile changed (%s -> %s); forcing clean rebuild ──\n' \
    "${previous_profile}" "${current_profile}" >&2
  need_clean=1
fi

want_cache_on() {
  [[ "${1:-0}" == "1" ]] && printf 'ON' || printf 'OFF'
}

if [[ -f "${build_dir}/CMakeCache.txt" ]]; then
  read_cmake_cache_bool() {
    awk -F= -v k="$1" '$1 == k { print $2; exit }' "${build_dir}/CMakeCache.txt"
  }
  c_cov="$(read_cmake_cache_bool NERO_ENABLE_COVERAGE:BOOL)"
  c_sa="$(read_cmake_cache_bool NERO_ENABLE_SANITIZER_ADDRESS:BOOL)"
  c_su="$(read_cmake_cache_bool NERO_ENABLE_SANITIZER_UNDEFINED:BOOL)"
  c_st="$(read_cmake_cache_bool NERO_ENABLE_SANITIZER_THREAD:BOOL)"
  c_gt="$(read_cmake_cache_bool NERO_USE_SYSTEM_GTEST:BOOL)"
  c_dbg="$(read_cmake_cache_bool NERO_TESTS_DEBUG_SANITIZERS:BOOL)"
  w_cov="$(want_cache_on "${COVERAGE:-0}")"
  w_sa="$(want_cache_on "${SANITIZE_ADDRESS:-0}")"
  w_su="$(want_cache_on "${SANITIZE_UNDEFINED:-0}")"
  w_st="$(want_cache_on "${SANITIZE_THREAD:-0}")"
  w_gt="$(want_cache_on "${NERO_USE_SYSTEM_GTEST:-0}")"
  w_dbg="$(want_cache_on "${debug_sanitizers_default}")"
  if [[ -n "${c_cov}" && "${c_cov}" != "${w_cov}" ]] ||
    [[ -n "${c_sa}" && "${c_sa}" != "${w_sa}" ]] ||
    [[ -n "${c_su}" && "${c_su}" != "${w_su}" ]] ||
    [[ -n "${c_st}" && "${c_st}" != "${w_st}" ]] ||
    [[ -n "${c_gt}" && "${c_gt}" != "${w_gt}" ]] ||
    [[ -n "${c_dbg}" && "${c_dbg}" != "${w_dbg}" ]]; then
    printf '── unit tests: CMakeCache out of sync with this run; forcing clean rebuild ──\n' >&2
    need_clean=1
  fi
fi

cmake "${cmake_args[@]}"
if [[ "${COVERAGE:-0}" == "1" ]]; then
  nero_wipe_gcda_profiles
fi
if [[ -n "${need_clean}" ]]; then
  env -u MAKEFLAGS cmake --build "${build_dir}" --clean-first -j "$(bash "${script_dir}/cpu-jobs.sh")"
else
  env -u MAKEFLAGS cmake --build "${build_dir}" -j "$(bash "${script_dir}/cpu-jobs.sh")"
fi
printf '%s' "${current_profile}" >"${profile_file}"

if [[ "${SANITIZE_ADDRESS:-0}" == "1" || "${SANITIZE_UNDEFINED:-0}" == "1" || "${SANITIZE_THREAD:-0}" == "1" ]]; then
  if [[ "${SANITIZE_ADDRESS:-0}" == "1" ]]; then
    export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_odr_violation=2:detect_stack_use_after_return=1:strict_string_checks=1:verify_asan_link_order=1:abort_on_error=1:halt_on_error=1:strict_init_order=1:detect_invalid_pointer_pairs=1}"
    export LSAN_OPTIONS="${LSAN_OPTIONS:-report_objects=1:abort_on_error=1}"
  fi
  if [[ "${SANITIZE_UNDEFINED:-0}" == "1" ]]; then
    export UBSAN_OPTIONS="${UBSAN_OPTIONS:-print_stacktrace=1:abort_on_error=1:halt_on_error=1}"
  fi
  if [[ "${SANITIZE_THREAD:-0}" == "1" ]]; then
    export TSAN_OPTIONS="${TSAN_OPTIONS:-halt_on_error=1:abort_on_error=1}"
  fi
fi

if [[ "${SKIP_CTEST:-0}" != "1" ]]; then
  if [[ "${COVERAGE:-0}" == "1" ]]; then
    nero_wipe_gcda_profiles
  fi
  ctest --test-dir "${build_dir}" --output-on-failure
else
  printf 'skip: ctest (SKIP_CTEST=1)\n' >&2
  exit 0
fi

if [[ "${COVERAGE:-0}" == "1" ]]; then
  if command -v lcov >/dev/null 2>&1 && command -v genhtml >/dev/null 2>&1; then
    rm -rf "${coverage_dir}"
    coverage_capture_log="${build_dir}/coverage-capture.log"
    coverage_remove_log="${build_dir}/coverage-remove.log"
    coverage_html_log="${build_dir}/coverage-html.log"
    # gcov writes .gcda as execute-only on some hosts; lcov cannot read them without u+r.
    find "${build_dir}" -name '*.gcda' -exec chmod u+r {} + 2>/dev/null || true
    LCOV_MODERN=()
    if nero_lcov_modern_ignore_flags; then
      LCOV_MODERN=(--ignore-errors mismatch)
    fi
    run_logged_or_fail "${coverage_capture_log}" \
      lcov --capture --directory "${build_dir}" --output-file "${lcov_info}.raw" \
      "${LCOV_MODERN[@]}" \
      --rc geninfo_unexecuted_blocks=1
    LCOV_REMOVE_EXTRA=()
    if nero_lcov_modern_ignore_flags; then
      LCOV_REMOVE_EXTRA=(--ignore-errors unused --ignore-errors mismatch)
    fi
    run_logged_or_fail "${coverage_remove_log}" \
      lcov --remove "${lcov_info}.raw" \
      '/usr/*' \
      '*/_deps/*' \
      '*/tests/*' \
      '*/userspace/app/nero_nfc_pcsc.cpp' \
      "${LCOV_REMOVE_EXTRA[@]}" \
      --output-file "${lcov_info}"
    nero_check_line_coverage_threshold
    run_logged_or_fail "${coverage_html_log}" \
      genhtml --quiet "${lcov_info}" --output-directory "${coverage_dir}"
    printf '\n── Line coverage summary (firmware/userspace focus; tests excluded) ──\n'
    lcov --summary "${lcov_info}" 2>/dev/null || true
    printf '\n── Line coverage report ──\n'
    printf '  HTML: %s/index.html\n' "${coverage_dir}"
    printf '  lcov: %s\n' "${lcov_info}"
  else
    printf 'skip: lcov/genhtml missing (install distro lcov package for HTML coverage)\n' >&2
    if [[ "${COVERAGE_STRICT:-0}" == "1" || -n "${COVERAGE_MIN_LINES:-}" ]]; then
      exit 1
    fi
  fi
fi

if [[ "${VALGRIND:-0}" == "1" ]]; then
  if ! command -v valgrind >/dev/null 2>&1; then
    printf 'error: VALGRIND=1 but valgrind not found\n' >&2
    exit 1
  fi
  for _test_bin in \
    "${build_dir}/firmware/nero_firmware_tests" \
    "${build_dir}/userspace/nero_userspace_tests"; do
    [[ -x "$_test_bin" ]] || continue
    _bin_name="$(basename "$_test_bin")"
    _valgrind_log="${build_dir}/${_bin_name}.valgrind.log"
    if valgrind --quiet --error-exitcode=1 --leak-check=full --track-origins=yes \
      "$_test_bin" >"${_valgrind_log}" 2>&1; then
      printf 'valgrind: %s OK\n' "${_bin_name}"
    else
      cat "${_valgrind_log}" >&2
      exit 1
    fi
  done
fi

if [[ "${PERF_RECORD:-0}" == "1" ]]; then
  if command -v perf >/dev/null 2>&1; then
    for _test_bin in \
      "${build_dir}/firmware/nero_firmware_tests" \
      "${build_dir}/userspace/nero_userspace_tests"; do
      [[ -x "$_test_bin" ]] || continue
      _bin_name="$(basename "$_test_bin")"
      perf_data="${build_dir}/${_bin_name}.perf.data"
      rm -f "${perf_data}"
      if perf record -g -o "${perf_data}" -- "$_test_bin" >/dev/null 2>&1; then
        perf report -i "${perf_data}" --stdio | head -n 80 || true
        printf 'perf.data written to %s (use: perf report -i \"%s\")\n' "${perf_data}" "${perf_data}"
      else
        printf 'skip: perf record failed for %s (permissions? try sysctl kernel.perf_event_paranoid=1 or run as root)\n' "$_bin_name" >&2
      fi
    done
  else
    printf 'skip: perf not installed (e.g. linux-tools package on Debian/Ubuntu)\n' >&2
  fi
fi
