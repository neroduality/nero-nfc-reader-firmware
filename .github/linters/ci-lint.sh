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

# Lint driver for the nero-nfc-st25r firmware repo.
#
# Checks (in order):
#   1. Apply license headers — SPDX / Apache-2.0 (--fail-on-change)
#   2. Sort and format YAML — spec-traceability.yaml (yamllint; --fail-on-change)
#   3. Fix and check Markdown — markdownlint (--fix then check)
#   4. Ban raw memory and heap — outside central helper functions
#   5. Ban unsafe libc and terminal I/O — outside central helper functions
#   6. Require NERO_NFC_NULL and NERO_NFC_NODISCARD
#   7. Ban relative #includes
#   8. Remove duplicate #includes
#   9. Ban duplicate spec constant definitions
#  10. Format in place — clang-format -i, shfmt -w (no section banner; optional)
#  11. Fix misspellings — codespell (Markdown/docs)
#  12. Require named constants and bounds
#  13. Enforce Google C++ naming conventions
#  14. Require shared tag metadata parsers
#  15. Require early-return guard clauses
#  16. Require safe external buffer indexing
#  17. Require RAII for C/C++ resource pairs
#  18. Generate compile databases — CMake configure only (no build, no ctest)
#  19. Verify spec traceability manifest
#  20. Bootstrap third-party lint tools — arduino-cli + NFC-RFAL/ST25R3916
#  21. Run cppcheck on firmware
#  22. Run cppcheck on userspace
#  23. Run clang-tidy — compile-DB TUs (firmware + userspace overlay)
#  24. Compile Arduino sketches — UNO R4 WiFi + Nucleo-WBA65RI (CCID + CDC)
#  25. Check clang-format drift — --dry-run --Werror
#  26. Run shellcheck on bash scripts
#
# Coverage gap: Arduino .ino and most firmware reader/writer TUs without host test linkage
# rely on directory cppcheck and compile-DB clang-tidy instead.
#
# Parallelism: all host CPUs drive arduino-cli, cppcheck, CMake configure, and clang-tidy.
#
# scan-build runs as part of `make verify`, not here, to keep the two
# complementary: lint catches static issues, tests catch runtime bugs.
# CodeQL runs via `.github/workflows/codeql.yml` only (not `make lint` / `make verify`).
#
# Distro packages for lint are installed via `make deps` / INSTALL_DEPS=1 (default: skip).
# In CI (CI=true, set automatically on GitHub Actions), optional tools must be present.
# Locally, missing optional tools are skipped unless you pass --strict-tools.
#
# Usage:
#   bash .github/linters/ci-lint.sh [--strict-tools]
#   make lint
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
usage() {
  cat <<'EOF'
Usage: .github/linters/ci-lint.sh [OPTIONS]

Run all lint and static-analysis checks for this firmware repo.

Options:
  --custom-lints-only
                   Run custom Python/shell linters only; stop before compile DB /
                   cppcheck / clang-tidy / Arduino compile (not used in CI)
  --strict-tools   Fail if any recommended lint tool is missing (CI=true does this automatically)
  -h, --help       Show this help and exit

Environment:
  NERO_KEEP_HOST_BUILDS=1  Skip wiping host CMake trees for make test/lint/verify (not CI; CI always wipes)

Required tools:
  python3, make (arduino-cli is bootstrapped under third-party/arduino-cli/)

Optional tools (skipped locally when missing; required when CI=true or --strict-tools):
EOF
}

strict_tools=0
custom_lints_only=0
if [[ ${CI:-} == "true" ]]; then
  strict_tools=1
fi
while (($# > 0)); do
  case "$1" in
    --custom-lints-only) custom_lints_only=1 ;;
    --strict-tools) strict_tools=1 ;;
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
  shift
done

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
linter_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$linter_dir/../.." && pwd)"
cd "$repo_root"
# shellcheck source=../.github/scripts/helper-host-toolchain.sh
source "${repo_root}/.github/scripts/helper-host-toolchain.sh"
nero_nfc_host_toolchain_activate
nero_nfc_host_toolchain_verify
cppcheck_nero_library="${linter_dir}/cppcheck-nero-forbidden.cfg"
clang_tidy_firmware_base_config="${linter_dir}/.clang-tidy-firmware-base"
clang_tidy_userspace_config="${linter_dir}/.clang-tidy-userspace"
clang_tidy_firmware_bounds_config="${linter_dir}/.clang-tidy-firmware-bounds"

# shellcheck source=helper-markdownlint.sh
source "$linter_dir/helper-markdownlint.sh"
# shellcheck source=helper-cppcheck.sh
source "$linter_dir/helper-cppcheck.sh"
# shellcheck source=helper-clang-tidy.sh
source "$linter_dir/helper-clang-tidy.sh"

scripts_dir="$repo_root/.github/scripts"
userspace_scripts="$repo_root/userspace/scripts"
clang_format_config="$linter_dir/.clang-format"
markdownlint_config="$linter_dir/.markdownlint.json"
clang_format_style="file:$clang_format_config"
clang_tidy_bin=""
run_clang_tidy_bin=""
clang_format_bin=""

shopt -s nullglob

# ---------------------------------------------------------------------------
# NFC frontend validation
# ---------------------------------------------------------------------------
nfc_frontend="${NFC_FRONTEND:-st25r3916}"
_nfc_allow="$repo_root/make/nfc-frontends.mk"
_nfc_allow_line=$(grep -E '^VALID_NFC_FRONTENDS[[:space:]]*:=' "$_nfc_allow" | head -n1 || true)
_nfc_allow_list=$(echo "${_nfc_allow_line#*:=}" | sed 's/#.*//' | xargs)
IFS=' ' read -r -a _nfc_allowed <<<"${_nfc_allow_list}"
_nfc_ok=0
for _tok in "${_nfc_allowed[@]}"; do
  [[ $_tok == "$nfc_frontend" ]] && _nfc_ok=1
done
if ((_nfc_ok == 0)); then
  printf 'error: NFC_FRONTEND=%s not in VALID_NFC_FRONTENDS (%s)\n' \
    "$nfc_frontend" "${_nfc_allowed[*]-?}" >&2
  printf '    See %s\n' "$_nfc_allow" >&2
  exit 1
fi
if [[ $nfc_frontend != "st25r3916" ]]; then
  printf 'error: ci-lint.sh vendor include wiring not implemented for NFC_FRONTEND=%s\n' "$nfc_frontend" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Include paths (mirrors Makefile)
# ---------------------------------------------------------------------------
nfc_core_common_inc="$repo_root/firmware/nfc_core/common"
nfc_core_arduino_inc="$repo_root/firmware/nfc_core/arduino"
nfc_core_frontend_inc="$repo_root/firmware/nfc_core/frontends/$nfc_frontend"
port_inc="$repo_root/firmware/port/include"
board_port="${BOARD_PORT:-arduino_spi_serial}"
port_hal_dir="$repo_root/firmware/port/${board_port}"
vendor_st25_inc="$repo_root/third-party/ST25R3916/src"
vendor_rfal_inc="$repo_root/third-party/NFC-RFAL/src"

board_hal_cppflags="-DNFC_BOARD_READER_HAL_INC=reader_hal_board.cpp \
-DNFC_BOARD_WRITER_HAL_INC=writer_hal_board.cpp \
-DNFC_BOARD_NFC_HAL_INC=nfc_hal_board.cpp"

# Match Makefile COMMON/C/CPP -W flags; --warnings all. Lint fails only on diagnostics in
# repo-owned paths (firmware/, userspace/, …). Anything under third-party/ is ignored —
# including Board Manager cores under third-party/arduino-user/packages/… .
arduino_vendor_st25_rfal_inc="-I${vendor_st25_inc} -I${vendor_rfal_inc}"

arduino_c_std="gnu11"
arduino_cpp_std="gnu++17"
arduino_common_hardening="-D_FORTIFY_SOURCE=2 -fstack-protector-strong -fno-delete-null-pointer-checks -fno-strict-overflow"
arduino_common_warnings="-Wformat=2 -Wformat-security -Wformat-overflow=2 -Wformat-truncation=2 -Wnull-dereference -Warray-bounds=2 -Wstringop-overflow=4 -Wvla -Walloca -Wstack-protector -Wshadow -Wcast-qual -Wundef -Wdouble-promotion -Wshift-overflow=2 -Wswitch-enum -Wunused-result -Wno-error"
arduino_c_warnings="${arduino_common_warnings} -Wstrict-overflow=2 -Wstrict-prototypes -Wwrite-strings"
arduino_cpp_warnings="${arduino_common_warnings} -Wstrict-overflow=2 -Wwrite-strings"
arduino_c_security="${arduino_common_hardening} ${arduino_c_warnings}"
arduino_cpp_security="${arduino_common_hardening} ${arduino_cpp_warnings}"

arduino_inc_rw_common="-DNFC_FRONTEND_ID_ST25R3916=1 \
-I${nfc_core_common_inc} -I${nfc_core_arduino_inc} -I${nfc_core_frontend_inc} \
-I${port_inc} -I${port_hal_dir} \
${board_hal_cppflags}"

nfc_lint_sketch_dir="firmware/nfc"
# Keep in sync with Makefile NFC_CDC_SERIAL_LINE_CAP.
nfc_cdc_serial_line_cap=1776

fqbn_uno_r4="arduino:renesas_uno:unor4wifi"
arduino_inc_rw_uno="${arduino_inc_rw_common}"
arduino_inc_nfc_uno="${arduino_inc_rw_uno} -I${repo_root}/firmware/reader/src -I${repo_root}/firmware/writer/src"
arduino_build_extra_nfc_uno_ccid="-DNERO_CCID_USB_BUILD=1 -DNERO_CCID_ONLY_BUILD=1 -UNO_USB -UBACKTRACE_SUPPORT"
arduino_build_extra_nfc_uno_cdc="-UNO_USB -UBACKTRACE_SUPPORT -DNERO_RAM_CONSTRAINED=1 -DSERIAL_RX_BUFFER_SIZE=${nfc_cdc_serial_line_cap}"

# Nucleo-WBA65RI (STM32WBA65): same -W as UNO; omit FORTIFY/stack-protector (stm32duino newlib lacks ssp.h).
fqbn_wba65='STMicroelectronics:stm32:Nucleo_64:pnum=NUCLEO_WBA65RI,upload_method=OpenOCDSTLink'
wba65_nfc_pins="-DNFC_BOARD_IRQ_PIN=16u"
# Keep in sync with make/board-nucleo_wba65ri.mk BOARD_CCID_INCLUDES.
wba65_ccid_includes="-I${repo_root}/third-party/tinyusb/src -I${repo_root}/firmware/port/stm32_wba65_ccid"
arduino_inc_rw_wba65="${arduino_inc_rw_common} ${wba65_nfc_pins}"
arduino_inc_nfc_wba65="${arduino_inc_rw_wba65} ${wba65_ccid_includes} -I${repo_root}/firmware/reader/src -I${repo_root}/firmware/writer/src"
arduino_build_extra_nfc_wba65_ccid="-DNERO_CCID_USB_BUILD=1 -DNERO_CCID_ONLY_BUILD=1 -DNERO_CCID_STM32_USB_BUILD=1 -DCFG_TUSB_MCU=OPT_MCU_STM32WBA -DSTM32WBA65xx -DUSBD_VID=0x2341 -DUSBD_PID=0x006E -DNERO_CCID_BULK_EPSIZE=512u ${wba65_nfc_pins}"
arduino_build_extra_nfc_wba65_cdc="${wba65_nfc_pins} -DNFC_HAL_RXBUF_CAP=${nfc_cdc_serial_line_cap}u -DSERIAL_RX_BUFFER_SIZE=${nfc_cdc_serial_line_cap}"

setup_arduino_lint_compile_flags() {
  local isystem_uno isystem_wba65
  isystem_uno="$(bash "${repo_root}/make/arduino-third-party-isystem.sh" "${repo_root}" uno | tr '\n' ' ')"
  isystem_wba65="$(bash "${repo_root}/make/arduino-third-party-isystem.sh" "${repo_root}" wba65 | tr '\n' ' ')"
  arduino_c_extra_nfc_uno="-std=${arduino_c_std} ${arduino_c_security} ${isystem_uno} ${arduino_vendor_st25_rfal_inc} ${arduino_inc_nfc_uno}"
  arduino_cpp_extra_nfc_uno="-std=${arduino_cpp_std} ${arduino_cpp_security} ${isystem_uno} ${arduino_vendor_st25_rfal_inc} ${arduino_inc_nfc_uno}"
  arduino_c_extra_nfc_wba65="-std=${arduino_c_std} ${arduino_c_warnings} ${isystem_wba65} ${arduino_inc_nfc_wba65}"
  arduino_cpp_extra_nfc_wba65="-std=${arduino_cpp_std} ${arduino_cpp_warnings} ${isystem_wba65} ${arduino_inc_nfc_wba65}"
}

# ---------------------------------------------------------------------------
# File lists
# ---------------------------------------------------------------------------
source_dirs=(
  "firmware/writer/src"
  "firmware/reader/src"
  "firmware/nfc/src"
)

mapfile -t md_files < <(nero_nfc_markdownlint_collect_targets "$repo_root")

format_files=(
  "firmware/writer/writer.ino"
  "firmware/reader/reader.ino"
  "firmware/nfc/nfc.ino"
)
for file in \
  "$repo_root/firmware/nfc_core/common/"*.{c,h,cpp} \
  "$repo_root/firmware/nfc_core/frontends/"*/*.{c,h,cpp}; do
  [[ -e $file ]] && format_files+=("${file#"$repo_root"/}")
done
for dir in "${source_dirs[@]}"; do
  for file in "$dir"/*.{c,cpp,h,hpp}; do
    [[ -e $file ]] && format_files+=("$file")
  done
done
for dir in \
  "$repo_root/firmware/port/include" \
  "$repo_root/firmware/port/${board_port}" \
  "$repo_root/userspace/app" \
  "$repo_root/userspace/cli"; do
  for file in "$dir"/*.{c,h,cpp}; do
    [[ -e $file ]] && format_files+=("${file#"$repo_root"/}")
  done
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
have_tool() { command -v "$1" >/dev/null 2>&1; }

require_tool() {
  if ! have_tool "$1"; then
    printf 'error: required tool not found: %s\n' "$1" >&2
    exit 1
  fi
}

want_tool() {
  local tool="$1" purpose="$2"
  if have_tool "$tool"; then return 0; fi
  if [[ $strict_tools -eq 1 ]]; then
    printf 'error: recommended tool not found in --strict-tools mode: %s (%s)\n' "$tool" "$purpose" >&2
    exit 1
  fi
  printf 'skip: %s not installed (%s)\n' "$tool" "$purpose"
  return 1
}

want_markdownlint() {
  local purpose="$1"
  if nero_nfc_ensure_markdownlint; then
    return 0
  fi
  if [[ $strict_tools -eq 1 ]]; then
    printf 'error: recommended tool not found in --strict-tools mode: markdownlint (%s)\n' "$purpose" >&2
    nero_nfc_markdownlint_hint
    exit 1
  fi
  printf 'skip: markdownlint not installed (%s)\n' "$purpose"
  return 1
}

want_pyyaml() {
  local purpose="$1"
  if python3 -c "import yaml" >/dev/null 2>&1; then
    return 0
  fi
  if [[ $strict_tools -eq 1 ]]; then
    printf 'error: PyYAML not found (%s)\n' "$purpose" >&2
    exit 1
  fi
  printf 'skip: PyYAML not installed (%s)\n' "$purpose"
  return 1
}

want_cppcheck() {
  local purpose="$1"
  if nero_nfc_ensure_cppcheck; then
    return 0
  fi
  if [[ $strict_tools -eq 1 ]]; then
    if have_tool cppcheck; then
      printf 'error: cppcheck >= %s required in --strict-tools mode (%s); found %s\n' \
        "$NERO_NFC_CPPCHECK_MIN_VERSION" "$purpose" \
        "$(nero_nfc_cppcheck_version_raw 2>/dev/null || echo unknown)" >&2
    else
      printf 'error: recommended tool not found in --strict-tools mode: cppcheck (%s)\n' "$purpose" >&2
    fi
    nero_nfc_cppcheck_hint
    exit 1
  fi
  printf 'skip: cppcheck not installed or too old (%s; need >= %s)\n' \
    "$purpose" "$NERO_NFC_CPPCHECK_MIN_VERSION"
  return 1
}

want_clang_tidy() {
  local purpose="$1"
  if clang_tidy_bin="$(nero_nfc_find_clang_tidy)"; then
    run_clang_tidy_bin="$(nero_nfc_find_run_clang_tidy "$clang_tidy_bin" || true)"
    nero_nfc_ensure_clang_tidy || true
    return 0
  fi
  if [[ $strict_tools -eq 1 ]]; then
    if have_tool clang-tidy; then
      printf 'error: clang-tidy >= %s required in --strict-tools mode (%s); found %s\n' \
        "$NERO_NFC_CLANG_TIDY_MIN_VERSION" "$purpose" \
        "$(nero_nfc_clang_tidy_version_raw 2>/dev/null || echo unknown)" >&2
    else
      printf 'error: recommended tool not found in --strict-tools mode: clang-tidy (%s)\n' "$purpose" >&2
    fi
    nero_nfc_clang_tidy_hint
    exit 1
  fi
  printf 'skip: clang-tidy not installed or too old (%s; need >= %s)\n' \
    "$purpose" "$NERO_NFC_CLANG_TIDY_MIN_VERSION"
  return 1
}

want_clang_format() {
  local purpose="$1"
  if clang_format_bin="$(nero_nfc_find_clang_format)"; then
    nero_nfc_ensure_clang_format || true
    return 0
  fi
  if [[ $strict_tools -eq 1 ]]; then
    if have_tool clang-format; then
      printf 'error: clang-format >= %s required in --strict-tools mode (%s); found %s\n' \
        "$NERO_NFC_CLANG_FORMAT_MIN_VERSION" "$purpose" \
        "$(nero_nfc_clang_format_version_raw 2>/dev/null || echo unknown)" >&2
    else
      printf 'error: recommended tool not found in --strict-tools mode: clang-format (%s)\n' "$purpose" >&2
    fi
    nero_nfc_clang_format_hint
    exit 1
  fi
  printf 'skip: clang-format not installed or too old (%s; need >= %s)\n' \
    "$purpose" "$NERO_NFC_CLANG_FORMAT_MIN_VERSION"
  return 1
}

run_markdownlint() {
  nero_nfc_run_markdownlint "$@"
}

_lint_section_n=0
section() {
  _lint_section_n=$((_lint_section_n + 1))
  printf '\n── %s. %s ──\n' "$_lint_section_n" "$1"
}

lint_jobs="$(bash "$repo_root/make/cpu-jobs.sh")"
arduino_lint_jobs="${lint_jobs}"
if [[ ${NERO_CI_LOCAL_IN_VM:-0} == 1 && ${arduino_lint_jobs} -gt 4 ]]; then
  arduino_lint_jobs=4
fi

setup_arduino_vm_paths() {
  [[ ${NERO_CI_LOCAL_IN_VM:-0} == 1 ]] || return 0
  export ARDUINO_USER_DIR="/tmp/nero-arduino-user"
  export ARDUINO_DIRECTORIES_DATA="${ARDUINO_USER_DIR}"
  export ARDUINO_DIRECTORIES_USER="${ARDUINO_USER_DIR}"
  export ARDUINO_BUILD_CACHE_PATH="/tmp/nero-arduino-build-cache"
  mkdir -p "${ARDUINO_DIRECTORIES_DATA}" "${ARDUINO_BUILD_CACHE_PATH}"
}

arduino_host_tools_make() {
  local -a make_args=(-C "$repo_root")
  # Inherit the parent make jobserver when lint is invoked via `make lint`; otherwise cap -j locally.
  if [[ ${MAKEFLAGS} != *'--jobserver'* ]]; then
    make_args+=(-j "${arduino_lint_jobs}")
  fi
  if [[ ${NERO_CI_LOCAL_IN_VM:-0} == 1 ]]; then
    setup_arduino_vm_paths
    make_args+=(ARDUINO_USER_DIR="${ARDUINO_USER_DIR}")
  fi
  run make "${make_args[@]}" "$@"
}

bootstrap_third_party_for_lint() {
  section "Bootstrap third-party lint tools (arduino-cli, NFC libs)"
  setup_arduino_vm_paths
  if [[ "$(uname -s)" == "Linux" ]]; then
    arduino_host_tools_make third-party-host-tools third-party-nfc-libs
  fi
  ARDUINO_CLI="$(bash "$repo_root/make/resolve-arduino-cli.sh" "$repo_root")"
  arduino_cli_dir="$(dirname "$ARDUINO_CLI")"
  if [[ ${NERO_CI_LOCAL_IN_VM:-0} == 1 ]]; then
    setup_arduino_vm_paths
  else
    eval "$(bash "$repo_root/make/export-arduino-isolated-env.sh" "$repo_root")"
  fi
  export PATH="${arduino_cli_dir}:${PATH}"
}

run() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

run_python_policy_linter() {
  local script=$1 fix_hint=$2
  run python3 "$linter_dir/$script" --self-test || exit 1
  run python3 "$linter_dir/$script" --repo-root "$repo_root" || {
    printf 'Fix: %s\n' "$fix_hint" >&2
    exit 1
  }
}

# Run clang-tidy on one or more TUs. Prefer ``run-clang-tidy -j`` (parallel) when available.
verify_clang_tidy_overlay_config() {
  local cfg="$1" out
  out="$("$clang_tidy_bin" --verify-config -config-file="$cfg" 2>&1)" || true
  if grep -q 'No config errors detected' <<<"$out"; then
    return 0
  fi
  printf 'error: clang-tidy --verify-config failed for %s (need clang-tidy >= %s)\n' \
    "$cfg" "$NERO_NFC_CLANG_TIDY_MIN_VERSION" >&2
  printf '%s\n' "$out" >&2
  exit 1
}

run_clang_tidy_filtered() {
  local tmp ec=0 jobs compile_db_p="" config_file=""
  local -a files=()

  while (($# > 0)); do
    case "$1" in
      -p)
        compile_db_p="$2"
        shift 2
        ;;
      -config-file)
        config_file="$2"
        shift 2
        ;;
      *)
        files+=("$1")
        shift
        ;;
    esac
  done

  jobs="${lint_jobs}"
  tmp=$(mktemp)
  local -a tidy_args=(-quiet -j"$jobs" -p "$compile_db_p")
  if [[ -n $config_file ]]; then
    tidy_args+=(-config-file="$config_file")
  fi
  if [[ -n $run_clang_tidy_bin ]] && ((${#files[@]} > 0)); then
    printf '+ %q -quiet -j %s -p %q' "$run_clang_tidy_bin" "$jobs" "$compile_db_p"
    if [[ -n $config_file ]]; then
      printf ' -config-file=%q' "$config_file"
    fi
    for f in "${files[@]}"; do printf ' %q' "$f"; done
    printf '\n'
    set +e
    "$run_clang_tidy_bin" "${tidy_args[@]}" "${files[@]}" &>"$tmp"
    ec=$?
    set -e
  else
    printf '+ %q --quiet -p %q' "$clang_tidy_bin" "$compile_db_p"
    if [[ -n $config_file ]]; then
      printf ' -config-file=%q' "$config_file"
    fi
    for f in "${files[@]}"; do printf ' %q' "$f"; done
    printf '\n'
    set +e
    if [[ -n $config_file ]]; then
      "$clang_tidy_bin" --quiet -p "$compile_db_p" -config-file="$config_file" "${files[@]}" &>"$tmp"
    else
      "$clang_tidy_bin" --quiet -p "$compile_db_p" "${files[@]}" &>"$tmp"
    fi
    ec=$?
    set -e
  fi
  if ((ec != 0)); then
    grep -vE \
      -e '^[0-9]+ warnings( and [0-9]+ notes)? generated\.?$' \
      -e '^Suppressed [0-9]+ warnings' \
      -e '^Use -header-filter=' \
      -e '^Running clang-tidy for ' \
      -e '^\[[0-9]+/[0-9]+\] Processing file ' \
      -e '^\[ ?[0-9]+/[0-9]+\]\[[0-9.]+s\]' \
      -e '^[[:space:]]*$' \
      "$tmp" >&2 || true
  fi
  rm -f "$tmp"
  return "$ec"
}

# ---------------------------------------------------------------------------
# 1–3. Apply license headers, sort YAML, fix Markdown
# ---------------------------------------------------------------------------
section "Apply license headers (SPDX / Apache-2.0)"
require_tool python3
run python3 "$linter_dir/helper-license-headers.py" --self-test
run python3 "$linter_dir/helper-license-headers.py" --repo-root "$repo_root" --skip-dir-name patches --fail-on-change

section "Sort and format YAML (yamllint)"
if want_pyyaml "spec-traceability.yaml"; then
  run python3 "$linter_dir/helper-yamllint.py" --fail-on-change --repo-root "$repo_root"
fi

section "Fix and check Markdown (markdownlint)"
if want_markdownlint "Markdown"; then
  run nero_nfc_markdownlint_fail_on_change "$markdownlint_config" "${md_files[@]}"
fi

# ---------------------------------------------------------------------------
# 4–9. Ban unsafe APIs/includes; remove duplicate includes/definitions
# ---------------------------------------------------------------------------
section "Ban raw memory and heap (outside central helper functions)"
run_python_policy_linter helper-unsafe-memory.py \
  "use nero_nfc_copy_bytes / nero_nfc_zero_bytes; no heap or raw libc memory APIs."

section "Ban unsafe libc and terminal I/O (outside central helper functions)"
run_python_policy_linter helper-unsafe-api.py \
  "use bounded project helpers and nero_nfc_* output wrappers (see cppcheck-nero-forbidden.cfg / .clang-tidy)."

section "Require NERO_NFC_NULL and NERO_NFC_NODISCARD"
run_python_policy_linter helper-null-nodiscard.py \
  "use NERO_NFC_NODISCARD on fallible bool APIs and NERO_NFC_NULL for null checks."

section "Ban relative #includes"
run_python_policy_linter helper-relative-includes.py \
  "add the target directory to the include path and include by basename; do not use ../ in #include paths."

section "Remove duplicate #includes"
run_python_policy_linter helper-duplicate-includes.py \
  "remove repeated #include lines; keep one include per header per file; headers must start with #pragma once."

section "Ban duplicate spec constant definitions"
run_python_policy_linter helper-duplicate-definitions.py \
  "keep one authoritative definition per spec constant; include the canonical header instead of re-#defining it."

# ---------------------------------------------------------------------------
# 10. Format in place (clang-format, shfmt; no section banner)
# ---------------------------------------------------------------------------
if want_clang_format "C/C++ formatting"; then
  for file in "${format_files[@]}"; do
    case "$file" in
      *.ino) "$clang_format_bin" -i --style="$clang_format_style" --assume-filename="${file%.ino}.cpp" "$file" ;;
      *) "$clang_format_bin" -i --style="$clang_format_style" "$file" ;;
    esac
  done
fi
if want_tool shfmt "shell formatting"; then
  shfmt -w -i 2 -ci -s "$repo_root/packaging"/*.sh "$scripts_dir"/*.sh "$linter_dir"/*.sh "$userspace_scripts"/*.sh || true
fi

section "Fix misspellings (codespell)"
if want_tool codespell "common misspelling detection"; then
  run bash "$linter_dir/helper-codespell.sh"
fi

section "Require named constants and bounds"
run_python_policy_linter helper-bounds-constants.py \
  "replace bare numeric literals with named constants (0, 1, 0u, 1u allowed); shared caps in canonical headers or file-local #define/constexpr."

section "Enforce Google C++ naming conventions"
run_python_policy_linter helper-macro-enum-naming.py \
  "follow Google C++ Style: ALL_CAPS macros; kCamelCase in C++ TUs; ALL_CAPS shared C enum constants per project C-ABI policy."

section "Require shared tag metadata parsers"
run_python_policy_linter helper-tag-metadata-policy.py \
  "route Type 2/4/5 CC, version, system-info, and MLEN-overflow interpretation through shared tag metadata helpers."

section "Require early-return guard clauses"
run_python_policy_linter helper-early-return.py \
  "use guard clauses (early return false) instead of positive if/return-true wrappers."

section "Require safe external buffer indexing"
run_python_policy_linter helper-safe-indexing.py \
  "use nero_nfc_span_ok / nero_nfc_copy_bytes for external buffers; centralize wire parsing."

section "Require RAII for C/C++ resource pairs"
run_python_policy_linter helper-resource-lifetime.py \
  "use project RAII wrappers for acquire/release pairs in .c and .cpp (see RESOURCE_LIFETIME_PAIRS)."

# ---------------------------------------------------------------------------
# Verify spec traceability manifest (docs/spec-traceability.yaml)
# ---------------------------------------------------------------------------
section "Verify spec traceability manifest"
if want_pyyaml "spec traceability"; then
  run bash "$linter_dir/helper-spec-traceability.sh"
fi

if ((custom_lints_only == 1)); then
  exit 0
fi

# ---------------------------------------------------------------------------
# Shared cppcheck argv (firmware TU scan + userspace --project reuse)
# ---------------------------------------------------------------------------
cppcheck_common=(
  --quiet
  "--enable=warning,style,performance,portability"
  --inconclusive
  --inline-suppr
  --error-exitcode=1
  --suppress=missingIncludeSystem
  "--library=${cppcheck_nero_library}"
  # CMake FetchContent / sub-build trees (googletest, etc.)
  "--suppress=*:*_deps/*"
  "--suppress=*:*/_deps/*"
  # st25r3916_runtime.h polls a hardware timer via ops->millis(); cppcheck cannot
  # model that the timer advances between two calls and emits false positives.
  "--suppress=knownConditionTrueFalse:firmware/nfc_core/frontends/st25r3916/st25r3916_runtime.h"
  "--suppress=duplicateExpression:firmware/nfc_core/frontends/st25r3916/st25r3916_runtime.h"
  # poll_one_cycle() and CCID-only early returns depend on runtime NFC/HAL state.
  "--suppress=knownConditionTrueFalse:firmware/reader/src/reader_app.cpp"
  "--suppress=unreachableCode:firmware/reader/src/reader_app.cpp"
  # Weak CCID HAL stubs in nfc_app.cpp always report ready outside board USB builds.
  "--suppress=knownConditionTrueFalse:firmware/nfc/src/nfc_app.cpp"
  "--suppress=knownConditionTrueFalse:firmware/reader/src/reader_ccid.cpp"
  # userspace lint may configure without libpcsclite; list_pcsc_readers stub always returns false.
  "--suppress=knownConditionTrueFalse:userspace/app/nero_nfc_pcsc.cpp"
  "--suppress=constParameterReference:userspace/app/nero_nfc_pcsc.cpp"
)

# ---------------------------------------------------------------------------
# 18. Generate compile databases (configure only — no build, no ctest)
# ---------------------------------------------------------------------------
section "Generate compile databases (configure only)"
lint_tests_build_dir="${repo_root}/build/lint/tests"
lint_userspace_build_dir="${repo_root}/build/lint/userspace"
lint_cmake_generator="Unix Makefiles"
if command -v ninja >/dev/null 2>&1; then
  lint_cmake_generator="Ninja"
fi

if want_tool cmake "compile database generation"; then
  parallel_fail=0
  (
    run cmake -S "${repo_root}/tests" -B "${lint_tests_build_dir}" \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
      -G "${lint_cmake_generator}" \
      -DNERO_ENABLE_COVERAGE=OFF \
      -DNERO_ENABLE_SANITIZER_ADDRESS=OFF \
      -DNERO_ENABLE_SANITIZER_UNDEFINED=OFF \
      -DNERO_ENABLE_SANITIZER_THREAD=OFF \
      -DNERO_TESTS_DEBUG_SANITIZERS=OFF \
      -DNERO_USE_SYSTEM_GTEST=OFF \
      -DNERO_TESTS_ENABLE_PCSC=OFF
  ) &
  tests_cfg_pid=$!
  (
    run cmake -S "${repo_root}/userspace" -B "${lint_userspace_build_dir}" \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
      -G "${lint_cmake_generator}" \
      -DCMAKE_RUNTIME_OUTPUT_DIRECTORY="${repo_root}/build/lint/userspace/bin"
  ) &
  userspace_cfg_pid=$!
  if ! wait "$tests_cfg_pid"; then
    parallel_fail=1
  fi
  if ! wait "$userspace_cfg_pid"; then
    parallel_fail=1
  fi
  if ((parallel_fail != 0)); then
    exit 1
  fi
else
  printf 'note: cmake not installed; compile DB generation skipped (also skips userspace cppcheck --project and clang-tidy)\n' >&2
fi

# ---------------------------------------------------------------------------
# cppcheck — static analysis on firmware C/C++ sources (+ shared core + board HAL)
# ---------------------------------------------------------------------------
bootstrap_third_party_for_lint
section "Run cppcheck on firmware"
if want_cppcheck "static analysis"; then
  cppcheck_firmware_dirs=(
    "${source_dirs[@]}"
    "firmware/nfc_core/common"
    "firmware/port/${board_port}"
  )
  for dir in "${cppcheck_firmware_dirs[@]}"; do
    c_sources=("$dir"/*.c)
    cpp_sources=("$dir"/*.cpp)
    common_incs=(
      -I "$nfc_core_common_inc" -I "$nfc_core_arduino_inc" -I "$nfc_core_frontend_inc"
      -I "$dir" -I "$vendor_st25_inc" -I "$vendor_rfal_inc"
      -I "$port_inc" -I "$port_hal_dir"
      -I "$repo_root/firmware/reader/src" -I "$repo_root/firmware/writer/src"
    )
    ((${#c_sources[@]} > 0)) && run cppcheck -j"${lint_jobs}" "${cppcheck_common[@]}" --std=c11 --language=c "${common_incs[@]}" "${c_sources[@]}"
    ((${#cpp_sources[@]} > 0)) && run cppcheck -j"${lint_jobs}" "${cppcheck_common[@]}" --std=c++17 --language=c++ "${common_incs[@]}" "${cpp_sources[@]}"
  done
fi

# ---------------------------------------------------------------------------
# cppcheck — userspace via CMake compile_commands.json
# ---------------------------------------------------------------------------
section "Run cppcheck on userspace"
if want_cppcheck "userspace static analysis"; then
  userspace_compile_commands="${lint_userspace_build_dir}/compile_commands.json"
  if [[ -f $userspace_compile_commands ]]; then
    us_ignore=()
    [[ -d ${lint_userspace_build_dir}/_deps ]] && us_ignore+=(-i "${lint_userspace_build_dir}/_deps")
    run cppcheck -j"${lint_jobs}" "${cppcheck_common[@]}" "${us_ignore[@]}" --project="$userspace_compile_commands"
  else
    printf 'skip: userspace compile_commands missing (%s expected after lint configure)\n' "$userspace_compile_commands" >&2
  fi
fi

# ---------------------------------------------------------------------------
# clang-tidy — C++ static analysis against compile_commands.json
# ---------------------------------------------------------------------------
section "Run clang-tidy"
if want_clang_tidy "C++ static analysis"; then
  userspace_db="${lint_userspace_build_dir}/compile_commands.json"
  tests_db="${lint_tests_build_dir}/compile_commands.json"
  merged_dir="${repo_root}/build/clang-tidy-compile-db"
  merged_json="${merged_dir}/compile_commands.json"
  compile_commands_db=""
  if command -v python3 >/dev/null 2>&1; then
    if [[ -f $userspace_db || -f $tests_db ]]; then
      if python3 - "$userspace_db" "$tests_db" "$merged_json" <<'PY'; then
import json, os, re, subprocess, sys

userspace, tests, out = sys.argv[1], sys.argv[2], sys.argv[3]
by_file = {}
for path in (tests, userspace):
    if not os.path.isfile(path):
        continue
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    for entry in data:
        by_file[entry["file"]] = entry

_GCC_CXX_ISYSTEM = None


def gcc_cxx_isystem_flags():
    global _GCC_CXX_ISYSTEM
    if _GCC_CXX_ISYSTEM is not None:
        return _GCC_CXX_ISYSTEM
    flags = []
    try:
        proc = subprocess.run(
            ["g++", "-xc++", "-E", "-v", "-"],
            input=b"",
            capture_output=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        _GCC_CXX_ISYSTEM = []
        return _GCC_CXX_ISYSTEM
    capture = False
    for line in proc.stderr.decode(errors="replace").splitlines():
        if "#include <...> search starts here:" in line:
            capture = True
            continue
        if capture:
            if line.startswith("End of search list"):
                break
            path = line.strip()
            if path:
                flags.extend(["-isystem", path])
    _GCC_CXX_ISYSTEM = flags
    return _GCC_CXX_ISYSTEM


def uses_gxx_driver(entry):
    cmd = entry.get("command", "")
    if re.search(r'(^|[\s/])(g\+\+|c\+\+)([\s"]|$)', cmd):
        return True
    args = entry.get("arguments") or []
    return bool(args) and re.search(r"(g\+\+|c\+\+)$", args[0])


def append_gcc_cxx_isystem(entry):
    if not uses_gxx_driver(entry):
        return
    extra = gcc_cxx_isystem_flags()
    if not extra:
        return
    if "command" in entry:
        entry["command"] = entry["command"] + " " + " ".join(extra)
    args = entry.get("arguments")
    if args is not None:
        entry["arguments"] = list(args) + extra


def scrub_compile_commands(entries):
    """Drop sanitizer driver flags; add libstdc++ -isystem paths for clang-tidy."""
    for entry in entries:
        if "command" in entry:
            cmd = entry["command"]
            cmd = re.sub(r"\s+-fsanitize=\S+", "", cmd)
            cmd = re.sub(r"\s+-fno-sanitize-recover=\S+", "", cmd)
            entry["command"] = cmd
        args = entry.get("arguments")
        if args:
            out_args = []
            skip_next = False
            for a in args:
                if skip_next:
                    skip_next = False
                    continue
                if a == "-fsanitize" or a == "-fno-sanitize-recover":
                    skip_next = True
                    continue
                if a.startswith("-fsanitize=") or a.startswith("-fno-sanitize-recover="):
                    continue
                out_args.append(a)
            entry["arguments"] = out_args
        append_gcc_cxx_isystem(entry)


merged = list(by_file.values())
scrub_compile_commands(merged)
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w", encoding="utf-8") as f:
    json.dump(merged, f, indent=2)
PY
        if [[ -f $merged_json ]]; then
          compile_commands_db="$merged_dir"
        fi
      fi
    fi
  fi
  if [[ -z $compile_commands_db ]]; then
    for _db in "$userspace_db" "$tests_db"; do
      if [[ -f $_db ]]; then
        compile_commands_db="$(cd "$(dirname "$_db")" && pwd)"
        break
      fi
    done
  fi

  if [[ -z $compile_commands_db ]]; then
    printf 'skip: clang-tidy needs compile_commands.json; lint configure step may have been skipped\n' >&2
  else
    compile_commands_json="${compile_commands_db}/compile_commands.json"
    if [[ ! -f $compile_commands_json ]]; then
      printf 'skip: missing %s\n' "$compile_commands_json" >&2
    else
      if ! run python3 "$linter_dir/helper-clang-tidy-files.py" --self-test; then
        exit 1
      fi
      mapfile -t tidy_firmware_base < <(
        python3 "$linter_dir/helper-clang-tidy-files.py" --repo-root "$repo_root" \
          --compile-db "$compile_commands_json" firmware-base
      )
      mapfile -t tidy_firmware_bounds < <(
        python3 "$linter_dir/helper-clang-tidy-files.py" --repo-root "$repo_root" \
          --compile-db "$compile_commands_json" firmware-bounds
      )
      mapfile -t tidy_userspace < <(
        python3 "$linter_dir/helper-clang-tidy-files.py" --repo-root "$repo_root" \
          --compile-db "$compile_commands_json" userspace
      )

      verify_clang_tidy_overlay_config "$clang_tidy_firmware_base_config"
      verify_clang_tidy_overlay_config "$clang_tidy_firmware_bounds_config"
      verify_clang_tidy_overlay_config "$clang_tidy_userspace_config"

      if ((${#tidy_firmware_base[@]} > 0)); then
        run_clang_tidy_filtered -p "$compile_commands_db" \
          -config-file "$clang_tidy_firmware_base_config" "${tidy_firmware_base[@]}"
      fi
      if ((${#tidy_firmware_bounds[@]} > 0)); then
        run_clang_tidy_filtered -p "$compile_commands_db" \
          -config-file "$clang_tidy_firmware_bounds_config" "${tidy_firmware_bounds[@]}"
      fi
      if ((${#tidy_userspace[@]} > 0)); then
        run_clang_tidy_filtered -p "$compile_commands_db" -config-file "$clang_tidy_userspace_config" \
          "${tidy_userspace[@]}"
      fi
      if ((${#tidy_firmware_base[@]} == 0 && ${#tidy_firmware_bounds[@]} == 0 && ${#tidy_userspace[@]} == 0)); then
        printf 'skip: no tidy-eligible files found in compile database\n' >&2
      fi
    fi
  fi
fi

# ---------------------------------------------------------------------------
# clang-format drift detection
# ---------------------------------------------------------------------------
section "Check clang-format drift"
if want_clang_format "format drift detection"; then
  for file in "${format_files[@]}"; do
    case "$file" in
      *.ino) run "$clang_format_bin" --dry-run --Werror --style="$clang_format_style" --assume-filename="${file%.ino}.cpp" "$file" ;;
      *) run "$clang_format_bin" --dry-run --Werror --style="$clang_format_style" "$file" ;;
    esac
  done
fi

# ---------------------------------------------------------------------------
# 26. Run shellcheck
# ---------------------------------------------------------------------------
section "Run shellcheck"
if want_tool shellcheck "bash script linting"; then
  shell_scripts=("$repo_root/packaging"/*.sh "$scripts_dir"/*.sh "$linter_dir"/*.sh "$repo_root/make"/*.sh "$userspace_scripts"/*.sh)
  ((${#shell_scripts[@]} > 0)) && run shellcheck -S warning -x -P SCRIPTDIR "${shell_scripts[@]}"
fi

# ---------------------------------------------------------------------------
# Arduino compile — firmware/nfc CCID + CDC per board (--warnings all; repo-owned diagnostics only)
# ---------------------------------------------------------------------------
setup_arduino_vm_paths
setup_arduino_lint_compile_flags

compile_log="$(mktemp)"
arduino_lint_build_root="${NERO_ARDUINO_LINT_BUILD_ROOT:-/tmp}/nero-nfc-arduino-lint"
rm -rf "${arduino_lint_build_root}"
mkdir -p "${arduino_lint_build_root}"
trap 'rm -f "$compile_log"; rm -rf "${arduino_lint_build_root}"' EXIT

arduino_fqbn_build_slug() {
  printf '%s' "$1" | tr -c '[:alnum:]._-' '_'
}

run_arduino_sketch_compile() {
  local fqbn="$1" sketch_dir="$2" c_flags="$3" cpp_flags="$4"
  local build_extra="${5:-}" display_label="${6:-$sketch_dir}"
  local build_label="${display_label// /-}"
  build_label="${build_label//[^a-zA-Z0-9._-]/_}"
  local fqbn_slug
  fqbn_slug="$(arduino_fqbn_build_slug "$fqbn")"
  local build_path="${arduino_lint_build_root}/${fqbn_slug}/${build_label}"
  local -a compile_props=(
    --build-property "compiler.c.extra_flags=${c_flags}"
    --build-property "compiler.cpp.extra_flags=${cpp_flags}"
  )
  if [[ -n $build_extra ]]; then
    compile_props+=(--build-property "build.extra_flags=${build_extra}")
  fi
  mkdir -p "${build_path}"
  local -a compile_cmd=(
    "$ARDUINO_CLI" compile --warnings all --fqbn "$fqbn" -j "${arduino_lint_jobs}"
    --build-path "${build_path}"
  )
  compile_cmd+=("${compile_props[@]}" "$sketch_dir")
  printf '+ %s compile --warnings all --fqbn %s %s\n' "$ARDUINO_CLI" "$fqbn" "$display_label"
  if [[ ${NERO_CI_LOCAL_IN_VM:-0} == 1 ]]; then
    printf '  build-path: %s\n' "${build_path}" >&2
  fi
  if ! bash "$repo_root/scripts/run-arduino-compile.sh" --board "$display_label" --repo-root "$repo_root" --log "$compile_log" -- \
    "${compile_cmd[@]}"; then
    printf 'error: Arduino compile failed for %s\n' "$display_label" >&2
    exit 1
  fi
}

run_arduino_board_profile() {
  local profile_label="$1" fqbn="$2" c_extra="$3" cpp_extra="$4"
  local build_extra_ccid="$5" build_extra_cdc="$6"
  shift 6

  section "Compile Arduino firmware (${profile_label})"
  if (($# > 0)); then
    run "$@"
  fi

  run_arduino_sketch_compile "$fqbn" "$nfc_lint_sketch_dir" "$c_extra" "$cpp_extra" \
    "$build_extra_ccid" "${nfc_lint_sketch_dir} (CCID)"

  run_arduino_sketch_compile "$fqbn" "$nfc_lint_sketch_dir" "$c_extra" "$cpp_extra" \
    "$build_extra_cdc" "${nfc_lint_sketch_dir} (CDC)"
}

run_arduino_board_profile \
  "UNO R4 WiFi" "$fqbn_uno_r4" \
  "$arduino_c_extra_nfc_uno" "$arduino_cpp_extra_nfc_uno" \
  "$arduino_build_extra_nfc_uno_ccid" "$arduino_build_extra_nfc_uno_cdc"

run_arduino_board_profile \
  "Nucleo-WBA65RI" "$fqbn_wba65" \
  "$arduino_c_extra_nfc_wba65" "$arduino_cpp_extra_nfc_wba65" \
  "$arduino_build_extra_nfc_wba65_ccid" "$arduino_build_extra_nfc_wba65_cdc" \
  arduino_host_tools_make TARGET=nucleo_wba65ri third-party-host-tools third-party-tinyusb-wba65

printf '\nAll lint checks passed.\n'
