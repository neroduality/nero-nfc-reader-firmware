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

# Host-only compile/link hardening (Linux desktop CLIs and host unit tests).
# Arduino firmware stays on GNU++17 via the top-level Makefile — do not include this from MCU builds.
#
# Aligned with OpenSSF “Compiler Options Hardening Guide” themes where they suit hosted glibc
# builds: aggressive warnings, -ftrivial-auto-var-init=zero / -fzero-call-used-regs when probed,
# -fno-delete-null-pointer-checks / -fno-strict-overflow (preserve security-relevant checks),
# -fstrict-flex-arrays=3 when probed (pairs with _FORTIFY_SOURCE), -fvisibility=hidden,
# stack/CET or AArch64 branch protection, _FORTIFY_SOURCE=3 + _GLIBCXX_ASSERTIONS (GCC/libstdc++),
# ELF PIE + relro/now/noexecstack on link; -fPIE/-pie on hosted Linux CMake roots (userspace/tests).
#
# Defines INTERFACE library target: nero_host_hardening
#
# Requires: CMake 3.20+
#
# NERO_STRIP_HOST_SYMBOLS (default OFF): when ON, Release/MinSizeRel host binaries are
# linked with -s. Keep OFF for Debug, sanitizer, coverage, and valgrind builds.

if(NOT DEFINED NERO_STRIP_HOST_SYMBOLS)
  set(NERO_STRIP_HOST_SYMBOLS OFF)
endif()

add_library(nero_host_hardening INTERFACE)

set(_nero_fortify_cfg $<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>,$<CONFIG:MinSizeRel>>)

include("${CMAKE_CURRENT_LIST_DIR}/NeroCompilerHardeningProbes.cmake")

# --- C and C++: _FORTIFY_SOURCE (compiler + language match each translation unit) ---
target_compile_options(
  nero_host_hardening
  INTERFACE
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU,Clang,AppleClang>,${_nero_fortify_cfg}>:-U_FORTIFY_SOURCE>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU,Clang,AppleClang>,${_nero_fortify_cfg}>:-D_FORTIFY_SOURCE=3>
  $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CXX_COMPILER_ID:GNU,Clang,AppleClang>,${_nero_fortify_cfg}>:-U_FORTIFY_SOURCE>
  $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CXX_COMPILER_ID:GNU,Clang,AppleClang>,${_nero_fortify_cfg}>:-D_FORTIFY_SOURCE=3>)

# --- C only (host unit tests compile NFC helpers as C) ---
target_compile_options(
  nero_host_hardening
  INTERFACE
  $<$<COMPILE_LANGUAGE:C>:-Wall>
  $<$<COMPILE_LANGUAGE:C>:-Wextra>
  $<$<COMPILE_LANGUAGE:C>:-Wpedantic>
  $<$<COMPILE_LANGUAGE:C>:-Wformat=2>
  $<$<COMPILE_LANGUAGE:C>:-Wformat-security>
  $<$<COMPILE_LANGUAGE:C>:-Wformat-overflow=2>
  $<$<COMPILE_LANGUAGE:C>:-Wformat-truncation=2>
  $<$<COMPILE_LANGUAGE:C>:-Werror=format-security>
  $<$<COMPILE_LANGUAGE:C>:-Wnull-dereference>
  $<$<COMPILE_LANGUAGE:C>:-Wshadow>
  $<$<COMPILE_LANGUAGE:C>:-Wcast-qual>
  $<$<COMPILE_LANGUAGE:C>:-Wundef>
  $<$<COMPILE_LANGUAGE:C>:-Wstrict-prototypes>
  $<$<COMPILE_LANGUAGE:C>:-Wwrite-strings>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU>>:-Wstrict-overflow=2>
  $<$<COMPILE_LANGUAGE:C>:-Wunused-result>
  $<$<COMPILE_LANGUAGE:C>:-Wconversion>
  $<$<COMPILE_LANGUAGE:C>:-Wsign-conversion>
  $<$<COMPILE_LANGUAGE:C>:-Wvla>
  $<$<COMPILE_LANGUAGE:C>:-Walloca>
  $<$<COMPILE_LANGUAGE:C>:-Wdouble-promotion>
  $<$<COMPILE_LANGUAGE:C>:-Wshift-overflow=2>
  $<$<COMPILE_LANGUAGE:C>:-Wswitch-enum>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU>>:-Wimplicit-fallthrough=5>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU>>:-Warray-bounds=2>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU>>:-Wstringop-overflow=4>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU>>:-Wduplicated-cond>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU>>:-Wduplicated-branches>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU>,$<BOOL:${NERO_HAVE_C_WTRAMPOLINES}>>:-Wtrampolines>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU>,$<BOOL:${NERO_HAVE_C_WBIDI_CHARS}>>:-Wbidi-chars=any>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU>,$<BOOL:${NERO_HAVE_C_WERROR_IMPLICIT}>>:-Werror=implicit>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU>,$<BOOL:${NERO_HAVE_C_WERROR_INCOMPATIBLE_POINTER_TYPES}>>:-Werror=incompatible-pointer-types>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU>,$<BOOL:${NERO_HAVE_C_WERROR_INT_CONVERSION}>>:-Werror=int-conversion>
  $<$<COMPILE_LANGUAGE:C>:-fno-strict-aliasing>
  $<$<COMPILE_LANGUAGE:C>:-fno-delete-null-pointer-checks>
  $<$<COMPILE_LANGUAGE:C>:-fno-strict-overflow>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<BOOL:${NERO_HAVE_C_STRICT_FLEX_ARRAYS_3}>>:-fstrict-flex-arrays=3>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<BOOL:${NERO_HAVE_C_TRIVIAL_AUTO_VAR_INIT_ZERO}>>:-ftrivial-auto-var-init=zero>
  $<$<AND:$<COMPILE_LANGUAGE:C>,$<BOOL:${NERO_HAVE_C_ZERO_CALL_USED_REGS_GPR}>>:-fzero-call-used-regs=used-gpr>)

# --- C++ only (MCU C++17 constraint does not apply here) ---
target_compile_options(
  nero_host_hardening
  INTERFACE
  $<$<COMPILE_LANGUAGE:CXX>:-Wall>
  $<$<COMPILE_LANGUAGE:CXX>:-Wextra>
  $<$<COMPILE_LANGUAGE:CXX>:-Wpedantic>
  $<$<COMPILE_LANGUAGE:CXX>:-Wformat=2>
  $<$<COMPILE_LANGUAGE:CXX>:-Wformat-security>
  $<$<COMPILE_LANGUAGE:CXX>:-Wformat-overflow=2>
  $<$<COMPILE_LANGUAGE:CXX>:-Wformat-truncation=2>
  $<$<COMPILE_LANGUAGE:CXX>:-Werror=format-security>
  $<$<COMPILE_LANGUAGE:CXX>:-Wnull-dereference>
  $<$<COMPILE_LANGUAGE:CXX>:-Wwrite-strings>
  $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CXX_COMPILER_ID:GNU>>:-Wstrict-overflow=2>
  $<$<COMPILE_LANGUAGE:CXX>:-Wshadow>
  $<$<COMPILE_LANGUAGE:CXX>:-Wundef>
  $<$<COMPILE_LANGUAGE:CXX>:-Wcast-qual>
  $<$<COMPILE_LANGUAGE:CXX>:-Wvla>
  $<$<COMPILE_LANGUAGE:CXX>:-Wpointer-arith>
  $<$<COMPILE_LANGUAGE:CXX>:-Wdate-time>
  $<$<COMPILE_LANGUAGE:CXX>:-Walloca>
  $<$<COMPILE_LANGUAGE:CXX>:-Wdouble-promotion>
  $<$<COMPILE_LANGUAGE:CXX>:-Wshift-overflow=2>
  $<$<COMPILE_LANGUAGE:CXX>:-Wswitch-enum>
  $<$<COMPILE_LANGUAGE:CXX>:-Wunused-result>
  $<$<COMPILE_LANGUAGE:CXX>:-Wconversion>
  $<$<COMPILE_LANGUAGE:CXX>:-Wsign-conversion>
  $<$<COMPILE_LANGUAGE:CXX>:-Wnon-virtual-dtor>
  $<$<COMPILE_LANGUAGE:CXX>:-Wdelete-non-virtual-dtor>
  $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CXX_COMPILER_ID:GNU>>:-Wimplicit-fallthrough=5>
  $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CXX_COMPILER_ID:GNU>>:-Warray-bounds=2>
  $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CXX_COMPILER_ID:GNU>>:-Wstringop-overflow=4>
  $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CXX_COMPILER_ID:GNU>>:-Wlogical-op>
  $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CXX_COMPILER_ID:GNU>>:-Wduplicated-cond>
  $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CXX_COMPILER_ID:GNU>>:-Wduplicated-branches>
  $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CXX_COMPILER_ID:GNU>,$<BOOL:${NERO_HAVE_CXX_ARITH_CONVERSION}>>:-Warith-conversion>
  $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CXX_COMPILER_ID:Clang,AppleClang>>:-Wcast-align>
  $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CXX_COMPILER_ID:Clang,AppleClang>>:-Wthread-safety>
  $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CXX_COMPILER_ID:GNU>,$<BOOL:${NERO_HAVE_CXX_WTRAMPOLINES}>>:-Wtrampolines>
  $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CXX_COMPILER_ID:GNU>,$<BOOL:${NERO_HAVE_CXX_WBIDI_CHARS}>>:-Wbidi-chars=any>
  $<$<COMPILE_LANGUAGE:CXX>:-fno-strict-aliasing>
  $<$<COMPILE_LANGUAGE:CXX>:-fno-delete-null-pointer-checks>
  $<$<COMPILE_LANGUAGE:CXX>:-fno-strict-overflow>
  $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<BOOL:${NERO_HAVE_CXX_STRICT_FLEX_ARRAYS_3}>>:-fstrict-flex-arrays=3>
  $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<BOOL:${NERO_HAVE_CXX_TRIVIAL_AUTO_VAR_INIT_ZERO}>>:-ftrivial-auto-var-init=zero>
  $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<BOOL:${NERO_HAVE_CXX_ZERO_CALL_USED_REGS_GPR}>>:-fzero-call-used-regs=used-gpr>)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$" AND NOT APPLE AND NOT CMAKE_CROSSCOMPILING)
  target_compile_options(nero_host_hardening INTERFACE
                         $<$<COMPILE_LANGUAGE:C>:$<$<C_COMPILER_ID:GNU,Clang>:-fcf-protection=full>>)
  target_compile_options(nero_host_hardening INTERFACE
                         $<$<COMPILE_LANGUAGE:CXX>:$<$<CXX_COMPILER_ID:GNU,Clang>:-fcf-protection=full>>)
elseif(NOT APPLE AND NERO_HAVE_ARM_BRANCH_PROTECTION_STANDARD)
  target_compile_options(
    nero_host_hardening INTERFACE $<$<COMPILE_LANGUAGE:C>:$<$<C_COMPILER_ID:GNU,Clang>:-mbranch-protection=standard>>)
  target_compile_options(
    nero_host_hardening INTERFACE $<$<COMPILE_LANGUAGE:CXX>:$<$<CXX_COMPILER_ID:GNU,Clang>:-mbranch-protection=standard>>)
endif()

target_compile_options(
  nero_host_hardening
  INTERFACE $<$<COMPILE_LANGUAGE:C>:$<$<C_COMPILER_ID:GNU,Clang,AppleClang>:-fstack-protector-strong>>)

target_compile_options(
  nero_host_hardening
  INTERFACE $<$<COMPILE_LANGUAGE:CXX>:$<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-fstack-protector-strong>>)

if(NOT APPLE)
  target_compile_options(
    nero_host_hardening INTERFACE $<$<COMPILE_LANGUAGE:C>:$<$<C_COMPILER_ID:GNU,Clang>:-fstack-clash-protection>>)
  target_compile_options(
    nero_host_hardening INTERFACE $<$<COMPILE_LANGUAGE:CXX>:$<$<CXX_COMPILER_ID:GNU,Clang>:-fstack-clash-protection>>)
endif()

# libstdc++: expensive iterator / bounds checks (all configs when using GCC libstdc++).
target_compile_definitions(
  nero_host_hardening
  INTERFACE
  $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CXX_COMPILER_ID:GNU>>:_GLIBCXX_ASSERTIONS>)

target_compile_options(
  nero_host_hardening
  INTERFACE
  $<$<COMPILE_LANGUAGE:C>:$<$<C_COMPILER_ID:GNU,Clang,AppleClang>:-fvisibility=hidden>>)

target_compile_options(
  nero_host_hardening
  INTERFACE
  $<$<COMPILE_LANGUAGE:CXX>:$<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-fvisibility=hidden>>
  $<$<COMPILE_LANGUAGE:CXX>:$<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-fvisibility-inlines-hidden>>)

if(UNIX AND NOT APPLE)
  target_link_options(
    nero_host_hardening INTERFACE "LINKER:-z,relro" "LINKER:-z,now" "LINKER:-z,noexecstack")
  if(NERO_HAVE_LINK_Z_NODLOPEN)
    target_link_options(nero_host_hardening INTERFACE "LINKER:-z,nodlopen")
  endif()
  if(NERO_HAVE_LINK_AS_NEEDED)
    target_link_options(nero_host_hardening INTERFACE "LINKER:--as-needed")
  endif()
endif()

if(NERO_STRIP_HOST_SYMBOLS)
  target_link_options(
    nero_host_hardening
    INTERFACE
    $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:LINKER:-s>)
endif()
