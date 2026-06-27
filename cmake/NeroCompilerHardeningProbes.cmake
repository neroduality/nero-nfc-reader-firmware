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

# Configure-time probes for optional hardening flags (do not include from MCU builds).
# Sets cache booleans consumed by HostHardening.cmake.

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(CheckLinkerFlag)

get_property(_nero_pl DIRECTORY "${CMAKE_SOURCE_DIR}" PROPERTY LANGUAGES)
if("C" IN_LIST _nero_pl)
  check_c_compiler_flag(-ftrivial-auto-var-init=zero NERO_HAVE_C_TRIVIAL_AUTO_VAR_INIT_ZERO)
  check_c_compiler_flag(-fzero-call-used-regs=used-gpr NERO_HAVE_C_ZERO_CALL_USED_REGS_GPR)
  check_c_compiler_flag(-fstrict-flex-arrays=3 NERO_HAVE_C_STRICT_FLEX_ARRAYS_3)
  check_c_compiler_flag(-Wtrampolines NERO_HAVE_C_WTRAMPOLINES)
  check_c_compiler_flag(-Wbidi-chars=any NERO_HAVE_C_WBIDI_CHARS)
  check_c_compiler_flag(-Werror=implicit NERO_HAVE_C_WERROR_IMPLICIT)
  check_c_compiler_flag(-Werror=incompatible-pointer-types NERO_HAVE_C_WERROR_INCOMPATIBLE_POINTER_TYPES)
  check_c_compiler_flag(-Werror=int-conversion NERO_HAVE_C_WERROR_INT_CONVERSION)
  set(_nero_probe_save_flags_c "${CMAKE_REQUIRED_FLAGS}")
  set(CMAKE_REQUIRED_FLAGS "-O2")
  check_c_compiler_flag(-fhardened NERO_HAVE_C_FHARDENED)
  set(CMAKE_REQUIRED_FLAGS "${_nero_probe_save_flags_c}")
else()
  set(NERO_HAVE_C_TRIVIAL_AUTO_VAR_INIT_ZERO 0)
  set(NERO_HAVE_C_ZERO_CALL_USED_REGS_GPR 0)
  set(NERO_HAVE_C_STRICT_FLEX_ARRAYS_3 0)
  set(NERO_HAVE_C_FHARDENED 0)
  set(NERO_HAVE_C_WTRAMPOLINES 0)
  set(NERO_HAVE_C_WBIDI_CHARS 0)
  set(NERO_HAVE_C_WERROR_IMPLICIT 0)
  set(NERO_HAVE_C_WERROR_INCOMPATIBLE_POINTER_TYPES 0)
  set(NERO_HAVE_C_WERROR_INT_CONVERSION 0)
endif()

check_cxx_compiler_flag(-ftrivial-auto-var-init=zero NERO_HAVE_CXX_TRIVIAL_AUTO_VAR_INIT_ZERO)
check_cxx_compiler_flag(-Wtrampolines NERO_HAVE_CXX_WTRAMPOLINES)
check_cxx_compiler_flag(-Wbidi-chars=any NERO_HAVE_CXX_WBIDI_CHARS)
check_cxx_compiler_flag(-fzero-call-used-regs=used-gpr NERO_HAVE_CXX_ZERO_CALL_USED_REGS_GPR)
check_cxx_compiler_flag(-Warith-conversion NERO_HAVE_CXX_ARITH_CONVERSION)
check_cxx_compiler_flag(-fstrict-flex-arrays=3 NERO_HAVE_CXX_STRICT_FLEX_ARRAYS_3)

set(_nero_probe_save_flags "${CMAKE_REQUIRED_FLAGS}")
set(CMAKE_REQUIRED_FLAGS "-O2")
check_cxx_compiler_flag(-fhardened NERO_HAVE_CXX_FHARDENED)
set(CMAKE_REQUIRED_FLAGS "${_nero_probe_save_flags}")

# AArch64 Linux (and cross-toolchains that report arm64/aarch64): branch-protection hints
# (OpenSSF / distro hardening guides). Not used on Darwin toolchains.
set(NERO_HAVE_ARM_BRANCH_PROTECTION_STANDARD 0)
if(UNIX
   AND NOT APPLE
   AND CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|AArch64|arm64|ARM64)$")
  check_cxx_compiler_flag(-mbranch-protection=standard NERO_HAVE_ARM_BRANCH_PROTECTION_STANDARD)
endif()

if(UNIX AND NOT APPLE)
  check_linker_flag(C "LINKER:-z,nodlopen" NERO_HAVE_LINK_Z_NODLOPEN)
  check_linker_flag(C "LINKER:--as-needed" NERO_HAVE_LINK_AS_NEEDED)
else()
  set(NERO_HAVE_LINK_Z_NODLOPEN 0)
  set(NERO_HAVE_LINK_AS_NEEDED 0)
endif()

mark_as_advanced(
  NERO_HAVE_CXX_TRIVIAL_AUTO_VAR_INIT_ZERO
  NERO_HAVE_CXX_ZERO_CALL_USED_REGS_GPR
  NERO_HAVE_CXX_ARITH_CONVERSION
  NERO_HAVE_CXX_STRICT_FLEX_ARRAYS_3
  NERO_HAVE_CXX_FHARDENED
  NERO_HAVE_ARM_BRANCH_PROTECTION_STANDARD
  NERO_HAVE_LINK_Z_NODLOPEN
  NERO_HAVE_LINK_AS_NEEDED)

if("C" IN_LIST _nero_pl)
  mark_as_advanced(
    NERO_HAVE_C_TRIVIAL_AUTO_VAR_INIT_ZERO
    NERO_HAVE_C_ZERO_CALL_USED_REGS_GPR
    NERO_HAVE_C_STRICT_FLEX_ARRAYS_3
    NERO_HAVE_C_FHARDENED
    NERO_HAVE_C_WTRAMPOLINES
    NERO_HAVE_C_WBIDI_CHARS
    NERO_HAVE_C_WERROR_IMPLICIT
    NERO_HAVE_C_WERROR_INCOMPATIBLE_POINTER_TYPES
    NERO_HAVE_C_WERROR_INT_CONVERSION)
endif()

mark_as_advanced(NERO_HAVE_CXX_WTRAMPOLINES NERO_HAVE_CXX_WBIDI_CHARS)
