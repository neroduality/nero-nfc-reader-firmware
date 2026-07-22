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
#
# Generated from kit openssf-hardening-manifest + dials for build/lint/firmware/arduino_uno_r4wifi/reader/ccid/compile_commands.json — do not hand-edit.
#
include(${CMAKE_CURRENT_LIST_DIR}/CompilerHardeningProbes.cmake)
include(CMakeParseArguments)
function(define_hardening)
  cmake_parse_arguments(HARDENING "" "TARGET;C_STANDARD;CXX_STANDARD" "" ${ARGN})
  if(NOT HARDENING_TARGET)
    message(FATAL_ERROR "define_hardening requires TARGET")
  endif()
  if(TARGET "${HARDENING_TARGET}")
    return()
  endif()
  add_library("${HARDENING_TARGET}" INTERFACE)
  set(_hardening_host $<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>)
  set(_hardening_fortify_cfg $<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>,$<CONFIG:MinSizeRel>>)
  set(_hardening_production_cfg $<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>)
  set(_hardening_relwithdebinfo_cfg $<CONFIG:RelWithDebInfo>)
  set(_hardening_debug_cfg $<CONFIG:Debug>)
  target_compile_options("${HARDENING_TARGET}" INTERFACE
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_WERROR_IMPLICIT}>:-Werror=implicit>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_WERROR_INCOMPATIBLE_POINTER_TYPES}>:-Werror=incompatible-pointer-types>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_WERROR_INT_CONVERSION}>:-Werror=int-conversion>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_WERROR_TRAMPOLINES}>:-Werror=trampolines>>
    $<$<COMPILE_LANGUAGE:C>:$<$<BOOL:${HAVE_C_WTRAMPOLINES}>:-Wtrampolines>>
    $<$<COMPILE_LANGUAGE:C>:-Wall>
    $<$<COMPILE_LANGUAGE:C>:-Wconversion>
    $<$<COMPILE_LANGUAGE:C>:-Wextra>
    $<$<COMPILE_LANGUAGE:C>:-Wformat>
    $<$<COMPILE_LANGUAGE:C>:-Wformat=2>
    $<$<COMPILE_LANGUAGE:C>:-Wimplicit-fallthrough>
    $<$<COMPILE_LANGUAGE:C>:-Wsign-conversion>
    $<$<COMPILE_LANGUAGE:C>:-fno-delete-null-pointer-checks>
    $<$<COMPILE_LANGUAGE:C>:-fno-strict-aliasing>
    $<$<COMPILE_LANGUAGE:C>:-fno-strict-overflow>
    $<$<COMPILE_LANGUAGE:C>:-fstack-protector-strong>
  )
  target_compile_options("${HARDENING_TARGET}" INTERFACE
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_CXX_WERROR_TRAMPOLINES}>:-Werror=trampolines>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<BOOL:${HAVE_CXX_WTRAMPOLINES}>:-Wtrampolines>>
    $<$<COMPILE_LANGUAGE:CXX>:-Wall>
    $<$<COMPILE_LANGUAGE:CXX>:-Wconversion>
    $<$<COMPILE_LANGUAGE:CXX>:-Wextra>
    $<$<COMPILE_LANGUAGE:CXX>:-Wformat>
    $<$<COMPILE_LANGUAGE:CXX>:-Wformat=2>
    $<$<COMPILE_LANGUAGE:CXX>:-Wimplicit-fallthrough>
    $<$<COMPILE_LANGUAGE:CXX>:-Wsign-conversion>
    $<$<COMPILE_LANGUAGE:CXX>:-fno-delete-null-pointer-checks>
    $<$<COMPILE_LANGUAGE:CXX>:-fno-strict-aliasing>
    $<$<COMPILE_LANGUAGE:CXX>:-fno-strict-overflow>
    $<$<COMPILE_LANGUAGE:CXX>:-fstack-protector-strong>
  )
endfunction()
