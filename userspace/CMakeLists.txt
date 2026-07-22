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

# Top-level CMake for the Nero NFC C++ userspace.
# Builds the shared app library and CLI binaries.
#
# Host userspace uses ISO C++23 + kit Hardening.cmake. MCU firmware remains GNU++17 (Makefile).
#
# Usage (from repo root):
#   cmake -S userspace -B build/userspace -DCMAKE_BUILD_TYPE=Release \
#         -DCMAKE_RUNTIME_OUTPUT_DIRECTORY=$(pwd)/build/userspace/bin
#   cmake --build build/userspace

cmake_minimum_required(VERSION 3.20)
project(nero-nfc-userspace LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(CheckIPOSupported)
check_ipo_supported(RESULT _nero_ipo_ok OUTPUT _nero_ipo_msg)
if(_nero_ipo_ok)
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO ON)
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_MINSIZEREL ON)
else()
  message(
    STATUS
      "IPO/LTO not enabled for userspace: ${_nero_ipo_msg}"
  )
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  option(
    NERO_USERSPACE_DEBUG_SANITIZERS
    "With CMAKE_BUILD_TYPE=Debug, link ASan+UBSan into host userspace binaries"
    ON)
  if(NERO_USERSPACE_DEBUG_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
  endif()
endif()

if(CMAKE_BUILD_TYPE MATCHES "^(Release|MinSizeRel)$")
  set(NERO_STRIP_HOST_SYMBOLS ON CACHE BOOL "Strip debug symbols from Release host binaries" FORCE)
else()
  set(NERO_STRIP_HOST_SYMBOLS OFF CACHE BOOL "Strip debug symbols from Release host binaries" FORCE)
endif()

# Org OpenSSF hardening (kit-owned cmake/Hardening.cmake; define_hardening → INTERFACE lib).
include("${CMAKE_CURRENT_SOURCE_DIR}/../cmake/Hardening.cmake")
define_hardening(
  TARGET hardening
  C_STANDARD 23
  CXX_STANDARD 23)

add_subdirectory(app)
add_subdirectory(cli)
