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

# Shared app library: detect, serial, line_pump, browser, driver.
#
set(NERO_FIRMWARE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")

add_library(
  nero_nfc_app STATIC
  nero_nfc_bridge.cpp
  nero_nfc_detect.cpp
  nero_nfc_serial.cpp
  nero_nfc_line_pump.cpp
  nero_nfc_browser.cpp
  nero_nfc_driver.cpp
  nero_nfc_hex.cpp
  nero_nfc_ndef.cpp
  nero_nfc_writer_payload.cpp
  nero_nfc_pcsc_format.cpp
  nero_nfc_pcsc_tag_details.cpp
  nero_nfc_pcsc_connect.cpp
  nero_nfc_pcsc_storage_common.cpp
  nero_nfc_pcsc_storage_type2.cpp
  nero_nfc_pcsc_storage_type5.cpp
  nero_nfc_pcsc_type4.cpp
  nero_nfc_pcsc.cpp
  nero_nfc_io.cpp
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/protocol/nfc_ndef_record_decode.c"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/core/nero_nfc_format.c")

target_include_directories(
  nero_nfc_app
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src")

find_package(Threads REQUIRED)
target_link_libraries(nero_nfc_app PUBLIC Threads::Threads hardening)
target_compile_features(nero_nfc_app PUBLIC cxx_std_23)
find_package(PkgConfig QUIET)
set(_nero_pcsc_found OFF)
set(_nero_pcsc_target "")
if(PkgConfig_FOUND)
  pkg_check_modules(PCSC QUIET IMPORTED_TARGET libpcsclite)
  if(PCSC_FOUND AND TARGET PkgConfig::PCSC)
    set(_nero_pcsc_found ON)
    set(_nero_pcsc_target PkgConfig::PCSC)
  else()
    pkg_check_modules(PCSC QUIET IMPORTED_TARGET pcsclite)
    if(PCSC_FOUND AND TARGET PkgConfig::PCSC)
      set(_nero_pcsc_found ON)
      set(_nero_pcsc_target PkgConfig::PCSC)
    endif()
  endif()
endif()
if(NOT _nero_pcsc_found AND APPLE)
  find_library(PCSC_FRAMEWORK PCSC)
  if(PCSC_FRAMEWORK)
    add_library(nero_pcsc_framework INTERFACE)
    target_link_libraries(nero_pcsc_framework INTERFACE "${PCSC_FRAMEWORK}")
    set(_nero_pcsc_found ON)
    set(_nero_pcsc_target nero_pcsc_framework)
  endif()
endif()
if(_nero_pcsc_found)
  target_compile_definitions(nero_nfc_app PUBLIC NERO_USERSPACE_HAVE_PCSC=1)
  target_link_libraries(nero_nfc_app PUBLIC ${_nero_pcsc_target})
endif()
target_compile_definitions(
  nero_nfc_app
  PUBLIC
  $<$<AND:$<CONFIG:Debug>,$<CXX_COMPILER_ID:GNU>>:_GLIBCXX_DEBUG>
  $<$<AND:$<CONFIG:Debug>,$<CXX_COMPILER_ID:GNU>>:_GLIBCXX_DEBUG_PEDANTIC>)
