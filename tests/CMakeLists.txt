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

# Host-side unit tests for firmware logic (no Arduino / RFAL).

cmake_minimum_required(VERSION 3.20)
if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

project(nero-nfc-reader-firmware-tests LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# Required so FetchContent gtest/gtest_main (static) can link into -pie test executables
# from cmake/Hardening.cmake. Matches userspace/CMakeLists.txt.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(NERO_ENABLE_COVERAGE "Compile with GCC/Clang coverage flags (--coverage)" OFF)
option(NERO_ENABLE_SANITIZER_ADDRESS "Enable AddressSanitizer" OFF)
option(NERO_ENABLE_SANITIZER_UNDEFINED "Enable UndefinedBehaviorSanitizer" OFF)
option(NERO_ENABLE_SANITIZER_THREAD "Enable ThreadSanitizer" OFF)
option(NERO_TESTS_ENABLE_PCSC "Link libpcsclite-backed PC/SC integration into unit tests" OFF)
option(
  NERO_ENABLE_EXTENDED_SANITIZERS
  "With ASan/UBSan enabled, probe extra -fsanitize flags (pointer-*, bounds-strict on GCC)" ON)
option(NERO_USE_SYSTEM_GTEST "Use find_package(GTest) instead of FetchContent (local/scan-build)" OFF)

set(NERO_FIRMWARE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")

if(NERO_ENABLE_COVERAGE AND (NERO_ENABLE_SANITIZER_ADDRESS OR NERO_ENABLE_SANITIZER_UNDEFINED OR NERO_ENABLE_SANITIZER_THREAD))
  message(FATAL_ERROR "Coverage builds cannot mix with sanitizers")
endif()

if(NERO_ENABLE_SANITIZER_THREAD AND (NERO_ENABLE_SANITIZER_ADDRESS OR NERO_ENABLE_SANITIZER_UNDEFINED))
  message(FATAL_ERROR "ThreadSanitizer cannot mix with ASan/UBSan in one build")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(_nero_tests_debug_sanitizers_default ON)
else()
  set(_nero_tests_debug_sanitizers_default OFF)
endif()
option(
  NERO_TESTS_DEBUG_SANITIZERS
  "With CMAKE_BUILD_TYPE=Debug, enable ASan+UBSan on host test binaries by default (no effect in Release)"
  "${_nero_tests_debug_sanitizers_default}")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  if(NERO_TESTS_DEBUG_SANITIZERS AND NOT NERO_ENABLE_COVERAGE AND NOT NERO_ENABLE_SANITIZER_THREAD AND NOT NERO_ENABLE_SANITIZER_ADDRESS AND NOT NERO_ENABLE_SANITIZER_UNDEFINED)
    set(NERO_ENABLE_SANITIZER_ADDRESS ON)
    set(NERO_ENABLE_SANITIZER_UNDEFINED ON)
  endif()
endif()

if(NERO_ENABLE_COVERAGE)
  if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(
      WARNING "NERO_ENABLE_COVERAGE is ON but CMAKE_BUILD_TYPE is not Debug; prefer -DCMAKE_BUILD_TYPE=Debug")
  endif()
  add_compile_options(--coverage -O0 -g)
  add_link_options(--coverage)
endif()

set(_nero_sanitizers "")
if(NERO_ENABLE_SANITIZER_ADDRESS)
  list(APPEND _nero_sanitizers "address")
endif()
if(NERO_ENABLE_SANITIZER_UNDEFINED)
  list(APPEND _nero_sanitizers "undefined")
endif()
if(NERO_ENABLE_SANITIZER_THREAD)
  list(APPEND _nero_sanitizers "thread")
endif()
if(_nero_sanitizers)
  string(REPLACE ";" "," _nero_san_join "${_nero_sanitizers}")
  include(CheckCXXCompilerFlag)

  if(NERO_ENABLE_EXTENDED_SANITIZERS)
    set(_nero_san_extra_list "")
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
      if(NERO_ENABLE_SANITIZER_ADDRESS)
        list(APPEND _nero_san_extra_list "pointer-compare" "pointer-subtract")
      endif()
      if(NERO_ENABLE_SANITIZER_UNDEFINED)
        list(APPEND _nero_san_extra_list "bounds-strict")
      endif()
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
      if(NERO_ENABLE_SANITIZER_ADDRESS)
        list(APPEND _nero_san_extra_list "pointer-compare" "pointer-subtract")
      endif()
    endif()
    if(_nero_san_extra_list)
      list(APPEND _nero_sanitizers ${_nero_san_extra_list})
      string(REPLACE ";" "," _nero_san_extended "${_nero_sanitizers}")
      set(_nero_try_compile_flags
          "-fsanitize=${_nero_san_extended} -fno-omit-frame-pointer -g")
      include(CMakePushCheckState)
      include(CheckCXXSourceCompiles)
      cmake_push_check_state()
      set(CMAKE_REQUIRED_FLAGS "${_nero_try_compile_flags}")
      set(CMAKE_REQUIRED_LINK_OPTIONS "-fsanitize=${_nero_san_extended}")
      check_cxx_source_compiles("int main(){return 0;}" NERO_TESTS_SANITIZER_EXTENDED_OK)
      cmake_pop_check_state()
      if(NERO_TESTS_SANITIZER_EXTENDED_OK)
        set(_nero_san_join "${_nero_san_extended}")
      endif()
    endif()
  endif()

  add_compile_options(-fsanitize=${_nero_san_join} -fno-omit-frame-pointer -g)

  check_cxx_compiler_flag(-fno-sanitize-recover=all NERO_TESTS_FNO_SANITIZE_RECOVER)
  if(NERO_TESTS_FNO_SANITIZE_RECOVER)
    add_compile_options(-fno-sanitize-recover=all)
  endif()

  add_link_options(-fsanitize=${_nero_san_join})
endif()

if(NERO_USE_SYSTEM_GTEST)
  find_package(GTest REQUIRED)
else()
  include(FetchContent)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
         URL_HASH SHA256=8ad598c73ad796e0d8280b082cebd82a630d73e73cd3c70057938a6501bba5d7
  )
  FetchContent_MakeAvailable(googletest)
  foreach(_nero_gtest_target IN ITEMS gtest gtest_main)
    if(TARGET ${_nero_gtest_target})
      set_property(TARGET ${_nero_gtest_target} PROPERTY POSITION_INDEPENDENT_CODE ON)
      target_compile_options(${_nero_gtest_target} PRIVATE
        $<$<CXX_COMPILER_ID:GNU>:-Wno-maybe-uninitialized>)
    endif()
  endforeach()
endif()

enable_testing()
include(GoogleTest)

find_package(Threads REQUIRED)
find_package(PkgConfig QUIET)

set(NERO_STRIP_HOST_SYMBOLS OFF CACHE BOOL "Strip debug symbols from Release host binaries" FORCE)

include("${CMAKE_CURRENT_SOURCE_DIR}/../cmake/Hardening.cmake")
define_hardening(
  TARGET hardening
  C_STANDARD 23
  CXX_STANDARD 23)

# Vendored trees as SYSTEM includes (host unit-test / lint CMake targets only).
# ST25R3916 + NFC-RFAL are required (make third-party-nfc-libs). TinyUSB is
# optional until a WBA CCID host path needs it.
function(nero_add_third_party_system_includes target)
  if(NOT TARGET ${target})
    message(FATAL_ERROR "nero_add_third_party_system_includes: no target ${target}")
  endif()
  if(NOT DEFINED NERO_FIRMWARE_ROOT)
    message(FATAL_ERROR "nero_add_third_party_system_includes: NERO_FIRMWARE_ROOT is not set")
  endif()
  set(_root "${NERO_FIRMWARE_ROOT}/third-party")
  foreach(_dir "${_root}/ST25R3916/src" "${_root}/NFC-RFAL/src")
    if(NOT EXISTS "${_dir}")
      message(
        FATAL_ERROR
        "nero_add_third_party_system_includes: missing ${_dir}\n"
        "  Fetch pinned ST libs first: make third-party-nfc-libs")
    endif()
    target_include_directories(${target} SYSTEM PUBLIC "${_dir}")
  endforeach()
  if(EXISTS "${_root}/tinyusb/src")
    target_include_directories(${target} SYSTEM PUBLIC "${_root}/tinyusb/src")
  endif()
endfunction()

# Host-side ISO C23 probes for unit-test C objects (MCU firmware stays on gnu11).
function(nero_try_compile_c_silent result_var std source)
  set(_probe_dir "${CMAKE_BINARY_DIR}/CMakeFiles/nero-silent-probes")
  file(MAKE_DIRECTORY "${_probe_dir}")
  set(_probe_file "${_probe_dir}/${result_var}.c")
  set(_probe_obj "${_probe_dir}/${result_var}.o")
  file(WRITE "${_probe_file}" "${source}")
  execute_process(
    COMMAND "${CMAKE_C_COMPILER}" -std=${std} -Werror=implicit-function-declaration -c
            "${_probe_file}" -o "${_probe_obj}"
    RESULT_VARIABLE _compile_rc
    ERROR_QUIET
    OUTPUT_QUIET)
  if(_compile_rc EQUAL 0)
    set(${result_var} TRUE PARENT_SCOPE)
  else()
    set(${result_var} FALSE PARENT_SCOPE)
  endif()
endfunction()

if(CMAKE_C_COMPILER_ID MATCHES "GNU")
  if(CMAKE_C_COMPILER_VERSION VERSION_LESS "15.0")
    message(FATAL_ERROR
      "nero-nfc host tests require GCC 15+ (found ${CMAKE_C_COMPILER_VERSION})")
  endif()
elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
  if(CMAKE_C_COMPILER_VERSION VERSION_LESS "16.0")
    message(FATAL_ERROR
      "nero-nfc host C tests require Clang 16+ for ISO C23 (found ${CMAKE_C_COMPILER_VERSION})")
  endif()
else()
  message(WARNING "nero-nfc: untested C compiler ${CMAKE_C_COMPILER_ID}; C23 support not verified")
endif()

set(_nero_c23_std_candidates c23 c2x gnu2x)
set(_nero_c23_probe_source
  "#include <stddef.h>\nint main(void){ void *p = nullptr; (void)p; return 0; }\n")

set(NERO_C23_NULLPTR_OK FALSE)
foreach(_std IN LISTS _nero_c23_std_candidates)
  nero_try_compile_c_silent(_nero_c23_nullptr_ok "${_std}" "${_nero_c23_probe_source}")
  if(_nero_c23_nullptr_ok)
    set(NERO_C23_NULLPTR_OK TRUE)
    break()
  endif()
endforeach()

if(NOT NERO_C23_NULLPTR_OK)
  message(FATAL_ERROR
    "Host C compiler does not accept ISO C23 nullptr (tried -std=c23, -std=c2x, -std=gnu2x)")
endif()

set(_nero_ckd_probe_source
  "#include <stdckdint.h>\n#include <stddef.h>\nint main(void){ size_t r; return ckd_add(&r,(size_t)1,(size_t)2)?1:0; }\n")
set(NERO_HAVE_STDCKDINT FALSE)
foreach(_std IN LISTS _nero_c23_std_candidates)
  nero_try_compile_c_silent(_nero_have_stdckdint "${_std}" "${_nero_ckd_probe_source}")
  if(_nero_have_stdckdint)
    set(NERO_HAVE_STDCKDINT TRUE)
    break()
  endif()
endforeach()

set(_nero_memset_probe_source
  "#include <string.h>\nint main(void){ char b[4]; memset_explicit(b,0,sizeof b); return 0; }\n")
set(NERO_HAVE_MEMSET_EXPLICIT FALSE)
foreach(_std IN LISTS _nero_c23_std_candidates)
  nero_try_compile_c_silent(_nero_have_memset_explicit "${_std}" "${_nero_memset_probe_source}")
  if(_nero_have_memset_explicit)
    set(NERO_HAVE_MEMSET_EXPLICIT TRUE)
    break()
  endif()
endforeach()

if(NERO_HAVE_STDCKDINT)
  message(STATUS "nero-nfc: ISO C23 stdckdint.h available for host C tests")
else()
  message(STATUS "nero-nfc: stdckdint.h unavailable; host C tests use overflow fallbacks")
endif()
if(NERO_HAVE_MEMSET_EXPLICIT)
  message(STATUS "nero-nfc: C23 memset_explicit available for host secure clear")
  add_compile_definitions(NERO_NFC_HAVE_MEMSET_EXPLICIT=1)
else()
  message(STATUS "nero-nfc: memset_explicit unavailable; secure clear uses volatile-byte fallback")
endif()

# Object library compiled once; linked into both test executables.
add_library(
  nero_under_test OBJECT
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/core/nero_nfc_format.c"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/protocol/nfc_mode_line_scan.c"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/protocol/nfc_ctap_codec.c"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/protocol/nfc_ccid_frame.c"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/protocol/nfc_ndef_record_decode.c"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/writer/writer_payload.c"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/reader/reader_cbor.c"
  "${NERO_FIRMWARE_ROOT}/userspace/app/nero_nfc_bridge.cpp"
  "${NERO_FIRMWARE_ROOT}/userspace/app/nero_nfc_detect.cpp"
  "${NERO_FIRMWARE_ROOT}/userspace/app/nero_nfc_line_pump.cpp"
  "${NERO_FIRMWARE_ROOT}/userspace/app/nero_nfc_serial.cpp"
  "${NERO_FIRMWARE_ROOT}/userspace/app/nero_nfc_browser.cpp"
  "${NERO_FIRMWARE_ROOT}/userspace/app/nero_nfc_driver.cpp"
  "${NERO_FIRMWARE_ROOT}/userspace/app/nero_nfc_io.cpp"
  "${NERO_FIRMWARE_ROOT}/userspace/app/nero_nfc_hex.cpp"
  "${NERO_FIRMWARE_ROOT}/userspace/app/nero_nfc_ndef.cpp"
  "${NERO_FIRMWARE_ROOT}/userspace/app/nero_nfc_writer_payload.cpp"
  "${NERO_FIRMWARE_ROOT}/userspace/app/nero_nfc_pcsc_format.cpp"
  "${NERO_FIRMWARE_ROOT}/userspace/app/nero_nfc_pcsc_tag_details.cpp"
  "${NERO_FIRMWARE_ROOT}/userspace/app/nero_nfc_pcsc_connect.cpp"
  "${NERO_FIRMWARE_ROOT}/userspace/app/nero_nfc_pcsc_storage_common.cpp"
  "${NERO_FIRMWARE_ROOT}/userspace/app/nero_nfc_pcsc_storage_type2.cpp"
  "${NERO_FIRMWARE_ROOT}/userspace/app/nero_nfc_pcsc_storage_type5.cpp"
  "${NERO_FIRMWARE_ROOT}/userspace/app/nero_nfc_pcsc_type4.cpp"
  "${NERO_FIRMWARE_ROOT}/userspace/app/nero_nfc_pcsc.cpp")

target_include_directories(
  nero_under_test
  PUBLIC "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src"
         "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/port"
         "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/writer"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/frontend"
         "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/reader"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/frontend"
         "${NERO_FIRMWARE_ROOT}/userspace/app")

target_compile_definitions(nero_under_test PRIVATE NERO_HOST_UNIT_TEST_HOOKS=1
                                                   NERO_NFC_BUILD_COMBINED=1)
target_link_libraries(nero_under_test PUBLIC Threads::Threads hardening)
nero_add_third_party_system_includes(nero_under_test)
set(_nero_test_pcsc_found OFF)
set(_nero_test_pcsc_target "")
if(NERO_TESTS_ENABLE_PCSC)
  if(PkgConfig_FOUND)
    pkg_check_modules(PCSC QUIET IMPORTED_TARGET libpcsclite)
    if(PCSC_FOUND AND TARGET PkgConfig::PCSC)
      set(_nero_test_pcsc_found ON)
      set(_nero_test_pcsc_target PkgConfig::PCSC)
    else()
      pkg_check_modules(PCSC QUIET IMPORTED_TARGET pcsclite)
      if(PCSC_FOUND AND TARGET PkgConfig::PCSC)
        set(_nero_test_pcsc_found ON)
        set(_nero_test_pcsc_target PkgConfig::PCSC)
      endif()
    endif()
  endif()
  if(NOT _nero_test_pcsc_found AND APPLE)
    find_library(PCSC_FRAMEWORK PCSC)
    if(PCSC_FRAMEWORK)
      add_library(nero_test_pcsc_framework INTERFACE)
      target_link_libraries(nero_test_pcsc_framework INTERFACE "${PCSC_FRAMEWORK}")
      set(_nero_test_pcsc_found ON)
      set(_nero_test_pcsc_target nero_test_pcsc_framework)
    endif()
  endif()
  if(_nero_test_pcsc_found)
    target_compile_definitions(nero_under_test PUBLIC NERO_USERSPACE_HAVE_PCSC=1)
    target_link_libraries(nero_under_test PUBLIC ${_nero_test_pcsc_target})
  else()
    message(
      FATAL_ERROR
      "NERO_TESTS_ENABLE_PCSC=ON but libpcsclite was not found. Install dev packages (make deps) and re-run.")
  endif()
endif()
set(NERO_TESTS_HAVE_PCSC "${_nero_test_pcsc_found}" CACHE INTERNAL "libpcsclite linked into nero_under_test")

# Compile-only TUs for clang-tidy compile_commands.json (not linked into test binaries).
add_library(
  nero_firmware_lint OBJECT
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/reader/reader_security_key_webauthn_select.c")

target_include_directories(
  nero_firmware_lint
  PUBLIC "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src"
         "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/port"
         "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/reader"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/frontend"
         "${CMAKE_CURRENT_SOURCE_DIR}/firmware/support")

target_compile_definitions(nero_firmware_lint PRIVATE NERO_HOST_UNIT_TEST_HOOKS=1 NERO_CCID_USB_BUILD=1)
target_link_libraries(nero_firmware_lint PUBLIC hardening Threads::Threads)

add_subdirectory(firmware)
add_subdirectory(userspace)
