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

# Firmware-layer host unit tests: NFC mode scanning, safe-copy, reader CBOR, writer payload.

set(_nero_reader_host_sources
    "${NERO_FIRMWARE_ROOT}/firmware/reader/src/reader_context.cpp"
    "${NERO_FIRMWARE_ROOT}/firmware/reader/src/reader_tags_ndef_decode.cpp"
    "${NERO_FIRMWARE_ROOT}/firmware/reader/src/reader_tags_ndef_print.cpp"
    "${NERO_FIRMWARE_ROOT}/firmware/reader/src/reader_output.cpp"
    "${NERO_FIRMWARE_ROOT}/firmware/reader/src/reader_ccid.cpp"
    "${NERO_FIRMWARE_ROOT}/firmware/reader/src/reader_ccid_xfr.cpp"
    "${NERO_FIRMWARE_ROOT}/firmware/reader/src/reader_ccid_bulk.cpp"
    "${NERO_FIRMWARE_ROOT}/firmware/reader/src/reader_ccid_storage.cpp"
    "${NERO_FIRMWARE_ROOT}/firmware/reader/src/reader_ccid_pn53x.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/support/reader_hal_utest_stub.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/support/reader_security_key_utest_stub.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/support/reader_tags_utest_stub.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/support/nfc_session_owner_utest_stub.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/support/reader_ccid_test_setup.c")

add_library(nero_reader_host OBJECT ${_nero_reader_host_sources})

target_include_directories(
  nero_reader_host
  PUBLIC "${NERO_FIRMWARE_ROOT}/firmware/nfc_core/common"
         "${NERO_FIRMWARE_ROOT}/firmware/nfc_core/frontends/st25r3916"
         "${NERO_FIRMWARE_ROOT}/firmware/port/include"
         "${NERO_FIRMWARE_ROOT}/firmware/reader/src"
         "${CMAKE_CURRENT_SOURCE_DIR}/support")

target_compile_definitions(nero_reader_host PRIVATE NERO_HOST_UNIT_TEST_HOOKS=1 NERO_CCID_USB_BUILD=1)
target_link_libraries(nero_reader_host PUBLIC nero_host_hardening Threads::Threads)
nero_add_third_party_system_includes(nero_reader_host)

set(_nero_reader_relay_host_sources
    "${NERO_FIRMWARE_ROOT}/firmware/reader/src/reader_security_key_iso_dep_session.cpp"
    "${NERO_FIRMWARE_ROOT}/firmware/reader/src/reader_security_key_iso_dep_transceive.cpp"
    "${NERO_FIRMWARE_ROOT}/firmware/reader/src/reader_iso_dep_debug.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/support/reader_protocol_utest_stub.cpp")

add_library(nero_reader_relay_host OBJECT ${_nero_reader_relay_host_sources})

target_include_directories(
  nero_reader_relay_host
  PUBLIC "${NERO_FIRMWARE_ROOT}/firmware/nfc_core/common"
         "${NERO_FIRMWARE_ROOT}/firmware/nfc_core/frontends/st25r3916"
         "${NERO_FIRMWARE_ROOT}/firmware/port/include"
         "${NERO_FIRMWARE_ROOT}/firmware/reader/src"
         "${CMAKE_CURRENT_SOURCE_DIR}/support")

target_compile_definitions(nero_reader_relay_host PRIVATE NERO_HOST_UNIT_TEST_HOOKS=1 NERO_CCID_USB_BUILD=1)
target_link_libraries(nero_reader_relay_host PUBLIC nero_host_hardening Threads::Threads)
nero_add_third_party_system_includes(nero_reader_relay_host)

add_executable(
  nero_firmware_tests
  "${NERO_FIRMWARE_ROOT}/firmware/nfc_core/common/nero_nfc_log.c"
  "${NERO_FIRMWARE_ROOT}/firmware/writer/src/writer_serial_cli.cpp"
  "${NERO_FIRMWARE_ROOT}/firmware/writer/src/nfc_runtime_mode_poll.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/support/writer_hal_utest_stub.cpp"
  test_nero_nfc_copy_bytes.cpp
  test_nfc_mode_line_scan.cpp
  test_nfc_print_utils.cpp
  test_nfc_print_utils_compile.c
  test_nfc_frontend.cpp
  test_nfc_tag_info.cpp
  test_nfc_pcsc_contactless.cpp
  test_nfc_ctap_codec.cpp
  test_nfc_ccid_frame.cpp
  test_nfc_storage_ndef.cpp
  test_reader_protocol_seams.cpp
  test_writer_payload.cpp
  test_reader_cbor.cpp
  test_reader_context.cpp
  test_reader_tags_ndef_print.cpp
  test_reader_ram_constrained.cpp
  test_reader_tags_ndef_decode.cpp
  test_reader_ccid_dispatch.cpp
  test_reader_security_key_transceive.cpp
  test_writer_serial_cli.cpp
  test_writer_type2_geometry.cpp
  test_nfc_ndef_tlv.cpp
  test_nfc_ndef_record_decode.cpp
  test_st25_iso15693_codec.cpp
  test_nero_nfc_limits.cpp)

target_include_directories(
  nero_firmware_tests
  PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/support"
          "${NERO_FIRMWARE_ROOT}/firmware/nfc_core/frontends/st25r3916")

target_link_libraries(nero_firmware_tests PRIVATE nero_under_test nero_reader_host nero_reader_relay_host
                                                   GTest::gtest_main)
target_compile_definitions(nero_firmware_tests PRIVATE NERO_HOST_UNIT_TEST_HOOKS=1 NERO_CCID_USB_BUILD=1)
set_source_files_properties(test_reader_ram_constrained.cpp PROPERTIES COMPILE_DEFINITIONS
                                                                               "NERO_RAM_CONSTRAINED=1")
target_compile_options(nero_firmware_tests PRIVATE -Wall -Wextra -Wpedantic)

gtest_discover_tests(
  nero_firmware_tests
  DISCOVERY_MODE PRE_TEST
  DISCOVERY_TIMEOUT 120
  PROPERTIES LABELS "host;firmware")
