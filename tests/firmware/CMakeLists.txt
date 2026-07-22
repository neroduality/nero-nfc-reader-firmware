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
    "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/reader/reader_context.c"
    "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/reader/reader_ccid_context.c"
    "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/reader/reader_tags_ndef_decode.c"
    "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/reader/reader_tags_ndef_print.c"
    "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/reader/reader_output.c"
    "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/reader/reader_ccid.c"
    "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/reader/reader_ccid_xfr.c"
    "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/reader/reader_ccid_bulk.c"
    "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/reader/reader_ccid_storage.c"
    "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/reader/reader_ccid_pn53x.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/support/reader_hal_utest_stub.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/support/reader_security_key_utest_stub.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/support/reader_tags_utest_stub.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/support/nfc_session_owner_utest_stub.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/support/reader_ccid_test_setup.c")

add_library(nero_reader_host OBJECT ${_nero_reader_host_sources})

target_include_directories(
  nero_reader_host
  PUBLIC "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src"
         "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/frontend/st25r3916"
         "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/port"
         "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/reader"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/frontend"
         "${CMAKE_CURRENT_SOURCE_DIR}/support")

target_compile_definitions(nero_reader_host PRIVATE NERO_HOST_UNIT_TEST_HOOKS=1 NERO_CCID_USB_BUILD=1)
target_link_libraries(nero_reader_host PUBLIC hardening Threads::Threads)
nero_add_third_party_system_includes(nero_reader_host)

set(_nero_reader_relay_host_sources
    "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/reader/reader_security_key_iso_dep_session.c"
    "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/reader/reader_security_key_iso_dep_transceive.c"
    "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/reader/reader_iso_dep_debug.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/support/reader_protocol_utest_stub.cpp")

add_library(nero_reader_relay_host OBJECT ${_nero_reader_relay_host_sources})

target_include_directories(
  nero_reader_relay_host
  PUBLIC "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src"
         "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/frontend/st25r3916"
         "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/port"
         "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/reader"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/frontend"
         "${CMAKE_CURRENT_SOURCE_DIR}/support")

target_compile_definitions(nero_reader_relay_host PRIVATE NERO_HOST_UNIT_TEST_HOOKS=1 NERO_CCID_USB_BUILD=1)
target_link_libraries(nero_reader_relay_host PUBLIC hardening Threads::Threads)
nero_add_third_party_system_includes(nero_reader_relay_host)

add_executable(
  nero_firmware_tests
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/core/nero_nfc_log.c"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/core/nero_nfc_platform.c"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/core/nero_nfc_board.c"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/core/nero_nfc_app.c"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/usb/nero_nfc_tinyusb_active.c"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/usb/ccid_usb_rx_assembly.c"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/reader/reader_tags_type2_geometry.c"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/frontend/st25r3916/st25r3916_iso14443a.c"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/frontend/st25r3916/st25r3916_iso14443a_uid.c"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/frontend/st25r3916/st25r3916_iso15693.c"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/frontend/st25r3916/st25r3916_runtime_timing.c"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/writer/writer_context.c"
  "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/writer/writer_serial_cli.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/support/nfc_runtime_mode_poll_stub.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/support/writer_hal_utest_stub.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/support/nero_nfc_platform_host_fake.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/support/nero_nfc_frontend_host_fake.c"
  test_nero_nfc_copy_bytes.cpp
  test_nero_nfc_platform_app.cpp
  test_nfc_mode_line_scan.cpp
  test_nfc_print_utils.cpp
  test_nfc_print_utils_compile.c
  test_nfc_frontend.cpp
  test_nfc_tag_info.cpp
  test_nfc_pcsc_contactless.cpp
  test_nfc_ctap_codec.cpp
  test_nfc_ccid_frame.cpp
  test_ccid_usb_rx_assembly.cpp
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
  test_reader_tags_type2_bounds.cpp
  test_nero_nfc_limits.cpp)

target_include_directories(
  nero_firmware_tests
  PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/support"
          "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/frontend/st25r3916"
          "${NERO_FIRMWARE_ROOT}/firmware/libraries/NeroNfc/src/writer")

target_link_libraries(nero_firmware_tests PRIVATE nero_under_test nero_reader_host nero_reader_relay_host
                                                   GTest::gtest_main)
nero_add_third_party_system_includes(nero_firmware_tests)
target_compile_definitions(
  nero_firmware_tests
  PRIVATE NERO_HOST_UNIT_TEST_HOOKS=1 NERO_CCID_USB_BUILD=1 NERO_NFC_BUILD_COMBINED=1
          NFC_FRONTEND_ID_ST25R3916=1)
set_source_files_properties(test_reader_ram_constrained.cpp PROPERTIES COMPILE_DEFINITIONS
                                                                               "NERO_RAM_CONSTRAINED=1")
target_compile_options(nero_firmware_tests PRIVATE -Wall -Wextra -Wpedantic)

gtest_discover_tests(
  nero_firmware_tests
  DISCOVERY_MODE PRE_TEST
  DISCOVERY_TIMEOUT 120
  PROPERTIES LABELS "host;firmware")
