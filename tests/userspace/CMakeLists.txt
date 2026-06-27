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

# Userspace-layer host unit tests: device detection, serial line pump.

set(_nero_userspace_test_sources
  test_userspace_bridge.cpp
  test_userspace_detect.cpp
  test_userspace_line_pump.cpp
  test_userspace_serial.cpp
  test_userspace_browser.cpp
  test_userspace_driver.cpp
  test_userspace_pcsc.cpp
  test_userspace_pcsc_tag_details.cpp
  test_userspace_writer_payload.cpp)
if(NERO_TESTS_HAVE_PCSC)
  list(APPEND _nero_userspace_test_sources test_userspace_pcsc_live.cpp)
endif()

add_executable(nero_userspace_tests ${_nero_userspace_test_sources})

target_include_directories(nero_userspace_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(nero_userspace_tests PRIVATE nero_under_test GTest::gtest_main Threads::Threads)
target_compile_options(nero_userspace_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(nero_userspace_tests PRIVATE NERO_HOST_UNIT_TEST_HOOKS=1)

gtest_discover_tests(
  nero_userspace_tests
  DISCOVERY_MODE PRE_TEST
  DISCOVERY_TIMEOUT 120
  PROPERTIES LABELS "host;userspace")
