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

# Mark vendored trees as SYSTEM includes (host unit-test / lint CMake targets only).
# Requires NERO_FIRMWARE_ROOT in the including CMakeLists.txt.

function(nero_add_third_party_system_includes target)
  if(NOT TARGET ${target})
    message(FATAL_ERROR "nero_add_third_party_system_includes: no target ${target}")
  endif()
  if(NOT DEFINED NERO_FIRMWARE_ROOT)
    message(FATAL_ERROR "nero_add_third_party_system_includes: NERO_FIRMWARE_ROOT is not set")
  endif()

  set(_root "${NERO_FIRMWARE_ROOT}/third-party")
  foreach(
    _dir
    "${_root}/ST25R3916/src"
    "${_root}/NFC-RFAL/src"
    "${_root}/tinyusb/src")
    if(EXISTS "${_dir}")
      target_include_directories(${target} SYSTEM PUBLIC "${_dir}")
    endif()
  endforeach()
endfunction()
