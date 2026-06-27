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

# Compile-only C probes without CMake's "Performing Test … Failed" CHECK_* noise.

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
