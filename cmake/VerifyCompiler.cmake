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

# Host-side ISO C23 probes for unit-test C objects (MCU firmware stays on gnu11).

include("${CMAKE_CURRENT_LIST_DIR}/NeroSilentProbe.cmake")

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
