// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2026 Nero Duality, LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include "nero_nfc_null.h"

#if defined(__cplusplus)
#if __cplusplus >= 201703L
#define NERO_NFC_NODISCARD [[nodiscard]]
#define NERO_NFC_MAYBE_UNUSED [[maybe_unused]]
#else
#define NERO_NFC_NODISCARD
#define NERO_NFC_MAYBE_UNUSED
#endif
#define NERO_NFC_UNREACHABLE() __builtin_unreachable()
#define NERO_NFC_COUNTED_BY(N)
#define NERO_NFC_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L
#define NERO_NFC_NODISCARD [[nodiscard]]
#define NERO_NFC_MAYBE_UNUSED [[maybe_unused]]
#define NERO_NFC_UNREACHABLE() unreachable()
#define NERO_NFC_COUNTED_BY(N) [[counted_by(N)]]
#define NERO_NFC_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#else
#define NERO_NFC_NODISCARD
#define NERO_NFC_MAYBE_UNUSED
#define NERO_NFC_UNREACHABLE() __builtin_unreachable()
#define NERO_NFC_COUNTED_BY(N)
#define NERO_NFC_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#endif
