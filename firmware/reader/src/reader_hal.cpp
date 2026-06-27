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

/*
Thin compile stub — board HAL body lives in port/<TARGET>/ (Makefile
NFC_BOARD_READER_HAL_INC).
*/

#define NFC_DETAIL_STRINGIFY(x) #x
#define NFC_STRINGIFY(x) NFC_DETAIL_STRINGIFY(x)
#ifndef NFC_BOARD_READER_HAL_INC
#error Missing NFC_BOARD_READER_HAL_INC (board fragment + Makefile BOARD_READER_HAL_UNIT)
#endif
#include NFC_STRINGIFY(NFC_BOARD_READER_HAL_INC)
