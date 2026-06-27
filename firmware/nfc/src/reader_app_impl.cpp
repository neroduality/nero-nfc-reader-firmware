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
 * Separate compilation-unit wrapper for reader_app.cpp.
 *
 * Compiling as its own TU (rather than via --library) ensures that:
 *   - static-inline bus functions in st25r3916_bus.h get their own copy
 *     per TU → no ODR conflicts with writer_app_impl.cpp.
 *   - static global state in reader_app.cpp stays separate from writer state.
 *   - reader_hal.cpp is NOT compiled here — nfc_hal.cpp provides all
 *     reader_hal_* symbols for the combined link.
 *
 * reader_app.cpp is found via compiler include path (-Ifirmware/reader/src),
 * injected as absolute paths for the combined sketch
 * (make/target-arduino_uno_r4wifi.mk).
 */

#include "reader_app.cpp"
