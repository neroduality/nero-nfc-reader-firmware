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
 * Separate compilation-unit wrapper for writer_app.cpp.
 * See reader_app_impl.cpp for design rationale.
 *
 * writer_hal.cpp is NOT compiled here — nfc_hal.cpp provides all
 * writer_hal_* symbols for the combined link.
 */

#include "writer_app.cpp"
