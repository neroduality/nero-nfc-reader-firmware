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
 * writer_tag_write.cpp — public API wrappers for tag NDEF write paths.
 */

#include "writer_tag_write.h"
#include "writer_tag_write_internal.h"

#include <stdbool.h>

writer_type2_family_t writer_tag_identify_type2(void) {
  return writer_tag_write_identify_type2_family();
}

bool writer_tag_write_type2_ndef(writer_type2_family_t fam) {
  return writer_tag_write_type2_impl(fam);
}

bool writer_tag_write_type4_ndef(void) {
  return writer_tag_write_type4_impl();
}

bool writer_tag_write_type5_ndef(void) {
  return writer_tag_write_type5_impl();
}

bool writer_tag_type5_inventory(void) {
  return writer_tag_write_type5_inventory_step();
}
