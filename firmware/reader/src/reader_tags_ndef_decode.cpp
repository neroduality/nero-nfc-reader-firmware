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

#include "reader_tags_ndef_decode.h"

#include "nfc_ndef_record_decode.h"

bool reader_tags_decode_uri_payload(const uint8_t *payload, uint32_t len, char *out,
                                    uint16_t out_cap) {
  return nfc_ndef_decode_uri_payload(payload, len, out, out_cap);
}

bool reader_tags_decode_text_payload(const uint8_t *payload, uint32_t len, char *out,
                                     uint16_t out_cap) {
  return nfc_ndef_decode_text_payload(payload, len, out, out_cap);
}
