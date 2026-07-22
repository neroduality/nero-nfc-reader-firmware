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

#include "reader_ccid_context.h"

#if defined(NERO_CCID_USB_BUILD)

#include "nero_nfc_app.h"
#include "nero_nfc_mem_util.h"
#include "nero_nfc_null.h"
#include "reader_ccid_cmd_codes.h"

reader_ccid_context_t* reader_ccid_context_active(void) {
  return nero_nfc_app_ccid(nero_nfc_app_active());
}

void reader_ccid_context_reset(reader_ccid_context_t* ctx) {
  if (ctx == NERO_NFC_NULL) {
    return;
  }
  nero_nfc_zero_bytes(ctx, sizeof(*ctx));
  ctx->tag_kind = READER_TAG_KIND_NONE;
  ctx->protocol_num = CCID_PROTOCOL_NUM_T1;
}

#else /* !NERO_CCID_USB_BUILD */

reader_ccid_context_t* reader_ccid_context_active(void) { return 0; }

void reader_ccid_context_reset(reader_ccid_context_t* ctx) { (void)ctx; }

#endif /* NERO_CCID_USB_BUILD */
