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

#include "writer_context.h"

#include "nero_nfc_app.h"
#include "nero_nfc_mem_util.h"
#include "nero_nfc_null.h"
#include "writer_payload.h"

writer_context_t* writer_context_active(void) {
  return nero_nfc_app_writer(nero_nfc_app_active());
}

void writer_context_reset(writer_context_t* ctx) {
  nfc_frontend_t* frontend;
  if (ctx == NERO_NFC_NULL) {
    return;
  }
  frontend = ctx->frontend;
  nero_nfc_zero_bytes(ctx, sizeof(*ctx));
  ctx->frontend = frontend;
  writer_payload_default(&ctx->payload);
}
