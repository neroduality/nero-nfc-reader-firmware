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

#include "reader_context.h"

#include "nero_nfc_mem_util.h"
#include "reader_iso_dep_timing.h"

reader_context_t g_reader;

void reader_context_reset(reader_context_t *ctx) {
  if (ctx == NERO_NFC_NULL) {
    return;
  }
  nero_nfc_secure_clear(ctx->iso_dep.iblock_tx, sizeof(ctx->iso_dep.iblock_tx));
  nero_nfc_secure_clear(ctx->iso_dep.raw_rx, sizeof(ctx->iso_dep.raw_rx));
  nero_nfc_secure_clear(ctx->iso_dep.ats_data, sizeof(ctx->iso_dep.ats_data));
  nero_nfc_zero_bytes(ctx, sizeof(*ctx));
  ctx->iso_dep.fwi = (uint8_t)ISO_DEP_FWI_DEFAULT;
  ctx->iso_dep.fwt_us = reader_iso_dep_fwt_us_from_fwi((uint8_t)ISO_DEP_FWI_DEFAULT);
  ctx->iso_dep.pic_frame_max = NFC_ISO14443_FSC_MAX;
}
