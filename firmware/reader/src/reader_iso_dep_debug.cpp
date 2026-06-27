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

#include "reader_iso_dep_debug.h"

#include "nero_nfc_null.h"
#include "reader_context.h"
#include "reader_output.h"

#include <stdint.h>
#include "nero_nfc_format.h"

enum {
  kReaderIsoDepIrqByteMask = 0xFFu,
  kReaderIsoDepIrqShiftTimer = 8u,
  kReaderIsoDepIrqShiftErr = 16u,
  kReaderIsoDepIrqShiftTarget = 24u,
};

void reader_iso_dep_debug_dump(const char *label, const uint8_t *buf, uint16_t len,
                               uint16_t max_show) {
#if !defined(NFC_DEBUG_ISO_DEP) || !NFC_DEBUG_ISO_DEP
  (void)label;
  (void)buf;
  (void)len;
  (void)max_show;
  return;
#else
  uint16_t show = len;

  if ((g_iso_dep_trace == 0u) || (label == NERO_NFC_NULL) || (buf == NERO_NFC_NULL)) {
    return;
  }
  if (show > max_show) {
    show = max_show;
  }
  nero_nfc_log_write("[ISO-DEP] ");
  nero_nfc_log_write(label);
  nero_nfc_log_write(" byte_len=");
  do {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(len));
    nero_nfc_log_write(ndc);
  } while (0);
  nero_nfc_log_write(" hex");
  if (len > max_show) {
    nero_nfc_log_write("_first");
  }
  nero_nfc_log_write("=");
  for (uint16_t i = 0u; i < show; i++) {
    nero_nfc_log_putc(' ');
    nero_nfc_log_hex_u8(buf[i]);
  }
  if (len > max_show) {
    nero_nfc_log_write(" ...(+");
    do {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)((len - max_show)));
      nero_nfc_log_write(ndc);
    } while (0);
    nero_nfc_log_write(" more)");
  }
  nero_nfc_log_write("\r\n");
#endif
}

void reader_iso_dep_debug_dump_irq_u32(const char *label, uint32_t irqs) {
  if (g_iso_dep_trace == 0u) {
    return;
  }
  nero_nfc_log_write("[ISO-DEP] ");
  nero_nfc_log_write(label);
  nero_nfc_log_write(" main=0x");
  do {
    char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
    (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X",
                            (unsigned)(uint8_t)(irqs & kReaderIsoDepIrqByteMask));
    nero_nfc_log_write(nhx);
  } while (0);
  nero_nfc_log_write(" timer=0x");
  do {
    char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
    (void)nero_nfc_snprintf(
      nhx, sizeof nhx, "%02X",
      (unsigned)(uint8_t)((irqs >> kReaderIsoDepIrqShiftTimer) & kReaderIsoDepIrqByteMask));
    nero_nfc_log_write(nhx);
  } while (0);
  nero_nfc_log_write(" err=0x");
  do {
    char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
    (void)nero_nfc_snprintf(
      nhx, sizeof nhx, "%02X",
      (unsigned)(uint8_t)((irqs >> kReaderIsoDepIrqShiftErr) & kReaderIsoDepIrqByteMask));
    nero_nfc_log_write(nhx);
  } while (0);
  nero_nfc_log_write(" target=0x");
  do {
    char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
    (void)nero_nfc_snprintf(
      nhx, sizeof nhx, "%02X",
      (unsigned)(uint8_t)((irqs >> kReaderIsoDepIrqShiftTarget) & kReaderIsoDepIrqByteMask));
    nero_nfc_log_write(nhx);
  } while (0);
  nero_nfc_log_write("\r\n");
}

void reader_iso_dep_debug_dump_xcvr_diag(uint16_t tx_len, uint16_t timeout_ms, int rlen) {
  const nfc_frontend_transceive_diag_t *d = &g_iso_dep_last_xcvr_diag;

  if (g_iso_dep_trace == 0u) {
    return;
  }
  nero_nfc_log_write("[ISO-DEP] XCVR tx_len=");
  do {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(tx_len));
    nero_nfc_log_write(ndc);
  } while (0);
  nero_nfc_log_write(" timeout_ms=");
  do {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(timeout_ms));
    nero_nfc_log_write(ndc);
  } while (0);
  nero_nfc_log_write(" txe=");
  nero_nfc_log_write(d->got_txe ? "1" : "0");
  nero_nfc_log_write(" rxe=");
  nero_nfc_log_write(d->got_rxe ? "1" : "0");
  nero_nfc_log_write(" nre=");
  nero_nfc_log_write(d->got_nre ? "1" : "0");
  nero_nfc_log_write(" rlen=");
  do {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(ndc, sizeof ndc, "%d", (int)(int32_t)(rlen));
    nero_nfc_log_write(ndc);
  } while (0);
  nero_nfc_log_write("\r\n");
  reader_iso_dep_debug_dump_irq_u32("XCVR irq_tx", d->tx_irq_status);
  reader_iso_dep_debug_dump_irq_u32("XCVR irq_final", d->final_irq_status);
}
