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

// CCID TinyUSB bindings for Arduino Renesas (UNO R4 WiFi). Declares HAL
// reader_hal_ccid_*.

#include "ccid_usb_desc.h"
#include "nero_nfc_format.h"
#include "nero_nfc_mem_util.h"
#include "nfc_ccid_frame.h"
#include "reader_ccid.h"
#include "reader_hal.h"

#include <Arduino.h>

#if defined(NERO_CCID_USB_BUILD)

extern "C" {
#include "common/tusb_common.h"
#include "common/tusb_types.h"
#include "device/dcd.h"
#include "device/usbd.h"
#include "device/usbd_pvt.h"

#include <string.h>
}

#include "tusb.h"

enum {
  kCdcDbgStrMax = 128u,
  kCciddDbgOpenStrMax = 64u,
  kCciddDbgSendSkipStrMax = 48u,
  kCciddHeartbeatMs = 2000u,
  kCciddSendClaimSpinMax = 64000u,
  kCciddSendDeadlineCapMs = 5000u,
  kCciddDescTailMinBytes = 4u,
  kCciddEndpointCount = 3u,
  kCciddUsbServiceWaitUs = 25u,
  kCciddNotifySendSpinMax = 20000u,
  kCciddOpenStateEpsOk = 2u,
  kCciddOpenStateSuccess = 3u,
};

static constexpr uint16_t kRxMaxF = NERO_CCID_DESC_MAX_MESSAGE_LENGTH;

#ifndef NERO_CCID_ENABLE_FASTPATH_SLOT_STATUS
#define NERO_CCID_ENABLE_FASTPATH_SLOT_STATUS 0
#endif

CFG_TUSB_MEM_ALIGN static uint8_t s_ep_bulk_out_buf[NERO_CCID_BULK_EPSIZE];
CFG_TUSB_MEM_ALIGN static uint8_t s_bulk_in_work[NERO_CCID_BULK_EPSIZE];
#if NERO_CCID_ENABLE_FASTPATH_SLOT_STATUS
CFG_TUSB_MEM_ALIGN static uint8_t s_slot_status_fastpath[NFC_CCID_BULK_HEADER_LEN];
#endif

static uint8_t s_ep_bulk_out{};
static uint8_t s_ep_bulk_in{};
static uint8_t s_ep_interrupt{};
static uint8_t s_interface_number{};

static uint16_t s_rx_store_len{};
static volatile bool s_rx_pending{false};
static uint8_t s_rx_assembly[kRxMaxF];
static uint16_t s_rx_assembly_len{};
static uint16_t s_rx_assembly_expected{};

static volatile bool s_bulk_out_busy{false};
static volatile bool s_abort_request_pending{false};
static volatile uint8_t s_abort_request_slot{0};
static volatile uint8_t s_abort_request_seq{0};

/* ISR-safe debug counters — written in ISR/tud context, read from main loop. */
static volatile uint8_t s_dbg_open_state{0};   /* 0=never,1=entered,2=eps_ok,3=success */
static volatile uint8_t s_dbg_xfer_out{0};     /* incremented each time bulk-OUT xfer_cb fires */
static volatile uint8_t s_dbg_arm_out_fail{0}; /* bulk-OUT re-arm attempts that failed to queue */
static volatile uint8_t s_dbg_fastpath_ok{0};
static volatile uint8_t s_dbg_queue_ok{0};
static volatile uint8_t s_dbg_poll_recv{0};
static volatile uint8_t s_dbg_send_ok{0};
static volatile uint8_t s_dbg_send_fail{0};
static volatile uint8_t s_dbg_last_seq{0};
static bool s_dbg_printed{false};      /* printed once from main-loop context */
static uint32_t s_dbg_heartbeat_ms{0}; /* last heartbeat timestamp */

CFG_TUSB_MEM_ALIGN static uint8_t s_notify_xfer[NERO_CCID_INT_EPSIZE];

static bool ccid_edpt_xfer(uint8_t rhport, uint8_t ep_addr, uint8_t *buffer, uint16_t total_bytes) {
  return usbd_edpt_xfer(rhport, ep_addr, buffer, total_bytes);
}

/* Service TinyUSB while CCID waits for endpoint claims/completion. STM32WBA
 * DWC2 needs this for bulk-IN completion, and UNO Renesas also needs it to keep
 * CCID progress non-blocking under pcscd polling. */
static void ccid_usb_service_wait(void) {
  tud_task();
  delayMicroseconds(kCciddUsbServiceWaitUs);
}

/* Write debug text to CDC. Always attempts write; drops silently if FIFO full.
 */
#if defined(NERO_CCID_ONLY_BUILD)
static void cdc_dbg(const char *s) {
  (void)s;
}
#else
static void cdc_dbg(const char *s) {
  size_t len = 0u;
  if ((s == NERO_NFC_NULL) || !nero_nfc_bounded_strlen(s, kCdcDbgStrMax, &len) || (len == 0u) ||
      !tud_cdc_connected()) {
    return;
  }
  tud_cdc_write(s, len);
  tud_cdc_write_flush();
}
#endif

static bool queue_rx(unsigned xferred_bytes) {
  if (xferred_bytes == 0 || xferred_bytes > kRxMaxF || s_rx_pending) {
    return false;
  }

  s_rx_store_len = (uint16_t)xferred_bytes;
  s_rx_pending = true;
  s_dbg_queue_ok++;
  if (xferred_bytes > NFC_CCID_BULK_SEQ_OFFSET) {
    s_dbg_last_seq = s_rx_assembly[NFC_CCID_BULK_SEQ_OFFSET];
  }
  return true;
}

static void reset_rx_assembly() {
  s_rx_assembly_len = 0U;
  s_rx_assembly_expected = 0U;
}

static bool queue_rx_packet(uint32_t xferred_bytes) {
  size_t assembled_len = 0u;
  if (xferred_bytes == 0U || xferred_bytes > NERO_CCID_BULK_EPSIZE) {
    return false;
  }
  if (!nero_nfc_try_add_size((size_t)s_rx_assembly_len, (size_t)xferred_bytes, &assembled_len) ||
      assembled_len > kRxMaxF) {
    reset_rx_assembly();
    return false;
  }

  if (!nero_nfc_copy_bytes(s_rx_assembly, sizeof(s_rx_assembly), s_rx_assembly_len,
                           s_ep_bulk_out_buf, (size_t)xferred_bytes)) {
    reset_rx_assembly();
    return false;
  }
  s_rx_assembly_len = static_cast<uint16_t>(assembled_len);

  if (s_rx_assembly_expected == 0U && s_rx_assembly_len >= NFC_CCID_BULK_HEADER_LEN) {
    uint32_t const payload_len = nfc_ccid_u32_load_le(s_rx_assembly + 1);
    size_t frame_len = 0u;
    if (payload_len > NFC_CCID_MAX_XFR_PAYLOAD ||
        !nero_nfc_try_add_size((size_t)NFC_CCID_BULK_HEADER_LEN, (size_t)payload_len, &frame_len) ||
        frame_len > kRxMaxF) {
      reset_rx_assembly();
      return false;
    }
    s_rx_assembly_expected = static_cast<uint16_t>(frame_len);
  }

  if (s_rx_assembly_expected != 0U && s_rx_assembly_len > s_rx_assembly_expected) {
    reset_rx_assembly();
    return false;
  }

  if (s_rx_assembly_expected != 0U && s_rx_assembly_len == s_rx_assembly_expected) {
    return queue_rx(s_rx_assembly_expected);
  }

  if (xferred_bytes < NERO_CCID_BULK_EPSIZE) {
    reset_rx_assembly();
  }
  return false;
}

#if NERO_CCID_ENABLE_FASTPATH_SLOT_STATUS
static bool try_fastpath_slot_status(uint8_t rhport, uint32_t xferred_bytes) {
  if ((s_ep_bulk_in == 0U) || (xferred_bytes != NFC_CCID_BULK_HEADER_LEN) ||
      (s_ep_bulk_out_buf[0] != NFC_CCID_MSG_PC_TO_RDR_SLOTSTATUS) ||
      (s_ep_bulk_out_buf[NFC_CCID_BULK_SLOT_OFFSET] != 0U) ||
      (s_ep_bulk_out_buf[NFC_CCID_BULK_LEVEL_PARAM_OFFSET] != 0U) ||
      (s_ep_bulk_out_buf[NFC_CCID_BULK_LEVEL_PARAM2_OFFSET] != 0U) ||
      (s_ep_bulk_out_buf[NFC_CCID_BULK_LEVEL_PARAM3_OFFSET] != 0U) ||
      (nfc_ccid_u32_load_le(s_ep_bulk_out_buf + 1) != 0U)) {
    return false;
  }

  nero_nfc_zero_bytes(s_slot_status_fastpath, sizeof(s_slot_status_fastpath));
  s_slot_status_fastpath[0] = NFC_CCID_MSG_RDR_TO_PC_SLOTSTATUS;
  s_slot_status_fastpath[NFC_CCID_BULK_SEQ_OFFSET] = s_ep_bulk_out_buf[NFC_CCID_BULK_SEQ_OFFSET];
  s_slot_status_fastpath[NFC_CCID_BULK_LEVEL_PARAM_OFFSET] = reader_ccid_icc_status();

  if (!usbd_edpt_claim(rhport, s_ep_bulk_in)) {
    return false;
  }
  if (ccid_edpt_xfer(rhport, s_ep_bulk_in, s_slot_status_fastpath,
                     (uint16_t)sizeof(s_slot_status_fastpath))) {
    s_dbg_fastpath_ok++;
    s_dbg_last_seq = s_ep_bulk_out_buf[NFC_CCID_BULK_SEQ_OFFSET];
    return true;
  }

  usbd_edpt_release(rhport, s_ep_bulk_in);
  return false;
}
#endif

static void arm_bulk_out(uint8_t rhport) {
  if (s_ep_bulk_out == 0U || s_bulk_out_busy || s_rx_pending) {
    return;
  }

  dcd_int_disable(rhport);
  bool const claimed = usbd_edpt_claim(rhport, s_ep_bulk_out);
  bool const queued =
    claimed && ccid_edpt_xfer(rhport, s_ep_bulk_out, s_ep_bulk_out_buf, NERO_CCID_BULK_EPSIZE);
  if (!queued && claimed) {
    usbd_edpt_release(rhport, s_ep_bulk_out);
  }
  dcd_int_enable(rhport);

  if (queued) {
    s_bulk_out_busy = true;
  } else {
    s_dbg_arm_out_fail++;
  }
}

static bool notify_send(uint8_t rhport, uint8_t bm_slot) {
  if (s_ep_interrupt == 0U) {
    return false;
  }
  nero_nfc_zero_bytes(s_notify_xfer, sizeof(s_notify_xfer));
  s_notify_xfer[0] = NFC_CCID_MSG_RDR_TO_PC_NOTIFY_SLOT_CHANGE;
  s_notify_xfer[1] = bm_slot;

  unsigned spin = kCciddNotifySendSpinMax;
  while (--spin != 0) {
    bool const claimed = usbd_edpt_claim(rhport, s_ep_interrupt);
    bool const ok = claimed && ccid_edpt_xfer(rhport, s_ep_interrupt, s_notify_xfer,
                                              (uint16_t)NERO_CCID_INT_EPSIZE);
    if (!ok && claimed) {
      usbd_edpt_release(rhport, s_ep_interrupt);
    }
    if (ok) {
      while (usbd_edpt_busy(rhport, s_ep_interrupt) && --spin != 0) {
        ccid_usb_service_wait();
      }
      return true;
    }
    ccid_usb_service_wait();
  }
  return false;
}

static void nero_ccidd_init(void) {
  s_rx_store_len = 0;
  s_rx_pending = false;
  reset_rx_assembly();
  s_ep_bulk_out = s_ep_bulk_in = s_ep_interrupt = 0;
  s_bulk_out_busy = false;
}

static void nero_ccidd_reset(uint8_t rhport) {
  (void)rhport;
  s_rx_store_len = 0;
  s_rx_pending = false;
  reset_rx_assembly();
  s_ep_bulk_out = s_ep_bulk_in = s_ep_interrupt = 0;
  s_bulk_out_busy = false;
  s_dbg_open_state = 0;
  s_dbg_xfer_out = 0;
  s_dbg_arm_out_fail = 0;
  s_dbg_fastpath_ok = 0;
  s_dbg_queue_ok = 0;
  s_dbg_poll_recv = 0;
  s_dbg_send_ok = 0;
  s_dbg_send_fail = 0;
  s_dbg_last_seq = 0;
  s_dbg_printed = false;
  s_dbg_heartbeat_ms = 0;
}

static uint16_t nero_ccidd_open(uint8_t rhport, tusb_desc_interface_t const *desc_itf,
                                uint16_t max_len) {
  uint8_t const *desc_start = reinterpret_cast<uint8_t const *>(desc_itf);
  uint8_t const *p = tu_desc_next(desc_itf);
  uint8_t const *desc_end = desc_start + max_len;

  if ((desc_itf->bInterfaceClass != TUSB_CLASS_SMART_CARD) || (desc_itf->bInterfaceSubClass != 0) ||
      (desc_itf->bInterfaceProtocol != 0) || desc_itf->bNumEndpoints != kCciddEndpointCount) {
    return 0U;
  }

  s_dbg_open_state = 1; /* entered with correct class/subclass/protocol */

  while (((unsigned)(desc_end - p) > kCciddDescTailMinBytes) &&
         (tu_desc_type(p) != TUSB_DESC_ENDPOINT)) {
    p = tu_desc_next(p);
  }

  s_ep_bulk_out = s_ep_bulk_in = s_ep_interrupt = 0;
  s_interface_number = desc_itf->bInterfaceNumber;

  for (unsigned i = 0; i < kCciddEndpointCount && p < desc_end; i++) {
    if (tu_desc_type(p) != TUSB_DESC_ENDPOINT) {
      return 0U;
    }
    tusb_desc_endpoint_t const *ep = reinterpret_cast<tusb_desc_endpoint_t const *>(p);

    if (!usbd_edpt_open(rhport, ep)) {
      return 0U;
    }

    tusb_dir_t const dir = tu_edpt_dir(ep->bEndpointAddress);
    unsigned const xt = ep->bmAttributes.xfer;

    if (dir == TUSB_DIR_OUT) {
      s_ep_bulk_out = ep->bEndpointAddress;
    } else if (dir == TUSB_DIR_IN) {
      if (xt == TUSB_XFER_INTERRUPT) {
        s_ep_interrupt = ep->bEndpointAddress;
      } else if (xt == TUSB_XFER_BULK) {
        s_ep_bulk_in = ep->bEndpointAddress;
      }
    }
    p = tu_desc_next(p);
  }

  if ((s_ep_bulk_out == 0U) || (s_ep_bulk_in == 0U) || (s_ep_interrupt == 0U)) {
    return 0U;
  }

  s_dbg_open_state = kCciddOpenStateEpsOk; /* all 3 endpoints opened */

  s_bulk_out_busy = false;
  arm_bulk_out(rhport);

  s_dbg_open_state = kCciddOpenStateSuccess; /* arm_bulk_out called — fully open */

  return static_cast<uint16_t>(p - desc_start);
}

static bool nero_ccidd_control_xfer_cb(uint8_t rhport, uint8_t stage,
                                       tusb_control_request_t const *request) {
  if (stage != CONTROL_STAGE_SETUP) {
    return true;
  }
  uint8_t slot = 0;
  uint8_t seq = 0;
  if (nfc_ccid_control_abort_request_matches_slot(
        request->bmRequestType, request->bRequest, request->wValue, request->wIndex,
        request->wLength, s_interface_number, 0u, &slot, &seq)) {
    s_abort_request_slot = slot;
    s_abort_request_seq = seq;
    s_abort_request_pending = true;
    return tud_control_status(rhport, request);
  }
  return false;
}

static bool nero_ccidd_xfer_cb(uint8_t rhport, uint8_t ep_addr, xfer_result_t evt,
                               uint32_t xferred_bytes) {
  if (ep_addr == s_ep_bulk_out) {
    if (evt == XFER_RESULT_SUCCESS) {
#if NERO_CCID_ENABLE_FASTPATH_SLOT_STATUS
      if (!try_fastpath_slot_status(rhport, xferred_bytes)) {
        queue_rx_packet(xferred_bytes);
      }
#else
      queue_rx_packet(xferred_bytes);
#endif
    }
    s_bulk_out_busy = false;
    s_dbg_xfer_out++; /* count bulk-OUT completions (ISR-safe: 8-bit write on
                         Cortex-M) */
    arm_bulk_out(rhport);
    return true;
  }
  (void)xferred_bytes;
  return ep_addr == s_ep_interrupt;
}

#if CFG_TUSB_DEBUG >= CFG_TUD_LOG_LEVEL
static char const kCcName[] = "CCID-NERO";
#endif

#if defined(NERO_CCID_STM32_USB_BUILD)
/* Vendored TinyUSB (WBA65): usbd_class_driver_t always includes
 * name/deinit/xfer_isr. */
static const usbd_class_driver_t kNeroCciddDriver = {
#if CFG_TUSB_DEBUG >= CFG_TUD_LOG_LEVEL
  .name = kCcName,
#else
  .name = NERO_NFC_NULL,
#endif
  .init = nero_ccidd_init,
  .deinit = NERO_NFC_NULL,
  .reset = nero_ccidd_reset,
  .open = nero_ccidd_open,
  .control_xfer_cb = nero_ccidd_control_xfer_cb,
  .xfer_cb = nero_ccidd_xfer_cb,
  .xfer_isr = NERO_NFC_NULL,
  .sof = NERO_NFC_NULL,
};
#else
/* Arduino core TinyUSB (UNO R4): older usbd_class_driver_t without
 * deinit/xfer_isr. */
static const usbd_class_driver_t kNeroCciddDriver = {
#if CFG_TUSB_DEBUG >= CFG_TUD_LOG_LEVEL
  .name = kCcName,
#endif
  .init = nero_ccidd_init,
  .reset = nero_ccidd_reset,
  .open = nero_ccidd_open,
  .control_xfer_cb = nero_ccidd_control_xfer_cb,
  .xfer_cb = nero_ccidd_xfer_cb,
  .sof = NERO_NFC_NULL,
};
#endif

extern "C" {

usbd_class_driver_t const *usbd_app_driver_get_cb(uint8_t *driver_count) {
  if (driver_count != NERO_NFC_NULL) {
    *driver_count = 1;
  }
  return &kNeroCciddDriver;
}

} /* extern "C" — TinyUSB C callbacks only above */

bool reader_hal_ccid_recv(uint8_t *buf, uint16_t *len_io) {
  if ((buf == NERO_NFC_NULL) || (len_io == NERO_NFC_NULL)) {
    return false;
  }
  uint16_t out_cap = *len_io;
  *len_io = 0U;

  if (!s_rx_pending && s_ep_bulk_out != 0U && !s_bulk_out_busy) {
    arm_bulk_out(0);
  }

  /* Heartbeat: print alive message every 2 s so we can verify CDC is working.
   */
  {
    uint32_t now = (uint32_t)millis();
    if ((now - s_dbg_heartbeat_ms) >= kCciddHeartbeatMs) {
      s_dbg_heartbeat_ms = now;
      char tmp[kCdcDbgStrMax];
      nero_nfc_snprintf(tmp, sizeof(tmp),
                        "[CCID] alive ms=%lu open=%u out=%u fast=%u queued=%u recv=%u "
                        "send_ok=%u "
                        "send_fail=%u arm_fail=%u seq=%u\r\n",
                        (unsigned long)now, s_dbg_open_state, s_dbg_xfer_out, s_dbg_fastpath_ok,
                        s_dbg_queue_ok, s_dbg_poll_recv, s_dbg_send_ok, s_dbg_send_fail,
                        s_dbg_arm_out_fail, s_dbg_last_seq);
      cdc_dbg(tmp);
    }
  }

  /* Print CCID open state once per open, from main-loop context. */
  if (!s_dbg_printed && s_dbg_open_state > 0) {
    char tmp[kCciddDbgOpenStrMax];
    nero_nfc_snprintf(tmp, sizeof(tmp), "[CCID] open=%u ep_out=%02X ep_in=%02X ep_int=%02X\r\n",
                      s_dbg_open_state, s_ep_bulk_out, s_ep_bulk_in, s_ep_interrupt);
    cdc_dbg(tmp);
    s_dbg_printed = true;
  }

  if (!s_rx_pending) {
    return false;
  }

  unsigned copy_n = static_cast<unsigned>(s_rx_store_len);
  if (out_cap == 0U) {
    return false;
  }
  if (copy_n > static_cast<unsigned>(out_cap)) {
    return false;
  }
  if (!nero_nfc_copy_bytes(buf, out_cap, 0u, s_rx_assembly, copy_n)) {
    return false;
  }
  *len_io = (uint16_t)copy_n;
  s_dbg_poll_recv++;
  if (nero_nfc_span_ok(NFC_CCID_BULK_SEQ_OFFSET, 1u, copy_n)) {
    s_dbg_last_seq = buf[NFC_CCID_BULK_SEQ_OFFSET];
  }

  {
    char tmp[kCciddDbgOpenStrMax];
    nero_nfc_snprintf(
      tmp, sizeof(tmp), "[CCID] recv len=%u seq=%u out_cnt=%u\r\n", copy_n,
      nero_nfc_span_ok(NFC_CCID_BULK_SEQ_OFFSET, 1u, copy_n) ? buf[NFC_CCID_BULK_SEQ_OFFSET] : 0U,
      s_dbg_xfer_out);
    cdc_dbg(tmp);
  }

  s_rx_pending = false;
  reset_rx_assembly();
  if (s_ep_bulk_out != 0U && !s_bulk_out_busy) {
    arm_bulk_out(0);
  }
  return true;
}

bool reader_hal_ccid_peek(const uint8_t **buf_out, uint16_t *len_out) {
  if ((buf_out == NERO_NFC_NULL) || (len_out == NERO_NFC_NULL)) {
    return false;
  }
  *buf_out = NERO_NFC_NULL;
  *len_out = 0U;
  if (!s_rx_pending && s_ep_bulk_out != 0U && !s_bulk_out_busy) {
    arm_bulk_out(0);
  }
  if (!s_rx_pending) {
    return false;
  }
  *buf_out = s_rx_assembly;
  *len_out = s_rx_store_len;
  s_dbg_poll_recv++;
  if (s_rx_store_len > NFC_CCID_BULK_SEQ_OFFSET) {
    s_dbg_last_seq = s_rx_assembly[NFC_CCID_BULK_SEQ_OFFSET];
  }
  return true;
}

void reader_hal_ccid_release(void) {
  if (!s_rx_pending) {
    return;
  }
  s_rx_pending = false;
  reset_rx_assembly();
  if (s_ep_bulk_out != 0U && !s_bulk_out_busy) {
    arm_bulk_out(0);
  }
}

static bool ccid_send_one_chunk(const uint8_t *src, unsigned chunk, uint32_t deadline) {
  if (!nero_nfc_copy_bytes(s_bulk_in_work, sizeof(s_bulk_in_work), 0u, src, chunk)) {
    s_dbg_send_fail++;
    return false;
  }

  unsigned const w_cap = kCciddSendClaimSpinMax;
  unsigned w = w_cap;
  bool xfer_ok = false;
  while (--w != 0) {
    if ((int32_t)(millis() - deadline) > 0) {
      s_dbg_send_fail++;
      cdc_dbg("[CCID] send TIMEOUT (claim)\r\n");
      return false;
    }
    bool const claimed = usbd_edpt_claim(0, s_ep_bulk_in);
    bool const ok =
      claimed && ccid_edpt_xfer(0, s_ep_bulk_in, s_bulk_in_work, static_cast<uint16_t>(chunk));
    if (!ok && claimed) {
      usbd_edpt_release(0, s_ep_bulk_in);
    }
    if (ok) {
      xfer_ok = true;
      break;
    }
    ccid_usb_service_wait();
  }
  if (!xfer_ok) {
    s_dbg_send_fail++;
    cdc_dbg("[CCID] send FAIL claim exhausted\r\n");
    return false;
  }

  while (usbd_edpt_busy(0, s_ep_bulk_in)) {
    ccid_usb_service_wait();
    if ((int32_t)(millis() - deadline) > 0) {
      s_dbg_send_fail++;
      cdc_dbg("[CCID] send TIMEOUT (busy)\r\n");
      return false;
    }
  }
  return true;
}

bool reader_hal_ccid_send(const uint8_t *buf, uint16_t len, uint32_t deadline_ms) {
  if ((buf == NERO_NFC_NULL) || (len == 0U) || (s_ep_bulk_in == 0U)) {
    s_dbg_send_fail++;
    {
      char tmp[kCciddDbgSendSkipStrMax];
      nero_nfc_snprintf(tmp, sizeof(tmp), "[CCID] send SKIP ep_in=%02X\r\n", s_ep_bulk_in);
      cdc_dbg(tmp);
    }
    return false;
  }

  {
    char tmp[kCciddDbgOpenStrMax];
    nero_nfc_snprintf(tmp, sizeof(tmp), "[CCID] send len=%u seq=%u ep_in=%02X\r\n", len,
                      (len > NFC_CCID_BULK_SEQ_OFFSET) ? buf[NFC_CCID_BULK_SEQ_OFFSET] : 0U,
                      s_ep_bulk_in);
    cdc_dbg(tmp);
  }

  /* Cap effective deadline: pcscd's ReadUSB timeout is 3 s (initial) or 100 ms
   * (retries). A 5-second cap prevents blocking the main loop indefinitely on
   * hardware failures. */
  if (deadline_ms > kCciddSendDeadlineCapMs) {
    deadline_ms = kCciddSendDeadlineCapMs;
  }

  uint32_t deadline = millis() + deadline_ms;
  unsigned off = 0;

  while (off < static_cast<unsigned>(len)) {
    if ((int32_t)(millis() - deadline) > 0) {
      s_dbg_send_fail++;
      cdc_dbg("[CCID] send TIMEOUT (outer)\r\n");
      return false;
    }
    unsigned chunk = ((static_cast<unsigned>(len - off)) <= NERO_CCID_BULK_EPSIZE)
                       ? static_cast<unsigned>(len - off)
                       : static_cast<unsigned>(NERO_CCID_BULK_EPSIZE);

    if (!ccid_send_one_chunk(buf + off, chunk, deadline)) {
      return false;
    }

    off += chunk;
  }

  s_dbg_send_ok++;
  cdc_dbg("[CCID] send complete\r\n");
  return true;
}

void reader_hal_ccid_notify_slot_change(bool card_present) {
  if (!tud_ready()) {
    return;
  }
  /* bmSlotICCState slot 0 bits: bit1=card-present-state, bit0=changed-flag.
   * Card arrived : bit1=1 present, bit0=1 changed → 0x03
   * Card left    : bit1=0 absent,  bit0=1 changed → 0x01  (was 0x02 =
   * present+no-change) */
  uint8_t bm =
    card_present ? NFC_CCID_NOTIFY_SLOT_PRESENT_CHANGED : NFC_CCID_NOTIFY_SLOT_ABSENT_CHANGED;
  (void)notify_send(0, bm);
}

bool reader_hal_ccid_abort_request_pending(uint8_t *slot_out, uint8_t *seq_out) {
  if (slot_out != NERO_NFC_NULL) {
    *slot_out = 0U;
  }
  if (seq_out != NERO_NFC_NULL) {
    *seq_out = 0U;
  }
  if (!s_abort_request_pending) {
    return false;
  }
  if (slot_out != NERO_NFC_NULL) {
    *slot_out = s_abort_request_slot;
  }
  if (seq_out != NERO_NFC_NULL) {
    *seq_out = s_abort_request_seq;
  }
  return true;
}

void reader_hal_ccid_clear_abort_request(uint8_t slot, uint8_t seq) {
  if (s_abort_request_pending && s_abort_request_slot == slot && s_abort_request_seq == seq) {
    s_abort_request_pending = false;
  }
}

#elif !defined(NERO_CCID_USB_BUILD)

bool reader_hal_ccid_recv(uint8_t *buf, uint16_t *len_io) {
  (void)buf;
  if (len_io != NERO_NFC_NULL) {
    *len_io = 0U;
  }
  return false;
}

bool reader_hal_ccid_peek(const uint8_t **buf_out, uint16_t *len_out) {
  if (buf_out != NERO_NFC_NULL) {
    *buf_out = NERO_NFC_NULL;
  }
  if (len_out != NERO_NFC_NULL) {
    *len_out = 0U;
  }
  return false;
}

void reader_hal_ccid_release(void) {}

bool reader_hal_ccid_send(const uint8_t *buf, uint16_t len, uint32_t deadline_ms) {
  (void)buf;
  (void)len;
  (void)deadline_ms;
  return false;
}

void reader_hal_ccid_notify_slot_change(bool card_present) {
  (void)card_present;
}

bool reader_hal_ccid_abort_request_pending(uint8_t *slot_out, uint8_t *seq_out) {
  if (slot_out != NERO_NFC_NULL) {
    *slot_out = 0U;
  }
  if (seq_out != NERO_NFC_NULL) {
    *seq_out = 0U;
  }
  return false;
}

void reader_hal_ccid_clear_abort_request(uint8_t slot, uint8_t seq) {
  (void)slot;
  (void)seq;
}

#endif /* NERO_CCID_USB_BUILD */
