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
#include "ccid_usb_rx_assembly.h"
#include "ccid_usb_tx.h"
#include "nero_nfc_format.h"
#include "nero_nfc_mem_util.h"
#include "nero_nfc_null.h"
#include "nfc_ccid_frame.h"
#include "reader_ccid.h"
#include "reader_ccid_context.h"
#include "reader_hal.h"

#if defined(NERO_CCID_USB_BUILD)

#include "common/tusb_common.h"
#include "common/tusb_types.h"
#include "device/dcd.h"
#include "device/usbd.h"
#include "device/usbd_pvt.h"

#include <string.h>

#include "tusb.h"

enum {
  K_CDC_DBG_STR_MAX = 128u,
  K_CCIDD_DBG_OPEN_STR_MAX = 64u,
  K_CCIDD_DBG_SEND_SKIP_STR_MAX = 48u,
  K_CCIDD_HEARTBEAT_MS = 2000u,
  K_CCIDD_SEND_CLAIM_SPIN_MAX = 64000u,
  K_CCIDD_SEND_DEADLINE_CAP_MS = 5000u,
  K_CCIDD_DESC_TAIL_MIN_BYTES = 4u,
  K_CCIDD_ENDPOINT_COUNT = 3u,
  K_CCIDD_USB_SERVICE_WAIT_US = 25u,
  K_CCIDD_NOTIFY_SEND_SPIN_MAX = 20000u,
  K_CCIDD_OPEN_STATE_EPS_OK = 2u,
  K_CCIDD_OPEN_STATE_SUCCESS = 3u,
};

enum { K_RX_MAX_F = NERO_CCID_DESC_MAX_MESSAGE_LENGTH };

#ifndef NERO_CCID_ENABLE_FASTPATH_SLOT_STATUS
#define NERO_CCID_ENABLE_FASTPATH_SLOT_STATUS 0
#endif

/*
 * TinyUSB starts before Arduino setup() on UNO R4 and remains alive across
 * application unbind/rebind. Its endpoint state must therefore have process
 * lifetime rather than live inside the currently bound NFC application.
 */
typedef struct {
  uint8_t ep_bulk_out_buf[NERO_CCID_BULK_EPSIZE];
  uint8_t bulk_in_work[NERO_CCID_BULK_EPSIZE];
  uint8_t slot_status_fastpath[NFC_CCID_BULK_HEADER_LEN];
  uint8_t notify_xfer[NERO_CCID_INT_EPSIZE];
  uint8_t ep_bulk_out;
  uint8_t ep_bulk_in;
  uint8_t ep_interrupt;
  uint8_t interface_number;
  uint16_t rx_store_len;
  volatile bool rx_pending;
  ccid_usb_rx_assembly_t rx_assembly;
  volatile bool bulk_out_busy;
  volatile bool abort_request_pending;
  volatile uint8_t abort_request_slot;
  volatile uint8_t abort_request_seq;
  volatile uint8_t dbg_open_state;
  volatile uint8_t dbg_xfer_out;
  volatile uint8_t dbg_arm_out_fail;
  volatile uint8_t dbg_fastpath_ok;
  volatile uint8_t dbg_queue_ok;
  volatile uint8_t dbg_poll_recv;
  volatile uint8_t dbg_send_ok;
  volatile uint8_t dbg_send_fail;
  volatile uint8_t dbg_last_seq;
  bool dbg_printed;
  uint32_t dbg_heartbeat_ms;
} ccid_usb_runtime_t;

CFG_TUSB_MEM_ALIGN static ccid_usb_runtime_t g_ccid_usb_runtime;

#define s_ep_bulk_out_buf (g_ccid_usb_runtime.ep_bulk_out_buf)
#define s_bulk_in_work (g_ccid_usb_runtime.bulk_in_work)
#define s_slot_status_fastpath (g_ccid_usb_runtime.slot_status_fastpath)
#define s_notify_xfer (g_ccid_usb_runtime.notify_xfer)
#define s_ep_bulk_out (g_ccid_usb_runtime.ep_bulk_out)
#define s_ep_bulk_in (g_ccid_usb_runtime.ep_bulk_in)
#define s_ep_interrupt (g_ccid_usb_runtime.ep_interrupt)
#define s_interface_number (g_ccid_usb_runtime.interface_number)
#define s_rx_store_len (g_ccid_usb_runtime.rx_store_len)
#define s_rx_pending (g_ccid_usb_runtime.rx_pending)
#define s_rx_assembly (g_ccid_usb_runtime.rx_assembly)
#define s_bulk_out_busy (g_ccid_usb_runtime.bulk_out_busy)
#define s_abort_request_pending (g_ccid_usb_runtime.abort_request_pending)
#define s_abort_request_slot (g_ccid_usb_runtime.abort_request_slot)
#define s_abort_request_seq (g_ccid_usb_runtime.abort_request_seq)
#define s_dbg_open_state (g_ccid_usb_runtime.dbg_open_state)
#define s_dbg_xfer_out (g_ccid_usb_runtime.dbg_xfer_out)
#define s_dbg_arm_out_fail (g_ccid_usb_runtime.dbg_arm_out_fail)
#define s_dbg_fastpath_ok (g_ccid_usb_runtime.dbg_fastpath_ok)
#define s_dbg_queue_ok (g_ccid_usb_runtime.dbg_queue_ok)
#define s_dbg_poll_recv (g_ccid_usb_runtime.dbg_poll_recv)
#define s_dbg_send_ok (g_ccid_usb_runtime.dbg_send_ok)
#define s_dbg_send_fail (g_ccid_usb_runtime.dbg_send_fail)
#define s_dbg_last_seq (g_ccid_usb_runtime.dbg_last_seq)
#define s_dbg_printed (g_ccid_usb_runtime.dbg_printed)
#define s_dbg_heartbeat_ms (g_ccid_usb_runtime.dbg_heartbeat_ms)

static bool ccid_usb_context_ready(void) {
  return reader_ccid_context_active() != NERO_NFC_NULL;
}

static bool ccid_edpt_xfer(uint8_t rhport, uint8_t ep_addr, uint8_t* buffer,
                           uint16_t total_bytes) {
  return usbd_edpt_xfer(rhport, ep_addr, buffer, total_bytes);
}

/* Service TinyUSB while CCID waits for endpoint claims/completion. STM32WBA
 * DWC2 needs this for bulk-IN completion, and UNO Renesas also needs it to keep
 * CCID progress non-blocking under pcscd polling. */
static void ccid_usb_service_wait(void) {
  tud_task();
  reader_hal_delay_us(K_CCIDD_USB_SERVICE_WAIT_US);
}

/* Write debug text to CDC. Always attempts write; drops silently if FIFO full.
 */
#if defined(NERO_CCID_ONLY_BUILD)
static void cdc_dbg(const char* s) { (void)s; }
#else
static void cdc_dbg(const char* s) {
  size_t len = 0u;
  if ((s == NERO_NFC_NULL) ||
      !nero_nfc_bounded_strlen(s, K_CDC_DBG_STR_MAX, &len) || (len == 0u) ||
      !tud_cdc_connected()) {
    return;
  }
  tud_cdc_write(s, len);
  tud_cdc_write_flush();
}
#endif

static bool queue_rx(unsigned xferred_bytes) {
  if (xferred_bytes == 0 || xferred_bytes > K_RX_MAX_F || s_rx_pending) {
    return false;
  }

  s_rx_store_len = (uint16_t)(xferred_bytes);
  s_rx_pending = true;
  s_dbg_queue_ok++;
  if (xferred_bytes > NFC_CCID_BULK_SEQ_OFFSET) {
    s_dbg_last_seq = s_rx_assembly.data[NFC_CCID_BULK_SEQ_OFFSET];
  }
  return true;
}

static void reset_rx_assembly(void) {
  ccid_usb_rx_assembly_reset(&s_rx_assembly);
}

static bool queue_rx_packet(uint32_t xferred_bytes) {
  if (xferred_bytes > UINT16_MAX) {
    reset_rx_assembly();
    return false;
  }
  const ccid_usb_rx_feed_result_t result = ccid_usb_rx_assembly_feed(
      &s_rx_assembly, s_ep_bulk_out_buf, (uint16_t)(xferred_bytes),
      NERO_CCID_BULK_EPSIZE);
  if (result == CCID_USB_RX_READY) {
    if (queue_rx(s_rx_assembly.len)) {
      return true;
    }
    reset_rx_assembly();
  }
  return false;
}

#if NERO_CCID_ENABLE_FASTPATH_SLOT_STATUS
static bool try_fastpath_slot_status(uint8_t rhport, uint32_t xferred_bytes) {
  if ((reader_ccid_context_active() == NERO_NFC_NULL) || (s_ep_bulk_in == 0U) ||
      (xferred_bytes != NFC_CCID_BULK_HEADER_LEN) ||
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
  s_slot_status_fastpath[NFC_CCID_BULK_SEQ_OFFSET] =
      s_ep_bulk_out_buf[NFC_CCID_BULK_SEQ_OFFSET];
  s_slot_status_fastpath[NFC_CCID_BULK_LEVEL_PARAM_OFFSET] =
      reader_ccid_icc_status();

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
  bool const k_claimed = usbd_edpt_claim(rhport, s_ep_bulk_out);
  bool const k_queued =
      k_claimed && ccid_edpt_xfer(rhport, s_ep_bulk_out, s_ep_bulk_out_buf,
                                  NERO_CCID_BULK_EPSIZE);
  if (!k_queued && k_claimed) {
    usbd_edpt_release(rhport, s_ep_bulk_out);
  }
  dcd_int_enable(rhport);

  if (k_queued) {
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

  unsigned spin = K_CCIDD_NOTIFY_SEND_SPIN_MAX;
  while (--spin != 0) {
    bool const k_claimed = usbd_edpt_claim(rhport, s_ep_interrupt);
    bool const k_ok =
        k_claimed && ccid_edpt_xfer(rhport, s_ep_interrupt, s_notify_xfer,
                                    (uint16_t)(NERO_CCID_INT_EPSIZE));
    if (!k_ok && k_claimed) {
      usbd_edpt_release(rhport, s_ep_interrupt);
    }
    if (k_ok) {
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

static uint16_t nero_ccidd_open(uint8_t rhport,
                                tusb_desc_interface_t const* desc_itf,
                                uint16_t max_len) {
  if (!ccid_usb_context_ready() || (desc_itf == NERO_NFC_NULL)) {
    return 0U;
  }
  const uint8_t* desc_start = (uint8_t const*)(desc_itf);
  uint8_t const* p = tu_desc_next(desc_itf);
  uint8_t const* desc_end = desc_start + max_len;

  if ((desc_itf->bInterfaceClass != TUSB_CLASS_SMART_CARD) ||
      (desc_itf->bInterfaceSubClass != 0) ||
      (desc_itf->bInterfaceProtocol != 0) ||
      desc_itf->bNumEndpoints != K_CCIDD_ENDPOINT_COUNT) {
    return 0U;
  }

  s_dbg_open_state = 1; /* entered with correct class/subclass/protocol */

  while (((unsigned)(desc_end - p) > K_CCIDD_DESC_TAIL_MIN_BYTES) &&
         (tu_desc_type(p) != TUSB_DESC_ENDPOINT)) {
    p = tu_desc_next(p);
  }

  s_ep_bulk_out = s_ep_bulk_in = s_ep_interrupt = 0;
  s_interface_number = desc_itf->bInterfaceNumber;

  for (unsigned i = 0; i < K_CCIDD_ENDPOINT_COUNT && p < desc_end; i++) {
    if (tu_desc_type(p) != TUSB_DESC_ENDPOINT) {
      return 0U;
    }
    const tusb_desc_endpoint_t* ep = (const tusb_desc_endpoint_t*)(p);

    if (!usbd_edpt_open(rhport, ep)) {
      return 0U;
    }

    tusb_dir_t const k_dir = tu_edpt_dir(ep->bEndpointAddress);
    unsigned const k_xt = ep->bmAttributes.xfer;

    if (k_dir == TUSB_DIR_OUT) {
      s_ep_bulk_out = ep->bEndpointAddress;
    } else if (k_dir == TUSB_DIR_IN) {
      if (k_xt == TUSB_XFER_INTERRUPT) {
        s_ep_interrupt = ep->bEndpointAddress;
      } else if (k_xt == TUSB_XFER_BULK) {
        s_ep_bulk_in = ep->bEndpointAddress;
      }
    }
    p = tu_desc_next(p);
  }

  if ((s_ep_bulk_out == 0U) || (s_ep_bulk_in == 0U) || (s_ep_interrupt == 0U)) {
    return 0U;
  }

  s_dbg_open_state = K_CCIDD_OPEN_STATE_EPS_OK; /* all 3 endpoints opened */

  s_bulk_out_busy = false;
  arm_bulk_out(rhport);

  s_dbg_open_state =
      K_CCIDD_OPEN_STATE_SUCCESS; /* arm_bulk_out called — fully open */

  return (uint16_t)(p - desc_start);
}

static bool nero_ccidd_control_xfer_cb(uint8_t rhport, uint8_t stage,
                                       tusb_control_request_t const* request) {
  if (!ccid_usb_context_ready() || (request == NERO_NFC_NULL)) {
    return false;
  }
  if (stage != CONTROL_STAGE_SETUP) {
    return true;
  }
  uint8_t slot = 0;
  uint8_t seq = 0;
  if (nfc_ccid_control_abort_request_matches_slot(
          request->bmRequestType, request->bRequest, request->wValue,
          request->wIndex, request->wLength, s_interface_number, 0u, &slot,
          &seq)) {
    s_abort_request_slot = slot;
    s_abort_request_seq = seq;
    s_abort_request_pending = true;
    return tud_control_status(rhport, request);
  }
  return false;
}

static bool nero_ccidd_xfer_cb(uint8_t rhport, uint8_t ep_addr,
                               xfer_result_t evt, uint32_t xferred_bytes) {
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
static char const K_CC_NAME[] = "CCID-NERO";
#endif

#if defined(NERO_CCID_STM32_USB_BUILD)
/* Vendored TinyUSB (WBA65): usbd_class_driver_t always includes
 * name/deinit/xfer_isr. */
static const usbd_class_driver_t K_NERO_CCIDD_DRIVER = {
#if CFG_TUSB_DEBUG >= CFG_TUD_LOG_LEVEL
    .name = K_CC_NAME,
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
static const usbd_class_driver_t K_NERO_CCIDD_DRIVER = {
#if CFG_TUSB_DEBUG >= CFG_TUD_LOG_LEVEL
    .name = K_CC_NAME,
#endif
    .init = nero_ccidd_init,
    .reset = nero_ccidd_reset,
    .open = nero_ccidd_open,
    .control_xfer_cb = nero_ccidd_control_xfer_cb,
    .xfer_cb = nero_ccidd_xfer_cb,
    .sof = NERO_NFC_NULL,
};
#endif

usbd_class_driver_t const* usbd_app_driver_get_cb(uint8_t* driver_count) {
  if (driver_count != NERO_NFC_NULL) {
    *driver_count = 1;
  }
  return &K_NERO_CCIDD_DRIVER;
}

bool reader_hal_ccid_recv(uint8_t* buf, uint16_t* len_io) {
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
    uint32_t now = (uint32_t)(reader_hal_millis());
    if ((now - s_dbg_heartbeat_ms) >= K_CCIDD_HEARTBEAT_MS) {
      s_dbg_heartbeat_ms = now;
      char tmp[K_CDC_DBG_STR_MAX];
      nero_nfc_snprintf(
          tmp, sizeof(tmp),
          "[CCID] alive ms=%lu open=%u out=%u fast=%u queued=%u recv=%u "
          "send_ok=%u "
          "send_fail=%u arm_fail=%u seq=%u\r\n",
          (unsigned long)(now), s_dbg_open_state, s_dbg_xfer_out,
          s_dbg_fastpath_ok, s_dbg_queue_ok, s_dbg_poll_recv, s_dbg_send_ok,
          s_dbg_send_fail, s_dbg_arm_out_fail, s_dbg_last_seq);
      cdc_dbg(tmp);
    }
  }

  /* Print CCID open state once per open, from main-loop context. */
  if (!s_dbg_printed && s_dbg_open_state > 0) {
    char tmp[K_CCIDD_DBG_OPEN_STR_MAX];
    nero_nfc_snprintf(tmp, sizeof(tmp),
                      "[CCID] open=%u ep_out=%02X ep_in=%02X ep_int=%02X\r\n",
                      s_dbg_open_state, s_ep_bulk_out, s_ep_bulk_in,
                      s_ep_interrupt);
    cdc_dbg(tmp);
    s_dbg_printed = true;
  }

  if (!s_rx_pending) {
    return false;
  }

  uint32_t copy_n = (unsigned)(s_rx_store_len);
  if (out_cap == 0U) {
    return false;
  }
  if (copy_n > (unsigned)(out_cap)) {
    return false;
  }
  if (!nero_nfc_copy_bytes(buf, out_cap, 0u, s_rx_assembly.data, copy_n)) {
    return false;
  }
  *len_io = (uint16_t)(copy_n);
  s_dbg_poll_recv++;
  if (nero_nfc_span_ok(NFC_CCID_BULK_SEQ_OFFSET, 1u, copy_n)) {
    s_dbg_last_seq = buf[NFC_CCID_BULK_SEQ_OFFSET];
  }

  {
    char tmp[K_CCIDD_DBG_OPEN_STR_MAX];
    nero_nfc_snprintf(
        tmp, sizeof(tmp), "[CCID] recv len=%u seq=%u out_cnt=%u\r\n",
        (unsigned)copy_n,
        (unsigned)(nero_nfc_span_ok(NFC_CCID_BULK_SEQ_OFFSET, 1u, copy_n)
                       ? buf[NFC_CCID_BULK_SEQ_OFFSET]
                       : 0U),
        (unsigned)s_dbg_xfer_out);
    cdc_dbg(tmp);
  }

  s_rx_pending = false;
  reset_rx_assembly();
  if (s_ep_bulk_out != 0U && !s_bulk_out_busy) {
    arm_bulk_out(0);
  }
  return true;
}

bool reader_hal_ccid_peek(const uint8_t** buf_out, uint16_t* len_out) {
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
  *buf_out = s_rx_assembly.data;
  *len_out = s_rx_store_len;
  s_dbg_poll_recv++;
  if (s_rx_store_len > NFC_CCID_BULK_SEQ_OFFSET) {
    s_dbg_last_seq = s_rx_assembly.data[NFC_CCID_BULK_SEQ_OFFSET];
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

static bool ccid_send_one_chunk(const uint8_t* src, unsigned chunk,
                                uint32_t deadline) {
  unsigned const k_w_cap = K_CCIDD_SEND_CLAIM_SPIN_MAX;
  unsigned w = k_w_cap;
  bool xfer_ok = false;
  while (--w != 0) {
    if ((int32_t)(reader_hal_millis() - deadline) > 0) {
      s_dbg_send_fail++;
      cdc_dbg("[CCID] send TIMEOUT (claim)\r\n");
      return false;
    }
    bool const k_claimed = usbd_edpt_claim(0, s_ep_bulk_in);
    bool k_ok = false;
    if (k_claimed) {
      if (!nero_nfc_copy_bytes(s_bulk_in_work, sizeof(s_bulk_in_work), 0u, src,
                               chunk)) {
        usbd_edpt_release(0, s_ep_bulk_in);
        s_dbg_send_fail++;
        return false;
      }
      k_ok = ccid_edpt_xfer(0, s_ep_bulk_in, s_bulk_in_work, (uint16_t)(chunk));
    }
    if (!k_ok && k_claimed) {
      usbd_edpt_release(0, s_ep_bulk_in);
    }
    if (k_ok) {
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
    if ((int32_t)(reader_hal_millis() - deadline) > 0) {
      s_dbg_send_fail++;
      cdc_dbg("[CCID] send TIMEOUT (busy)\r\n");
      return false;
    }
  }
  return true;
}

bool reader_hal_ccid_send(const uint8_t* buf, uint16_t len,
                          uint32_t deadline_ms) {
  if ((buf == NERO_NFC_NULL) || (len == 0U) || (s_ep_bulk_in == 0U)) {
    s_dbg_send_fail++;
    {
      char tmp[K_CCIDD_DBG_SEND_SKIP_STR_MAX];
      nero_nfc_snprintf(tmp, sizeof(tmp), "[CCID] send SKIP ep_in=%02X\r\n",
                        s_ep_bulk_in);
      cdc_dbg(tmp);
    }
    return false;
  }

  {
    char tmp[K_CCIDD_DBG_OPEN_STR_MAX];
    nero_nfc_snprintf(
        tmp, sizeof(tmp), "[CCID] send len=%u seq=%u ep_in=%02X\r\n", len,
        (len > NFC_CCID_BULK_SEQ_OFFSET) ? buf[NFC_CCID_BULK_SEQ_OFFSET] : 0U,
        s_ep_bulk_in);
    cdc_dbg(tmp);
  }

  /* Cap effective deadline: pcscd's ReadUSB timeout is 3 s (initial) or 100 ms
   * (retries). A 5-second cap prevents blocking the main loop indefinitely on
   * hardware failures. */
  deadline_ms = (((deadline_ms) < (K_CCIDD_SEND_DEADLINE_CAP_MS))
                     ? (deadline_ms)
                     : (K_CCIDD_SEND_DEADLINE_CAP_MS));

  uint32_t deadline = reader_hal_millis() + deadline_ms;
  unsigned off = 0;

  while (off < (unsigned)(len)) {
    if ((int32_t)(reader_hal_millis() - deadline) > 0) {
      s_dbg_send_fail++;
      cdc_dbg("[CCID] send TIMEOUT (outer)\r\n");
      return false;
    }
    unsigned chunk = (((unsigned)(len - off)) <= NERO_CCID_BULK_EPSIZE)
                         ? (unsigned)(len - off)
                         : NERO_CCID_BULK_EPSIZE;

    if (!ccid_send_one_chunk(buf + off, chunk, deadline)) {
      return false;
    }

    off += chunk;
  }
  if (ccid_usb_bulk_in_needs_zlp(len, NERO_CCID_BULK_EPSIZE) &&
      !ccid_send_one_chunk(buf, 0u, deadline)) {
    return false;
  }

  s_dbg_send_ok++;
  cdc_dbg("[CCID] send complete\r\n");
  return true;
}

void reader_hal_ccid_notify_slot_change(bool card_present) {
  if (!tud_ready()) {
    return;
  }
  /* CCID 1.1 §6.3.1 bmSlotICCState slot 0: bit0=present, bit1=changed.
   * Arrived → 0x03; left → 0x02. */
  uint8_t bm = card_present ? NFC_CCID_NOTIFY_SLOT_PRESENT_CHANGED
                            : NFC_CCID_NOTIFY_SLOT_ABSENT_CHANGED;
  (void)notify_send(0, bm);
}

bool reader_hal_ccid_abort_request_pending(uint8_t* slot_out,
                                           uint8_t* seq_out) {
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
  if (s_abort_request_pending && s_abort_request_slot == slot &&
      s_abort_request_seq == seq) {
    s_abort_request_pending = false;
  }
}

#elif !defined(NERO_CCID_USB_BUILD)

bool reader_hal_ccid_recv(uint8_t* buf, uint16_t* len_io) {
  /* Stub keeps the mutable API of the CCID build; no payload is produced. */
  if (buf != NERO_NFC_NULL) {
    *buf = *buf;
  }
  if (len_io != NERO_NFC_NULL) {
    *len_io = 0U;
  }
  return false;
}

bool reader_hal_ccid_peek(const uint8_t** buf_out, uint16_t* len_out) {
  if (buf_out != NERO_NFC_NULL) {
    *buf_out = NERO_NFC_NULL;
  }
  if (len_out != NERO_NFC_NULL) {
    *len_out = 0U;
  }
  return false;
}

void reader_hal_ccid_release(void) {}

bool reader_hal_ccid_send(const uint8_t* buf, uint16_t len,
                          uint32_t deadline_ms) {
  (void)buf;
  (void)len;
  (void)deadline_ms;
  return false;
}

void reader_hal_ccid_notify_slot_change(bool card_present) {
  (void)card_present;
}

bool reader_hal_ccid_abort_request_pending(uint8_t* slot_out,
                                           uint8_t* seq_out) {
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
