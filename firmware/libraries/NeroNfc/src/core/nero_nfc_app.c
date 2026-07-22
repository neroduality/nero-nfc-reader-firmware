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

#include "nero_nfc_app.h"

#include "nero_nfc_frontend.h"
#include "nero_nfc_mem_util.h"
#include "nero_nfc_null.h"
#if NERO_NFC_APP_HAS_READER_CONTEXT
#include "reader_context.h"
#endif
#if NERO_NFC_APP_HAS_WRITER_CONTEXT
#include "writer_context.h"
#endif
#if defined(NERO_CCID_USB_BUILD)
#include "reader_ccid_context.h"
#endif
#if !defined(NERO_HOST_UNIT_TEST_HOOKS)
#include "nfc_app.h"
#include "reader_app.h"
#if NERO_NFC_APP_HAS_WRITER_CONTEXT
#include "writer_app.h"
#endif
#endif
#include "usb/nero_nfc_tinyusb_active.h"

typedef struct nero_nfc_app_serial_rx {
  uint8_t bytes[NERO_NFC_APP_SERIAL_RX_CAP];
  uint16_t head;
  uint16_t tail;
} nero_nfc_app_serial_rx_t;

typedef struct nero_nfc_app {
  nero_nfc_platform_ops_t ops;
  nero_nfc_board_config_t board;
  nero_nfc_product_t product;
  nero_nfc_runtime_mode_t runtime_mode;
  nfc_mode_scan_state_t mode_scan;
  nero_nfc_app_serial_rx_t serial_rx;
  uint32_t ccid_configured_at_ms;
  nero_nfc_log_sink_fn_t log_sink;
  bool ccid_bootstrapped;
  bool ccid_hardware_started;
  volatile uint8_t session_owner;
  st25r3916_t st25;
  nfc_frontend_t frontend;
#if NERO_NFC_APP_HAS_READER_CONTEXT
  reader_context_t reader;
#endif
#if NERO_NFC_APP_HAS_WRITER_CONTEXT
  writer_context_t writer;
#endif
#if defined(NERO_CCID_USB_BUILD)
  reader_ccid_context_t ccid;
#endif
} nero_nfc_app_impl_t;

#if NERO_NFC_APP_HAS_READER_CONTEXT
NERO_NFC_STATIC_ASSERT(sizeof(reader_context_t) <=
                           NERO_NFC_APP_READER_CONTEXT_BYTES,
                       "NERO_NFC_APP_READER_CONTEXT_BYTES too small");
#endif
#if NERO_NFC_APP_HAS_WRITER_CONTEXT
NERO_NFC_STATIC_ASSERT(sizeof(writer_context_t) <=
                           NERO_NFC_APP_WRITER_CONTEXT_BYTES,
                       "NERO_NFC_APP_WRITER_CONTEXT_BYTES too small");
#endif
#if defined(NERO_CCID_USB_BUILD)
NERO_NFC_STATIC_ASSERT(sizeof(reader_ccid_context_t) <=
                           NERO_NFC_APP_CCID_CONTEXT_BYTES,
                       "NERO_NFC_APP_CCID_CONTEXT_BYTES too small");
#endif
NERO_NFC_STATIC_ASSERT(sizeof(nero_nfc_app_impl_t) <=
                           NERO_NFC_APP_STORAGE_BYTES,
                       "nero_nfc_app_storage_t too small for private context");
NERO_NFC_STATIC_ASSERT(
    _Alignof(nero_nfc_app_impl_t) <= NERO_NFC_APP_STORAGE_ALIGN,
    "nero_nfc_app_storage_t alignment too weak for private context");

static bool product_ok(nero_nfc_product_t product) {
#if defined(NERO_CCID_ONLY_BUILD)
  return product == NERO_NFC_PRODUCT_READER;
#else
  return (product == NERO_NFC_PRODUCT_READER) ||
         (product == NERO_NFC_PRODUCT_WRITER) ||
         (product == NERO_NFC_PRODUCT_COMBINED);
#endif
}

static uint16_t serial_count(const nero_nfc_app_serial_rx_t* rx) {
  return (uint16_t)(((uint32_t)rx->tail + (uint32_t)NERO_NFC_APP_SERIAL_RX_CAP -
                     (uint32_t)rx->head) %
                    (uint32_t)NERO_NFC_APP_SERIAL_RX_CAP);
}

static uint16_t serial_free(const nero_nfc_app_serial_rx_t* rx) {
  return (uint16_t)((uint32_t)NERO_NFC_APP_SERIAL_RX_CAP - 1u -
                    (uint32_t)serial_count(rx));
}

static void serial_push_tail(nero_nfc_app_serial_rx_t* rx, uint8_t b) {
  rx->bytes[rx->tail] = b;
  rx->tail = (uint16_t)(((uint32_t)rx->tail + 1u) %
                        (uint32_t)NERO_NFC_APP_SERIAL_RX_CAP);
}

static uint8_t serial_pop_head(nero_nfc_app_serial_rx_t* rx) {
  uint8_t b = rx->bytes[rx->head];
  rx->head = (uint16_t)(((uint32_t)rx->head + 1u) %
                        (uint32_t)NERO_NFC_APP_SERIAL_RX_CAP);
  return b;
}

static void serial_prepend_head(nero_nfc_app_serial_rx_t* rx, uint8_t b) {
  rx->head = (uint16_t)(((uint32_t)rx->head +
                         (uint32_t)NERO_NFC_APP_SERIAL_RX_CAP - 1u) %
                        (uint32_t)NERO_NFC_APP_SERIAL_RX_CAP);
  rx->bytes[rx->head] = b;
}

nero_nfc_app_t* nero_nfc_app_init(nero_nfc_app_storage_t* storage,
                                  const nero_nfc_platform_ops_t* ops,
                                  const nero_nfc_board_config_t* board,
                                  nero_nfc_product_t product) {
  nero_nfc_app_impl_t* app;

  if ((nero_nfc_tinyusb_active_get() != NERO_NFC_NULL) ||
      (storage == NERO_NFC_NULL) || !nero_nfc_platform_ops_validate(ops) ||
      !nero_nfc_board_config_validate(board) || !product_ok(product)) {
    return NERO_NFC_NULL;
  }

  nero_nfc_zero_bytes(storage->bytes, sizeof(storage->bytes));
  app = (nero_nfc_app_impl_t*)storage->bytes;
  nero_nfc_platform_ops_copy(&app->ops, ops);
  nero_nfc_board_config_copy(&app->board, board);
  app->product = product;
  app->runtime_mode = NERO_NFC_RUNTIME_MODE_READER;
  nfc_mode_scan_reset(&app->mode_scan);
  nero_nfc_st25_frontend_bind(&app->frontend, &app->st25, &app->ops,
                              &app->board);
#if NERO_NFC_APP_HAS_READER_CONTEXT
  if (product != NERO_NFC_PRODUCT_WRITER) {
    reader_context_reset(&app->reader);
    app->reader.frontend = &app->frontend;
  }
#endif
#if NERO_NFC_APP_HAS_WRITER_CONTEXT
  if (product != NERO_NFC_PRODUCT_READER) {
    writer_context_reset(&app->writer);
    app->writer.frontend = &app->frontend;
  }
#endif
#if defined(NERO_CCID_USB_BUILD)
  reader_ccid_context_reset(&app->ccid);
#endif

  if (!nero_nfc_tinyusb_active_bind((nero_nfc_app_t*)app)) {
    return NERO_NFC_NULL;
  }
  return (nero_nfc_app_t*)app;
}

void nero_nfc_app_begin(nero_nfc_app_t* app) {
  nero_nfc_app_impl_t* impl = (nero_nfc_app_impl_t*)app;

  if (impl == NERO_NFC_NULL) {
    return;
  }
  if (!nero_nfc_app_bind_active(app)) {
    return;
  }
#if !defined(NERO_HOST_UNIT_TEST_HOOKS)
  if (impl->product == NERO_NFC_PRODUCT_READER) {
#if defined(NERO_CCID_ONLY_BUILD)
    nfc_app_setup();
#else
    reader_setup();
#endif
  } else if (impl->product == NERO_NFC_PRODUCT_WRITER) {
#if NERO_NFC_APP_HAS_WRITER_CONTEXT
    writer_setup();
#endif
  } else if (impl->product == NERO_NFC_PRODUCT_COMBINED) {
    nfc_app_setup();
  }
#else
  (void)impl;
#endif
}

void nero_nfc_app_step(nero_nfc_app_t* app) {
  nero_nfc_app_impl_t* impl = (nero_nfc_app_impl_t*)app;

  if (impl == NERO_NFC_NULL) {
    return;
  }
#if !defined(NERO_HOST_UNIT_TEST_HOOKS)
  if (impl->product == NERO_NFC_PRODUCT_READER) {
#if defined(NERO_CCID_ONLY_BUILD)
    nfc_app_loop();
#else
    reader_loop();
#endif
  } else if (impl->product == NERO_NFC_PRODUCT_WRITER) {
#if NERO_NFC_APP_HAS_WRITER_CONTEXT
    writer_loop();
#endif
  } else if (impl->product == NERO_NFC_PRODUCT_COMBINED) {
    nfc_app_loop();
  }
#else
  (void)impl;
#endif
  nero_nfc_platform_service();
}

bool nero_nfc_app_bind_active(nero_nfc_app_t* app) {
  return nero_nfc_tinyusb_active_bind(app);
}

bool nero_nfc_app_unbind_active(nero_nfc_app_t* app) {
  if ((app == NERO_NFC_NULL) || (nero_nfc_tinyusb_active_get() != app)) {
    return false;
  }
  nero_nfc_tinyusb_active_unbind();
  return true;
}

nero_nfc_app_t* nero_nfc_app_active(void) {
  return nero_nfc_tinyusb_active_get();
}

nero_nfc_product_t nero_nfc_app_product(const nero_nfc_app_t* app) {
  const nero_nfc_app_impl_t* impl = (const nero_nfc_app_impl_t*)app;
  if (impl == NERO_NFC_NULL) {
    return NERO_NFC_PRODUCT_INVALID;
  }
  return impl->product;
}

const nero_nfc_board_config_t* nero_nfc_app_board(const nero_nfc_app_t* app) {
  const nero_nfc_app_impl_t* impl = (const nero_nfc_app_impl_t*)app;
  if (impl == NERO_NFC_NULL) {
    return NERO_NFC_NULL;
  }
  return &impl->board;
}

const nero_nfc_platform_ops_t* nero_nfc_app_platform_ops(
    const nero_nfc_app_t* app) {
  const nero_nfc_app_impl_t* impl = (const nero_nfc_app_impl_t*)app;
  if (impl == NERO_NFC_NULL) {
    return NERO_NFC_NULL;
  }
  return &impl->ops;
}

nero_nfc_runtime_mode_t nero_nfc_app_runtime_mode(const nero_nfc_app_t* app) {
  const nero_nfc_app_impl_t* impl = (const nero_nfc_app_impl_t*)app;
  if (impl == NERO_NFC_NULL) {
    return NERO_NFC_RUNTIME_MODE_READER;
  }
  return impl->runtime_mode;
}

void nero_nfc_app_set_runtime_mode(nero_nfc_app_t* app,
                                   nero_nfc_runtime_mode_t mode) {
  nero_nfc_app_impl_t* impl = (nero_nfc_app_impl_t*)app;
  if (impl == NERO_NFC_NULL) {
    return;
  }
  if ((impl->product == NERO_NFC_PRODUCT_COMBINED) && impl->st25.initialized &&
      (impl->runtime_mode != mode) && (impl->frontend.ops != NERO_NFC_NULL) &&
      (impl->frontend.ops->quiesce != NERO_NFC_NULL)) {
    impl->frontend.ops->quiesce(impl->frontend.state);
  }
  impl->runtime_mode = mode;
}

nfc_mode_scan_state_t* nero_nfc_app_mode_scan(nero_nfc_app_t* app) {
  nero_nfc_app_impl_t* impl = (nero_nfc_app_impl_t*)app;
  if (impl == NERO_NFC_NULL) {
    return NERO_NFC_NULL;
  }
  return &impl->mode_scan;
}

void nero_nfc_app_serial_preload(nero_nfc_app_t* app) {
  nero_nfc_app_impl_t* impl = (nero_nfc_app_impl_t*)app;
  if (impl == NERO_NFC_NULL) {
    return;
  }
  while ((nero_nfc_platform_serial_available() > 0) &&
         (serial_free(&impl->serial_rx) > 0u)) {
    const int byte = nero_nfc_platform_serial_read_byte();
    if (byte < 0) {
      break;
    }
    serial_push_tail(&impl->serial_rx, (uint8_t)byte);
  }
}

int nero_nfc_app_serial_pushback_available(const nero_nfc_app_t* app) {
  const nero_nfc_app_impl_t* impl = (const nero_nfc_app_impl_t*)app;
  if (impl == NERO_NFC_NULL) {
    return 0;
  }
  return (int)serial_count(&impl->serial_rx);
}

int nero_nfc_app_serial_pushback_read(nero_nfc_app_t* app) {
  nero_nfc_app_impl_t* impl = (nero_nfc_app_impl_t*)app;
  if ((impl == NERO_NFC_NULL) || (serial_count(&impl->serial_rx) == 0u)) {
    return -1;
  }
  return (int)serial_pop_head(&impl->serial_rx);
}

void nero_nfc_app_serial_pushback_return(nero_nfc_app_t* app,
                                         const uint8_t* bytes, uint16_t len) {
  nero_nfc_app_impl_t* impl = (nero_nfc_app_impl_t*)app;
  uint16_t i;

  if ((impl == NERO_NFC_NULL) || (bytes == NERO_NFC_NULL) || (len == 0u) ||
      (len > serial_free(&impl->serial_rx))) {
    return;
  }
  for (i = len; i > 0u; i--) {
    serial_prepend_head(&impl->serial_rx, bytes[i - 1u]);
  }
}

bool nero_nfc_app_ccid_bootstrapped(const nero_nfc_app_t* app) {
  const nero_nfc_app_impl_t* impl = (const nero_nfc_app_impl_t*)app;
  return (impl != NERO_NFC_NULL) && impl->ccid_bootstrapped;
}

void nero_nfc_app_set_ccid_bootstrapped(nero_nfc_app_t* app) {
  nero_nfc_app_impl_t* impl = (nero_nfc_app_impl_t*)app;
  if (impl != NERO_NFC_NULL) {
    impl->ccid_bootstrapped = true;
  }
}

uint32_t nero_nfc_app_ccid_configured_at_ms(const nero_nfc_app_t* app) {
  const nero_nfc_app_impl_t* impl = (const nero_nfc_app_impl_t*)app;
  return (impl == NERO_NFC_NULL) ? 0u : impl->ccid_configured_at_ms;
}

void nero_nfc_app_set_ccid_configured_at_ms(nero_nfc_app_t* app,
                                            uint32_t configured_at_ms) {
  nero_nfc_app_impl_t* impl = (nero_nfc_app_impl_t*)app;
  if (impl != NERO_NFC_NULL) {
    impl->ccid_configured_at_ms = configured_at_ms;
  }
}

bool nero_nfc_app_ccid_hardware_started(const nero_nfc_app_t* app) {
  const nero_nfc_app_impl_t* impl = (const nero_nfc_app_impl_t*)app;
  return (impl != NERO_NFC_NULL) && impl->ccid_hardware_started;
}

void nero_nfc_app_set_ccid_hardware_started(nero_nfc_app_t* app) {
  nero_nfc_app_impl_t* impl = (nero_nfc_app_impl_t*)app;
  if (impl != NERO_NFC_NULL) {
    impl->ccid_hardware_started = true;
  }
}

void nero_nfc_app_set_log_sink(nero_nfc_app_t* app,
                               nero_nfc_log_sink_fn_t sink) {
  nero_nfc_app_impl_t* impl = (nero_nfc_app_impl_t*)app;
  if (impl != NERO_NFC_NULL) {
    impl->log_sink = sink;
  }
}

nero_nfc_log_sink_fn_t nero_nfc_app_log_sink(const nero_nfc_app_t* app) {
  const nero_nfc_app_impl_t* impl = (const nero_nfc_app_impl_t*)app;
  return (impl == NERO_NFC_NULL) ? NERO_NFC_NULL : impl->log_sink;
}

void nero_nfc_app_set_session_owner(nero_nfc_app_t* app, uint8_t owner) {
  nero_nfc_app_impl_t* impl = (nero_nfc_app_impl_t*)app;
  if (impl != NERO_NFC_NULL) {
    impl->session_owner = owner;
  }
}

uint8_t nero_nfc_app_session_owner(const nero_nfc_app_t* app) {
  const nero_nfc_app_impl_t* impl = (const nero_nfc_app_impl_t*)app;
  return (impl == NERO_NFC_NULL) ? 0u : impl->session_owner;
}

struct reader_context* nero_nfc_app_reader(nero_nfc_app_t* app) {
#if NERO_NFC_APP_HAS_READER_CONTEXT
  nero_nfc_app_impl_t* impl = (nero_nfc_app_impl_t*)app;
  if (impl == NERO_NFC_NULL) {
    return NERO_NFC_NULL;
  }
  return &impl->reader;
#else
  (void)app;
  return NERO_NFC_NULL;
#endif
}

struct writer_context* nero_nfc_app_writer(nero_nfc_app_t* app) {
#if NERO_NFC_APP_HAS_WRITER_CONTEXT
  nero_nfc_app_impl_t* impl = (nero_nfc_app_impl_t*)app;
  if (impl == NERO_NFC_NULL) {
    return NERO_NFC_NULL;
  }
  return &impl->writer;
#else
  (void)app;
  return NERO_NFC_NULL;
#endif
}

struct reader_ccid_context* nero_nfc_app_ccid(nero_nfc_app_t* app) {
#if defined(NERO_CCID_USB_BUILD)
  nero_nfc_app_impl_t* impl = (nero_nfc_app_impl_t*)app;
  if (impl == NERO_NFC_NULL) {
    return NERO_NFC_NULL;
  }
  return &impl->ccid;
#else
  (void)app;
  return NERO_NFC_NULL;
#endif
}

struct nfc_frontend* nero_nfc_app_frontend(nero_nfc_app_t* app) {
  nero_nfc_app_impl_t* impl = (nero_nfc_app_impl_t*)app;
  if (impl == NERO_NFC_NULL) {
    return NERO_NFC_NULL;
  }
  return &impl->frontend;
}
