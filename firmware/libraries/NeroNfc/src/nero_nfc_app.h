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

#pragma once

#include "nero_nfc_attrs.h"
#include "nero_nfc_board.h"
#include "nero_nfc_log.h"
#include "nero_nfc_platform.h"
#include "nero_nfc_types.h"
#include "nfc_mode_line_scan.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nero_nfc_app nero_nfc_app_t;

/* CDC products keep both contexts so library commands stay identical. Device
 * CCID is reader-only and omits the writer context for UNO RAM; host unit tests
 * keep both even when they enable the CCID compile path. */
#define NERO_NFC_APP_HAS_READER_CONTEXT 1
#if defined(NERO_CCID_USB_BUILD) && !defined(NERO_HOST_UNIT_TEST_HOOKS)
#define NERO_NFC_APP_HAS_WRITER_CONTEXT 0
#else
#define NERO_NFC_APP_HAS_WRITER_CONTEXT 1
#endif

enum {
  NERO_NFC_APP_STORAGE_ALIGN = 8u,
  /* Platform/board/mode/serial bookkeeping plus selected product contexts. */
  NERO_NFC_APP_STORAGE_FIXED_BYTES = 384u,
#if NERO_NFC_APP_HAS_READER_CONTEXT
  NERO_NFC_APP_READER_CONTEXT_BYTES = 3584u,
#else
  NERO_NFC_APP_READER_CONTEXT_BYTES = 1u,
#endif
#if NERO_NFC_APP_HAS_WRITER_CONTEXT
  NERO_NFC_APP_WRITER_CONTEXT_BYTES = 4096u,
#else
  NERO_NFC_APP_WRITER_CONTEXT_BYTES = 1u,
#endif
#if defined(NERO_CCID_USB_BUILD)
  NERO_NFC_APP_CCID_CONTEXT_BYTES = 9216u,
#else
  NERO_NFC_APP_CCID_CONTEXT_BYTES = 0u,
#endif
};

#if !defined(NERO_NFC_APP_SERIAL_RX_CAP)
#if defined(NERO_CCID_ONLY_BUILD)
#define NERO_NFC_APP_SERIAL_RX_CAP 1u
#elif defined(NFC_HAL_RXBUF_CAP)
#define NERO_NFC_APP_SERIAL_RX_CAP NFC_HAL_RXBUF_CAP
#else
#define NERO_NFC_APP_SERIAL_RX_CAP 128u
#endif
#endif

enum {
  NERO_NFC_APP_STORAGE_BYTES =
      NERO_NFC_APP_STORAGE_FIXED_BYTES + NERO_NFC_APP_READER_CONTEXT_BYTES +
      NERO_NFC_APP_WRITER_CONTEXT_BYTES + NERO_NFC_APP_CCID_CONTEXT_BYTES +
      NERO_NFC_APP_SERIAL_RX_CAP + 16u,
};

typedef enum nero_nfc_runtime_mode {
  NERO_NFC_RUNTIME_MODE_READER = 0,
  NERO_NFC_RUNTIME_MODE_WRITER = 1,
} nero_nfc_runtime_mode_t;

typedef struct nero_nfc_app_storage {
  unsigned char bytes[NERO_NFC_APP_STORAGE_BYTES]
      __attribute__((aligned(NERO_NFC_APP_STORAGE_ALIGN)));
} nero_nfc_app_storage_t;

NERO_NFC_NODISCARD nero_nfc_app_t* nero_nfc_app_init(
    nero_nfc_app_storage_t* storage, const nero_nfc_platform_ops_t* ops,
    const nero_nfc_board_config_t* board, nero_nfc_product_t product);

/* Product begin after sketch-owned init + bind (reader/writer/combined). */
void nero_nfc_app_begin(nero_nfc_app_t* app);

/* One application step for the selected product / runtime mode. */
void nero_nfc_app_step(nero_nfc_app_t* app);

NERO_NFC_NODISCARD bool nero_nfc_app_bind_active(nero_nfc_app_t* app);
NERO_NFC_NODISCARD bool nero_nfc_app_unbind_active(nero_nfc_app_t* app);
NERO_NFC_NODISCARD nero_nfc_app_t* nero_nfc_app_active(void);

NERO_NFC_NODISCARD nero_nfc_product_t
nero_nfc_app_product(const nero_nfc_app_t* app);
NERO_NFC_NODISCARD const nero_nfc_board_config_t* nero_nfc_app_board(
    const nero_nfc_app_t* app);
NERO_NFC_NODISCARD const nero_nfc_platform_ops_t* nero_nfc_app_platform_ops(
    const nero_nfc_app_t* app);

NERO_NFC_NODISCARD nero_nfc_runtime_mode_t
nero_nfc_app_runtime_mode(const nero_nfc_app_t* app);
void nero_nfc_app_set_runtime_mode(nero_nfc_app_t* app,
                                   nero_nfc_runtime_mode_t mode);
nfc_mode_scan_state_t* nero_nfc_app_mode_scan(nero_nfc_app_t* app);

void nero_nfc_app_serial_preload(nero_nfc_app_t* app);
int nero_nfc_app_serial_pushback_available(const nero_nfc_app_t* app);
int nero_nfc_app_serial_pushback_read(nero_nfc_app_t* app);
void nero_nfc_app_serial_pushback_return(nero_nfc_app_t* app,
                                         const uint8_t* bytes, uint16_t len);

NERO_NFC_NODISCARD bool nero_nfc_app_ccid_bootstrapped(
    const nero_nfc_app_t* app);
void nero_nfc_app_set_ccid_bootstrapped(nero_nfc_app_t* app);
NERO_NFC_NODISCARD uint32_t
nero_nfc_app_ccid_configured_at_ms(const nero_nfc_app_t* app);
void nero_nfc_app_set_ccid_configured_at_ms(nero_nfc_app_t* app,
                                            uint32_t configured_at_ms);
NERO_NFC_NODISCARD bool nero_nfc_app_ccid_hardware_started(
    const nero_nfc_app_t* app);
void nero_nfc_app_set_ccid_hardware_started(nero_nfc_app_t* app);
void nero_nfc_app_set_log_sink(nero_nfc_app_t* app,
                               nero_nfc_log_sink_fn_t sink);
NERO_NFC_NODISCARD nero_nfc_log_sink_fn_t
nero_nfc_app_log_sink(const nero_nfc_app_t* app);
void nero_nfc_app_set_session_owner(nero_nfc_app_t* app, uint8_t owner);
NERO_NFC_NODISCARD uint8_t
nero_nfc_app_session_owner(const nero_nfc_app_t* app);

struct reader_context;
NERO_NFC_NODISCARD struct reader_context* nero_nfc_app_reader(
    nero_nfc_app_t* app);
struct writer_context;
NERO_NFC_NODISCARD struct writer_context* nero_nfc_app_writer(
    nero_nfc_app_t* app);
struct reader_ccid_context;
NERO_NFC_NODISCARD struct reader_ccid_context* nero_nfc_app_ccid(
    nero_nfc_app_t* app);

struct nfc_frontend;
NERO_NFC_NODISCARD struct nfc_frontend* nero_nfc_app_frontend(
    nero_nfc_app_t* app);

#ifdef __cplusplus
}
#endif
