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

// STM32WBA65 CCID USB transport (Phase 1 plan): TinyUSB BSP USB init +
// tusb_init in nfc_hal_usb_begin(); tud_task() in reader_hal_delay_ms
// (nfc_hal_board.c).

#include "ccid_usb_desc.h"
#include "reader_hal.h"

#if defined(NERO_CCID_USB_BUILD) && defined(NERO_CCID_STM32_USB_BUILD)

#include "tusb.h"
#include "nero_nfc_attrs.h"

NERO_NFC_STATIC_ASSERT(CFG_TUD_ENDPOINT0_SIZE == NERO_USB_EP0_MAX_PACKET_SIZE,
                       "TinyUSB EP0 size matches ccid_usb_desc.h");

void nero_wba65_board_usb_init(void);
void nero_ccid_stm32_setup_usb_descriptors(void);

static bool s_stm32_usb_started;

uint32_t tusb_time_millis_api(void) { return reader_hal_millis(); }

void reader_hal_ccid_usb_begin(void) {
  if (s_stm32_usb_started) {
    return;
  }

  nero_wba65_board_usb_init();
  nero_ccid_stm32_setup_usb_descriptors();

  if (!tusb_inited()) {
    tusb_init();
  }
  (void)tud_connect();

  s_stm32_usb_started = true;
}

bool reader_hal_ccid_usb_configured(void) { return tud_mounted(); }

void reader_hal_ccid_usb_service_poll(void) { tud_task(); }

#endif /* NERO_CCID_USB_BUILD && NERO_CCID_STM32_USB_BUILD */
