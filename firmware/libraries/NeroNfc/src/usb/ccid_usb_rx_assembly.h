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

#include "ccid_usb_desc.h"
#include "nfc_ccid_frame.h"

#include <stdbool.h>
#include <stdint.h>

typedef enum ccid_usb_rx_feed_result {
  CCID_USB_RX_MORE = 0,
  CCID_USB_RX_READY,
  CCID_USB_RX_DROPPED,
} ccid_usb_rx_feed_result_t;

typedef struct ccid_usb_rx_assembly {
  uint8_t data[NERO_CCID_DESC_MAX_MESSAGE_LENGTH];
  uint16_t len;
  uint16_t expected;
  bool discarding_malformed;
} ccid_usb_rx_assembly_t;

#ifdef __cplusplus
extern "C" {
#endif

void ccid_usb_rx_assembly_reset(ccid_usb_rx_assembly_t* state);

ccid_usb_rx_feed_result_t ccid_usb_rx_assembly_feed(
    ccid_usb_rx_assembly_t* state, const uint8_t* packet, uint16_t packet_len,
    uint16_t endpoint_size);

#ifdef __cplusplus
}
#endif
