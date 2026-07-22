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

#include "ccid_usb_rx_assembly.h"

#include "nero_nfc_mem_util.h"
#include "nero_nfc_null.h"

#include <stddef.h>

static ccid_usb_rx_feed_result_t malformed_result(ccid_usb_rx_assembly_t* state,
                                                  uint16_t packet_len,
                                                  uint16_t endpoint_size) {
  if (state->len < NFC_CCID_BULK_HEADER_LEN) {
    ccid_usb_rx_assembly_reset(state);
    return CCID_USB_RX_DROPPED;
  }
  if (packet_len < endpoint_size) {
    return CCID_USB_RX_READY;
  }
  state->discarding_malformed = true;
  return CCID_USB_RX_MORE;
}

void ccid_usb_rx_assembly_reset(ccid_usb_rx_assembly_t* state) {
  if (state == NERO_NFC_NULL) {
    return;
  }
  state->len = 0u;
  state->expected = 0u;
  state->discarding_malformed = false;
}

ccid_usb_rx_feed_result_t ccid_usb_rx_assembly_feed(
    ccid_usb_rx_assembly_t* state, const uint8_t* packet, uint16_t packet_len,
    uint16_t endpoint_size) {
  size_t assembled_len = 0u;

  if ((state == NERO_NFC_NULL) || (endpoint_size == 0u) ||
      (packet_len > endpoint_size) ||
      ((packet == NERO_NFC_NULL) && (packet_len != 0u))) {
    ccid_usb_rx_assembly_reset(state);
    return CCID_USB_RX_DROPPED;
  }
  if (state->discarding_malformed) {
    return malformed_result(state, packet_len, endpoint_size);
  }
  if (packet_len == 0u) {
    return malformed_result(state, packet_len, endpoint_size);
  }
  if (!nero_nfc_try_add_size((size_t)(state->len), (size_t)(packet_len),
                             &assembled_len) ||
      assembled_len > sizeof(state->data) ||
      !nero_nfc_copy_bytes(state->data, sizeof(state->data), state->len, packet,
                           packet_len)) {
    return malformed_result(state, packet_len, endpoint_size);
  }
  state->len = (uint16_t)(assembled_len);

  if ((state->expected == 0u) && (state->len >= NFC_CCID_BULK_HEADER_LEN)) {
    const uint32_t payload_len = nfc_ccid_u32_load_le(state->data + 1u);
    size_t frame_len = 0u;
    if ((payload_len > NFC_CCID_MAX_XFR_PAYLOAD) ||
        !nero_nfc_try_add_size(NFC_CCID_BULK_HEADER_LEN, payload_len,
                               &frame_len) ||
        (frame_len > sizeof(state->data))) {
      return malformed_result(state, packet_len, endpoint_size);
    }
    state->expected = (uint16_t)(frame_len);
  }

  if ((state->expected != 0u) && (state->len > state->expected)) {
    return malformed_result(state, packet_len, endpoint_size);
  }
  if ((state->expected != 0u) && (state->len == state->expected)) {
    return CCID_USB_RX_READY;
  }
  if (packet_len < endpoint_size) {
    return malformed_result(state, packet_len, endpoint_size);
  }
  return CCID_USB_RX_MORE;
}
