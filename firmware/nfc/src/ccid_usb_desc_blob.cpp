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

#include "nero_nfc_null.h"
// 54-byte USB CCID 1.10 functional descriptor copied into the configuration
// blob.
//
// References: DWG Smart-Card_CCID Rev1.10; T=1 APDU-level contactless reader.

#include "ccid_usb_desc.h"
#include "nero_nfc_mem_util.h"
#include "nfc_ccid_frame.h"

#if defined(NERO_CCID_USB_BUILD)

/*
 * CCID_DW_FEATURES_EXTENDED_APDU = 0x000404BA :
 * AUTO_CONF_ATR | AUTO_VOLTAGE | AUTO_CLOCK | AUTO_BAUD |
 * AUTO_PPS_CUR | AUTO_IFSD | EXTENDED_APDU_LEVEL_EXCHANGE.
 */

static const uint8_t kCc54[54] = {
  54,   0x21, 0x10, 0x01, 0x00, 0x07, 0x02, 0x00, 0x00, 0x00, 0xF8, 0x34, 0x00, 0x00,
  0xF8, 0x34, 0x00, 0x00, 0x00, 0x10, 0x9E, 0x01, 0x00, 0x80, 0xF0, 0x0C, 0x00, 0x00,
  0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBA, 0x04,
  0x04, 0x00, 0x0C, 0x08, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
};

size_t nero_ccid_copy_interface_descriptor_blob_with_endpoints_cap(uint8_t *dst, size_t dst_cap,
                                                                   unsigned interface_number,
                                                                   unsigned ccid_string_index,
                                                                   uint8_t ep_interrupt,
                                                                   uint8_t ep_out, uint8_t ep_in) {
  if ((dst == NERO_NFC_NULL) || (dst_cap < NERO_CCID_CFG_DESC_TOTAL)) {
    return 0u;
  }
  uint8_t *p = dst;

  /* Standard interface — class 11 smart card CCID — three endpoints. Bulk IN/OUT
   * share endpoint number 2 (distinct directions); the interrupt IN uses a
   * separate address. */
  *p++ = NERO_USB_DESC_LEN_INTERFACE;
  *p++ = NERO_USB_DESC_TYPE_INTERFACE;
  *p++ = static_cast<uint8_t>(interface_number);
  *p++ = 0;
  *p++ = NERO_USB_CCID_INTERFACE_NUM_ENDPOINTS;
  *p++ = NERO_USB_CLASS_SMART_CARD;
  *p++ = 0;
  *p++ = 0;
  *p++ = static_cast<uint8_t>(ccid_string_index & NERO_USB_LOW_BYTE_MASK);

  if (!nero_nfc_copy_bytes(dst, dst_cap, static_cast<size_t>(p - dst), kCc54, sizeof(kCc54))) {
    return 0u;
  }
  p += sizeof(kCc54);

  *p++ = NERO_USB_DESC_LEN_ENDPOINT;
  *p++ = NERO_USB_DESC_TYPE_ENDPOINT;
  *p++ = ep_out;
  *p++ = NERO_USB_XFER_BULK;
  *p++ = static_cast<uint8_t>(NERO_CCID_BULK_EPSIZE & NERO_USB_LOW_BYTE_MASK);
  *p++ = static_cast<uint8_t>((NERO_CCID_BULK_EPSIZE >> NFC_CCID_U32_SHIFT_BYTE1) &
                              NERO_USB_LOW_BYTE_MASK);
  *p++ = 0;

  *p++ = NERO_USB_DESC_LEN_ENDPOINT;
  *p++ = NERO_USB_DESC_TYPE_ENDPOINT;
  *p++ = ep_in;
  *p++ = NERO_USB_XFER_BULK;
  *p++ = static_cast<uint8_t>(NERO_CCID_BULK_EPSIZE & NERO_USB_LOW_BYTE_MASK);
  *p++ = static_cast<uint8_t>((NERO_CCID_BULK_EPSIZE >> NFC_CCID_U32_SHIFT_BYTE1) &
                              NERO_USB_LOW_BYTE_MASK);
  *p++ = 0;

  *p++ = NERO_USB_DESC_LEN_ENDPOINT;
  *p++ = NERO_USB_DESC_TYPE_ENDPOINT;
  *p++ = ep_interrupt;
  *p++ = NERO_USB_XFER_INTERRUPT;
  *p++ = static_cast<uint8_t>(NERO_CCID_INT_EPSIZE & NERO_USB_LOW_BYTE_MASK);
  *p++ = static_cast<uint8_t>((NERO_CCID_INT_EPSIZE >> NFC_CCID_U32_SHIFT_BYTE1) &
                              NERO_USB_LOW_BYTE_MASK);
  *p++ = NERO_USB_EP_INTERRUPT_POLLING_INTERVAL_MS;

  return static_cast<size_t>(p - dst);
}

size_t nero_ccid_copy_interface_descriptor_blob(uint8_t *dst, unsigned interface_number,
                                                unsigned ccid_string_index) {
  return nero_ccid_copy_interface_descriptor_blob_with_endpoints_cap(
    dst, NERO_CCID_CFG_DESC_TOTAL, interface_number, ccid_string_index, NERO_CCID_EP_INT,
    NERO_CCID_EP_OUT, NERO_CCID_EP_IN);
}

size_t nero_ccid_copy_interface_descriptor_blob_with_endpoints(uint8_t *dst,
                                                               unsigned interface_number,
                                                               unsigned ccid_string_index,
                                                               uint8_t ep_interrupt, uint8_t ep_out,
                                                               uint8_t ep_in) {
  return nero_ccid_copy_interface_descriptor_blob_with_endpoints_cap(
    dst, NERO_CCID_CFG_DESC_TOTAL, interface_number, ccid_string_index, ep_interrupt, ep_out,
    ep_in);
}

#endif /* NERO_CCID_USB_BUILD */
