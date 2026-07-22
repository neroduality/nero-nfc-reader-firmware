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

// Arduino Renesas `USB.cpp` patch must match these endpoint IDs and lengths.
// Dynamic TinyUSB ports may pass board-allocated endpoint IDs instead.

#pragma once

#include "nfc_ccid_frame.h"

#include <stddef.h>
#include <stdint.h>

/* CCID-only images use a paired bulk endpoint: EP2 OUT and EP2 IN share the
 * endpoint number with opposite directions. */
#define NERO_CCID_EP_INT 0x81u /* interrupt IN (notify) */
#define NERO_CCID_EP_OUT 0x02u /* bulk OUT */
#define NERO_CCID_EP_IN 0x82u  /* bulk IN */

#ifndef NERO_CCID_BULK_EPSIZE
#define NERO_CCID_BULK_EPSIZE 64u
#endif
#ifndef NERO_CCID_INT_EPSIZE
#define NERO_CCID_INT_EPSIZE NERO_CCID_INT_EPSIZE_BYTES
#endif

/* USB 2.0 descriptor type / class / transfer bytes (DWG Smart Card CCID). */
enum {
  NERO_CCID_INT_EPSIZE_BYTES = 8u,
  NERO_USB_DESC_LEN_INTERFACE = 9u,
  NERO_USB_DESC_LEN_ENDPOINT = 7u,
  NERO_USB_DESC_LEN_CCID_FUNCTIONAL = 54u,
  NERO_USB_CCID_INTERFACE_NUM_ENDPOINTS = 3u,
  NERO_USB_EP_INTERRUPT_POLLING_INTERVAL_MS = 50u,
  NERO_USB_CFG_DESC_INTERFACE_OFFSET = 9u,
  NERO_USB_CONFIG_MAX_POWER_MA = 500u,
  NERO_USB_DESC_TYPE_STRING_SHIFT = 8u,
  NERO_USB_HEX_NIBBLE_SHIFT = 4u,
  NERO_USB_ASCII_DIGIT_MAX = 9u,
  NERO_USB_ASCII_HEX_LETTER_BASE = 10u,
  NERO_USB_SERIAL_HEX_CHUNK_CHARS = 8u,
  NERO_USB_SERIAL_HEX_WORD_COUNT = 3u,
  NERO_USB_SERIAL_HEX_WORD1_CHAR_OFFSET = NERO_USB_SERIAL_HEX_CHUNK_CHARS,
  NERO_USB_SERIAL_HEX_WORD2_CHAR_OFFSET = NERO_USB_SERIAL_HEX_CHUNK_CHARS * 2u,
  NERO_USB_SERIAL_HEX_TOTAL_CHARS =
      NERO_USB_SERIAL_HEX_CHUNK_CHARS * NERO_USB_SERIAL_HEX_WORD_COUNT,
  NERO_USB_STRING_DESC_WORD_CAP = 33u,
  NERO_USB_DESC_TYPE_INTERFACE = 0x04u,
  NERO_USB_DESC_TYPE_ENDPOINT = 0x05u,
  NERO_USB_CLASS_SMART_CARD = 0x0Bu,
  NERO_USB_XFER_BULK = 0x02u,
  NERO_USB_XFER_INTERRUPT = 0x03u,
  NERO_USB_LOW_BYTE_MASK = 0xFFu,
  NERO_USB_BCD_USB_2_0 = 0x0200u,
  NERO_USB_BCD_DEVICE_1_0 = 0x0100u,
  NERO_USB_LANGID_EN_US = 0x0409u,
  NERO_USB_EP0_MAX_PACKET_SIZE =
      64u, /* must match CFG_TUD_ENDPOINT0_SIZE in tusb_config.h */
};

/* USB Smart Card descriptor length = interface + CCID functional + 3 endpoints
 */
/* 9-byte interface + functional + triple 7-byte endpoints */
#define NERO_CCID_CFG_DESC_TOTAL (9u + 54u + 21u)

/* CCID functional descriptor fields (must match ccid_usb_desc_blob.c K_CC54).
 */
#define NERO_CCID_DESC_DW_FEATURES 0x000404BAu
#define NERO_CCID_DESC_MAX_MESSAGE_LENGTH NFC_CCID_WORK_BUF_SIZE
#define NERO_CCID_DESC_DEFAULT_CLOCK_KHZ 13560u
#define NERO_CCID_DESC_MAX_CLOCK_KHZ 13560u
#define NERO_CCID_DESC_DEFAULT_DATA_RATE_BPS 106000u
#define NERO_CCID_DESC_MAX_DATA_RATE_BPS 848000u

size_t nero_ccid_copy_interface_descriptor_blob(uint8_t* dst,
                                                unsigned interface_number,
                                                unsigned ccid_string_index);
size_t nero_ccid_copy_interface_descriptor_blob_with_endpoints_cap(
    uint8_t* dst, size_t dst_cap, unsigned interface_number,
    unsigned ccid_string_index, uint8_t ep_interrupt, uint8_t ep_out,
    uint8_t ep_in);
size_t nero_ccid_copy_interface_descriptor_blob_with_endpoints(
    uint8_t* dst, unsigned interface_number, unsigned ccid_string_index,
    uint8_t ep_interrupt, uint8_t ep_out, uint8_t ep_in);
