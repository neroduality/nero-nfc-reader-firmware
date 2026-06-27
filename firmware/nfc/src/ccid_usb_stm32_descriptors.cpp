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
// CCID-only TinyUSB descriptors for NUCLEO-WBA65RI.
// Minimal port of
// patches/arduino/renesas_uno/1.6.0/0001-ccid-usb-descriptors.patch (UNO R4
// USB.cpp CCID-only path). ccid_usb_tinyusb.cpp is unchanged.

#include "ccid_usb_desc.h"
#include "nero_nfc_mem_util.h"

#if defined(NERO_CCID_USB_BUILD) && defined(NERO_CCID_STM32_USB_BUILD)

extern "C" {
#include "common/tusb_types.h"
#include "device/usbd.h"
#include "stm32wba65xx.h"
#include "tusb.h"
}

#include <cstring>

#include "nero_nfc_attrs.h"

NERO_NFC_STATIC_ASSERT(CFG_TUSB_DEBUG >= 0, "TinyUSB debug level");
NERO_NFC_STATIC_ASSERT(CFG_TUD_ENDPOINT0_SIZE == NERO_USB_EP0_MAX_PACKET_SIZE,
                       "TinyUSB EP0 size matches ccid_usb_desc.h");
typedef struct {
  CFG_TUSB_MEM_ALIGN uint8_t mem_align_probe;
} nero_ccid_tusb_mem_align_probe_t;

#ifndef USB_VID
#ifdef USBD_VID
#define USB_VID USBD_VID
#else
#define USB_VID 0x2341u
#endif
#endif

#ifndef USB_PID
#ifdef USBD_PID
#define USB_PID USBD_PID
#else
#define USB_PID 0x006Eu
#endif
#endif

#define USBD_STR_0 0x00u
#define USBD_STR_MANUF 0x01u
#define USBD_STR_PRODUCT 0x02u
#define USBD_STR_SERIAL 0x03u
#define USBD_STR_CCID 0x04u

enum {
  kUsbHexNibbleMask = 0xFu,
  kUsbSerialHexDigits = 8u,
  kUsbStringDescCharMax = 32u,
  kUsbStringDescHdrBytes = 2u,
  kStm32UidWordIndex1 = 1u,
  kStm32UidWordIndex2 = 2u,
};

static uint8_t s_cfg_desc[TUD_CONFIG_DESC_LEN + NERO_CCID_CFG_DESC_TOTAL];
static bool s_cfg_built = false;

static void build_ccid_configuration(void) {
  if (s_cfg_built) {
    return;
  }

  const unsigned cfg_total = static_cast<unsigned>(sizeof(s_cfg_desc));
  /* TUD_CONFIG_DESCRIPTOR: config_num, itf_count, str_idx, total_len, attr, mA
   */
  const uint8_t tud_cfg_hdr[TUD_CONFIG_DESC_LEN] = {
    TUD_CONFIG_DESCRIPTOR(1, 1, 0, cfg_total, 0, NERO_USB_CONFIG_MAX_POWER_MA)};

  (void)nero_nfc_copy_bytes(s_cfg_desc, sizeof(s_cfg_desc), 0u, tud_cfg_hdr, sizeof(tud_cfg_hdr));
  (void)nero_ccid_copy_interface_descriptor_blob(&s_cfg_desc[NERO_USB_CFG_DESC_INTERFACE_OFFSET],
                                                 0u, USBD_STR_CCID);
  s_cfg_built = true;
}

extern "C" void nero_ccid_stm32_setup_usb_descriptors(void) {
  build_ccid_configuration();
}

extern "C" const uint8_t *tud_descriptor_device_cb(void) {
  static tusb_desc_device_t desc = {.bLength = sizeof(tusb_desc_device_t),
                                    .bDescriptorType = TUSB_DESC_DEVICE,
                                    .bcdUSB = NERO_USB_BCD_USB_2_0,
                                    .bDeviceClass = TUSB_CLASS_SMART_CARD,
                                    .bDeviceSubClass = 0,
                                    .bDeviceProtocol = 0,
                                    .bMaxPacketSize0 = NERO_USB_EP0_MAX_PACKET_SIZE,
                                    .idVendor = static_cast<uint16_t>(USB_VID),
                                    .idProduct = static_cast<uint16_t>(USB_PID),
                                    .bcdDevice = NERO_USB_BCD_DEVICE_1_0,
                                    .iManufacturer = USBD_STR_MANUF,
                                    .iProduct = USBD_STR_PRODUCT,
                                    .iSerialNumber = USBD_STR_SERIAL,
                                    .bNumConfigurations = 1};

  return reinterpret_cast<const uint8_t *>(&desc);
}

extern "C" const uint8_t *tud_descriptor_configuration_cb(uint8_t index) {
  (void)index;
  build_ccid_configuration();
  return s_cfg_desc;
}

static void utox8(uint32_t val, char *s) {
  for (int i = 0; i < kUsbSerialHexDigits; i++) {
    const int d = static_cast<int>(val & kUsbHexNibbleMask);
    val >>= NERO_USB_HEX_NIBBLE_SHIFT;
    s[(kUsbSerialHexDigits - 1) - i] = static_cast<char>(
      d > NERO_USB_ASCII_DIGIT_MAX ? ('A' + d - NERO_USB_ASCII_HEX_LETTER_BASE) : ('0' + d));
  }
}

extern "C" const uint16_t *tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
  (void)langid;
  static uint16_t desc_str[NERO_USB_STRING_DESC_WORD_CAP];
  static char id_string[NERO_USB_STRING_DESC_WORD_CAP] = {0};

  static const char *const kStrings[] = {
    [USBD_STR_0] = "",
    [USBD_STR_MANUF] = "Nero NFC",
    [USBD_STR_PRODUCT] = "NUCLEO-WBA65 CCID",
    [USBD_STR_SERIAL] = id_string,
    [USBD_STR_CCID] = "NERO NFC CCID",
  };

  if (id_string[0] == '\0') {
    const uint32_t uid0 = *reinterpret_cast<volatile uint32_t *>(UID_BASE);
    const uint32_t uid1 = *(reinterpret_cast<volatile uint32_t *>(UID_BASE) + kStm32UidWordIndex1);
    const uint32_t uid2 = *(reinterpret_cast<volatile uint32_t *>(UID_BASE) + kStm32UidWordIndex2);
    utox8(uid0, &id_string[0]);
    utox8(uid1, &id_string[NERO_USB_SERIAL_HEX_WORD1_CHAR_OFFSET]);
    utox8(uid2, &id_string[NERO_USB_SERIAL_HEX_WORD2_CHAR_OFFSET]);
    id_string[NERO_USB_SERIAL_HEX_TOTAL_CHARS] = '\0';
  }

  uint8_t len = 0;
  if (index == 0) {
    desc_str[1] = NERO_USB_LANGID_EN_US;
    len = 1;
  } else {
    if (index >= (sizeof(kStrings) / sizeof(kStrings[0]))) {
      return NERO_NFC_NULL;
    }
    const char *str = kStrings[index];
    for (len = 0; len < kUsbStringDescCharMax && str[len] != '\0'; ++len) {
      desc_str[1u + len] = static_cast<uint16_t>(str[len]);
    }
  }

  desc_str[0] = static_cast<uint16_t>((TUSB_DESC_STRING << NERO_USB_DESC_TYPE_STRING_SHIFT) |
                                      (kUsbStringDescHdrBytes * len + kUsbStringDescHdrBytes));
  return desc_str;
}

#endif /* NERO_CCID_USB_BUILD && NERO_CCID_STM32_USB_BUILD */
