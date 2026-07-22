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

/*
 * Default (no-op) CCID USB HAL for combined-firmware images whose board handles
 * USB through the Arduino core rather than the repo's TinyUSB port (e.g. UNO
 * R4). Weak so the STM32/WBA65 TinyUSB port (ccid_usb_stm32_tinyusb.c) provides
 * the strong override when NERO_CCID_STM32_USB_BUILD is defined.
 */

#include "reader_hal_ccid_usb.h"

__attribute__((weak)) void reader_hal_ccid_usb_begin(void) {}

__attribute__((weak)) bool reader_hal_ccid_usb_configured(void) { return true; }

__attribute__((weak)) void reader_hal_ccid_usb_service_poll(void) {}
