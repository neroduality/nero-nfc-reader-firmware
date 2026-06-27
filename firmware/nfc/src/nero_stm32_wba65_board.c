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

// USB OTG HS init for NUCLEO-WBA65RI — verbatim sequence from TinyUSB BSP:
// third-party/tinyusb/hw/bsp/stm32wba/family.c (board_init, USB_OTG_HS block).
// Arduino/stmdunio owns system clock via SystemClock_Config (matching board.h).

#if defined(NERO_CCID_USB_BUILD) && defined(NERO_CCID_STM32_USB_BUILD)

#include "stm32wbaxx_hal.h"
#include "tusb.h"

enum { NERO_WBA65_USB_OTG_HS_IRQ_PRIORITY = 5u };

void nero_wba65_board_usb_init(void) {
#ifdef USB_OTG_HS
  __HAL_RCC_USB_OTG_HS_CLK_ENABLE();
  __HAL_RCC_USB_OTG_HS_PHY_CLK_ENABLE();

  PWR->SVMCR |= PWR_SVMCR_USV;

  PWR->VOSR &= ~PWR_VOSR_VDD11USBDIS;
  PWR->VOSR |= PWR_VOSR_USBPWREN;
  while ((PWR->VOSR & PWR_VOSR_VDD11USBRDY) == 0) {}

  PWR->VOSR |= PWR_VOSR_USBBOOSTEN;
  while ((PWR->VOSR & PWR_VOSR_USBBOOSTRDY) == 0) {}

  PWR->SVMCR |= PWR_SVMCR_USV;

  SYSCFG->OTGHSPHYCR &= ~SYSCFG_OTGHSPHYCR_CLKSEL;
  SYSCFG->OTGHSPHYCR |=
    SYSCFG_OTGHSPHYCR_CLKSEL_0 | SYSCFG_OTGHSPHYCR_CLKSEL_1 | SYSCFG_OTGHSPHYCR_CLKSEL_3;
  SYSCFG->OTGHSPHYCR |= SYSCFG_OTGHSPHYCR_EN;

  /* CN9 has no dedicated VBUS sense — match TinyUSB stm32wba BSP (family.c). */
  USB_OTG_HS->GCCFG &= ~USB_OTG_GCCFG_VBDEN;
  USB_OTG_HS->GCCFG |= USB_OTG_GCCFG_VBVALEXTOEN;
  USB_OTG_HS->GCCFG |= USB_OTG_GCCFG_VBVALOVAL;

  HAL_NVIC_SetPriority(USB_OTG_HS_IRQn, NERO_WBA65_USB_OTG_HS_IRQ_PRIORITY, 0);
  HAL_NVIC_EnableIRQ(USB_OTG_HS_IRQn);
#endif
}

void USB_OTG_HS_IRQHandler(void) {
  tud_int_handler(0);
}

#endif /* NERO_CCID_USB_BUILD && NERO_CCID_STM32_USB_BUILD */
