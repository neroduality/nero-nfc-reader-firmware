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
// Arduino/stm32duino owns system clock via SystemClock_Config (matching
// board.h).
//
// Host clang-tidy scrub drops -mcpu= (keeps --target=arm-none-eabi only), so
// CMSIS HAL headers fail closed. Gate the HAL body on Cortex-M33 macros that
// arm-none-eabi -mcpu=cortex-m33 defines; tidy then sees snake_case stubs only.

#if defined(NERO_CCID_USB_BUILD) && defined(NERO_CCID_STM32_USB_BUILD)

#if defined(__ARM_ARCH_8M_MAIN__) || defined(__ARM_ARCH_8M_BASE__)

#include "stm32wbaxx_hal.h"
#include "nero_wba65_cmsis_compat.h"
#include "tusb.h"

enum { NERO_WBA65_USB_OTG_HS_IRQ_PRIORITY = 5u };

void nero_wba65_board_usb_init(void) {
#ifdef USB_OTG_HS
  __HAL_RCC_USB_OTG_HS_CLK_ENABLE();
  __HAL_RCC_USB_OTG_HS_PHY_CLK_ENABLE();

  PWR->SVMCR |= PWR_SVMCR_USV;

  PWR->VOSR &= ~PWR_VOSR_VDD11USBDIS;
  PWR->VOSR |= PWR_VOSR_USBPWREN;
  while ((PWR->VOSR & PWR_VOSR_VDD11USBRDY) == 0) {
  }

  PWR->VOSR |= PWR_VOSR_USBBOOSTEN;
  while ((PWR->VOSR & PWR_VOSR_USBBOOSTRDY) == 0) {
  }

  PWR->SVMCR |= PWR_SVMCR_USV;

  SYSCFG->OTGHSPHYCR &= ~SYSCFG_OTGHSPHYCR_CLKSEL;
  SYSCFG->OTGHSPHYCR |= SYSCFG_OTGHSPHYCR_CLKSEL_0 |
                        SYSCFG_OTGHSPHYCR_CLKSEL_1 | SYSCFG_OTGHSPHYCR_CLKSEL_3;
  SYSCFG->OTGHSPHYCR |= SYSCFG_OTGHSPHYCR_EN;

  /* CN9 has no dedicated VBUS sense — match TinyUSB stm32wba BSP (family.c). */
  USB_OTG_HS->GCCFG &= ~USB_OTG_GCCFG_VBDEN;
  USB_OTG_HS->GCCFG |= USB_OTG_GCCFG_VBVALEXTOEN;
  USB_OTG_HS->GCCFG |= USB_OTG_GCCFG_VBVALOVAL;

  HAL_NVIC_SetPriority(USB_OTG_HS_IRQn, NERO_WBA65_USB_OTG_HS_IRQ_PRIORITY, 0);
  HAL_NVIC_EnableIRQ(USB_OTG_HS_IRQn);
#endif
}

/* CMSIS vector symbol; C name stays snake_case for clang-tidy. */
void usb_otg_hs_irq_handler(void) asm("USB_OTG_HS_IRQHandler");
void usb_otg_hs_irq_handler(void) { tud_int_handler(0); }

#else /* host clang-tidy scrub (no -mcpu) */

void nero_wba65_board_usb_init(void) {}

void usb_otg_hs_irq_handler(void) asm("USB_OTG_HS_IRQHandler");
void usb_otg_hs_irq_handler(void) {}

#endif /* __ARM_ARCH_8M_* */

#endif /* NERO_CCID_USB_BUILD && NERO_CCID_STM32_USB_BUILD */
