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
 *******************************************************************************
 * Copyright (c) 2023, STMicroelectronics
 * All rights reserved.
 *
 * This software component is licensed by ST under BSD 3-Clause license,
 * the "License"; You may not use this file except in compliance with the
 * License. You may obtain a copy of the License at:
 *                        opensource.org/licenses/BSD-3-Clause
 *
 *******************************************************************************
 */
#pragma once

/*----------------------------------------------------------------------------
 *        STM32 pins number — NUCLEO-WBA65RI Arduino Uno V3 (UM3610)
 *----------------------------------------------------------------------------*/
#define PA11                    0
#define PA12                    1
#define PE0                     2
#define PB13                    3
#define PA3                     4
#define PB14                    5
#define PB0                     6
#define PD14                    7
#define PA10                    8
#define PB11                    9
#define PB9                     10
#define PC3                     11
#define PA9                     12
#define PB10                    13
#define PB1                     14
#define PB2                     15

#define PA4                     PIN_A0
#define PA6                     PIN_A1
#define PA2                     PIN_A2
#define PA1                     PIN_A3
#define PA5                     PIN_A4
#define PA0                     PIN_A5

#define PD8                     22
#define PC4                     23
#define PB8                     24
#define PC13                    25
#define PC5                     26
#define PB4                     27
#define PB12                    28
#define PA8                     29
#define PC15                    30
#define PC14                    31
#define PA14                    32
#define PA13                    33
#define PH3                     34

// Alternate pins number
#define PA0_ALT1                (PA0  | ALT1)
#define PA1_ALT1                (PA1  | ALT1)
#define PA1_ALT2                (PA1  | ALT2)
#define PA2_ALT1                (PA2  | ALT1)
#define PA3_ALT1                (PA3  | ALT1)
#define PA9_ALT1                (PA9  | ALT1)
#define PA10_ALT1               (PA10 | ALT1)
#define PA11_ALT1               (PA11 | ALT1)
#define PA12_ALT1               (PA12 | ALT1)
#define PB1_ALT1                (PB1  | ALT1)
#define PB2_ALT1                (PB2  | ALT1)
#define PB4_ALT1                (PB4  | ALT1)
#define PB8_ALT1                (PB8  | ALT1)
#define PB9_ALT1                (PB9  | ALT1)
#define PB9_ALT2                (PB9  | ALT2)
#define PB10_ALT1               (PB10 | ALT1)
#define PB11_ALT1               (PB11 | ALT1)
#define PB13_ALT1               (PB13 | ALT1)
#define PC3_ALT1                (PC3  | ALT1)
#define PD14_ALT1               (PD14 | ALT1)

#define NUM_DIGITAL_PINS        35
#define NUM_ANALOG_INPUTS       6

// On-board LED pin number (active low)
#define LED1                    PD8
#define LED2                    PC4
#define LED3                    PB8
#ifndef LED_BUILTIN
  #define LED_BUILTIN           LED1
#endif
#define LED_BLUE                LED1
#define LED_GREEN               LED2
#define LED_RED                 LED3

// On-board user button
#define B1_BTN                  PC13
#define B2_BTN                  PC5
#define B3_BTN                  PB4
#ifndef USER_BTN
  #define USER_BTN              B1_BTN
#endif

// Timer Definitions
#ifndef TIMER_TONE
  #define TIMER_TONE            TIM16
#endif
#ifndef TIMER_SERVO
  #define TIMER_SERVO           TIM17
#endif

// UART Definitions
#ifndef SERIAL_UART_INSTANCE
  #define SERIAL_UART_INSTANCE  1
#endif

#ifndef PIN_SERIAL_RX
  #define PIN_SERIAL_RX         PA8
#endif
#ifndef PIN_SERIAL_TX
  #define PIN_SERIAL_TX         PB12
#endif

// Alternate SYS_WKUP definition
#define PWR_WAKEUP_PIN1_1
#define PWR_WAKEUP_PIN3_1
#define PWR_WAKEUP_PIN4_1
#define PWR_WAKEUP_PIN6_1
#define PWR_WAKEUP_PIN7_1
#define PWR_WAKEUP_PIN8_1

/*----------------------------------------------------------------------------
 *        Arduino objects - C++ only
 *----------------------------------------------------------------------------*/

#ifdef __cplusplus
  #ifndef SERIAL_PORT_MONITOR
    #define SERIAL_PORT_MONITOR   Serial
  #endif
  #ifndef SERIAL_PORT_HARDWARE
    #define SERIAL_PORT_HARDWARE  Serial
  #endif
#endif
