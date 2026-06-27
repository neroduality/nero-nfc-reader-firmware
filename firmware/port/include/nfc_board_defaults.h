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

#ifdef __cplusplus
#include <cstdint>
#else
#include <stdint.h>
#endif

/*
 * Default GPIO map: Arduino UNO R4 WiFi + X-NUCLEO-NFC08A1 (ARDUINO header).
 *
 * Override per board by defining these macros before including this header, or
 * pass -DNFC_BOARD_CS_PIN=… on the compiler command line.
 */

#ifndef NFC_BOARD_CS_PIN
#define NFC_BOARD_CS_PIN 10u
#endif

#ifndef NFC_BOARD_IRQ_PIN
#define NFC_BOARD_IRQ_PIN 14u /* A0 on UNO footprint */
#endif

#ifndef NFC_BOARD_LED_PIN
#define NFC_BOARD_LED_PIN 7u
#endif

/* Serial banner; override per board via -DNFC_HOST_BOARD_NAME=\"…\" in board mk. */
#ifndef NFC_HOST_BOARD_NAME
#define NFC_HOST_BOARD_NAME "Arduino UNO R4 WiFi"
#endif
/* Host UART/CDC console baud rate; override per board via -DNFC_HOST_SERIAL_BAUD=… */
#ifndef NFC_HOST_SERIAL_BAUD
#define NFC_HOST_SERIAL_BAUD 115200u
#endif
/* ST25R3916 SPI clock on Arduino UNO R4 + X-NUCLEO-NFC08A1 (override per board). */
#ifndef NFC_BOARD_SPI_CLOCK_HZ
#define NFC_BOARD_SPI_CLOCK_HZ 2000000u
#endif
