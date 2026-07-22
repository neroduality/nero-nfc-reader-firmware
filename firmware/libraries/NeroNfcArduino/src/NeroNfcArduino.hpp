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

#include <Arduino.h>
#include <SPI.h>

#include "nero_nfc_platform.h"

#ifndef NERO_NFC_ARDUINO_DEFAULT_SPI_CLOCK_HZ
#define NERO_NFC_ARDUINO_DEFAULT_SPI_CLOCK_HZ 2000000u
#endif

/* Owns Arduino Serial, SPI, GPIO, clock, and delay behind platform ops. */
class NfcArduinoPort {
 public:
  explicit NfcArduinoPort(
      HardwareSerial& serial = Serial, SPIClass& spi = SPI,
      uint32_t spi_clock_hz = NERO_NFC_ARDUINO_DEFAULT_SPI_CLOCK_HZ);

  void SetSpiClockHz(uint32_t spi_clock_hz);
  nero_nfc_platform_ops_t MakeOps();

  static uint32_t MillisImpl();
  static uint32_t MicrosImpl();
  static void DelayMsImpl(uint32_t ms);
  static void DelayUsImpl(uint32_t us);
  void SerialBeginImpl(uint32_t baud);
  NERO_NFC_NODISCARD bool SerialReadyImpl();
  void SerialWriteCharImpl(char c);
  int SerialAvailableImpl();
  int SerialReadByteImpl();
  static void PinModeImpl(uint8_t pin, uint8_t mode);
  static void DigitalWriteImpl(uint8_t pin, uint8_t value);
  static int DigitalReadImpl(uint8_t pin);
  void SpiBeginImpl();
  void SpiBeginTransactionImpl();
  void SpiEndTransactionImpl();
  uint8_t SpiTransferImpl(uint8_t data);

 private:
  HardwareSerial* serial_;
  SPIClass* spi_;
  SPISettings spi_settings_;
};
