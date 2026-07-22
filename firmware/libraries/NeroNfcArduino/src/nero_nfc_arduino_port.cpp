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

#include "NeroNfcArduino.hpp"

#include "nero_nfc_null.h"

namespace {

NfcArduinoPort* AsPort(void* context) {
  return static_cast<NfcArduinoPort*>(context);
}

uint32_t TrampolineMillis(void* context) {
  (void)context;
  return NfcArduinoPort::MillisImpl();
}

uint32_t TrampolineMicros(void* context) {
  (void)context;
  return NfcArduinoPort::MicrosImpl();
}

void TrampolineDelayMs(void* context, uint32_t ms) {
  (void)context;
  NfcArduinoPort::DelayMsImpl(ms);
}

void TrampolineDelayUs(void* context, uint32_t us) {
  (void)context;
  NfcArduinoPort::DelayUsImpl(us);
}

void TrampolineSerialBegin(void* context, uint32_t baud) {
  AsPort(context)->SerialBeginImpl(baud);
}

bool TrampolineSerialReady(void* context) {
  return AsPort(context)->SerialReadyImpl();
}

void TrampolineSerialWriteChar(void* context, char c) {
  AsPort(context)->SerialWriteCharImpl(c);
}

int TrampolineSerialAvailable(void* context) {
  return AsPort(context)->SerialAvailableImpl();
}

int TrampolineSerialReadByte(void* context) {
  return AsPort(context)->SerialReadByteImpl();
}

void TrampolinePinMode(void* context, uint8_t pin, uint8_t mode) {
  (void)context;
  NfcArduinoPort::PinModeImpl(pin, mode);
}

void TrampolineDigitalWrite(void* context, uint8_t pin, uint8_t value) {
  (void)context;
  NfcArduinoPort::DigitalWriteImpl(pin, value);
}

int TrampolineDigitalRead(void* context, uint8_t pin) {
  (void)context;
  return NfcArduinoPort::DigitalReadImpl(pin);
}

void TrampolineSpiBegin(void* context) { AsPort(context)->SpiBeginImpl(); }

void TrampolineSpiBeginTransaction(void* context) {
  AsPort(context)->SpiBeginTransactionImpl();
}

void TrampolineSpiEndTransaction(void* context) {
  AsPort(context)->SpiEndTransactionImpl();
}

uint8_t TrampolineSpiTransfer(void* context, uint8_t data) {
  return AsPort(context)->SpiTransferImpl(data);
}

}  // namespace

NfcArduinoPort::NfcArduinoPort(HardwareSerial& serial, SPIClass& spi,
                               uint32_t spi_clock_hz)
    : serial_(&serial),
      spi_(&spi),
      spi_settings_(spi_clock_hz, MSBFIRST, SPI_MODE1) {}

void NfcArduinoPort::SetSpiClockHz(uint32_t spi_clock_hz) {
  spi_settings_ = SPISettings(spi_clock_hz, MSBFIRST, SPI_MODE1);
}

nero_nfc_platform_ops_t NfcArduinoPort::MakeOps() {
  nero_nfc_platform_ops_t ops{};
  ops.abi_version = NERO_NFC_PLATFORM_OPS_ABI_VERSION;
  ops.struct_size = sizeof(ops);
  ops.context = this;
  ops.millis = &TrampolineMillis;
  ops.micros = &TrampolineMicros;
  ops.delay_ms = &TrampolineDelayMs;
  ops.delay_us = &TrampolineDelayUs;
  ops.service = NERO_NFC_NULL;
  ops.serial_begin = &TrampolineSerialBegin;
  ops.serial_ready = &TrampolineSerialReady;
  ops.serial_write_char = &TrampolineSerialWriteChar;
  ops.serial_available = &TrampolineSerialAvailable;
  ops.serial_read_byte = &TrampolineSerialReadByte;
  ops.pin_mode = &TrampolinePinMode;
  ops.digital_write = &TrampolineDigitalWrite;
  ops.digital_read = &TrampolineDigitalRead;
  ops.spi_begin = &TrampolineSpiBegin;
  ops.spi_begin_transaction = &TrampolineSpiBeginTransaction;
  ops.spi_end_transaction = &TrampolineSpiEndTransaction;
  ops.spi_transfer = &TrampolineSpiTransfer;
  return ops;
}

uint32_t NfcArduinoPort::MillisImpl() { return millis(); }

uint32_t NfcArduinoPort::MicrosImpl() { return micros(); }

void NfcArduinoPort::DelayMsImpl(uint32_t ms) { delay(ms); }

void NfcArduinoPort::DelayUsImpl(uint32_t us) { delayMicroseconds(us); }

void NfcArduinoPort::SerialBeginImpl(uint32_t baud) { serial_->begin(baud); }

bool NfcArduinoPort::SerialReadyImpl() { return static_cast<bool>(*serial_); }

void NfcArduinoPort::SerialWriteCharImpl(char c) {
  serial_->write(static_cast<uint8_t>(c));
}

int NfcArduinoPort::SerialAvailableImpl() { return serial_->available(); }

int NfcArduinoPort::SerialReadByteImpl() { return serial_->read(); }

void NfcArduinoPort::PinModeImpl(uint8_t pin, uint8_t mode) {
  pinMode(pin, mode == NERO_NFC_PIN_OUTPUT ? OUTPUT : INPUT);
}

void NfcArduinoPort::DigitalWriteImpl(uint8_t pin, uint8_t value) {
  digitalWrite(pin, (value != 0u) ? HIGH : LOW);
}

int NfcArduinoPort::DigitalReadImpl(uint8_t pin) { return digitalRead(pin); }

void NfcArduinoPort::SpiBeginImpl() { spi_->begin(); }

void NfcArduinoPort::SpiBeginTransactionImpl() {
  spi_->beginTransaction(spi_settings_);
}

void NfcArduinoPort::SpiEndTransactionImpl() { spi_->endTransaction(); }

uint8_t NfcArduinoPort::SpiTransferImpl(uint8_t data) {
  return spi_->transfer(data);
}
