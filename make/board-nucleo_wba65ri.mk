# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2026 Nero Duality, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# NUCLEO-WBA65RI + X-NUCLEO-NFC08A1 (ST25R3916B).

BOARD_DESCRIPTION ?= Nucleo-WBA65RI + X-NUCLEO-NFC08A1
BOARD_HOST_BANNER ?= Nucleo-WBA65RI, X-NUCLEO-NFC08A1
BOARD_TARGET_DRIVER := arduino_cli
ARDUINO_ISYSTEM_PROFILE := wba65

# stm32duino newlib lacks ssp.h required by -fstack-protector-strong / _FORTIFY_SOURCE.
BOARD_SKIP_HOST_HARDENING := 1

FQBN := STMicroelectronics:stm32:Nucleo_64:pnum=NUCLEO_WBA65RI,upload_method=OpenOCDSTLink

# CCID via vendored TinyUSB (USER USB-C CN9). Serial CDC remains available via `make flash-cdc`.
BOARD_DEFAULT_NFC_USB_MODE := ccid
BOARD_SUPPORTED_NFC_USB_MODES := cdc ccid
BOARD_DEFAULT_NFC_FRONTEND := st25r3916
BOARD_CCID_USB_SYNC_REQUIRED := 0
BOARD_CCID_EXTRA_DEPS := third-party-tinyusb-wba65
BOARD_NFC_EXTRA_DEPS := third-party-wba65-openocd

TINYUSB_WBA65_SRC := $(CURDIR)/third-party/tinyusb/src
BOARD_CCID_INCLUDES := \
  -I$(TINYUSB_WBA65_SRC) \
  -I$(CURDIR)/firmware/port/stm32_wba65_ccid

# X-NUCLEO-NFC08A1 (UM3007): CS=D10, IRQ=A0, LED106 field=D7.
# WBA65RI Arduino map (UM3610): A0 = digital index 16 (PA4); defaults CS=10 LED=7.
WBA65_NFC_PINS := -DNFC_FRONTEND_ID_ST25R3916=1 -DNFC_BOARD_IRQ_PIN=16u

BOARD_CCID_BUILD_EXTRA_FLAGS := \
  -DNERO_CCID_USB_BUILD=1 \
  -DNERO_CCID_ONLY_BUILD=1 \
  -DNERO_CCID_STM32_USB_BUILD=1 \
  -DCFG_TUSB_MCU=OPT_MCU_STM32WBA \
  -DSTM32WBA65xx \
  -DUSBD_VID=0x2341 \
  -DUSBD_PID=0x006E \
  -DNERO_CCID_BULK_EPSIZE=512u \
  $(WBA65_NFC_PINS)
# CN9 is USB OTG HS (TinyUSB stm32wba family.cmake OPT_MODE_HIGH_SPEED).
# Bulk wMaxPacketSize must be 512 at HS; ccid_usb_desc.h stays 64 for UNO.

ARDUINO_CORE_PACKAGE := STMicroelectronics:stm32
ARDUINO_MIN_BOARD_CORE_VERSION ?= 2.12.0
WBA65_STM32_CORE_VERSION ?= $(ARDUINO_MIN_BOARD_CORE_VERSION)
WBA65_STM32_BOARD_MANAGER_URLS := https://github.com/stm32duino/BoardManagerFiles/raw/main/package_stmicroelectronics_index.json
ARDUINO_BOARD_MANAGER_URLS := $(WBA65_STM32_BOARD_MANAGER_URLS)

BOARD_ARDUINO_PLATFORM_SETUP := $(CURDIR)/make/ensure-wba65-stm32-core.sh
BOARD_ARDUINO_PLATFORM_FILES := \
  $(CURDIR)/make/ensure-wba65-stm32-core.sh \
  $(CURDIR)/scripts/stm32-sync-wba65-board.sh \
  $(CURDIR)/patches/arduino/stm32/wba65/nucleo_wba65ri_boards.fragment \
  $(CURDIR)/patches/arduino/stm32/wba65/variant_NUCLEO_WBA65RI.h \
  $(CURDIR)/patches/arduino/stm32/wba65/variant_NUCLEO_WBA65RI.cpp \
  $(CURDIR)/patches/arduino/stm32/wba65/ldscript.ld

BOARD_UPLOAD_SCRIPT := $(CURDIR)/scripts/wba65-openocd-flash.sh
BOARD_UPLOAD_NEEDS_PORT := 0
BOARD_UPLOAD_HINT := ST-Link OpenOCD upload (project WBA6-capable OpenOCD)
BOARD_UPLOAD_PREP := echo "   Nucleo-WBA65RI upload:"; echo "   1. USB connected (ST-Link 0483:3753)"; echo "   2. No bootloader button needed"; echo "   3. Uses third-party/openocd-wba65 (project OpenOCD build)"
BOARD_PORT_DISCOVERY_SECONDS := 15

# X-NUCLEO-NFC08A1 on Arduino Uno V3 header — see WBA65_NFC_PINS above.
BOARD_CDC_BUILD_EXTRA_FLAGS := $(WBA65_NFC_PINS) -DNFC_HAL_RXBUF_CAP=$(NFC_CDC_SERIAL_LINE_CAP)u

PORT_LIB_DIR := $(CURDIR)/firmware/port/arduino_spi_serial
BOARD_READER_HAL_UNIT := reader_hal_board.cpp
BOARD_WRITER_HAL_UNIT := writer_hal_board.cpp
BOARD_NFC_HAL_UNIT := nfc_hal_board.cpp
