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

# make/board-<TARGET>.mk — board SKU + toolchain identity (MCU / Arduino FQBN / HAL subtree).
#
# Included from the top Makefile when TARGET matches the filename suffix.

BOARD_DESCRIPTION ?= Arduino UNO R4 WiFi
BOARD_HOST_BANNER ?= Arduino UNO R4 WiFi
BOARD_TARGET_DRIVER := arduino_cli
ARDUINO_ISYSTEM_PROFILE := uno

FQBN := arduino:renesas_uno:unor4wifi
BOARD_DEFAULT_NFC_USB_MODE := ccid
BOARD_SUPPORTED_NFC_USB_MODES := cdc ccid
BOARD_UPLOAD_HINT := Arduino bootloader upload
BOARD_UPLOAD_PREP := echo "   Arduino UNO R4 WiFi upload sequence:"; echo "   1. Connect the UNO R4 WiFi over USB"; echo "   2. Double-click RESET now to enter the Arduino bootloader"; echo "   3. make will show a spinner while waiting for the bootloader upload port (up to 30s)"; echo "   4. Leave the bootloader USB port connected while arduino-cli uploads"
BOARD_PORT_DISCOVERY_SECONDS := 30
BOARD_UPLOAD_READY_BANNER := Arduino bootloader upload ready
BOARD_UPLOAD_WAIT_MESSAGE := User Action required (read above) — waiting for bootloader port
BOARD_CDC_BUILD_EXTRA_FLAGS := -UNO_USB -UBACKTRACE_SUPPORT -DNERO_RAM_CONSTRAINED=1
BOARD_CCID_BUILD_EXTRA_FLAGS := -DNERO_CCID_USB_BUILD=1 -DNERO_CCID_ONLY_BUILD=1 -UNO_USB -UBACKTRACE_SUPPORT
BOARD_CCID_USB_SYNC_REQUIRED := 1

# arduino-cli "core list" primary column — used by host bootstrap.
ARDUINO_CORE_PACKAGE := arduino:renesas_uno

# Pinned Arduino core semver for `arduino-cli core install`; UNO R4 WiFi inherits Renesas default.
ARDUINO_MIN_BOARD_CORE_VERSION ?= $(ARDUINO_MIN_RENESAS_CORE)
