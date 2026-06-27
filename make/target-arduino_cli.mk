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

# Reusable Arduino-CLI build/upload driver. Board-specific identity stays in
# make/board-<TARGET>.mk (FQBN, core package, HAL subtree, description).

# ── Combined (nfc) ────────────────────────────────────────────────────────────
NFC_INCLUDES = $(ARDUINO_PROJECT_INCLUDES) \
               -I$(CURDIR)/$(FIRMWARE_DIR)/reader/src \
               -I$(CURDIR)/$(FIRMWARE_DIR)/writer/src \
               $(if $(filter ccid,$(NFC_USB_MODE)),$(BOARD_CCID_INCLUDES),)

NFC_DEFAULT_FLAG = $(if $(filter writer,$(NFC_MODE)),-DNFC_DEFAULT_WRITER=1,)

VALID_NFC_USB_MODES := $(BOARD_SUPPORTED_NFC_USB_MODES)
ifeq ($(filter $(NFC_USB_MODE),$(VALID_NFC_USB_MODES)),)
  $(error NFC_USB_MODE '$(NFC_USB_MODE)' is not supported. Use one of: $(VALID_NFC_USB_MODES))
endif

ifeq ($(NFC_USB_MODE),ccid)
ifneq ($(NFC_MODE),reader)
  $(error NFC_USB_MODE=ccid only supports NFC_MODE=reader because CCID-only builds do not expose the serial writer shell)
endif
endif

# build.extra_flags applies to sketch + core; board fragments add any core-wide
# USB or board-package flags they need.
BOARD_CDC_BUILD_EXTRA_FLAGS ?=
BOARD_CCID_BUILD_EXTRA_FLAGS ?= -DNERO_CCID_USB_BUILD=1 -DNERO_CCID_ONLY_BUILD=1
BOARD_CCID_USB_SYNC_REQUIRED ?= 0
NFC_BUILD_EXTRA_FLAGS :=
ifneq ($(strip $(BOARD_HOST_BANNER)),)
NFC_BUILD_EXTRA_FLAGS += '-DNFC_HOST_BOARD_NAME=\"$(BOARD_HOST_BANNER)\"'
endif
ifeq ($(NFC_USB_MODE),cdc)
# UNO R4 boards.txt defines -DNO_USB by default; clear it so Serial stays on
# USB CDC for the reader/writer workflow.
NFC_BUILD_EXTRA_FLAGS += $(BOARD_CDC_BUILD_EXTRA_FLAGS)
# stm32duino defaults to 64 B; must cover full writer_serial_cli lines.
NFC_BUILD_EXTRA_FLAGS += -DSERIAL_RX_BUFFER_SIZE=$(NFC_CDC_SERIAL_LINE_CAP)
endif
ifeq ($(NFC_USB_MODE),ccid)
NFC_BUILD_EXTRA_FLAGS += $(BOARD_CCID_BUILD_EXTRA_FLAGS)
endif
ifeq ($(FIRMWARE_MIN_SIZE),1)
NFC_BUILD_EXTRA_FLAGS += -UBACKTRACE_SUPPORT
endif

NFC_USB_SYNC_REQUIRED := $(if $(filter ccid,$(NFC_USB_MODE)),$(filter 1,$(BOARD_CCID_USB_SYNC_REQUIRED)),)

# Default 1: wipe build/nfc and pass --clean (reproducible). Set NFC_ARDUINO_CLEAN=0 for faster dev rebuilds.
NFC_ARDUINO_CLEAN ?= 1
ifeq ($(NFC_ARDUINO_CLEAN),0)
NFC_COMPILE_PREP := mkdir -p $(NFC_BUILD_DIR)
NFC_ARDUINO_COMPILE_FLAGS :=
else
NFC_COMPILE_PREP := rm -rf $(NFC_BUILD_DIR) && mkdir -p $(NFC_BUILD_DIR)
NFC_ARDUINO_COMPILE_FLAGS := --clean
endif

ARDUINO_BUILD_PROPS_NFC = \
	--warnings $(ARDUINO_WARNINGS) \
	--build-property compiler.c.extra_flags="-std=$(C_STD) $(C_SECURITY_FLAGS) $(ARDUINO_VENDOR_ISYSTEM_FLAGS) $(NFC_INCLUDES)" \
	--build-property compiler.cpp.extra_flags="-std=$(CPP_STD) $(CPP_SECURITY_FLAGS) $(ARDUINO_VENDOR_ISYSTEM_FLAGS) $(NFC_INCLUDES) $(NFC_DEFAULT_FLAG)" \
	$(if $(strip $(NFC_BUILD_EXTRA_FLAGS)),--build-property "build.extra_flags=$(NFC_BUILD_EXTRA_FLAGS)",)

define COMPILE_NFC
echo "── Building $(notdir $(1)) for $(BOARD_DESCRIPTION) ($(NFC_MODE) default boot · USB $(NFC_USB_MODE)) ──"; \
$(if $(NFC_USB_SYNC_REQUIRED),bash "$(CURDIR)/scripts/ccid-sync-arduino-usb-cpp.sh" "$(CURDIR)" "$(ARDUINO_CLI)" "$(ARDUINO_MIN_BOARD_CORE_VERSION)" && ,)$(NFC_COMPILE_PREP) && \
bash "$(CURDIR)/scripts/run-arduino-compile.sh" --board "$(BOARD_DESCRIPTION)" --repo-root "$(CURDIR)" -- \
  $(ARDUINO_CLI) compile --fqbn $(FQBN) $(NFC_ARDUINO_COMPILE_FLAGS) \
  $(ARDUINO_BUILD_PROPS_NFC) \
  --output-dir $(2) $(1)
endef

.PHONY: nfc nfc-cdc nfc-ccid flash flash-cdc flash-ccid _do-flash

BOARD_NFC_EXTRA_DEPS ?=
BOARD_CCID_EXTRA_DEPS ?=

nfc: third-party-host-tools third-party-nfc-libs $(BOARD_NFC_EXTRA_DEPS) \
  $(if $(filter ccid,$(NFC_USB_MODE)),$(BOARD_CCID_EXTRA_DEPS),)
	@$(call COMPILE_NFC,$(NFC_DIR),$(NFC_BUILD_DIR))

nfc-cdc:
	@$(MAKE) nfc NFC_USB_MODE=cdc

nfc-ccid:
	@$(MAKE) nfc NFC_USB_MODE=ccid

_do-flash: nfc
	@$(call UPLOAD_C_SKETCH,nfc,$(NFC_DIR),$(NFC_BUILD_DIR))
ifeq ($(NFC_USB_MODE),ccid)
	@echo ""
ifeq ($(TARGET),nucleo_wba65ri)
	@echo "── CCID: plug Nucleo USER USB-C (CN9, not ST-Link CN15), then ──"
	@echo "  sudo make install-pcsc-driver   # once per host"
	@echo "  lsusb | rg -i '2341:006e'"
	@echo "  pcsc_scan"
else ifeq ($(TARGET),arduino_uno_r4wifi)
	@echo "── CCID: replug USB if the host did not enumerate the reader, then ──"
	@echo "  sudo make install-pcsc-driver   # once per host (Linux)"
	@echo "  lsusb | rg -i '2341:006d'"
	@echo "  pcsc_scan"
endif
endif

flash:
	@$(MAKE) _do-flash NFC_USB_MODE=ccid

flash-cdc:
	@$(MAKE) _do-flash NFC_USB_MODE=cdc

flash-ccid:
	@$(MAKE) _do-flash NFC_USB_MODE=ccid
