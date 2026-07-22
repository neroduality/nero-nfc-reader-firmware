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

NFC_DEFAULT_FLAG = $(if $(filter writer,$(NFC_MODE)),-DNFC_DEFAULT_WRITER=1,)

# ── Product selection ─────────────────────────────────────────────────────────
VALID_FIRMWARE_PRODUCTS := reader writer nfc
FIRMWARE_PRODUCT ?= nfc

ifeq ($(filter $(FIRMWARE_PRODUCT),$(VALID_FIRMWARE_PRODUCTS)),)
  $(error FIRMWARE_PRODUCT '$(FIRMWARE_PRODUCT)' is invalid. Use one of: $(VALID_FIRMWARE_PRODUCTS))
endif

READER_SKETCH_DIR := $(CURDIR)/$(FIRMWARE_DIR)/reader
WRITER_SKETCH_DIR := $(CURDIR)/$(FIRMWARE_DIR)/writer
NFC_SKETCH_DIR := $(CURDIR)/$(FIRMWARE_DIR)/nfc

ifeq ($(FIRMWARE_PRODUCT),reader)
  SKETCH_DIR := $(READER_SKETCH_DIR)
  SKETCH_INCLUDES := $(ARDUINO_PROJECT_INCLUDES) \
                     $(if $(filter ccid,$(NFC_USB_MODE)),$(BOARD_CCID_INCLUDES),)
  SKETCH_C_EXTRA :=
  SKETCH_CPP_EXTRA :=
else ifeq ($(FIRMWARE_PRODUCT),writer)
  SKETCH_DIR := $(WRITER_SKETCH_DIR)
  SKETCH_INCLUDES := $(ARDUINO_PROJECT_INCLUDES)
  SKETCH_C_EXTRA :=
  SKETCH_CPP_EXTRA :=
else
  SKETCH_DIR := $(NFC_SKETCH_DIR)
  SKETCH_INCLUDES := $(ARDUINO_PROJECT_INCLUDES) \
                     $(if $(filter ccid,$(NFC_USB_MODE)),$(BOARD_CCID_INCLUDES),)
  SKETCH_C_EXTRA := $(NFC_DEFAULT_FLAG)
  SKETCH_CPP_EXTRA := $(NFC_DEFAULT_FLAG)
endif
# Product selection is runtime via nero_nfc_app_init; CDC library commands stay
# identical across reader/writer/nfc (no NERO_NFC_BUILD_* macros).

FIRMWARE_BUILD_DIR := $(BUILD_DIR)/firmware/$(TARGET)/$(FIRMWARE_PRODUCT)/$(NFC_USB_MODE)

# Repo-local Arduino libraries (NeroNfc + NeroNfcArduino).
ARDUINO_LIBRARIES_DIR := $(CURDIR)/$(FIRMWARE_DIR)/libraries
ARDUINO_LIBRARIES_FLAG := --libraries $(ARDUINO_LIBRARIES_DIR)

# Reject invalid product/USB before invoking Arduino (firmware product builds).
define ASSERT_VALID_FIRMWARE_PRODUCT_USB
$(if $(and $(filter writer,$(FIRMWARE_PRODUCT)),$(filter ccid,$(NFC_USB_MODE))),$(error writer-ccid is invalid: CCID is a reader personality))
$(if $(and $(filter nfc,$(FIRMWARE_PRODUCT)),$(filter ccid,$(NFC_USB_MODE))),$(error nfc-ccid is invalid: CCID-only builds remove the serial shell; use reader-ccid))
endef

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

# NERO_OPENSSF_CPPFLAGS (libstdc++/libc++ assertion defines) are intentionally NOT
# applied to the MCU cross-build: policy.overrides.openssf-hardening removes them for
# the firmware compile DBs (embedded newlib, no libc++). Kit 0.2.0 Make fragments omit
# mutually exclusive _LIBCPP_HARDENING_MODE defines; CMake still uses CONFIG genex.
# Surviving warning/hardening flags come in via C_SECURITY_FLAGS/CPP_SECURITY_FLAGS.

NFC_USB_SYNC_REQUIRED := $(if $(filter ccid,$(NFC_USB_MODE)),$(filter 1,$(BOARD_CCID_USB_SYNC_REQUIRED)),)

# Default 1: wipe build dirs and pass --clean (reproducible). Set NFC_ARDUINO_CLEAN=0 for faster dev rebuilds.
NFC_ARDUINO_CLEAN ?= 1
ifeq ($(NFC_ARDUINO_CLEAN),0)
FIRMWARE_COMPILE_PREP := mkdir -p $(FIRMWARE_BUILD_DIR)
NFC_ARDUINO_COMPILE_FLAGS :=
else
FIRMWARE_COMPILE_PREP := rm -rf $(FIRMWARE_BUILD_DIR) && mkdir -p $(FIRMWARE_BUILD_DIR)
NFC_ARDUINO_COMPILE_FLAGS := --clean
endif

# WBA CCID: link the separately compiled TinyUSB vendor archive (§6).
BOARD_CCID_LIBRARIES_LDFLAGS ?=
ARDUINO_CCID_LIBRARIES_LDFLAGS := $(if $(and $(filter ccid,$(NFC_USB_MODE)),$(strip $(BOARD_CCID_LIBRARIES_LDFLAGS))),--build-property compiler.libraries.ldflags="$(BOARD_CCID_LIBRARIES_LDFLAGS)",)

ARDUINO_BUILD_PROPS_FIRMWARE = \
	--warnings $(ARDUINO_WARNINGS) \
	--build-property compiler.c.extra_flags="-std=$(C_STD) $(C_SECURITY_FLAGS) $(ARDUINO_VENDOR_ISYSTEM_FLAGS) $(SKETCH_INCLUDES) $(SKETCH_C_EXTRA)" \
	--build-property compiler.cpp.extra_flags="-std=$(CPP_STD) $(CPP_SECURITY_FLAGS) $(ARDUINO_VENDOR_ISYSTEM_FLAGS) $(SKETCH_INCLUDES) $(SKETCH_CPP_EXTRA)" \
	$(if $(strip $(NFC_BUILD_EXTRA_FLAGS)),--build-property "build.extra_flags=$(NFC_BUILD_EXTRA_FLAGS)",) \
	$(ARDUINO_CCID_LIBRARIES_LDFLAGS)

define COMPILE_FIRMWARE
$(ASSERT_VALID_FIRMWARE_PRODUCT_USB) \
echo "── Building $(FIRMWARE_PRODUCT) for $(BOARD_DESCRIPTION) (USB $(NFC_USB_MODE)) ──"; \
$(if $(NFC_USB_SYNC_REQUIRED),bash "$(CURDIR)/scripts/ccid-sync-arduino-usb-cpp.sh" "$(CURDIR)" "$(ARDUINO_CLI)" "$(ARDUINO_MIN_BOARD_CORE_VERSION)" && ,)$(FIRMWARE_COMPILE_PREP) && \
bash "$(CURDIR)/scripts/run-arduino-compile.sh" --board "$(BOARD_DESCRIPTION)" --repo-root "$(CURDIR)" -- \
  $(ARDUINO_CLI) compile --fqbn $(FQBN) $(NFC_ARDUINO_COMPILE_FLAGS) \
  $(ARDUINO_LIBRARIES_FLAG) \
  $(ARDUINO_BUILD_PROPS_FIRMWARE) \
  --build-path $(2)/arduino-build \
  --output-dir $(2) $(1)
endef

.PHONY: firmware reader-cdc reader-ccid writer-cdc nfc nfc-cdc \
        flash-reader-cdc flash-reader-ccid flash-writer-cdc flash-nfc-cdc \
        flash flash-cdc flash-ccid _do-flash-firmware firmware-compile-db \
        print-hardening-profile

BOARD_NFC_EXTRA_DEPS ?=
BOARD_CCID_EXTRA_DEPS ?=

firmware: third-party-host-tools third-party-nfc-libs $(BOARD_NFC_EXTRA_DEPS) \
  $(if $(filter ccid,$(NFC_USB_MODE)),$(BOARD_CCID_EXTRA_DEPS),)
	@$(call COMPILE_FIRMWARE,$(SKETCH_DIR),$(FIRMWARE_BUILD_DIR))
	@$(if $(and $(filter nucleo_wba65ri,$(TARGET)),$(filter reader,$(FIRMWARE_PRODUCT)),$(filter ccid,$(NFC_USB_MODE))),\
	  python3 "$(CURDIR)/scripts/check-wba-tinyusb-artifacts.py" \
	    --repo-root "$(CURDIR)" \
	    --archive "$(TINYUSB_WBA65_ARCHIVE)" \
	    --compile-db "$(TINYUSB_WBA65_COMPILE_DB)" \
	    --link-map "$(FIRMWARE_BUILD_DIR)/reader.ino.map" \
	    --require-link-map,true)

print-hardening-profile:
	@printf '%s\n' "$(NERO_OPENSSF_SELECTED_PROFILES)"

reader-cdc:
	@$(MAKE) firmware FIRMWARE_PRODUCT=reader NFC_USB_MODE=cdc

reader-ccid:
	@$(MAKE) firmware FIRMWARE_PRODUCT=reader NFC_USB_MODE=ccid

writer-cdc:
	@$(MAKE) firmware FIRMWARE_PRODUCT=writer NFC_USB_MODE=cdc

nfc: nfc-cdc

nfc-cdc:
	@$(MAKE) firmware FIRMWARE_PRODUCT=nfc NFC_USB_MODE=cdc

# Compile database for the org lint kit (openssf/clang-tidy/cppcheck firmware analysis).
# --only-compilation-database skips actual compilation; build props mirror `make firmware`
# for the selected FIRMWARE_PRODUCT. Output path matches compile_db.firmware in
# .github/lint-c-cpp.yaml (all eight valid board/product/USB entries).
FIRMWARE_COMPILE_DB_DIR   := $(CURDIR)/build/lint/firmware/$(TARGET)/$(FIRMWARE_PRODUCT)/$(NFC_USB_MODE)
FIRMWARE_COMPILE_DB_BUILD := $(FIRMWARE_COMPILE_DB_DIR)/arduino-build
FIRMWARE_COMPILE_DB_SKETCH_REL := $(patsubst $(CURDIR)/%,%,$(SKETCH_DIR))

firmware-compile-db: third-party-host-tools third-party-nfc-libs $(BOARD_NFC_EXTRA_DEPS) \
  $(if $(filter ccid,$(NFC_USB_MODE)),$(BOARD_CCID_EXTRA_DEPS),)
	@$(ASSERT_VALID_FIRMWARE_PRODUCT_USB)echo "── Firmware compile DB for $(BOARD_DESCRIPTION) ($(FIRMWARE_PRODUCT) · USB $(NFC_USB_MODE)) ──"
	@rm -rf $(FIRMWARE_COMPILE_DB_BUILD) && mkdir -p $(FIRMWARE_COMPILE_DB_DIR)
	$(if $(NFC_USB_SYNC_REQUIRED),@bash "$(CURDIR)/scripts/ccid-sync-arduino-usb-cpp.sh" "$(CURDIR)" "$(ARDUINO_CLI)" "$(ARDUINO_MIN_BOARD_CORE_VERSION)",@true)
	@bash "$(CURDIR)/scripts/run-arduino-compile.sh" --board "$(BOARD_DESCRIPTION)" --repo-root "$(CURDIR)" -- \
	  $(ARDUINO_CLI) compile --fqbn $(FQBN) --only-compilation-database \
	  --build-path $(FIRMWARE_COMPILE_DB_BUILD) \
	  $(ARDUINO_LIBRARIES_FLAG) \
	  $(ARDUINO_BUILD_PROPS_FIRMWARE) \
	  $(SKETCH_DIR)
	@cp $(FIRMWARE_COMPILE_DB_BUILD)/compile_commands.json $(FIRMWARE_COMPILE_DB_DIR)/compile_commands.json
	@python3 "$(CURDIR)/scripts/rewrite-arduino-compile-db.py" \
	  $(FIRMWARE_COMPILE_DB_DIR)/compile_commands.json \
	  $(FIRMWARE_COMPILE_DB_BUILD) "$(CURDIR)" "$(FIRMWARE_COMPILE_DB_SKETCH_REL)"
	@$(if $(and $(filter nucleo_wba65ri,$(TARGET)),$(filter reader,$(FIRMWARE_PRODUCT)),$(filter ccid,$(NFC_USB_MODE))),\
	  $(MAKE) vendor-tinyusb-wba65 && \
	  python3 "$(CURDIR)/scripts/merge-compile-commands.py" \
	    --out "$(FIRMWARE_COMPILE_DB_DIR)/compile_commands.json" \
	    "$(FIRMWARE_COMPILE_DB_DIR)/compile_commands.json" \
	    "$(TINYUSB_WBA65_COMPILE_DB)" && \
	  python3 "$(CURDIR)/scripts/check-wba-tinyusb-artifacts.py" \
	    --repo-root "$(CURDIR)" \
	    --archive "$(TINYUSB_WBA65_ARCHIVE)" \
	    --compile-db "$(FIRMWARE_COMPILE_DB_DIR)/compile_commands.json",true)
	@echo "── firmware compile DB → $(FIRMWARE_COMPILE_DB_DIR)/compile_commands.json ──"

_do-flash-firmware:
	@$(MAKE) firmware
	@$(call UPLOAD_C_SKETCH,$(FIRMWARE_PRODUCT),$(SKETCH_DIR),$(FIRMWARE_BUILD_DIR))
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

flash-reader-cdc:
	@$(MAKE) _do-flash-firmware FIRMWARE_PRODUCT=reader NFC_USB_MODE=cdc

flash-reader-ccid:
	@$(MAKE) _do-flash-firmware FIRMWARE_PRODUCT=reader NFC_USB_MODE=ccid

flash-writer-cdc:
	@$(MAKE) _do-flash-firmware FIRMWARE_PRODUCT=writer NFC_USB_MODE=cdc

flash-nfc-cdc:
	@$(MAKE) _do-flash-firmware FIRMWARE_PRODUCT=nfc NFC_USB_MODE=cdc

flash:
	@$(MAKE) flash-reader-ccid

flash-cdc:
	@$(MAKE) flash-nfc-cdc

flash-ccid:
	@$(MAKE) flash-reader-ccid
