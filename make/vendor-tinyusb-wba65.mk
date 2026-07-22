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

# Compile pinned TinyUSB sources as separate TUs and archive them for WBA65 CCID
# (§6). Linked via compiler.libraries.ldflags; amalgamation TUs are deleted.

_VTUSB_MKDIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
_VTUSB_ROOT := $(abspath $(_VTUSB_MKDIR)/..)

TINYUSB_WBA65_SRC ?= $(_VTUSB_ROOT)/third-party/tinyusb/src
TINYUSB_WBA65_VENDOR_DIR := $(_VTUSB_ROOT)/build/vendor/tinyusb/wba65
TINYUSB_WBA65_ARCHIVE := $(TINYUSB_WBA65_VENDOR_DIR)/libtinyusb_wba65.a
TINYUSB_WBA65_COMPILE_DB := $(TINYUSB_WBA65_VENDOR_DIR)/compile_commands.json
TINYUSB_WBA65_IDENTITY := $(TINYUSB_WBA65_VENDOR_DIR)/identity.sha256
TINYUSB_WBA65_STAMP ?= $(_VTUSB_ROOT)/third-party/.tinyusb-wba65-version
# Host vs container bind mounts use different absolute roots for the same tree.
# Stamp the root Make is using so a path change invalidates vendor artifacts.
TINYUSB_WBA65_ROOT_PATH := $(TINYUSB_WBA65_VENDOR_DIR)/repo-root.path
$(shell mkdir -p "$(TINYUSB_WBA65_VENDOR_DIR)" && \
	printf '%s\n' "$(_VTUSB_ROOT)" > "$(TINYUSB_WBA65_ROOT_PATH).new" && \
	(cmp -s "$(TINYUSB_WBA65_ROOT_PATH).new" "$(TINYUSB_WBA65_ROOT_PATH)" 2>/dev/null || \
		mv -f "$(TINYUSB_WBA65_ROOT_PATH).new" "$(TINYUSB_WBA65_ROOT_PATH)") && \
	rm -f "$(TINYUSB_WBA65_ROOT_PATH).new")

STM32_CORE_ROOT := $(_VTUSB_ROOT)/third-party/arduino-user/packages/STMicroelectronics/hardware/stm32/2.12.0
STM32_TOOLS := $(_VTUSB_ROOT)/third-party/arduino-user/packages/STMicroelectronics/tools
WBA65_ARM_GCC := $(STM32_TOOLS)/xpack-arm-none-eabi-gcc/14.2.1-1.1/bin/arm-none-eabi-gcc
WBA65_ARM_AR := $(STM32_TOOLS)/xpack-arm-none-eabi-gcc/14.2.1-1.1/bin/arm-none-eabi-ar

TINYUSB_WBA65_SOURCES := \
  $(TINYUSB_WBA65_SRC)/tusb.c \
  $(TINYUSB_WBA65_SRC)/common/tusb_fifo.c \
  $(TINYUSB_WBA65_SRC)/device/usbd.c \
  $(TINYUSB_WBA65_SRC)/device/usbd_control.c \
  $(TINYUSB_WBA65_SRC)/portable/synopsys/dwc2/dwc2_common.c \
  $(TINYUSB_WBA65_SRC)/portable/synopsys/dwc2/dcd_dwc2.c

# The vendored source tree is populated by the bootstrap target. Declaring
# this relationship lets Make create a missing tree before resolving sources.
$(TINYUSB_WBA65_SOURCES): | third-party-tinyusb-wba65

TINYUSB_WBA65_OBJECTS := \
  $(TINYUSB_WBA65_VENDOR_DIR)/tusb.o \
  $(TINYUSB_WBA65_VENDOR_DIR)/tusb_fifo.o \
  $(TINYUSB_WBA65_VENDOR_DIR)/usbd.o \
  $(TINYUSB_WBA65_VENDOR_DIR)/usbd_control.o \
  $(TINYUSB_WBA65_VENDOR_DIR)/dwc2_common.o \
  $(TINYUSB_WBA65_VENDOR_DIR)/dcd_dwc2.o

# STM32 core variant dir has parentheses; expose a paren-free -I via symlink.
TINYUSB_WBA65_VARIANT_REAL := $(STM32_CORE_ROOT)/variants/STM32WBAxx/WBA65R(G-I)V
TINYUSB_WBA65_VARIANT_LINK := $(TINYUSB_WBA65_VENDOR_DIR)/variant-inc

# firmware lists third-party-host-tools and vendor-tinyusb-wba65 as siblings; without
# this edge, -j races identity/CC ahead of STM32 core + arm-none-eabi-gcc (and CMSIS).
TINYUSB_WBA65_TOOLCHAIN_READY := third-party-host-tools

TINYUSB_WBA65_CFLAGS := \
  -std=gnu11 \
  -mcpu=cortex-m33 -mfpu=fpv5-sp-d16 -mfloat-abi=hard -mthumb \
  -ffunction-sections -fdata-sections \
  -DNDEBUG \
  -DSTM32WBAxx -DSTM32WBA65xx \
  -DUSE_HAL_DRIVER -DUSE_FULL_LL_DRIVER \
  -DNERO_CCID_USB_BUILD=1 -DNERO_CCID_ONLY_BUILD=1 -DNERO_CCID_STM32_USB_BUILD=1 \
  -DCFG_TUSB_MCU=OPT_MCU_STM32WBA \
  -DNERO_CCID_BULK_EPSIZE=512u \
  -DUSB_OTG_HS_IRQn=USB_OTG_HS_IR_QN \
  -DSystemCoreClock=system_core_clock \
  -include $(_VTUSB_ROOT)/firmware/port/stm32_wba65_ccid/nero_wba65_cmsis_compat.h \
  -I$(_VTUSB_ROOT)/firmware/port/stm32_wba65_ccid \
  -I$(TINYUSB_WBA65_SRC) \
  -I$(STM32_CORE_ROOT)/cores/arduino \
  -I$(STM32_CORE_ROOT)/cores/arduino/stm32 \
  -I$(STM32_CORE_ROOT)/system/Drivers/STM32WBAxx_HAL_Driver/Inc \
  -I$(STM32_CORE_ROOT)/system/STM32WBAxx \
  -I$(STM32_CORE_ROOT)/system/Drivers/CMSIS/Device/ST/STM32WBAxx/Include \
  -I$(STM32_TOOLS)/CMSIS/6.2.0/CMSIS/Core/Include \
  -I$(TINYUSB_WBA65_VARIANT_LINK) \
  -DVARIANT_H=\"variant_NUCLEO_WBA65RI.h\" \
  -DARDUINO_NUCLEO_WBA65RI \
  -DARDUINO_ARCH_STM32

$(TINYUSB_WBA65_VENDOR_DIR):
	@mkdir -p "$@"

$(TINYUSB_WBA65_VARIANT_LINK): | $(TINYUSB_WBA65_VENDOR_DIR) $(TINYUSB_WBA65_TOOLCHAIN_READY)
	@ln -sfn "$(TINYUSB_WBA65_VARIANT_REAL)" "$@"

$(TINYUSB_WBA65_IDENTITY): $(TINYUSB_WBA65_STAMP) $(TINYUSB_WBA65_SOURCES) \
  $(TINYUSB_WBA65_ROOT_PATH) $(TINYUSB_WBA65_VARIANT_LINK) \
  $(_VTUSB_ROOT)/make/vendor-tinyusb-wba65.mk \
  $(_VTUSB_ROOT)/scripts/write-tinyusb-wba65-identity.py | $(TINYUSB_WBA65_VENDOR_DIR) $(TINYUSB_WBA65_TOOLCHAIN_READY)
	@# Refresh the variant -I symlink when the absolute repo root changes (bind mounts).
	@ln -sfn "$(TINYUSB_WBA65_VARIANT_REAL)" "$(TINYUSB_WBA65_VARIANT_LINK)"
	@python3 "$(_VTUSB_ROOT)/scripts/write-tinyusb-wba65-identity.py" \
	  --out "$(TINYUSB_WBA65_IDENTITY)" \
	  --pin-stamp "$(TINYUSB_WBA65_STAMP)" \
	  --gcc "$(WBA65_ARM_GCC)" \
	  --cflags "$(TINYUSB_WBA65_CFLAGS)" \
	  $(TINYUSB_WBA65_SOURCES)

define TINYUSB_WBA65_CC_RULE
$(TINYUSB_WBA65_VENDOR_DIR)/$(1).o: $(2) $(TINYUSB_WBA65_IDENTITY) $(TINYUSB_WBA65_VARIANT_LINK) | $(TINYUSB_WBA65_VENDOR_DIR) third-party-tinyusb-wba65 $(TINYUSB_WBA65_TOOLCHAIN_READY)
	@echo "── TinyUSB WBA65 vendor CC $$(notdir $(2)) ──"
	@"$(WBA65_ARM_GCC)" $(TINYUSB_WBA65_CFLAGS) -c "$(2)" -o "$$@"
endef

$(eval $(call TINYUSB_WBA65_CC_RULE,tusb,$(TINYUSB_WBA65_SRC)/tusb.c))
$(eval $(call TINYUSB_WBA65_CC_RULE,tusb_fifo,$(TINYUSB_WBA65_SRC)/common/tusb_fifo.c))
$(eval $(call TINYUSB_WBA65_CC_RULE,usbd,$(TINYUSB_WBA65_SRC)/device/usbd.c))
$(eval $(call TINYUSB_WBA65_CC_RULE,usbd_control,$(TINYUSB_WBA65_SRC)/device/usbd_control.c))
$(eval $(call TINYUSB_WBA65_CC_RULE,dwc2_common,$(TINYUSB_WBA65_SRC)/portable/synopsys/dwc2/dwc2_common.c))
$(eval $(call TINYUSB_WBA65_CC_RULE,dcd_dwc2,$(TINYUSB_WBA65_SRC)/portable/synopsys/dwc2/dcd_dwc2.c))

$(TINYUSB_WBA65_ARCHIVE): $(TINYUSB_WBA65_OBJECTS)
	@echo "── TinyUSB WBA65 archive $@ ──"
	@"$(WBA65_ARM_AR)" rcs "$@" $^

$(TINYUSB_WBA65_COMPILE_DB): $(TINYUSB_WBA65_OBJECTS) \
  $(_VTUSB_ROOT)/scripts/write-tinyusb-wba65-compile-db.py
	@python3 "$(_VTUSB_ROOT)/scripts/write-tinyusb-wba65-compile-db.py" \
	  --out "$(TINYUSB_WBA65_COMPILE_DB)" \
	  --repo-root "$(_VTUSB_ROOT)" \
	  --gcc "$(WBA65_ARM_GCC)" \
	  --cflags "$(TINYUSB_WBA65_CFLAGS)" \
	  --obj-dir "$(TINYUSB_WBA65_VENDOR_DIR)" \
	  $(TINYUSB_WBA65_SOURCES)

.PHONY: vendor-tinyusb-wba65
vendor-tinyusb-wba65: $(TINYUSB_WBA65_TOOLCHAIN_READY) $(TINYUSB_WBA65_ARCHIVE) $(TINYUSB_WBA65_COMPILE_DB)

TINYUSB_WBA65_LINK_FLAGS := -Wl,--whole-archive $(TINYUSB_WBA65_ARCHIVE) -Wl,--no-whole-archive
