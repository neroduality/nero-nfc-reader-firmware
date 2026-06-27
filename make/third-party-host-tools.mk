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

# make/third-party-host-tools.mk — pinned host Arduino toolchain under third-party/.
#
# arduino-cli binary: third-party/arduino-cli/arduino-cli (+ .arduino-cli-version stamp)
# Board Manager cores: third-party/arduino-user/ via ARDUINO_DIRECTORIES_DATA
# and ARDUINO_DIRECTORIES_USER (never ~/.arduino15); per-target stamp under .arduino-core-<TARGET>-version

_HOST3P_MKDIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
_HOST3P_ROOT := $(abspath $(_HOST3P_MKDIR)/..)

_FETCH_CLI := $(_HOST3P_MKDIR)/fetch-arduino-cli.sh
_ENSURE_CLI := $(_HOST3P_MKDIR)/ensure-arduino-cli.sh
_ENSURE_CORE := $(_HOST3P_MKDIR)/ensure-arduino-core.sh

ARDUINO_CLI_DIR := $(_HOST3P_ROOT)/third-party/arduino-cli
ARDUINO_USER_DIR ?= $(abspath $(_HOST3P_ROOT)/third-party/arduino-user)
_REPO_ARDUINO_USER_DIR := $(abspath $(_HOST3P_ROOT)/third-party/arduino-user)
ARDUINO_CLI_STAMP := $(_HOST3P_ROOT)/third-party/.arduino-cli-version
ifeq ($(abspath $(ARDUINO_USER_DIR)),$(_REPO_ARDUINO_USER_DIR))
ARDUINO_CORE_STAMP := $(_HOST3P_ROOT)/third-party/.arduino-core-$(TARGET)-version
else
ARDUINO_CORE_STAMP := $(ARDUINO_USER_DIR)/.arduino-core-$(TARGET)-version
endif
ARDUINO_CLI_MARKER := $(ARDUINO_CLI_DIR)/arduino-cli
export ARDUINO_DIRECTORIES_DATA := $(ARDUINO_USER_DIR)
export ARDUINO_DIRECTORIES_USER := $(ARDUINO_USER_DIR)
export NERO_NFC_FW_ROOT := $(_HOST3P_ROOT)

$(ARDUINO_CLI_MARKER): Makefile make/board-$(TARGET).mk $(_FETCH_CLI) $(_ENSURE_CLI) make/fetch-tarball.sh
	@bash "$(_ENSURE_CLI)" "$(_HOST3P_ROOT)" "$(abspath $(ARDUINO_CLI_DIR))" \
	  "$(ARDUINO_CLI_STAMP)" "$(ARDUINO_CLI_VERSION)" "$(_FETCH_CLI)" "$(FORCE_EXTERNAL)"

ifneq ($(strip $(BOARD_ARDUINO_PLATFORM_SETUP)),)
$(ARDUINO_CORE_STAMP): $(ARDUINO_CLI_MARKER) Makefile make/board-$(TARGET).mk $(BOARD_ARDUINO_PLATFORM_SETUP) $(BOARD_ARDUINO_PLATFORM_FILES)
	@WBA65_STM32_CORE_PACKAGE="$(ARDUINO_CORE_PACKAGE)" \
	WBA65_STM32_CORE_VERSION="$(ARDUINO_MIN_BOARD_CORE_VERSION)" \
	WBA65_STM32_BOARD_MANAGER_URLS="$(ARDUINO_BOARD_MANAGER_URLS)" \
	ARDUINO_USER_DIR="$(ARDUINO_USER_DIR)" \
	bash "$(BOARD_ARDUINO_PLATFORM_SETUP)" "$(_HOST3P_ROOT)" "$(abspath $(ARDUINO_CLI_MARKER))" \
	  "$(ARDUINO_CORE_STAMP)" "$(FORCE_EXTERNAL)"
else
$(ARDUINO_CORE_STAMP): $(ARDUINO_CLI_MARKER) Makefile make/board-$(TARGET).mk $(_ENSURE_CORE)
	@bash "$(_ENSURE_CORE)" "$(_HOST3P_ROOT)" "$(abspath $(ARDUINO_CLI_MARKER))" \
	  "$(ARDUINO_CORE_STAMP)" "$(ARDUINO_CORE_PACKAGE)" "$(ARDUINO_MIN_BOARD_CORE_VERSION)" \
	  "$(ARDUINO_BOARD_MANAGER_URLS)" "$(FORCE_EXTERNAL)" \
	  "$(ARDUINO_USER_DIR)"
endif

.PHONY: third-party-host-tools
third-party-host-tools: $(ARDUINO_CORE_STAMP)
