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

# Upstream TinyUSB with OPT_MCU_STM32WBA (NUCLEO-WBA65RI CCID).

_TUSBWBA_MKDIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
_TUSBWBA_ROOT := $(abspath $(_TUSBWBA_MKDIR)/..)
_ENSURE_TUSBWBA := $(_TUSBWBA_MKDIR)/ensure-tinyusb-wba65.sh

TINYUSB_WBA65_STAMP := $(_TUSBWBA_ROOT)/third-party/.tinyusb-wba65-version
TINYUSB_WBA65_SRC := $(_TUSBWBA_ROOT)/third-party/tinyusb/src

$(TINYUSB_WBA65_STAMP): | third-party-tinyusb-wba65

.PHONY: third-party-tinyusb-wba65
third-party-tinyusb-wba65:
	@bash "$(_ENSURE_TUSBWBA)" "$(_TUSBWBA_ROOT)" "$(TINYUSB_WBA65_STAMP)" "$(FORCE_EXTERNAL)"
