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

# Project-local OpenOCD with STM32WBA6x flash support (bundled xpack lacks WBA65).

_WBA65OCD_MKDIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
_WBA65OCD_ROOT := $(abspath $(_WBA65OCD_MKDIR)/..)
_ENSURE_WBA65OCD := $(_WBA65OCD_MKDIR)/ensure-wba65-openocd.sh

WBA65_OPENOCD_STAMP := $(_WBA65OCD_ROOT)/third-party/.wba65-openocd-version

$(WBA65_OPENOCD_STAMP): $(_ENSURE_WBA65OCD) $(wildcard $(CURDIR)/patches/openocd/*.patch)
	@INSTALL_DEPS="$(INSTALL_DEPS)" bash "$(_ENSURE_WBA65OCD)" "$(_WBA65OCD_ROOT)" "$(WBA65_OPENOCD_STAMP)" "$(FORCE_EXTERNAL)"

.PHONY: third-party-wba65-openocd
third-party-wba65-openocd: $(WBA65_OPENOCD_STAMP)
