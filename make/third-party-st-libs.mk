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

# make/third-party-st-libs.mk — NFC-RFAL and ST25R3916 archive dependencies (ST SLA0052).
#
# Included by the top-level Makefile. NFC_FRONTEND= must be listed in make/st25r-nfc-frontends.mk
# (ST25R family only). Provides the third-party-st-libs phony target that writer/reader depend on.

_ST25R_MKDIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
include $(_ST25R_MKDIR)/st25r-nfc-frontends.mk

ifneq ($(NFC_FRONTEND),st25r3916)
$(error third_party fetch is only implemented for NFC_FRONTEND=st25r3916 — extend make/third-party-st-libs.mk after adding another ST25R part to VALID_ST25R_NFC_FRONTENDS.)
endif

_EXTST_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
_EXTST_MDIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

_FETCH := $(_EXTST_MDIR)/fetch-archive.sh
_STAMP := $(_EXTST_MDIR)/ensure-stamp.sh

# ── NFC-RFAL ──────────────────────────────────────────────────────────────────
NFCRFAL_VERSION     := 2.0.2
NFCRFAL_DIR         := $(_EXTST_ROOT)/third-party/NFC-RFAL
NFCRFAL_STAMP       := $(_EXTST_ROOT)/third-party/.nfc-rfal-version
NFCRFAL_SHA256_FILE := $(_EXTST_MDIR)/nfc-rfal-$(NFCRFAL_VERSION).sha256
NFCRFAL_SHA256      := $(shell cat "$(NFCRFAL_SHA256_FILE)" 2>/dev/null | tr -cd '[:xdigit:]')
NFCRFAL_URL         := https://github.com/stm32duino/NFC-RFAL/archive/refs/tags/$(NFCRFAL_VERSION).zip

# ── ST25R3916 ─────────────────────────────────────────────────────────────────
ST25R3916_VERSION     := 2.0.2
ST25R3916_DIR         := $(_EXTST_ROOT)/third-party/ST25R3916
ST25R3916_STAMP       := $(_EXTST_ROOT)/third-party/.st25r3916-version
ST25R3916_SHA256_FILE := $(_EXTST_MDIR)/st25r3916-$(ST25R3916_VERSION).sha256
ST25R3916_SHA256      := $(shell cat "$(ST25R3916_SHA256_FILE)" 2>/dev/null | tr -cd '[:xdigit:]')
ST25R3916_URL         := https://github.com/stm32duino/ST25R3916/archive/refs/tags/$(ST25R3916_VERSION).zip

# Real prerequisites are marker files inside each extracted tree.  Stamp files
# under third-party/. *-version alone are insufficient: if someone deletes
# third-party/NFC-RFAL/ but leaves the stamp, GNU Make would skip the recipe.
# Depending on library.properties forces a refetch whenever that tree is gone.
NFCRFAL_MARKER     := $(NFCRFAL_DIR)/library.properties
ST25R3916_MARKER := $(ST25R3916_DIR)/library.properties

$(NFCRFAL_MARKER): $(NFCRFAL_SHA256_FILE) $(_FETCH) $(_STAMP)
	@test -s "$(NFCRFAL_SHA256_FILE)" || { echo 'ERROR: missing $(NFCRFAL_SHA256_FILE)'; exit 1; }
	@test $$(printf '%s' '$(NFCRFAL_SHA256)' | wc -c) -eq 64 || { echo 'ERROR: bad NFC-RFAL SHA256 pin (want 64 hex chars)'; exit 1; }
	@bash "$(_STAMP)" "$(_EXTST_ROOT)" "$(abspath $(NFCRFAL_DIR))" \
	  "$(NFCRFAL_STAMP)" "$(NFCRFAL_VERSION)" "$(NFCRFAL_SHA256)" "$(NFCRFAL_URL)" \
	  "$(_FETCH)" "library.properties" "$(FORCE_EXTERNAL)"

$(ST25R3916_MARKER): $(ST25R3916_SHA256_FILE) $(_FETCH) $(_STAMP)
	@test -s "$(ST25R3916_SHA256_FILE)" || { echo 'ERROR: missing $(ST25R3916_SHA256_FILE)'; exit 1; }
	@test $$(printf '%s' '$(ST25R3916_SHA256)' | wc -c) -eq 64 || { echo 'ERROR: bad ST25R3916 SHA256 pin (want 64 hex chars)'; exit 1; }
	@bash "$(_STAMP)" "$(_EXTST_ROOT)" "$(abspath $(ST25R3916_DIR))" \
	  "$(ST25R3916_STAMP)" "$(ST25R3916_VERSION)" "$(ST25R3916_SHA256)" "$(ST25R3916_URL)" \
	  "$(_FETCH)" "library.properties" "$(FORCE_EXTERNAL)"

.PHONY: third-party-st-libs
third-party-st-libs: $(NFCRFAL_MARKER) $(ST25R3916_MARKER)
