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

# Combined NFC firmware + C++ userspace. Main targets: all/build, userspace,
# install-userspace, test, verify, lint, security-lint, ci-local, clean, help; plus flash
# (see ``make help``).
#
# Arduino UNO R4 WiFi (`TARGET=arduino_uno_r4wifi`, default); analogue front
# end via `NFC_FRONTEND` (see `make/nfc-frontends.mk`).

# Third-party pins (exact versions; ST ZIPs also have SHA256 under make/*.sha256):
#   arduino-cli 1.5.1 | arduino:renesas_uno 1.6.0 | NFC-RFAL 2.0.2 | ST25R3916 2.0.2
ARDUINO_MIN_CLI_VERSION ?= 1.5.1
ARDUINO_CLI_VERSION ?= $(ARDUINO_MIN_CLI_VERSION)
ARDUINO_MIN_RENESAS_CORE ?= 1.6.0

# ── Target selection ───────────────────────────────────────────────────────────
# Parallel builds: all host CPUs unless the make command already passes -jN.
_CPU_COUNT := $(shell bash $(CURDIR)/make/cpu-jobs.sh 2>/dev/null || echo 4)
ifeq ($(filter -j%,$(MAKEFLAGS)),)
MAKEFLAGS += -j$(_CPU_COUNT)
endif

# TARGET selects make/board-<TARGET>.mk + port/<matching>/HAL units (see BOARD_* macros there).
VALID_BOARD_TARGETS := $(sort $(patsubst $(CURDIR)/make/board-%.mk,%,$(wildcard $(CURDIR)/make/board-*.mk)))
TARGET ?= arduino_uno_r4wifi

ifeq ($(filter $(TARGET),$(VALID_BOARD_TARGETS)),)
  $(error Unknown TARGET '$(TARGET)'. Supported boards: $(VALID_BOARD_TARGETS))
endif

# CDC serial line / RX sizing — keep equal to WRITER_CLI_LINE_CAP in writer_payload.h.
NFC_CDC_SERIAL_LINE_CAP := 1776

include $(CURDIR)/make/board-$(TARGET).mk
BOARD_TARGET_DRIVER ?= $(TARGET)

include $(CURDIR)/make/nfc-frontends.mk

# ── NFC analogue front end ─────────────────────────────────────────────────────
NFC_FRONTEND ?= $(if $(BOARD_DEFAULT_NFC_FRONTEND),$(BOARD_DEFAULT_NFC_FRONTEND),st25r3916)
ifeq ($(filter $(VALID_NFC_FRONTENDS),$(NFC_FRONTEND)),)
$(error NFC_FRONTEND '$(NFC_FRONTEND)' is not allowed — supported: $(VALID_NFC_FRONTENDS))
endif
ifeq ($(NFC_FRONTEND),st25r3916)
NFC_FRONTEND_CPPFLAGS := -DNFC_FRONTEND_ID_ST25R3916=1
VENDOR_PROJECT_INCLUDES := -I$(CURDIR)/third-party/ST25R3916/src -I$(CURDIR)/third-party/NFC-RFAL/src
else
$(error NFC_FRONTEND=$(NFC_FRONTEND) is listed as allowed but has no toolchain wiring yet.)
endif

# ── Combined firmware default mode ────────────────────────────────────────────
# Compile-time default for combined firmware (`reader` | `writer`); override with NFC_MODE=
NFC_MODE ?= reader

# ── USB mode selection ──────────────────────────────────────────────────────────
# cdc       = serial only (combined reader/writer shell over USB CDC/serial)
# ccid      = CCID only (reader-only USB smart-card personality; board-dependent)
BOARD_DEFAULT_NFC_USB_MODE ?= ccid
BOARD_SUPPORTED_NFC_USB_MODES ?= cdc ccid
BOARD_UPLOAD_NEEDS_PORT ?= 1
BOARD_UPLOAD_PSEUDO_PORT ?=
BOARD_PORT_DISCOVERY_SECONDS ?= 6
NFC_USB_MODE ?= $(BOARD_DEFAULT_NFC_USB_MODE)

# ── Arduino CLI board toolchain ─────────────────────────────────────────────────
# Language standard + hardening profile (override as needed):
# UNO R4 core currently ships GCC 7.2.1, so the practical maximum here is
# C11/GNU11 and C++17/GNU++17 (C23/C++23 are not supported by this toolchain).
#
# Flash size: the arduino:renesas_uno core already builds with -Os, -ffunction-sections /
# -fdata-sections, -Wl,--gc-sections, and newlib nano.specs. Uploaded .hex/.bin
# only include .text and .data, so strip/objcopy strip-debug does not shrink
# what the MCU stores — it only shrinks the ELF on disk.
#
# FIRMWARE_MIN_SIZE=1 trades hardening and firmware backtraces for smaller code
# (~7–8 KiB program flash in typical builds): drops _FORTIFY_SOURCE /
# -fstack-protector-strong from this Makefile and adds -UBACKTRACE_SUPPORT
# (see arduino:renesas_uno build.defines).
FIRMWARE_MIN_SIZE ?= 0
C_STD  ?= gnu11
CPP_STD ?= gnu++17
COMMON_HARDENING_FLAGS_DEFAULT := -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fno-delete-null-pointer-checks -fno-strict-overflow
ifeq ($(FIRMWARE_MIN_SIZE),1)
  COMMON_HARDENING_FLAGS :=
else ifeq ($(BOARD_SKIP_HOST_HARDENING),1)
  COMMON_HARDENING_FLAGS :=
else
  COMMON_HARDENING_FLAGS ?= $(COMMON_HARDENING_FLAGS_DEFAULT)
endif
COMMON_WARNING_FLAGS ?= -Wformat=2 -Wformat-security -Wformat-overflow=2 -Wformat-truncation=2 -Wnull-dereference -Warray-bounds=2 -Wstringop-overflow=4 -Wvla -Walloca -Wstack-protector -Wshadow -Wcast-qual -Wundef -Wdouble-promotion -Wshift-overflow=2 -Wswitch-enum -Wunused-result -Wno-error
C_WARNING_FLAGS ?= $(COMMON_WARNING_FLAGS) -Wstrict-overflow=2 -Wstrict-prototypes -Wwrite-strings
CPP_WARNING_FLAGS ?= $(COMMON_WARNING_FLAGS) -Wstrict-overflow=2 -Wwrite-strings

# Arduino CLI applies extra flags to sketch/core/library compilation units.
# Default matches make lint (ci-lint.sh): --warnings all, full -W* in extra_flags, vendor -isystem.
# Set SUPPRESS_ARDUINO_3P_WARNINGS=1 for quiet local rebuilds (--warnings none, no -W*).
SUPPRESS_ARDUINO_3P_WARNINGS ?= 0
ifeq ($(SUPPRESS_ARDUINO_3P_WARNINGS),1)
  ARDUINO_WARNINGS ?= none
  C_WARNING_FLAGS :=
  CPP_WARNING_FLAGS :=
  ARDUINO_VENDOR_ISYSTEM_FLAGS :=
else
  ARDUINO_WARNINGS ?= all
  ARDUINO_VENDOR_ISYSTEM_FLAGS := $(shell bash $(CURDIR)/make/arduino-third-party-isystem.sh $(CURDIR) $(ARDUINO_ISYSTEM_PROFILE) 2>/dev/null | tr '\n' ' ')
endif

C_SECURITY_FLAGS ?= $(COMMON_HARDENING_FLAGS) $(C_WARNING_FLAGS)
CPP_SECURITY_FLAGS ?= $(COMMON_HARDENING_FLAGS) $(CPP_WARNING_FLAGS)

# firmware/nfc_core/common/ — shared helpers · firmware/nfc_core/frontends/$(NFC_FRONTEND)/ — ST25 reader IC glue only
NFC_CORE_COMMON_INC := $(CURDIR)/firmware/nfc_core/common
NFC_CORE_ARDUINO_INC := $(CURDIR)/firmware/nfc_core/arduino
NFC_CORE_FRONTEND_INC := $(CURDIR)/firmware/nfc_core/frontends/$(NFC_FRONTEND)
# firmware/port/include/ — stable HAL interface headers shared by target ports
PORT_INC := $(CURDIR)/firmware/port/include

# Board HAL .cpp files live under $(PORT_LIB_DIR); firmware/*/src/*_hal.cpp are thin #include stubs.
BOARD_HAL_CPPFLAGS := \
	-DNFC_BOARD_READER_HAL_INC=$(BOARD_READER_HAL_UNIT) \
	-DNFC_BOARD_WRITER_HAL_INC=$(BOARD_WRITER_HAL_UNIT) \
	-DNFC_BOARD_NFC_HAL_INC=$(BOARD_NFC_HAL_UNIT)

ARDUINO_PROJECT_INCLUDES := $(NFC_FRONTEND_CPPFLAGS) \
	$(VENDOR_PROJECT_INCLUDES) \
	-I$(NFC_CORE_COMMON_INC) -I$(NFC_CORE_ARDUINO_INC) -I$(NFC_CORE_FRONTEND_INC) \
	-I$(PORT_INC) -I$(PORT_LIB_DIR) \
	$(BOARD_HAL_CPPFLAGS)

# Paths
BUILD_DIR = build
TOOL_HOST_BIN := $(abspath $(CURDIR)/third-party/arduino-cli)
ARDUINO_CLI := $(TOOL_HOST_BIN)/arduino-cli
ARDUINO_USER_DIR ?= $(abspath $(CURDIR)/third-party/arduino-user)
# Prepend pinned CLI; all recipes use $(ARDUINO_CLI) (absolute path), never bare arduino-cli.
# Board Manager cores/libraries install only under third-party/arduino-user (never ~/.arduino15).
export ARDUINO_DIRECTORIES_DATA := $(ARDUINO_USER_DIR)
export ARDUINO_DIRECTORIES_USER := $(ARDUINO_USER_DIR)
export PATH := $(TOOL_HOST_BIN):$(PATH)
PORT     ?=
DISCOVERY_TIMEOUT ?= 10s
BOARD_UPLOAD_HINT ?= Arduino CLI upload
BOARD_UPLOAD_PREP ?= true
BOARD_UPLOAD_READY_MARKER ?=
BOARD_UPLOAD_READY_BANNER ?=
BOARD_UPLOAD_WAIT_MESSAGE ?= Processing — wait
INSTALL_DEPS ?= 0
AUTO_INSTALL_LINUX_DEPS ?= $(INSTALL_DEPS)
FORCE_EXTERNAL ?=

# Distro dev packages (cmake, valgrind, …) — opt-in via INSTALL_DEPS=1.
# Pinned third-party trees (arduino-cli, NFC-RFAL, …) are fetched by build targets.

FIRMWARE_DIR  = firmware
NFC_DIR       = $(FIRMWARE_DIR)/nfc
NFC_BUILD_DIR = $(BUILD_DIR)/nfc

.DEFAULT_GOAL := all

.PHONY: all build help clean install install-userspace require-userspace-binaries install-udev install-pcsc-driver test verify asan ubsan tsan valgrind lint lint-self-test security-lint ci-local lima userspace deps maybe-deps

define RUN_LINUX_DEPS
@INSTALL_DEPS=1 AUTO_INSTALL_LINUX_DEPS=1 \
	FIRMWARE_ROOT="$(CURDIR)" \
	bash "$(CURDIR)/make/install-linux-deps.sh"
endef

deps:
	$(RUN_LINUX_DEPS)

maybe-deps:
	@if [ "$(INSTALL_DEPS)" != "0" ]; then \
	  $(MAKE) deps INSTALL_DEPS="$(INSTALL_DEPS)" AUTO_INSTALL_LINUX_DEPS="$(AUTO_INSTALL_LINUX_DEPS)" TARGET="$(TARGET)"; \
	fi

define UPLOAD_C_SKETCH
echo "── Uploading $(notdir $(2)) to $(BOARD_DESCRIPTION): $(BOARD_UPLOAD_HINT) ──"; \
$(BOARD_UPLOAD_PREP); \
$(if $(BOARD_UPLOAD_SCRIPT),bash "$(BOARD_UPLOAD_SCRIPT)" --build-dir "$(3)",bash "$(CURDIR)/scripts/run-board-upload.sh" \
  --arduino-cli "$(ARDUINO_CLI)" \
  --fqbn "$(FQBN)" \
  --input-dir "$(3)" \
  --build-dir "$(BUILD_DIR)" \
  --port "$(PORT)" \
  --pseudo-port "$(BOARD_UPLOAD_PSEUDO_PORT)" \
  --needs-port "$(BOARD_UPLOAD_NEEDS_PORT)" \
  --discovery-timeout "$(DISCOVERY_TIMEOUT)" \
  --port-wait-seconds "$(BOARD_PORT_DISCOVERY_SECONDS)" \
  --ready-marker "$(BOARD_UPLOAD_READY_MARKER)" \
  --ready-banner "$(BOARD_UPLOAD_READY_BANNER)" \
  --wait-message "$(BOARD_UPLOAD_WAIT_MESSAGE)") && \
if [ "$(NFC_USB_MODE)" = "ccid" ]; then \
  echo "── Upload complete for $(BOARD_DESCRIPTION). For CCID: run \`sudo make install-pcsc-driver\` once, then \`pcsc_scan\`; see docs/CCID.md. ──"; \
else \
  echo "── Upload complete for $(BOARD_DESCRIPTION). For serial: run \`make install-userspace\` then \`reader\` / \`writer\`; see INSTALLATION.md. ──"; \
fi
endef

# ── Userspace C++ build ───────────────────────────────────────────────────────
# USERSPACE_BUILD_LABEL: optional suffix for build dir (e.g. linux_arm64 for release tarballs).
# USERSPACE_CMAKE_EXTRA: extra cmake args (e.g. -DCMAKE_CXX_COMPILER=aarch64-linux-gnu-g++).
USERSPACE_DIR         = userspace
USERSPACE_BUILD_LABEL ?=
USERSPACE_BUILD_TYPE  ?= Release
USERSPACE_CMAKE_EXTRA ?=
USERSPACE_BUILD_DIR   = $(BUILD_DIR)/userspace$(if $(USERSPACE_BUILD_LABEL),-$(USERSPACE_BUILD_LABEL),)
USERSPACE_BIN_DIR     = $(USERSPACE_BUILD_DIR)/bin

INSTALL_PREFIX ?= $(HOME)/.local
INSTALL_BINDIR ?= $(INSTALL_PREFIX)/bin
USERSPACE_TOOLS := nero_nfc_uart reader writer

userspace: maybe-deps
	@rm -rf $(USERSPACE_BUILD_DIR)
	@cmake -S $(CURDIR)/$(USERSPACE_DIR) -B $(USERSPACE_BUILD_DIR) \
	  -DCMAKE_BUILD_TYPE=$(USERSPACE_BUILD_TYPE) -DCMAKE_RUNTIME_OUTPUT_DIRECTORY=$(CURDIR)/$(USERSPACE_BIN_DIR) --log-level=WARNING \
	  $(USERSPACE_CMAKE_EXTRA)
	@env -u MAKEFLAGS cmake --build $(USERSPACE_BUILD_DIR) -j$(_CPU_COUNT)

require-userspace-binaries:
	@missing=0; \
	for tool in $(USERSPACE_TOOLS); do \
	  if [ ! -x "$(CURDIR)/$(USERSPACE_BIN_DIR)/$$tool" ]; then \
	    echo "ERROR: missing built binary: $(CURDIR)/$(USERSPACE_BIN_DIR)/$$tool" >&2; \
	    missing=1; \
	  fi; \
	done; \
	if [ "$$missing" -ne 0 ]; then \
	  echo "Run 'make userspace' (or 'make' for firmware + userspace), then rerun 'make install-userspace'." >&2; \
	  exit 1; \
	fi

install-userspace: require-userspace-binaries
	@mkdir -p "$(DESTDIR)$(INSTALL_BINDIR)"
	@for tool in $(USERSPACE_TOOLS); do \
	  install -m 0755 "$(CURDIR)/$(USERSPACE_BIN_DIR)/$$tool" "$(DESTDIR)$(INSTALL_BINDIR)/$$tool"; \
	done
	@echo "Installed userspace CLIs ($(USERSPACE_TOOLS)) → $(DESTDIR)$(INSTALL_BINDIR)"
	@echo "Make sure $(INSTALL_BINDIR) is in your PATH."

install: install-userspace

install-udev:
	@echo "Installing packaging/70-nero-nfc-arduino.rules (requires sudo)..."
	@sudo bash "$(CURDIR)/scripts/install-udev.sh"

install-pcsc-driver:
	@echo "Registering MCU board CCID VID:PID entries with pcscd (requires sudo)..."
	@echo "Note: commercial PC/SC readers (ACS, OMNIKEY, etc.) use upstream libccid — skip this target."
	@if [ "$$(id -u)" -eq 0 ]; then \
		bash "$(CURDIR)/scripts/install-pcsc-driver.sh"; \
	else \
		sudo bash "$(CURDIR)/scripts/install-pcsc-driver.sh"; \
	fi

test: maybe-deps
	@bash "$(CURDIR)/make/wipe-host-build-trees.sh" test
	@INSTALL_DEPS="$(INSTALL_DEPS)" AUTO_INSTALL_LINUX_DEPS="$(AUTO_INSTALL_LINUX_DEPS)" \
	  SANITIZE_ADDRESS=0 SANITIZE_UNDEFINED=0 NERO_TESTS_BUILD_TYPE=Release \
	  bash "$(CURDIR)/make/run-unit-tests.sh"

asan: maybe-deps
	@bash "$(CURDIR)/make/wipe-host-build-trees.sh" test
	@INSTALL_DEPS="$(INSTALL_DEPS)" AUTO_INSTALL_LINUX_DEPS="$(AUTO_INSTALL_LINUX_DEPS)" \
	  SANITIZE_ADDRESS=1 SANITIZE_UNDEFINED=0 bash "$(CURDIR)/make/run-unit-tests.sh"

ubsan: maybe-deps
	@bash "$(CURDIR)/make/wipe-host-build-trees.sh" test
	@INSTALL_DEPS="$(INSTALL_DEPS)" AUTO_INSTALL_LINUX_DEPS="$(AUTO_INSTALL_LINUX_DEPS)" \
	  SANITIZE_ADDRESS=0 SANITIZE_UNDEFINED=1 bash "$(CURDIR)/make/run-unit-tests.sh"

tsan: maybe-deps
	@bash "$(CURDIR)/make/wipe-host-build-trees.sh" test
	@INSTALL_DEPS="$(INSTALL_DEPS)" AUTO_INSTALL_LINUX_DEPS="$(AUTO_INSTALL_LINUX_DEPS)" \
	  SANITIZE_THREAD=1 bash "$(CURDIR)/make/run-unit-tests.sh"

valgrind: maybe-deps
	@if ! command -v valgrind >/dev/null 2>&1; then \
	  printf 'error: valgrind not found (install via: make deps or INSTALL_DEPS=1 make valgrind)\n' >&2; \
	  exit 1; \
	fi
	@bash "$(CURDIR)/make/wipe-host-build-trees.sh" test
	@INSTALL_DEPS="$(INSTALL_DEPS)" AUTO_INSTALL_LINUX_DEPS="$(AUTO_INSTALL_LINUX_DEPS)" \
	  VALGRIND=1 bash "$(CURDIR)/make/run-unit-tests.sh"

coverage: maybe-deps
	@bash "$(CURDIR)/make/wipe-host-build-trees.sh" test
	@INSTALL_DEPS="$(INSTALL_DEPS)" AUTO_INSTALL_LINUX_DEPS="$(AUTO_INSTALL_LINUX_DEPS)" \
	  COVERAGE=1 bash "$(CURDIR)/make/run-unit-tests.sh"

verify: maybe-deps
	@bash "$(CURDIR)/make/wipe-host-build-trees.sh" verify
	@NERO_KEEP_HOST_BUILDS=1 $(MAKE) asan INSTALL_DEPS=0
	@NERO_KEEP_HOST_BUILDS=1 $(MAKE) ubsan INSTALL_DEPS=0
	@NERO_KEEP_HOST_BUILDS=1 $(MAKE) tsan INSTALL_DEPS=0
	@NERO_KEEP_HOST_BUILDS=1 $(MAKE) valgrind INSTALL_DEPS=0
	@NERO_KEEP_HOST_BUILDS=1 INSTALL_DEPS=0 AUTO_INSTALL_LINUX_DEPS=0 \
	  bash "$(CURDIR)/make/scan-build-tests.sh"
	@NERO_KEEP_HOST_BUILDS=1 $(MAKE) userspace USERSPACE_BUILD_TYPE=Release INSTALL_DEPS=0
	@bash "$(CURDIR)/make/verify-host-binary-hardening.sh"

CI_LOCAL_FLAGS ?=
LINT_FLAGS ?=

lint: maybe-deps lint-self-test
	@case ' $(LINT_FLAGS) ' in \
	  *' --custom-lints-only '*) ;; \
	  *) \
	    if [ "$${CI:-}" = "true" ]; then \
	      bash "$(CURDIR)/make/wipe-host-build-trees.sh" ci; \
	    else \
	      bash "$(CURDIR)/make/wipe-host-build-trees.sh" lint; \
	    fi ;; \
	esac
	@bash "$(CURDIR)/.github/linters/ci-lint.sh" $(LINT_FLAGS)

lint-self-test:
	@python3 "$(CURDIR)/.github/linters/lint_self_test.py"

security-lint:
	@bash "$(CURDIR)/.github/scripts/run-security-suite-locally.sh"

ci-local:
	@bash "$(CURDIR)/.github/scripts/run-ci-locally.sh" $(CI_LOCAL_FLAGS)

lima:
	@bash "$(CURDIR)/.github/scripts/run-ci-locally.sh" --lima $(CI_LOCAL_FLAGS)

help:
	@printf '\nnero-nfc\n\n'
	@printf '  %-38s %s\n' 'make' 'Compile nfc firmware + userspace (no upload; use make flash or make flash-cdc)'
	@printf '  %-38s %s\n' 'make userspace' 'Compile Linux host CLIs only (reader, writer, nero_nfc_uart)'
	@printf '  %-38s %s\n' 'make install-userspace' 'Install built userspace CLIs to ~/.local/bin (no rebuild; alias: make install)'
	@printf '  %-38s %s\n' 'make flash' 'Build + upload USB CCID reader on any supported board (NFC_USB_MODE=ccid)'
	@printf '  %-38s %s\n' 'make flash-cdc' 'Build + upload serial reader/writer shell (NFC_USB_MODE=cdc)'
	@printf '  %-38s %s\n' 'make flash-ccid' 'Build + upload USB CCID reader (NFC_USB_MODE=ccid)'
	@printf '  %-38s %s\n' 'make test' 'Run Release unit tests (wipes tests/build first; no sanitizers)'
	@printf '  %-38s %s\n' 'make asan' 'Run unit tests with AddressSanitizer only'
	@printf '  %-38s %s\n' 'make ubsan' 'Run unit tests with UndefinedBehaviorSanitizer only'
	@printf '  %-38s %s\n' 'make tsan' 'Run unit tests with ThreadSanitizer only (no ASan/UBSan mix)'
	@printf '  %-38s %s\n' 'make coverage' 'Run unit tests with gcov/lcov HTML (tests/build/coverage-html/)'
	@printf '  %-38s %s\n' 'make verify' 'Run asan, ubsan, tsan, valgrind, scan-build, userspace hardening (wipes host trees once at start)'
	@printf '  %-38s %s\n' 'make lint' 'License/format, spec-traceability (symbol+value), cppcheck/clang-tidy, UNO R4+WBA65 sketch smoke (wipes lint trees first)'
	@printf '  %-38s %s\n' 'make security-lint' 'zizmor and TruffleHog'
	@printf '  %-38s %s\n' 'make ci-local' 'Reproduce Main CI locally (host lint + Debian/Fedora containers)'
	@printf '  %-38s %s\n' 'make lima' 'Same as ci-local in a fresh ubuntu-24.04 Lima VM (non-interactive)'
	@printf '  %-38s %s\n' 'sudo make install-udev' 'Install packaging/70-nero-nfc-arduino.rules (ModemManager + serial permissions)'
	@printf '  %-38s %s\n' 'sudo make install-pcsc-driver' 'Register MCU board CCID in pcscd (docs/CCID.md)'
	@printf '  %-38s %s\n' 'make clean' 'Remove build/, tests/build/, and entire third-party/ (refetched on next build)'
	@printf '\nFirst-time host setup (optional):\n\n'
	@printf '  %-38s %s\n' 'make deps' 'Install missing Linux dev packages (build, test, lint, WBA65 OpenOCD compile tools; same as INSTALL_DEPS=1 make …)'
	@printf '  %-38s %s\n' 'INSTALL_DEPS=1 make' 'Install missing Linux dev packages, then compile firmware + userspace'
	@printf '\nmake ci-local (pass flags via CI_LOCAL_FLAGS, not as make arguments):\n\n'
	@printf '  %-52s %s\n' 'make ci-local' 'Default: native host lint + container matrix'
	@printf '  %-52s %s\n' 'make lima' 'Main CI in fresh ubuntu-24.04 Lima VM (auto; no limactl editor prompt)'
	@printf '  %-52s %s\n' 'make ci-local CI_LOCAL_FLAGS=--lima' 'Same as make lima (legacy flag form)'
	@printf '  %-52s %s\n' 'make ci-local CI_LOCAL_FLAGS=--containers-only' 'Skip host lint'
	@printf '  %-52s %s\n' 'make ci-local CI_LOCAL_FLAGS=--debian-only' 'Debian container only'
	@printf '  %-52s %s\n' 'make ci-local CI_LOCAL_FLAGS='\''--lima --skip-lint'\''' 'Multiple flags: quote the value'
	@printf '\nKey variables (VAR=value make …):\n\n'
	@printf '  %-38s %s\n' 'TARGET=$(TARGET)' 'Board target ($(BOARD_DESCRIPTION)); supported: $(VALID_BOARD_TARGETS)'
	@printf '  %-38s %s\n' 'NFC_MODE=reader|writer' 'Combined-sketch boot default (default: $(NFC_MODE))'
	@printf '  %-38s %s\n' 'NFC_USB_MODE=cdc|ccid' 'USB personality (default: $(NFC_USB_MODE); see board mk for supported modes)'
	@printf '  %-38s %s\n' 'NFC_FRONTEND=$(NFC_FRONTEND)' 'Analogue front-end ($(VALID_NFC_FRONTENDS))'
	@printf '  %-38s %s\n' 'PORT=' 'Serial port for flash/upload (default: auto-detect)'
	@printf '  %-38s %s\n' 'USERSPACE_BUILD_TYPE=Release|Debug' 'Host CLI CMake build type (default: $(USERSPACE_BUILD_TYPE))'
	@printf '  %-38s %s\n' 'INSTALL_DEPS=1' 'Install Linux dev packages via make/install-linux-deps.sh (default: 0; sudo)'
	@printf '  %-38s %s\n' 'FIRMWARE_MIN_SIZE=1' 'Smaller MCU image; drops FORTIFY/stack-protector and firmware backtraces'
	@printf '  %-38s %s\n' '(third-party/)' 'Pinned arduino-cli, cores, NFC-RFAL, ST25R3916; WBA65 adds OpenOCD + TinyUSB'
	@printf '  %-38s %s\n' 'COVERAGE_MIN_LINES=90' 'Fail if line coverage is below N%% (use with make coverage / COVERAGE=1)'
	@printf '  %-38s %s\n' 'NERO_KEEP_HOST_BUILDS=1' 'Skip wipe for make test/lint/verify only (CI always wipes CMake trees)'
	@printf '\n'

clean:
	@echo "Releasing serial ports..."
	@for p in /dev/ttyACM*; do \
	   [ -e "$$p" ] && fuser -k "$$p" >/dev/null 2>&1 && echo "  killed process on $$p" || true; \
	 done
	@sleep 0.3
	@echo "Stopping stale processes..."
	@pgrep -x bossac | xargs -r kill 2>/dev/null || true
	@pgrep -x arduino-cli | xargs -r kill 2>/dev/null || true
	@echo "Removing third-party/ (arduino-cli, cores, NFC-RFAL, ST25R3916; WBA65-only: TinyUSB, OpenOCD; refetched on next build)..."
	rm -rf $(CURDIR)/third-party
	@echo "Removing build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -rf $(CURDIR)/tests/build $(CURDIR)/tests/build-scan $(CURDIR)/tests/scan-build-report
	@echo "Done. Port released for other tools."

# Combined NFC build + flash (see make/target-$(BOARD_TARGET_DRIVER).mk).
ifeq ($(TARGET),nucleo_wba65ri)
include make/third-party-wba65-openocd.mk
include make/third-party-tinyusb-wba65.mk
endif
include make/third-party-host-tools.mk
include make/third-party-nfc-libs.mk
include make/target-$(BOARD_TARGET_DRIVER).mk

all: build

build: maybe-deps nfc userspace
