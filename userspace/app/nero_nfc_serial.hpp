// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2026 Nero Duality, LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include "nero_nfc_attrs.h"

#include <string>

#ifdef NERO_HOST_UNIT_TEST_HOOKS
#include <functional>
#endif

namespace nero_nfc {

// Open a serial port at 115200 8N1. Returns fd >= 0 on success, -1 on error.
int SerialOpen(const std::string& path);

// Assert DTR and RTS to reset the connected MCU, then release them.
// Blocks for kResetSettleS + kPostResetReopenWaitS.
NERO_NFC_NODISCARD bool SerialReset(int fd);

// Close a serial fd.
NERO_NFC_NODISCARD bool SerialClose(int fd);

#ifdef NERO_HOST_UNIT_TEST_HOOKS
// Replace serial_open behavior (non-null → hook runs instead of
// open/tcsetattr).
void NeroNfcUtestSetSerialOpenHook(
    std::function<int(const std::string& path)> hook);
void NeroNfcUtestClearSerialOpenHook();

// When true, serial_reset is a no-op (for fast tests).
void NeroNfcUtestSetSerialResetNoop(bool noop);

// When true, serial_reset still toggles DTR/RTS but skips the long sleeps
// (requires a real TTY fd).
void NeroNfcUtestSetSerialResetSkipDelays(bool skip);
#endif

}  // namespace nero_nfc
