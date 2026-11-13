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

#include "nero_nfc_ctap.hpp"
#include "nero_nfc_pcsc.hpp"

#include <string>
#include <string_view>

namespace nero_nfc {

struct FidoTokenRequest {
  bool info_{};
  bool reset_{};
  bool set_pin_{};
  bool change_pin_{};
  std::string current_pin_;
  std::string new_pin_;
  PcscShareMode share_mode_{PcscShareMode::kShared};
};

enum class FidoTokenResult : std::uint8_t {
  kOk,
  kFailed,
  /* authenticatorReset refused outside its post-power-up window; re-tap. */
  kRetryReset,
};

std::string FormatAuthenticatorInfo(const ctap::AuthenticatorInfo& info);

/* SELECTs the FIDO applet, then runs the requested operations. */
FidoTokenResult RunFidoTokenOperations(ctap::Client& client,
                                       const FidoTokenRequest& request);

int RunFidoTokenList();
/* Waits for a tap, then runs the request; PINs in request are wiped. */
int RunFidoToken(std::string_view reader_substring, FidoTokenRequest& request);

}  // namespace nero_nfc
