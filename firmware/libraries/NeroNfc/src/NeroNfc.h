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

/* Arduino discovery umbrella for the NeroNfc C library. */

#include "nero_nfc_attrs.h"
#include "nero_nfc_app.h"
#include "nero_nfc_board.h"
#include "nero_nfc_format.h"
#include "nero_nfc_frontend.h"
#include "nero_nfc_limits.h"
#include "nero_nfc_log.h"
#include "nero_nfc_mem_util.h"
#include "nero_nfc_null.h"
#include "nero_nfc_platform.h"
#include "nero_nfc_types.h"

#include "nfc_ccid_frame.h"
#include "nfc_ctap_codec.h"
#include "nfc_mode_line_scan.h"
#include "nfc_ndef_record_decode.h"
#include "nfc_ndef_tlv.h"
#include "nfc_pcsc_contactless.h"
#include "nfc_storage_ndef.h"
