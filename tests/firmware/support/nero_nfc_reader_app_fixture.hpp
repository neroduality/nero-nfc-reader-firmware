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

#include "nero_nfc_app.h"
#include "nero_nfc_board.h"
#include "nero_nfc_null.h"
#include "nero_nfc_platform_host_fake.h"
#include "reader_context.h"

#include <gtest/gtest.h>

/* Host tests that touch G_* / G_READER must bind an application context. */
class NeroNfcReaderAppFixture : public ::testing::Test {
 protected:
  void SetUp() override { BindReaderApp(); }

  void TearDown() override { UnbindReaderApp(); }

  void BindReaderApp() {
    nero_nfc_platform_host_fake_reset();
    nero_nfc_board_config_defaults(&board_);
    const nero_nfc_platform_ops_t kOps = nero_nfc_platform_host_fake_ops();
    app_ =
        nero_nfc_app_init(&storage_, &kOps, &board_, NERO_NFC_PRODUCT_READER);
    ASSERT_NE(app_, NERO_NFC_NULL);
    ASSERT_TRUE(nero_nfc_app_bind_active(app_));
    ASSERT_NE(reader_context_active(), NERO_NFC_NULL);
  }

  void UnbindReaderApp() {
    EXPECT_TRUE(nero_nfc_app_unbind_active(app_));
    app_ = NERO_NFC_NULL;
  }

  nero_nfc_app_t* App() { return app_; }

 private:
  nero_nfc_app_storage_t storage_{};
  nero_nfc_board_config_t board_{};
  nero_nfc_app_t* app_{NERO_NFC_NULL};
};
