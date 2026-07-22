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

#include "nero_nfc_app.h"
#include "nero_nfc_board.h"
#include "nero_nfc_frontend.h"
#include "nero_nfc_null.h"
#include "nero_nfc_platform.h"
#include "nero_nfc_platform_host_fake.h"
#include "reader_context.h"
#include "writer_context.h"

#include <gtest/gtest.h>

namespace {

constexpr uint32_t kHostFakeMillis = 42u;
constexpr uint8_t kHostFakeSpiByte = 0xA5u;
constexpr uint8_t kPushbackLen = 3u;
constexpr uint8_t kRuntimeCsPin = 9u;
constexpr uint8_t kRuntimeIrqPin = 7u;
constexpr uint8_t kRuntimeLedPin = 6u;
constexpr uint32_t kRuntimeBaud = 230400u;
constexpr uint32_t kRuntimeSpiClockHz = 2800000u;

}  // namespace

TEST(NeroNfcPlatformApp, RejectsInvalidOpsAndUsesAppOwnedHostFake) {
  nero_nfc_platform_host_fake_reset();
  nero_nfc_platform_ops_t bad{};
  EXPECT_FALSE(nero_nfc_platform_ops_validate(&bad));

  nero_nfc_app_storage_t storage{};
  nero_nfc_board_config_t board{};
  nero_nfc_board_config_defaults(&board);
  const nero_nfc_platform_ops_t kOps = nero_nfc_platform_host_fake_ops();
  EXPECT_TRUE(nero_nfc_platform_ops_validate(&kOps));
  nero_nfc_app_t* app =
      nero_nfc_app_init(&storage, &kOps, &board, NERO_NFC_PRODUCT_READER);
  ASSERT_NE(app, NERO_NFC_NULL);
  ASSERT_NE(nero_nfc_app_platform_ops(app), NERO_NFC_NULL);
  EXPECT_EQ(nero_nfc_app_platform_ops(app)->context, kOps.context);

  nero_nfc_platform_host_fake_set_millis(kHostFakeMillis);
  EXPECT_EQ(nero_nfc_platform_millis(), kHostFakeMillis);
  nero_nfc_platform_serial_write_char('Z');
  EXPECT_EQ(nero_nfc_platform_host_fake_last_serial_char(), 'Z');
  EXPECT_EQ(nero_nfc_platform_spi_transfer(kHostFakeSpiByte), kHostFakeSpiByte);
  EXPECT_EQ(nero_nfc_platform_host_fake_last_spi(), kHostFakeSpiByte);
  EXPECT_TRUE(nero_nfc_app_unbind_active(app));
}

TEST(NeroNfcPlatformApp, CopiesRuntimeBoardConfigurationIntoApp) {
  nero_nfc_platform_host_fake_reset();
  nero_nfc_app_storage_t storage{};
  nero_nfc_board_config_t board{};
  nero_nfc_board_config_defaults(&board);
  board.cs_pin = kRuntimeCsPin;
  board.irq_pin = kRuntimeIrqPin;
  board.led_pin = kRuntimeLedPin;
  board.serial_baud = kRuntimeBaud;
  board.spi_clock_hz = kRuntimeSpiClockHz;
  board.host_board_name[0] = 'X';
  const nero_nfc_platform_ops_t kOps = nero_nfc_platform_host_fake_ops();

  nero_nfc_app_t* app =
      nero_nfc_app_init(&storage, &kOps, &board, NERO_NFC_PRODUCT_READER);
  ASSERT_NE(app, NERO_NFC_NULL);
  board.cs_pin = 0u;
  board.serial_baud = 0u;

  const nero_nfc_board_config_t* stored = nero_nfc_app_board(app);
  ASSERT_NE(stored, NERO_NFC_NULL);
  EXPECT_EQ(stored->cs_pin, kRuntimeCsPin);
  EXPECT_EQ(stored->irq_pin, kRuntimeIrqPin);
  EXPECT_EQ(stored->led_pin, kRuntimeLedPin);
  EXPECT_EQ(stored->serial_baud, kRuntimeBaud);
  EXPECT_EQ(stored->spi_clock_hz, kRuntimeSpiClockHz);
  EXPECT_EQ(stored->host_board_name[0], 'X');
  EXPECT_TRUE(nero_nfc_app_unbind_active(app));
}

TEST(NeroNfcPlatformApp, SerialPushbackLivesInAppContext) {
  nero_nfc_platform_host_fake_reset();
  nero_nfc_app_storage_t storage{};
  nero_nfc_board_config_t board{};
  nero_nfc_board_config_defaults(&board);
  const nero_nfc_platform_ops_t kOps = nero_nfc_platform_host_fake_ops();
  nero_nfc_app_t* app =
      nero_nfc_app_init(&storage, &kOps, &board, NERO_NFC_PRODUCT_COMBINED);
  ASSERT_NE(app, NERO_NFC_NULL);
  nfc_frontend_t* frontend = nero_nfc_app_frontend(app);
  ASSERT_NE(frontend, NERO_NFC_NULL);
  EXPECT_EQ(nero_nfc_app_reader(app)->frontend, frontend);
  EXPECT_EQ(nero_nfc_app_writer(app)->frontend, frontend);

  const uint8_t kBytes[] = {0x41u, 0x42u, 0x43u};
  nero_nfc_app_serial_pushback_return(app, &kBytes[0], kPushbackLen);
  EXPECT_EQ(nero_nfc_app_serial_pushback_available(app),
            static_cast<int>(kPushbackLen));
  EXPECT_EQ(nero_nfc_app_serial_pushback_read(app), 0x41);
  EXPECT_EQ(nero_nfc_app_serial_pushback_read(app), 0x42);
  EXPECT_EQ(nero_nfc_app_serial_pushback_read(app), 0x43);
  EXPECT_EQ(nero_nfc_app_serial_pushback_read(app), -1);
  EXPECT_TRUE(nero_nfc_app_unbind_active(app));
}

TEST(NeroNfcPlatformApp, QuiescesOnlyInitializedFrontendOnModeChange) {
  nero_nfc_platform_host_fake_reset();
  nero_nfc_app_storage_t storage{};
  nero_nfc_board_config_t board{};
  nero_nfc_board_config_defaults(&board);
  const nero_nfc_platform_ops_t kOps = nero_nfc_platform_host_fake_ops();
  nero_nfc_app_t* app =
      nero_nfc_app_init(&storage, &kOps, &board, NERO_NFC_PRODUCT_COMBINED);
  ASSERT_NE(app, NERO_NFC_NULL);
  nfc_frontend_t* frontend = nero_nfc_app_frontend(app);
  ASSERT_NE(frontend, NERO_NFC_NULL);
  ASSERT_NE(frontend->ops, NERO_NFC_NULL);
  ASSERT_NE(frontend->state, NERO_NFC_NULL);
  auto* st25 = static_cast<st25r3916_t*>(frontend->state);

  nero_nfc_app_set_runtime_mode(app, NERO_NFC_RUNTIME_MODE_WRITER);
  EXPECT_EQ(st25->quiesce_count, 0u);

  uint8_t chip_id = 0u;
  uint16_t vdd_mv = 0u;
  ASSERT_EQ(frontend->ops->init(frontend->state, &chip_id, &vdd_mv),
            NFC_FRONTEND_INIT_OK);
  nero_nfc_app_set_runtime_mode(app, NERO_NFC_RUNTIME_MODE_READER);
  EXPECT_EQ(st25->quiesce_count, 1u);
  nero_nfc_app_set_runtime_mode(app, NERO_NFC_RUNTIME_MODE_READER);
  EXPECT_EQ(st25->quiesce_count, 1u);
  EXPECT_TRUE(nero_nfc_app_unbind_active(app));
}

TEST(NeroNfcPlatformApp, RejectsSecondActiveInstance) {
  nero_nfc_platform_host_fake_reset();
  nero_nfc_app_storage_t first_storage{};
  nero_nfc_app_storage_t second_storage{};
  nero_nfc_board_config_t board{};
  nero_nfc_board_config_defaults(&board);
  const nero_nfc_platform_ops_t kOps = nero_nfc_platform_host_fake_ops();

  nero_nfc_app_t* first =
      nero_nfc_app_init(&first_storage, &kOps, &board, NERO_NFC_PRODUCT_READER);
  ASSERT_NE(first, NERO_NFC_NULL);
  EXPECT_EQ(nero_nfc_app_init(&second_storage, &kOps, &board,
                              NERO_NFC_PRODUCT_READER),
            NERO_NFC_NULL);
  EXPECT_FALSE(nero_nfc_app_unbind_active(
      reinterpret_cast<nero_nfc_app_t*>(&second_storage)));
  EXPECT_EQ(nero_nfc_app_active(), first);
  EXPECT_TRUE(nero_nfc_app_unbind_active(first));

  nero_nfc_app_t* second = nero_nfc_app_init(&second_storage, &kOps, &board,
                                             NERO_NFC_PRODUCT_READER);
  ASSERT_NE(second, NERO_NFC_NULL);
  EXPECT_EQ(nero_nfc_app_active(), second);
  EXPECT_TRUE(nero_nfc_app_unbind_active(second));
}
