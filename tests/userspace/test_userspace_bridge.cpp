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

#include "nero_nfc_bridge.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <optional>
#include <string>

#include "nero_nfc_detect.hpp"
#include "nero_nfc_null.h"
#include "nero_nfc_pcsc.hpp"

class UserspaceBridgeTest : public ::testing::Test {
 protected:
  void TearDown() override {
    nero_nfc::NeroNfcUtestClearFindSerialPortsOverride();
    nero_nfc::NeroNfcUtestClearListPcscReadersOverride();
    if (env_saved_) {
      if (saved_pcsc_reader_.has_value()) {
        setenv("NFC_PCSC_READER", saved_pcsc_reader_->c_str(), 1);
      } else {
        unsetenv("NFC_PCSC_READER");
      }
    }
  }

  void SetPcscReaderEnv(const char* value) {
    if (!env_saved_) {
      const char* current = std::getenv("NFC_PCSC_READER");
      if (current != NERO_NFC_NULL) {
        saved_pcsc_reader_ = std::string(current);
      }
      env_saved_ = true;
    }
    setenv("NFC_PCSC_READER", value, 1);
  }

 private:
  bool env_saved_{};
  std::optional<std::string> saved_pcsc_reader_;
};

TEST(ParseHostBridge, AcceptsCanonicalNamesOnly) {
  EXPECT_EQ(nero_nfc::ParseHostBridge("cdc"), nero_nfc::HostBridge::kCdc);
  EXPECT_EQ(nero_nfc::ParseHostBridge("PCSC"), nero_nfc::HostBridge::kPcsc);
  EXPECT_FALSE(nero_nfc::ParseHostBridge("ccid").has_value());
  EXPECT_FALSE(nero_nfc::ParseHostBridge("serial").has_value());
}

TEST_F(UserspaceBridgeTest, AutoPrefersPcscWhenBothBridgesArePresent) {
  std::vector<std::string> serial_ports = {"/dev/ttyACM1"};
  std::vector<std::string> pcsc_readers = {"Nero NFC PCSC Reader"};
  nero_nfc::NeroNfcUtestSetFindSerialPortsOverride(&serial_ports);
  nero_nfc::NeroNfcUtestSetListPcscReadersOverride(&pcsc_readers);

  nero_nfc::HostBridgeSelection selection;
  std::string err;
  ASSERT_TRUE(nero_nfc::ChooseHostBridge(std::nullopt, "", "", selection, err));
  EXPECT_EQ(selection.bridge_, nero_nfc::HostBridge::kPcsc);
  EXPECT_TRUE(selection.pcsc_reader_.empty());
}

TEST_F(UserspaceBridgeTest, AutoFallsBackToSerialWhenPcscMissing) {
  std::vector<std::string> serial_ports = {"/dev/ttyACM1"};
  std::vector<std::string> no_pcsc_readers;
  nero_nfc::NeroNfcUtestSetFindSerialPortsOverride(&serial_ports);
  nero_nfc::NeroNfcUtestSetListPcscReadersOverride(&no_pcsc_readers);

  nero_nfc::HostBridgeSelection selection;
  std::string err;
  ASSERT_TRUE(nero_nfc::ChooseHostBridge(std::nullopt, "", "", selection, err));
  EXPECT_EQ(selection.bridge_, nero_nfc::HostBridge::kCdc);
  EXPECT_EQ(selection.serial_port_, "/dev/ttyACM1");
}

TEST_F(UserspaceBridgeTest, AutoFallsBackToPcsc) {
  std::vector<std::string> no_serial_ports;
  std::vector<std::string> pcsc_readers = {"Nero NFC PCSC Reader"};
  nero_nfc::NeroNfcUtestSetFindSerialPortsOverride(&no_serial_ports);
  nero_nfc::NeroNfcUtestSetListPcscReadersOverride(&pcsc_readers);

  nero_nfc::HostBridgeSelection selection;
  std::string err;
  ASSERT_TRUE(nero_nfc::ChooseHostBridge(std::nullopt, "", "", selection, err));
  EXPECT_EQ(selection.bridge_, nero_nfc::HostBridge::kPcsc);
  EXPECT_TRUE(selection.pcsc_reader_.empty());
}

TEST_F(UserspaceBridgeTest, AutoPcscAllowsMultipleReadersForPresenceSelection) {
  std::vector<std::string> no_serial_ports;
  std::vector<std::string> pcsc_readers = {
      "HID Global OMNIKEY 5422 Smartcard Reader 00 00", "Nero NFC PCSC Reader"};
  nero_nfc::NeroNfcUtestSetFindSerialPortsOverride(&no_serial_ports);
  nero_nfc::NeroNfcUtestSetListPcscReadersOverride(&pcsc_readers);

  nero_nfc::HostBridgeSelection selection;
  std::string err;
  ASSERT_TRUE(nero_nfc::ChooseHostBridge(std::nullopt, "", "", selection, err));
  EXPECT_EQ(selection.bridge_, nero_nfc::HostBridge::kPcsc);
  EXPECT_TRUE(selection.pcsc_reader_.empty());
}

TEST_F(UserspaceBridgeTest, ExplicitPcscReaderMakesPcscSelection) {
  std::vector<std::string> serial_ports = {"/dev/ttyACM1"};
  std::vector<std::string> pcsc_readers = {"Nero NFC PCSC Reader"};
  nero_nfc::NeroNfcUtestSetFindSerialPortsOverride(&serial_ports);
  nero_nfc::NeroNfcUtestSetListPcscReadersOverride(&pcsc_readers);

  nero_nfc::HostBridgeSelection selection;
  std::string err;
  ASSERT_TRUE(
      nero_nfc::ChooseHostBridge(std::nullopt, "", "pcsc", selection, err));
  EXPECT_EQ(selection.bridge_, nero_nfc::HostBridge::kPcsc);
  EXPECT_EQ(selection.pcsc_reader_, "Nero NFC PCSC Reader");
}

TEST_F(UserspaceBridgeTest, EnvPcscReaderMakesPcscSelection) {
  std::vector<std::string> serial_ports = {"/dev/ttyACM1"};
  std::vector<std::string> pcsc_readers = {"Nero NFC PCSC Reader"};
  nero_nfc::NeroNfcUtestSetFindSerialPortsOverride(&serial_ports);
  nero_nfc::NeroNfcUtestSetListPcscReadersOverride(&pcsc_readers);
  SetPcscReaderEnv("pcsc");

  nero_nfc::HostBridgeSelection selection;
  std::string err;
  ASSERT_TRUE(nero_nfc::ChooseHostBridge(std::nullopt, "", "", selection, err));
  EXPECT_EQ(selection.bridge_, nero_nfc::HostBridge::kPcsc);
  EXPECT_EQ(selection.pcsc_reader_, "Nero NFC PCSC Reader");
}

TEST_F(UserspaceBridgeTest, RejectsPcscShareWhenCdcIsSelected) {
  nero_nfc::HostBridgeSelection selection;
  std::string err;
  EXPECT_FALSE(nero_nfc::ChooseHostBridge(nero_nfc::HostBridge::kCdc, "", "",
                                          selection, err, true));
  EXPECT_NE(err.find("PC/SC options"), std::string::npos);
}

TEST_F(UserspaceBridgeTest, RejectsConflictingTransportSpecificOptions) {
  nero_nfc::HostBridgeSelection selection;
  std::string err;
  EXPECT_FALSE(nero_nfc::ChooseHostBridge(std::nullopt, "/dev/ttyACM0", "Nero",
                                          selection, err));
  EXPECT_NE(err.find("choose either --port"), std::string::npos);
}

TEST_F(UserspaceBridgeTest, ExplicitPcscGetsCompatibilityHintWithoutReader) {
  std::vector<std::string> no_serial_ports;
  std::vector<std::string> no_pcsc_readers;
  nero_nfc::NeroNfcUtestSetFindSerialPortsOverride(&no_serial_ports);
  nero_nfc::NeroNfcUtestSetListPcscReadersOverride(&no_pcsc_readers);

  nero_nfc::HostBridgeSelection selection;
  std::string err;
  EXPECT_FALSE(nero_nfc::ChooseHostBridge(nero_nfc::HostBridge::kPcsc, "", "",
                                          selection, err));
  EXPECT_NE(err.find("PC/SC bridge requested"), std::string::npos);
  EXPECT_NE(err.find("--bridge=cdc"), std::string::npos);
}
