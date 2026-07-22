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

// Unit tests for nero_nfc_detect (port-selection logic).
// These run on the host with GoogleTest; no hardware required.
//
#include "nero_nfc_detect.hpp"

#include <algorithm>
#include <gtest/gtest.h>

using nero_nfc::FindSerialPorts;
using nero_nfc::NeroNfcUtestClearFindSerialPortsOverride;
using nero_nfc::NeroNfcUtestSetFindSerialPortsOverride;
using nero_nfc::ResolveSerialPortChoice;
using nero_nfc::SelectBestPort;

class UserspaceDetectTest : public ::testing::Test {
 protected:
  void TearDown() override {
    nero_nfc::NeroNfcUtestClearFindSerialPortsOverride();
  }
};

TEST(SelectBestPort, EmptyListReturnsEmpty) {
  EXPECT_EQ(SelectBestPort({}), "");
}

TEST(SelectBestPort, SingleEntryReturned) {
  EXPECT_EQ(SelectBestPort({"/dev/ttyACM0"}), "/dev/ttyACM0");
}

TEST(SelectBestPort, PrefersTtyACMOverTtyUSB) {
  std::vector<std::string> ports = {"/dev/ttyUSB0", "/dev/ttyACM1"};
  EXPECT_EQ(SelectBestPort(ports), "/dev/ttyACM1");
}

TEST(SelectBestPort, LowestACMWinsWhenMultipleACM) {
  std::vector<std::string> ports = {"/dev/ttyACM0", "/dev/ttyACM2",
                                    "/dev/ttyACM1"};
  // After sort (done by find_serial_ports), ACM0 comes first.
  std::ranges::sort(ports);
  EXPECT_EQ(SelectBestPort(ports), "/dev/ttyACM0");
}

TEST(SelectBestPort, OnlyUSBPortsPicksFirst) {
  std::vector<std::string> ports = {"/dev/ttyUSB1", "/dev/ttyUSB0"};
  std::ranges::sort(ports);
  EXPECT_EQ(SelectBestPort(ports), "/dev/ttyUSB0");
}

TEST_F(UserspaceDetectTest, FindSerialPortsUsesOverrideList) {
  std::vector<std::string> fake = {"/dev/ttyUSB2", "/dev/ttyACM0"};
  NeroNfcUtestSetFindSerialPortsOverride(&fake);
  auto found = FindSerialPorts();
  ASSERT_EQ(found.size(), 2u);
  EXPECT_EQ(found[0], "/dev/ttyACM0");
  EXPECT_EQ(found[1], "/dev/ttyUSB2");
}

TEST(ResolveSerialPortChoice, ExplicitWinsOverDiscovery) {
  std::vector<std::string> discovered = {"/dev/ttyACM0"};
  EXPECT_EQ(ResolveSerialPortChoice("/dev/custom", discovered), "/dev/custom");
}

TEST(ResolveSerialPortChoice, AutoUsesSelectBest) {
  std::vector<std::string> discovered = {"/dev/ttyUSB1", "/dev/ttyACM3"};
  std::ranges::sort(discovered);
  EXPECT_EQ(ResolveSerialPortChoice("", discovered), "/dev/ttyACM3");
}

TEST(ResolveSerialPortChoice, AutoEmptyDiscoveryReturnsEmpty) {
  testing::internal::CaptureStderr();
  EXPECT_EQ(ResolveSerialPortChoice("", {}), "");
  (void)testing::internal::GetCapturedStderr();
}

TEST(FindSerialPorts, RunsGlobWhenNoOverride) {
  nero_nfc::NeroNfcUtestClearFindSerialPortsOverride();
  (void)FindSerialPorts();
}
