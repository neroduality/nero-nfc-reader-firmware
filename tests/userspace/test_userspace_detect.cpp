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
#include "nero_nfc_detect.h"

#include <algorithm>
#include <gtest/gtest.h>

using nero_nfc::find_serial_ports;
using nero_nfc::nero_nfc_utest_clear_find_serial_ports_override;
using nero_nfc::nero_nfc_utest_set_find_serial_ports_override;
using nero_nfc::resolve_serial_port_choice;
using nero_nfc::select_best_port;

class UserspaceDetectTest : public ::testing::Test {
protected:
  void TearDown() override {
    nero_nfc::nero_nfc_utest_clear_find_serial_ports_override();
  }
};

TEST(SelectBestPort, EmptyListReturnsEmpty) {
  EXPECT_EQ(select_best_port({}), "");
}

TEST(SelectBestPort, SingleEntryReturned) {
  EXPECT_EQ(select_best_port({"/dev/ttyACM0"}), "/dev/ttyACM0");
}

TEST(SelectBestPort, PrefersTtyACMOverTtyUSB) {
  std::vector<std::string> ports = {"/dev/ttyUSB0", "/dev/ttyACM1"};
  EXPECT_EQ(select_best_port(ports), "/dev/ttyACM1");
}

TEST(SelectBestPort, LowestACMWinsWhenMultipleACM) {
  std::vector<std::string> ports = {"/dev/ttyACM0", "/dev/ttyACM2",
                                    "/dev/ttyACM1"};
  // After sort (done by find_serial_ports), ACM0 comes first.
  std::sort(ports.begin(), ports.end());
  EXPECT_EQ(select_best_port(ports), "/dev/ttyACM0");
}

TEST(SelectBestPort, OnlyUSBPortsPicksFirst) {
  std::vector<std::string> ports = {"/dev/ttyUSB1", "/dev/ttyUSB0"};
  std::sort(ports.begin(), ports.end());
  EXPECT_EQ(select_best_port(ports), "/dev/ttyUSB0");
}

TEST_F(UserspaceDetectTest, FindSerialPortsUsesOverrideList) {
  std::vector<std::string> fake = {"/dev/ttyUSB2", "/dev/ttyACM0"};
  nero_nfc_utest_set_find_serial_ports_override(&fake);
  auto found = find_serial_ports();
  ASSERT_EQ(found.size(), 2u);
  EXPECT_EQ(found[0], "/dev/ttyACM0");
  EXPECT_EQ(found[1], "/dev/ttyUSB2");
}

TEST(ResolveSerialPortChoice, ExplicitWinsOverDiscovery) {
  std::vector<std::string> discovered = {"/dev/ttyACM0"};
  EXPECT_EQ(resolve_serial_port_choice("/dev/custom", discovered),
            "/dev/custom");
}

TEST(ResolveSerialPortChoice, AutoUsesSelectBest) {
  std::vector<std::string> discovered = {"/dev/ttyUSB1", "/dev/ttyACM3"};
  std::sort(discovered.begin(), discovered.end());
  EXPECT_EQ(resolve_serial_port_choice("", discovered), "/dev/ttyACM3");
}

TEST(ResolveSerialPortChoice, AutoEmptyDiscoveryReturnsEmpty) {
  testing::internal::CaptureStderr();
  EXPECT_EQ(resolve_serial_port_choice("", {}), "");
  (void)testing::internal::GetCapturedStderr();
}

TEST(FindSerialPorts, RunsGlobWhenNoOverride) {
  nero_nfc::nero_nfc_utest_clear_find_serial_ports_override();
  (void)find_serial_ports();
}
