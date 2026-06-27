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

#include "reader_security_key_iso_dep_transceive.h"
#include "reader_security_key_utest_iso_dep.h"

#include "nero_nfc_null.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>

class ReaderSecurityKeyTransceiveTest : public ::testing::Test {
protected:
  void SetUp() override {
    reader_security_key_utest_reset_iso_dep();
  }
};

TEST_F(ReaderSecurityKeyTransceiveTest, SendApduRejectsNullBuffers) {
  std::array<std::uint8_t, 8> rsp{};

  EXPECT_LT(reader_security_key_send_apdu_timeout_ex(NERO_NFC_NULL, 1u, rsp.data(), (uint16_t)rsp.size(),
                                             100u, false),
            0);
  EXPECT_LT(reader_security_key_send_apdu_timeout_ex(rsp.data(), 1u, NERO_NFC_NULL, 0u, 100u, false), 0);
}

TEST_F(ReaderSecurityKeyTransceiveTest, SendApduReturnsShortWhenIsoDepHookFails) {
  reader_security_key_utest_set_iso_dep_transceive(
    +[](const std::uint8_t *, std::uint16_t, std::uint8_t *, std::uint16_t, bool,
        std::uint16_t) -> int { return -1; });

  std::array<std::uint8_t, 5> apdu{0x00u, 0xA4u, 0x04u, 0x00u, 0x00u};
  std::array<std::uint8_t, 16> rsp{};

  EXPECT_LT(reader_security_key_send_apdu_timeout_ex(apdu.data(), (uint16_t)apdu.size(), rsp.data(),
                                             (uint16_t)rsp.size(), 100u, false),
            2);
}

TEST_F(ReaderSecurityKeyTransceiveTest, SendApduDoesNotWritePastResponseCap) {
  reader_security_key_utest_set_iso_dep_transceive(
    +[](const std::uint8_t *, std::uint16_t tx_len, std::uint8_t *rx, std::uint16_t rx_max,
        bool, std::uint16_t) -> int {
      if ((rx == NERO_NFC_NULL) || (rx_max < 6u)) {
        return -1;
      }
      /* Minimal ISO-DEP I-block PCB + INF(90 00) + CRC placeholder. */
      rx[0] = 0x02u;
      rx[1] = 0x90u;
      rx[2] = 0x00u;
      rx[3] = 0x00u;
      rx[4] = 0x00u;
      rx[5] = 0x00u;
      (void)tx_len;
      return 6;
    });

  std::array<std::uint8_t, 5> apdu{0x00u, 0xA4u, 0x04u, 0x00u, 0x00u};
  std::array<std::uint8_t, 4> rsp{};
  rsp.fill(0xAAu);

  const int total = reader_security_key_send_apdu_timeout_ex(
    apdu.data(), (uint16_t)apdu.size(), rsp.data(), (uint16_t)rsp.size(), 100u, false);
  EXPECT_LT(total, 2);
  EXPECT_EQ(rsp[3], 0xAAu);
}
