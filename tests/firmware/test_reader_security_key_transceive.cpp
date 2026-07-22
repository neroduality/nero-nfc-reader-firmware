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

#include "nero_nfc_mem_util.h"
#include "nero_nfc_null.h"
#include "nero_nfc_reader_app_fixture.hpp"
#include "nfc_pcsc_contactless.h"
#include "reader_iso_dep_frame.h"
#include "reader_security_key_iso_dep_transceive.h"
#include "reader_security_key_utest_iso_dep.h"

namespace {
enum {
  kTestLit0x01u = 0x01u,
  kTestLit0x02u = 0x02u,
  kTestLit0x03u = 0x03u,
  kTestLit0x04u = 0x04u,
  kTestLit0x10u = 0x10u,
  kTestLit0x12u = 0x12u,
  kTestLit0x16u = 0x16u,
  kTestLit0x40u = 0x40u,
  kTestLit0x7Fu = 0x7Fu,
  kTestLit0x80u = 0x80u,
  kTestLit0x90u = 0x90u,
  kTestLit0xA2u = 0xA2u,
  kTestLit0xA3u = 0xA3u,
  kTestLit0xA4u = 0xA4u,
  kTestLit0xA5u = 0xA5u,
  kTestLit0xAAu = 0xAAu,
  kTestLit0xB2u = 0xB2u,
  kTestLit0xCCu = 0xCCu,
  kTestLit0xF2u = 0xF2u,
  kTestLit0xFFu = 0xFFu,
  kTestLit1000u = 1000u,
  kTestLit100u = 100u,
  kTestLit105u = 105u,
  kTestLit106u = 106u,
  kTestLit10u = 10u,
  kTestLit16 = 16,
  kTestLit16u = 16u,
  kTestLit205 = 205,
  kTestLit206 = 206,
  kTestLit256 = 256,
  kTestLit2 = 2,
  kTestLit2u = 2u,
  kTestLit3 = 3,
  kTestLit30 = 30,
  kTestLit3u = 3u,
  kTestLit4 = 4,
  kTestLit49 = 49,
  kTestLit4u = 4u,
  kTestLit5 = 5,
  kTestLit5u = 5u,
  kTestLit6 = 6,
  kTestLit6u = 6u,
  kTestLit8 = 8,
};
}  // namespace

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <iterator>
#include <span>
#include <vector>

namespace {
std::uint8_t g_chained_response_step;
std::uint8_t g_webauthn_step;
std::uint8_t g_simple_script_calls;
std::vector<std::uint8_t> g_first_relayed_apdu;
std::vector<std::uint8_t> g_second_relayed_apdu;
std::vector<std::vector<std::uint8_t>> g_observed_frames;

constexpr std::uint16_t kWebAuthnApduLen = 170u;
constexpr std::uint16_t kWebAuthnFragmentLen = 48u;
constexpr std::uint16_t kWebAuthnLastFragmentLen =
    kWebAuthnApduLen - (kTestLit3u * kWebAuthnFragmentLen);
constexpr std::uint16_t kWebAuthnResponseFirstInfLen = 100u;
constexpr std::uint16_t kChainedFrameOverhead =
    static_cast<std::uint16_t>(ISO_DEP_HDR_BASE_LEN + ISO_DEP_CRC_LEN);
constexpr std::uint16_t kWebAuthnStepsPerCommand = kTestLit5u;
constexpr std::uint16_t kWebAuthnTxFragmentSteps = kTestLit4u;
constexpr std::size_t kNadChainedFrameLen = 5u;
constexpr std::size_t kRspScratchCap = kTestLit256;
constexpr std::size_t kRecoveryApduLen = kTestLit49;
constexpr std::size_t kSmallFscApduLen = kTestLit30;
constexpr std::uint16_t kSmallFscFrameMax = kTestLit16u;
constexpr std::uint16_t kFirstAssertionInfLen = kTestLit105u;
constexpr std::uint16_t kSecondAssertionInfLen = kTestLit106u;

template <std::size_t N>
bool CopyScriptResponse(std::uint8_t* rx, std::uint16_t rx_max,
                        const std::array<std::uint8_t, N>& frame) {
  return nero_nfc_copy_bytes(rx, rx_max, 0u, frame.data(), frame.size());
}

void AppendObservedFrame(const std::uint8_t* tx, std::uint16_t tx_len) {
  const std::span<const std::uint8_t> kTx(tx, tx_len);
  g_observed_frames.emplace_back(kTx.begin(), kTx.end());
}

void StoreCrcASuffix(std::uint8_t* buf, std::size_t buf_cap,
                     std::uint16_t payload_len) {
  const auto kCrc = reader_iso_dep_crc_a(buf, payload_len);
  (void)nero_nfc_store_u8(
      buf, buf_cap, payload_len,
      static_cast<std::uint8_t>(kCrc & ISO_DEP_BYTE_MASK_LOW));
  (void)nero_nfc_store_u8(
      buf, buf_cap, static_cast<std::size_t>(payload_len + 1u),
      static_cast<std::uint8_t>(kCrc >> ISO_DEP_BYTE_SHIFT_8));
}

std::array<std::uint8_t, kWebAuthnResponseFirstInfLen + kChainedFrameOverhead>
ChainedResponseFrame(std::uint8_t block, std::uint8_t fill) {
  std::array<std::uint8_t, kWebAuthnResponseFirstInfLen + kChainedFrameOverhead>
      frame{};
  frame.fill(fill);
  frame[0] = static_cast<std::uint8_t>(ISO_DEP_PCB_I_BLOCK_BASE |
                                       ISO_DEP_PCB_CHAIN_BIT |
                                       (block & ISO_DEP_BLOCK_NUM_MASK));
  StoreCrcASuffix(frame.data(), frame.size(),
                  static_cast<std::uint16_t>(frame.size() - ISO_DEP_CRC_LEN));
  return frame;
}

template <std::size_t InfLen>
std::array<std::uint8_t, InfLen + ISO_DEP_HDR_BASE_LEN> FinalResponseFrame(
    std::uint8_t block, std::uint8_t fill) {
  static_assert(InfLen >= NFC_ISO7816_SW_STATUS_WORD_LEN);
  std::array<std::uint8_t, InfLen + ISO_DEP_HDR_BASE_LEN> frame{};
  frame.fill(fill);
  frame[0] = static_cast<std::uint8_t>(ISO_DEP_PCB_I_BLOCK_BASE |
                                       (block & ISO_DEP_BLOCK_NUM_MASK));
  frame[frame.size() - ISO_DEP_CRC_LEN] =
      static_cast<std::uint8_t>(NFC_ISO7816_SW1_SUCCESS);
  frame[frame.size() - ISO_DEP_HDR_BASE_LEN] =
      static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS);
  return frame;
}

int WebAuthnTwoAssertionScript(const std::uint8_t* tx, std::uint16_t tx_len,
                               std::uint8_t* rx, std::uint16_t rx_max,
                               bool /*unused_cid*/,
                               std::uint16_t /*unused_timeout*/) {
  if ((tx == NERO_NFC_NULL) || (rx == NERO_NFC_NULL) || (tx_len < 1u)) {
    return -1;
  }
  const std::span<const std::uint8_t> kTx(tx, tx_len);
  const auto kCommand =
      static_cast<std::uint8_t>(g_webauthn_step / kWebAuthnStepsPerCommand);
  const auto kExchangeStep =
      static_cast<std::uint8_t>(g_webauthn_step % kWebAuthnStepsPerCommand);
  std::vector<std::uint8_t>& observed =
      (kCommand == 0u) ? g_first_relayed_apdu : g_second_relayed_apdu;
  const auto kStartBlock = kCommand;

  if (kExchangeStep < kWebAuthnTxFragmentSteps) {
    const auto kExpectedBlock = static_cast<std::uint8_t>(
        (kStartBlock + kExchangeStep) & ISO_DEP_BLOCK_NUM_MASK);
    const bool kFinalFragment =
        kExchangeStep ==
        static_cast<std::uint8_t>(kWebAuthnTxFragmentSteps - 1u);
    const auto kExpectedInfLen =
        kFinalFragment ? kWebAuthnLastFragmentLen : kWebAuthnFragmentLen;
    EXPECT_EQ(kTx[0] & ISO_DEP_BLOCK_NUM_MASK, kExpectedBlock);
    EXPECT_EQ((kTx[0] & ISO_DEP_PCB_CHAIN_BIT) != 0u, !kFinalFragment);
    EXPECT_EQ(tx_len, static_cast<std::uint16_t>(kExpectedInfLen + 1u));
    if (kTx.size() > 1u) {
      observed.insert(observed.end(), std::next(kTx.begin()), kTx.end());
    }
    g_webauthn_step++;
    if (!kFinalFragment) {
      if (!nero_nfc_store_u8(rx, rx_max, 0u,
                             static_cast<std::uint8_t>(
                                 ISO_DEP_PCB_R_BLOCK_BASE | kExpectedBlock))) {
        return -1;
      }
      return 1;
    }
    const auto kFrame = ChainedResponseFrame(kExpectedBlock, kCommand);
    if (!CopyScriptResponse(rx, rx_max, kFrame)) {
      return -1;
    }
    return static_cast<int>(kFrame.size());
  }

  const auto kResponseFinalBlock = kStartBlock;
  EXPECT_EQ(tx_len, 1u);
  EXPECT_EQ(kTx[0], static_cast<std::uint8_t>(ISO_DEP_PCB_R_BLOCK_BASE |
                                              kResponseFinalBlock));
  if (kCommand == 0u) {
    const auto kFrame = FinalResponseFrame<kFirstAssertionInfLen>(
        kResponseFinalBlock, kCommand);
    if (!CopyScriptResponse(rx, rx_max, kFrame)) {
      return -1;
    }
    g_webauthn_step++;
    return static_cast<int>(kFrame.size());
  }
  const auto kFrame =
      FinalResponseFrame<kSecondAssertionInfLen>(kResponseFinalBlock, kCommand);
  if (!CopyScriptResponse(rx, rx_max, kFrame)) {
    return -1;
  }
  g_webauthn_step++;
  return static_cast<int>(kFrame.size());
}

int WrongBlockResponseScript(const std::uint8_t* /*unused_tx*/,
                             std::uint16_t /*unused_tx_len*/, std::uint8_t* rx,
                             std::uint16_t rx_max, bool /*unused_cid*/,
                             std::uint16_t /*unused_timeout*/) {
  g_simple_script_calls++;
  const std::array<std::uint8_t, kTestLit3> kWrongBlock = {
      kTestLit0x03u, static_cast<std::uint8_t>(NFC_ISO7816_SW1_SUCCESS),
      static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS)};
  if (!nero_nfc_copy_bytes(rx, rx_max, 0u, kWrongBlock.data(),
                           kWrongBlock.size())) {
    return -1;
  }
  return static_cast<int>(kWrongBlock.size());
}

int TruncatedResponseScript(const std::uint8_t* /*unused_tx*/,
                            std::uint16_t /*unused_tx_len*/, std::uint8_t* rx,
                            std::uint16_t rx_max, bool /*unused_cid*/,
                            std::uint16_t /*unused_timeout*/) {
  g_simple_script_calls++;
  const std::array<std::uint8_t, kTestLit2> kTruncated = {kTestLit0x02u,
                                                          kTestLit0xAAu};
  if (!nero_nfc_copy_bytes(rx, rx_max, 0u, kTruncated.data(),
                           kTruncated.size())) {
    return -1;
  }
  return static_cast<int>(kTruncated.size());
}

int WtxThenSuccessScript(const std::uint8_t* tx, std::uint16_t tx_len,
                         std::uint8_t* rx, std::uint16_t rx_max,
                         bool /*unused_cid*/,
                         std::uint16_t /*unused_timeout*/) {
  if ((tx == NERO_NFC_NULL) || (rx == NERO_NFC_NULL) || (tx_len < 1u)) {
    return -1;
  }
  const std::span<const std::uint8_t> kTx(tx, tx_len);
  if (g_simple_script_calls == 0u) {
    EXPECT_EQ(kTx[0] & ISO_DEP_BLOCK_NUM_MASK, 0u);
    const std::array<std::uint8_t, kTestLit2> kWtx = {kTestLit0xF2u,
                                                      kTestLit0x01u};
    if (!nero_nfc_copy_bytes(rx, rx_max, 0u, kWtx.data(), kWtx.size())) {
      return -1;
    }
    g_simple_script_calls++;
    return static_cast<int>(kWtx.size());
  }
  EXPECT_EQ(tx_len, kTestLit2u);
  EXPECT_EQ(kTx[0], kTestLit0xF2u);
  EXPECT_EQ(kTx[1], kTestLit0x01u);
  const std::array<std::uint8_t, kTestLit3> kSuccess = {
      kTestLit0x02u, static_cast<std::uint8_t>(NFC_ISO7816_SW1_SUCCESS),
      static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS)};
  if (!nero_nfc_copy_bytes(rx, rx_max, 0u, kSuccess.data(), kSuccess.size())) {
    return -1;
  }
  g_simple_script_calls++;
  return static_cast<int>(kSuccess.size());
}

int RecoveryRetransmitScript(const std::uint8_t* tx, std::uint16_t tx_len,
                             std::uint8_t* rx, std::uint16_t rx_max,
                             bool /*unused_cid*/,
                             std::uint16_t /*unused_timeout*/) {
  if ((tx == NERO_NFC_NULL) || (rx == NERO_NFC_NULL) || (tx_len < 1u)) {
    return -1;
  }
  AppendObservedFrame(tx, tx_len);
  const auto kCall = g_simple_script_calls++;
  if (kCall == 0u) {
    const std::array<std::uint8_t, 1> kNak = {kTestLit0xB2u};
    return CopyScriptResponse(rx, rx_max, kNak) ? 1 : -1;
  }
  if (kCall == 1u) {
    const std::array<std::uint8_t, 1> kMismatchedAck = {kTestLit0xA3u};
    return CopyScriptResponse(rx, rx_max, kMismatchedAck) ? 1 : -1;
  }
  if (kCall == kTestLit2u) {
    const std::array<std::uint8_t, 1> kAck = {kTestLit0xA2u};
    return CopyScriptResponse(rx, rx_max, kAck) ? 1 : -1;
  }
  const std::array<std::uint8_t, kTestLit3> kSuccess = {
      kTestLit0x03u, static_cast<std::uint8_t>(NFC_ISO7816_SW1_SUCCESS),
      static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS)};
  return CopyScriptResponse(rx, rx_max, kSuccess)
             ? static_cast<int>(kSuccess.size())
             : -1;
}

int NadChainedResponseScript(const std::uint8_t* tx, std::uint16_t tx_len,
                             std::uint8_t* rx, std::uint16_t rx_max,
                             bool /*unused_cid*/,
                             std::uint16_t /*unused_timeout*/) {
  if ((tx == NERO_NFC_NULL) || (rx == NERO_NFC_NULL) || (tx_len < 1u)) {
    return -1;
  }
  AppendObservedFrame(tx, tx_len);
  if (g_simple_script_calls++ == 0u) {
    std::array<std::uint8_t, kNadChainedFrameLen> frame = {
        kTestLit0x16u, kTestLit0x7Fu, kTestLit0xA5u, 0u, 0u};
    StoreCrcASuffix(frame.data(), frame.size(), kTestLit3u);
    return CopyScriptResponse(rx, rx_max, frame)
               ? static_cast<int>(frame.size())
               : -1;
  }
  const std::array<std::uint8_t, kTestLit3> kSuccess = {
      kTestLit0x03u, static_cast<std::uint8_t>(NFC_ISO7816_SW1_SUCCESS),
      static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS)};
  return CopyScriptResponse(rx, rx_max, kSuccess)
             ? static_cast<int>(kSuccess.size())
             : -1;
}

int SmallFscFragmentScript(const std::uint8_t* tx, std::uint16_t tx_len,
                           std::uint8_t* rx, std::uint16_t rx_max,
                           bool /*unused_cid*/,
                           std::uint16_t /*unused_timeout*/) {
  if ((tx == NERO_NFC_NULL) || (rx == NERO_NFC_NULL) || (tx_len < 1u)) {
    return -1;
  }
  AppendObservedFrame(tx, tx_len);
  const std::span<const std::uint8_t> kTx(tx, tx_len);
  const bool kChained = (kTx[0] & ISO_DEP_PCB_CHAIN_BIT) != 0u;
  const auto kBlock =
      static_cast<std::uint8_t>(kTx[0] & ISO_DEP_BLOCK_NUM_MASK);
  g_simple_script_calls++;
  if (kChained) {
    const std::array<std::uint8_t, 1> kAck = {
        static_cast<std::uint8_t>(ISO_DEP_PCB_R_BLOCK_BASE | kBlock)};
    return CopyScriptResponse(rx, rx_max, kAck) ? 1 : -1;
  }
  const std::array<std::uint8_t, kTestLit3> kSuccess = {
      static_cast<std::uint8_t>(ISO_DEP_PCB_I_BLOCK_BASE | kBlock),
      static_cast<std::uint8_t>(NFC_ISO7816_SW1_SUCCESS),
      static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS)};
  return CopyScriptResponse(rx, rx_max, kSuccess)
             ? static_cast<int>(kSuccess.size())
             : -1;
}

int ChainedResponseScript(const std::uint8_t* tx, std::uint16_t tx_len,
                          std::uint8_t* rx, std::uint16_t rx_max,
                          bool /*unused_cid*/,
                          std::uint16_t /*unused_timeout*/) {
  if ((tx == NERO_NFC_NULL) || (rx == NERO_NFC_NULL)) {
    return -1;
  }
  const std::span<const std::uint8_t> kTx(tx, tx_len);
  if (g_chained_response_step == 0u) {
    EXPECT_GE(tx_len, 1u);
    EXPECT_EQ(kTx[0] & ISO_DEP_BLOCK_NUM_MASK, 0u);
    if (rx_max < kTestLit4u) {
      return -1;
    }
    if (!nero_nfc_store_u8(rx, rx_max, 0u, kTestLit0x12u) ||
        !nero_nfc_store_u8(rx, rx_max, 1u, kTestLit0xA5u)) {
      return -1;
    }
    StoreCrcASuffix(rx, rx_max, kTestLit2u);
    g_chained_response_step++;
    return kTestLit4;
  }
  if (g_chained_response_step == 1u) {
    EXPECT_GE(tx_len, 1u);
    EXPECT_EQ(kTx[0], kTestLit0xA3u);
    if (rx_max < kTestLit3u) {
      return -1;
    }
    if (!nero_nfc_store_u8(rx, rx_max, 0u, kTestLit0x03u) ||
        !nero_nfc_store_u8(
            rx, rx_max, 1u,
            static_cast<std::uint8_t>(NFC_ISO7816_SW1_SUCCESS)) ||
        !nero_nfc_store_u8(
            rx, rx_max, kTestLit2u,
            static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS))) {
      return -1;
    }
    g_chained_response_step++;
    return kTestLit3;
  }
  if (g_chained_response_step == kTestLit2u) {
    EXPECT_GE(tx_len, 1u);
    EXPECT_EQ(kTx[0] & ISO_DEP_BLOCK_NUM_MASK, 0u);
    if (rx_max < kTestLit3u) {
      return -1;
    }
    if (!nero_nfc_store_u8(rx, rx_max, 0u, kTestLit0x02u) ||
        !nero_nfc_store_u8(
            rx, rx_max, 1u,
            static_cast<std::uint8_t>(NFC_ISO7816_SW1_SUCCESS)) ||
        !nero_nfc_store_u8(
            rx, rx_max, kTestLit2u,
            static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS))) {
      return -1;
    }
    g_chained_response_step++;
    return kTestLit3;
  }
  return -1;
}
}  // namespace

class ReaderSecurityKeyTransceiveTest : public NeroNfcReaderAppFixture {
 protected:
  void SetUp() override {
    BindReaderApp();
    reader_security_key_utest_reset_iso_dep();
    g_chained_response_step = 0u;
    g_webauthn_step = 0u;
    g_simple_script_calls = 0u;
    g_first_relayed_apdu.clear();
    g_second_relayed_apdu.clear();
    g_observed_frames.clear();
  }
};

TEST_F(ReaderSecurityKeyTransceiveTest, SendApduRejectsNullBuffers) {
  std::array<std::uint8_t, kTestLit8> rsp{};

  EXPECT_LT(reader_security_key_send_apdu_timeout_ex(
                NERO_NFC_NULL, 1u, rsp.data(),
                static_cast<uint16_t>(rsp.size()), kTestLit100u, false),
            0);
  EXPECT_LT(reader_security_key_send_apdu_timeout_ex(
                rsp.data(), 1u, NERO_NFC_NULL, 0u, kTestLit100u, false),
            0);
}

TEST_F(ReaderSecurityKeyTransceiveTest,
       SendApduReturnsShortWhenIsoDepHookFails) {
  reader_security_key_utest_set_iso_dep_transceive(
      +[](const std::uint8_t* /*unused_tx*/, std::uint16_t /*unused_tx_len*/,
          std::uint8_t* /*unused_rx*/, std::uint16_t /*unused_rx_max*/,
          bool /*unused_cid*/,
          std::uint16_t /*unused_timeout*/) -> int { return -1; });

  std::array<std::uint8_t, kTestLit5> apdu{0x00u, kTestLit0xA4u, kTestLit0x04u,
                                           0x00u, 0x00u};
  std::array<std::uint8_t, kTestLit16> rsp{};

  EXPECT_LT(reader_security_key_send_apdu_timeout_ex(
                apdu.data(), static_cast<uint16_t>(apdu.size()), rsp.data(),
                static_cast<uint16_t>(rsp.size()), kTestLit100u, false),
            kTestLit2);
}

TEST_F(ReaderSecurityKeyTransceiveTest, SendApduDoesNotWritePastResponseCap) {
  reader_security_key_utest_set_iso_dep_transceive(
      +[](const std::uint8_t* /*unused_tx*/, std::uint16_t tx_len,
          std::uint8_t* rx, std::uint16_t rx_max, bool /*unused_cid*/,
          std::uint16_t /*unused_timeout*/) -> int {
        /* Minimal ISO-DEP I-block PCB + INF(90 00) + CRC placeholder. */
        const std::uint8_t kFrame[kTestLit6] = {
            kTestLit0x02u,
            static_cast<std::uint8_t>(NFC_ISO7816_SW1_SUCCESS),
            static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS),
            0x00u,
            0x00u,
            0x00u};
        if (!nero_nfc_copy_bytes(rx, rx_max, 0u, &kFrame[0], sizeof(kFrame))) {
          return -1;
        }
        (void)tx_len;
        return kTestLit6;
      });

  std::array<std::uint8_t, kTestLit5> apdu{0x00u, kTestLit0xA4u, kTestLit0x04u,
                                           0x00u, 0x00u};
  std::array<std::uint8_t, kTestLit4> rsp{};
  rsp.fill(kTestLit0xAAu);

  const int kTotal = reader_security_key_send_apdu_timeout_ex(
      apdu.data(), static_cast<uint16_t>(apdu.size()), rsp.data(),
      static_cast<uint16_t>(rsp.size()), kTestLit100u, false);
  EXPECT_LT(kTotal, kTestLit2);
  EXPECT_EQ(rsp[kTestLit3], kTestLit0xAAu);
}

TEST_F(ReaderSecurityKeyTransceiveTest,
       ChainedResponsePersistsEveryAcceptedIBlockToggle) {
  reader_security_key_utest_set_iso_dep_transceive(&ChainedResponseScript);
  G_BLOCK_NUM = 0u;

  const std::array<std::uint8_t, 1> kFirstApdu = {kTestLit0x01u};
  std::array<std::uint8_t, kTestLit8> rsp{};
  const int kFirstTotal = reader_security_key_send_apdu_timeout_ex(
      kFirstApdu.data(), static_cast<std::uint16_t>(kFirstApdu.size()),
      rsp.data(), static_cast<std::uint16_t>(rsp.size()), kTestLit100u, false);

  ASSERT_EQ(kFirstTotal, kTestLit3);
  EXPECT_EQ(rsp[0], kTestLit0xA5u);
  EXPECT_EQ(rsp[1], static_cast<std::uint8_t>(NFC_ISO7816_SW1_SUCCESS));
  EXPECT_EQ(rsp[kTestLit2], static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS));
  EXPECT_EQ(G_BLOCK_NUM, 0u);

  const std::array<std::uint8_t, 1> kSecondApdu = {kTestLit0x02u};
  const int kSecondTotal = reader_security_key_send_apdu_timeout_ex(
      kSecondApdu.data(), static_cast<std::uint16_t>(kSecondApdu.size()),
      rsp.data(), static_cast<std::uint16_t>(rsp.size()), kTestLit100u, false);

  EXPECT_EQ(kSecondTotal, kTestLit2);
  EXPECT_EQ(G_BLOCK_NUM, 1u);
  EXPECT_EQ(g_chained_response_step, kTestLit3u);
}

TEST_F(ReaderSecurityKeyTransceiveTest,
       ConsecutiveWebAuthnAssertionsPreserveBytesAndBlockState) {
  reader_security_key_utest_set_iso_dep_transceive(&WebAuthnTwoAssertionScript);
  G_BLOCK_NUM = 0u;
  G_ISO_DEP_PIC_FRAME_MAX = NFC_ISO14443_FSC_MAX;

  std::array<std::uint8_t, kWebAuthnApduLen> first{};
  std::array<std::uint8_t, kWebAuthnApduLen> second{};
  for (std::size_t i = 0u; i < first.size(); ++i) {
    first.at(i) = static_cast<std::uint8_t>(i & kTestLit0xFFu);
    second.at(i) =
        static_cast<std::uint8_t>((i + kTestLit0x80u) & kTestLit0xFFu);
  }
  std::array<std::uint8_t, kRspScratchCap> rsp{};

  const int kFirstTotal = reader_security_key_send_apdu_timeout_ex(
      first.data(), static_cast<std::uint16_t>(first.size()), rsp.data(),
      static_cast<std::uint16_t>(rsp.size()), kTestLit1000u, false);
  ASSERT_EQ(kFirstTotal, kTestLit205);
  EXPECT_EQ(g_first_relayed_apdu,
            std::vector<std::uint8_t>(first.begin(), first.end()));
  EXPECT_EQ(G_BLOCK_NUM, 1u);

  const int kSecondTotal = reader_security_key_send_apdu_timeout_ex(
      second.data(), static_cast<std::uint16_t>(second.size()), rsp.data(),
      static_cast<std::uint16_t>(rsp.size()), kTestLit1000u, false);
  ASSERT_EQ(kSecondTotal, kTestLit206);
  EXPECT_EQ(g_second_relayed_apdu,
            std::vector<std::uint8_t>(second.begin(), second.end()));
  EXPECT_EQ(G_BLOCK_NUM, 0u);
  EXPECT_EQ(g_webauthn_step, kTestLit10u);
}

TEST_F(ReaderSecurityKeyTransceiveTest,
       WrongResponseBlockIsRejectedWithoutAdvancingState) {
  reader_security_key_utest_set_iso_dep_transceive(&WrongBlockResponseScript);
  G_BLOCK_NUM = 0u;
  const std::array<std::uint8_t, 1> kApdu = {kTestLit0x80u};
  std::array<std::uint8_t, kTestLit8> rsp{};
  rsp.fill(kTestLit0xCCu);

  const int kTotal = reader_security_key_send_apdu_timeout_ex(
      kApdu.data(), static_cast<std::uint16_t>(kApdu.size()), rsp.data(),
      static_cast<std::uint16_t>(rsp.size()), kTestLit100u, false);

  EXPECT_LT(kTotal, 0);
  EXPECT_EQ(G_BLOCK_NUM, 0u);
  EXPECT_EQ(g_simple_script_calls, 1u);
  EXPECT_EQ(rsp[0], kTestLit0xCCu);
}

TEST_F(ReaderSecurityKeyTransceiveTest,
       TruncatedResponseNeverReplaysStatefulCommand) {
  reader_security_key_utest_set_iso_dep_transceive(&TruncatedResponseScript);
  G_BLOCK_NUM = 0u;
  const std::array<std::uint8_t, kTestLit4> kApdu = {
      kTestLit0x80u, kTestLit0x10u, 0x00u, 0x00u};
  std::array<std::uint8_t, kTestLit8> rsp{};

  const int kTotal = reader_security_key_send_apdu_timeout_ex(
      kApdu.data(), static_cast<std::uint16_t>(kApdu.size()), rsp.data(),
      static_cast<std::uint16_t>(rsp.size()), kTestLit100u, false);

  EXPECT_LT(kTotal, 0);
  EXPECT_EQ(g_simple_script_calls, 1u);
  EXPECT_EQ(G_BLOCK_NUM, 0u);
}

TEST_F(ReaderSecurityKeyTransceiveTest, WtxExchangeDoesNotAdvanceIBlockNumber) {
  reader_security_key_utest_set_iso_dep_transceive(&WtxThenSuccessScript);
  G_BLOCK_NUM = 0u;
  const std::array<std::uint8_t, 1> kApdu = {kTestLit0x04u};
  std::array<std::uint8_t, kTestLit8> rsp{};

  const int kTotal = reader_security_key_send_apdu_timeout_ex(
      kApdu.data(), static_cast<std::uint16_t>(kApdu.size()), rsp.data(),
      static_cast<std::uint16_t>(rsp.size()), kTestLit100u, false);

  ASSERT_EQ(kTotal, kTestLit2);
  EXPECT_EQ(rsp[0], static_cast<std::uint8_t>(NFC_ISO7816_SW1_SUCCESS));
  EXPECT_EQ(rsp[1], static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS));
  EXPECT_EQ(g_simple_script_calls, kTestLit2u);
  EXPECT_EQ(G_BLOCK_NUM, 1u);
}

TEST_F(ReaderSecurityKeyTransceiveTest,
       NakAndMismatchedAckRetransmitExactlyTheLastIBlock) {
  reader_security_key_utest_set_iso_dep_transceive(&RecoveryRetransmitScript);
  G_BLOCK_NUM = 0u;
  G_ISO_DEP_PIC_FRAME_MAX = NFC_ISO14443_FSC_MAX;
  std::array<std::uint8_t, kRecoveryApduLen> apdu{};
  for (std::size_t i = 0u; i < apdu.size(); ++i) {
    apdu.at(i) = static_cast<std::uint8_t>(i);
  }
  std::array<std::uint8_t, kTestLit8> rsp{};

  const int kTotal = reader_security_key_send_apdu_timeout_ex(
      apdu.data(), static_cast<std::uint16_t>(apdu.size()), rsp.data(),
      static_cast<std::uint16_t>(rsp.size()), kTestLit100u, false);

  ASSERT_EQ(kTotal, kTestLit2);
  ASSERT_EQ(g_observed_frames.size(), kTestLit4u);
  EXPECT_EQ(g_observed_frames[0], g_observed_frames[1]);
  EXPECT_EQ(g_observed_frames[1], g_observed_frames[kTestLit2]);
  EXPECT_EQ(g_observed_frames[0].size(), kRecoveryApduLen);
  ASSERT_EQ(g_observed_frames[kTestLit3].size(), kTestLit2u);
  EXPECT_EQ(g_observed_frames[kTestLit3][0] & ISO_DEP_BLOCK_NUM_MASK, 1u);
  EXPECT_EQ(g_observed_frames[kTestLit3][1], apdu.back());
  EXPECT_EQ(G_BLOCK_NUM, 0u);
}

TEST_F(ReaderSecurityKeyTransceiveTest,
       AckForNadChainedResponseContainsOnlyRBlockAndNoNad) {
  reader_security_key_utest_set_iso_dep_transceive(&NadChainedResponseScript);
  G_BLOCK_NUM = 0u;
  G_ISO_DEP_HAVE_TC = true;
  G_ISO_DEP_TC_BYTE = kTestLit0x01u;
  G_ISO_DEP_PCB_HAS_CID = false;
  const std::array<std::uint8_t, 1> kApdu = {kTestLit0x80u};
  std::array<std::uint8_t, kTestLit8> rsp{};

  const int kTotal = reader_security_key_send_apdu_timeout_ex(
      kApdu.data(), static_cast<std::uint16_t>(kApdu.size()), rsp.data(),
      static_cast<std::uint16_t>(rsp.size()), kTestLit100u, false);

  ASSERT_EQ(kTotal, kTestLit3);
  EXPECT_EQ(rsp[0], kTestLit0xA5u);
  ASSERT_EQ(g_observed_frames.size(), kTestLit2u);
  ASSERT_EQ(g_observed_frames[1].size(), 1u);
  EXPECT_EQ(g_observed_frames[1][0], kTestLit0xA3u);
  EXPECT_EQ(G_BLOCK_NUM, 0u);
}

TEST_F(ReaderSecurityKeyTransceiveTest,
       SmallAdvertisedFscLimitsEveryTransmittedFrame) {
  reader_security_key_utest_set_iso_dep_transceive(&SmallFscFragmentScript);
  G_BLOCK_NUM = 0u;
  G_ISO_DEP_PIC_FRAME_MAX = kSmallFscFrameMax;
  std::array<std::uint8_t, kSmallFscApduLen> apdu{};
  for (std::size_t i = 0u; i < apdu.size(); ++i) {
    apdu.at(i) = static_cast<std::uint8_t>(kTestLit0x40u + i);
  }
  std::array<std::uint8_t, kTestLit8> rsp{};

  const int kTotal = reader_security_key_send_apdu_timeout_ex(
      apdu.data(), static_cast<std::uint16_t>(apdu.size()), rsp.data(),
      static_cast<std::uint16_t>(rsp.size()), kTestLit100u, false);

  ASSERT_EQ(kTotal, kTestLit2);
  ASSERT_EQ(g_observed_frames.size(), kTestLit3u);
  std::vector<std::uint8_t> relayed;
  for (const auto& frame : g_observed_frames) {
    /* FSC includes the two-byte RF CRC which the frontend appends. */
    EXPECT_LE(frame.size() + ISO_DEP_CRC_LEN, kSmallFscFrameMax);
    if (frame.size() > 1u) {
      relayed.insert(relayed.end(), std::next(frame.begin()), frame.end());
    }
  }
  EXPECT_EQ(relayed, std::vector<std::uint8_t>(apdu.begin(), apdu.end()));
  EXPECT_EQ(G_BLOCK_NUM, 1u);
}
