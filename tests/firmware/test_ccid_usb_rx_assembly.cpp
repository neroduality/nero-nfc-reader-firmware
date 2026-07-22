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

#include "nero_nfc_null.h"
#include "usb/ccid_usb_rx_assembly.h"
#include "usb/ccid_usb_tx.h"

#include <array>
#include <gtest/gtest.h>

namespace {
enum {
  kTestLit0x31u = 0x31u,
  kTestLit0x32u = 0x32u,
  kTestLit0x33u = 0x33u,
  kTestLit0x34u = 0x34u,
  kTestLit0x35u = 0x35u,
  kTestLit12u = 12u,
  kTestLit3u = 3u,
  kTestLit64u = 64u,
  kTestLit7u = 7u,
};

constexpr uint16_t kEndpointSize = kTestLit64u;

std::array<uint8_t, kEndpointSize> HeaderPacket(uint32_t payload_len,
                                                uint8_t seq) {
  std::array<uint8_t, kEndpointSize> packet{};
  packet[0] = NFC_CCID_MSG_PC_TO_RDR_XFR;
  nfc_ccid_u32_store_le(&packet[1], payload_len);
  packet[NFC_CCID_BULK_SEQ_OFFSET] = seq;
  return packet;
}
}  // namespace

TEST(CcidUsbRxAssembly, CompletesValidSplitFrameAtDeclaredLength) {
  ccid_usb_rx_assembly_t state{};
  auto first = HeaderPacket(kEndpointSize, kTestLit0x31u);
  std::array<uint8_t, NFC_CCID_BULK_HEADER_LEN> final_packet{};

  EXPECT_EQ(ccid_usb_rx_assembly_feed(&state, first.data(), first.size(),
                                      kEndpointSize),
            CCID_USB_RX_MORE);
  EXPECT_EQ(ccid_usb_rx_assembly_feed(&state, final_packet.data(),
                                      final_packet.size(), kEndpointSize),
            CCID_USB_RX_READY);
  EXPECT_EQ(state.len, NFC_CCID_BULK_HEADER_LEN + kEndpointSize);
}

TEST(CcidUsbRxAssembly, DrainsOversizedFrameThroughShortPacket) {
  ccid_usb_rx_assembly_t state{};
  auto first = HeaderPacket(NFC_CCID_MAX_XFR_PAYLOAD + 1u, kTestLit0x32u);
  std::array<uint8_t, kEndpointSize> continuation{};
  std::array<uint8_t, kTestLit3u> final_packet{};

  EXPECT_EQ(ccid_usb_rx_assembly_feed(&state, first.data(), first.size(),
                                      kEndpointSize),
            CCID_USB_RX_MORE);
  EXPECT_TRUE(state.discarding_malformed);
  EXPECT_EQ(ccid_usb_rx_assembly_feed(&state, continuation.data(),
                                      continuation.size(), kEndpointSize),
            CCID_USB_RX_MORE);
  EXPECT_EQ(ccid_usb_rx_assembly_feed(&state, final_packet.data(),
                                      final_packet.size(), kEndpointSize),
            CCID_USB_RX_READY);
  EXPECT_EQ(state.data[NFC_CCID_BULK_SEQ_OFFSET], kTestLit0x32u);
  EXPECT_EQ(state.len, kEndpointSize);

  ccid_usb_rx_assembly_reset(&state);
  auto next = HeaderPacket(0u, kTestLit0x34u);
  EXPECT_EQ(ccid_usb_rx_assembly_feed(&state, next.data(),
                                      NFC_CCID_BULK_HEADER_LEN, kEndpointSize),
            CCID_USB_RX_READY);
  EXPECT_EQ(state.data[NFC_CCID_BULK_SEQ_OFFSET], kTestLit0x34u);
}

TEST(CcidUsbRxAssembly, ZeroLengthPacketTerminatesMalformedFrame) {
  ccid_usb_rx_assembly_t state{};
  auto packet = HeaderPacket(0u, kTestLit0x33u);

  EXPECT_EQ(ccid_usb_rx_assembly_feed(&state, packet.data(), packet.size(),
                                      kEndpointSize),
            CCID_USB_RX_MORE);
  EXPECT_EQ(ccid_usb_rx_assembly_feed(&state, NERO_NFC_NULL, 0u, kEndpointSize),
            CCID_USB_RX_READY);
  EXPECT_EQ(state.data[NFC_CCID_BULK_SEQ_OFFSET], kTestLit0x33u);
}

TEST(CcidUsbRxAssembly, DropsHeaderIncompleteShortPacket) {
  ccid_usb_rx_assembly_t state{};
  std::array<uint8_t, NFC_CCID_BULK_HEADER_LEN - 1u> packet{};

  EXPECT_EQ(ccid_usb_rx_assembly_feed(&state, packet.data(), packet.size(),
                                      kEndpointSize),
            CCID_USB_RX_DROPPED);
  EXPECT_EQ(state.len, 0u);
}

TEST(CcidUsbRxAssembly, RejectsInvalidFeedArgumentsAndResetsState) {
  ccid_usb_rx_assembly_t state{};
  state.len = kTestLit7u;
  state.expected = kTestLit12u;
  state.discarding_malformed = true;
  std::array<uint8_t, kEndpointSize + 1u> oversized{};
  std::array<uint8_t, 1u> byte{};

  ccid_usb_rx_assembly_reset(NERO_NFC_NULL);
  EXPECT_EQ(ccid_usb_rx_assembly_feed(NERO_NFC_NULL, byte.data(), byte.size(),
                                      kEndpointSize),
            CCID_USB_RX_DROPPED);
  EXPECT_EQ(ccid_usb_rx_assembly_feed(&state, byte.data(), byte.size(), 0u),
            CCID_USB_RX_DROPPED);
  EXPECT_EQ(state.len, 0u);
  EXPECT_EQ(state.expected, 0u);
  EXPECT_FALSE(state.discarding_malformed);

  state.len = 1u;
  EXPECT_EQ(ccid_usb_rx_assembly_feed(&state, oversized.data(),
                                      oversized.size(), kEndpointSize),
            CCID_USB_RX_DROPPED);
  EXPECT_EQ(state.len, 0u);

  state.len = 1u;
  EXPECT_EQ(ccid_usb_rx_assembly_feed(&state, NERO_NFC_NULL, 1u, kEndpointSize),
            CCID_USB_RX_DROPPED);
  EXPECT_EQ(state.len, 0u);
}

TEST(CcidUsbRxAssembly, DrainsBytesBeyondDeclaredFrameBoundary) {
  ccid_usb_rx_assembly_t state{};
  auto packet = HeaderPacket(0u, kTestLit0x35u);
  std::array<uint8_t, 1u> terminator{};

  EXPECT_EQ(ccid_usb_rx_assembly_feed(&state, packet.data(), packet.size(),
                                      kEndpointSize),
            CCID_USB_RX_MORE);
  EXPECT_TRUE(state.discarding_malformed);
  EXPECT_EQ(state.len, kEndpointSize);
  EXPECT_EQ(ccid_usb_rx_assembly_feed(&state, terminator.data(),
                                      terminator.size(), kEndpointSize),
            CCID_USB_RX_READY);
  EXPECT_EQ(state.data[NFC_CCID_BULK_SEQ_OFFSET], kTestLit0x35u);
}

TEST(CcidUsbTx, RequiresZlpOnlyForNonemptyExactPacketMultiple) {
  EXPECT_TRUE(ccid_usb_bulk_in_needs_zlp(kEndpointSize, kEndpointSize));
  EXPECT_TRUE(ccid_usb_bulk_in_needs_zlp(2u * kEndpointSize, kEndpointSize));
  EXPECT_FALSE(ccid_usb_bulk_in_needs_zlp(kEndpointSize + 1u, kEndpointSize));
  EXPECT_FALSE(ccid_usb_bulk_in_needs_zlp(0u, kEndpointSize));
  EXPECT_FALSE(ccid_usb_bulk_in_needs_zlp(kEndpointSize, 0u));
}
