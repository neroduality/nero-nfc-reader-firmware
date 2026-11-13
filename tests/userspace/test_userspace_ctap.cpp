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

#include "nero_nfc_cbor.hpp"
#include "nero_nfc_ctap.hpp"
#include "nero_nfc_ctap_pin.hpp"
#include "nero_nfc_fido_token.hpp"
#include "nero_nfc_hex.hpp"
#include "nero_nfc_null.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <openssl/evp.h>

namespace {

using Bytes = std::vector<std::uint8_t>;
using nero_nfc::cbor::Value;
namespace ctap = nero_nfc::ctap;

/* [ISO7816-4] / [CTAP2.3] section 11.3 -- APDU framing the fake parses. */
constexpr std::size_t kApduHeaderLen = 4u;
constexpr std::uint8_t kClaIso = 0x00u;
constexpr std::uint8_t kClaCtap = 0x80u;
constexpr std::uint8_t kInsSelect = 0xA4u;
constexpr std::uint8_t kInsGetResponse = 0xC0u;
constexpr std::uint8_t kInsCtapMsg = 0x10u;
constexpr std::uint8_t kInsCtapGetResponse = 0x11u;
constexpr std::size_t kShortLcOffset = 4u;
constexpr std::size_t kShortDataOffset = 5u;
constexpr std::size_t kExtLcHighOffset = 5u;
constexpr std::size_t kExtLcLowOffset = 6u;
constexpr std::size_t kExtDataOffset = 7u;
constexpr std::size_t kMinCtapApduLen = 6u;
constexpr unsigned kByteBits = 8u;
constexpr std::uint16_t kSwSuccess = 0x9000u;
constexpr std::uint16_t kSwFileNotFound = 0x6A82u;
constexpr std::uint8_t kSw1Success = 0x90u;
constexpr std::uint8_t kSw1MoreData = 0x61u;
constexpr std::uint8_t kSw1CtapStatusUpdate = 0x91u;
constexpr std::uint8_t kSw1InsNotSupported = 0x6Du;
constexpr std::size_t kSw2MaxRemaining = 0xFFu;
constexpr std::uint8_t kCtapStatusProcessing = 0x01u;

/* [CTAP2.3] sections 6 and 8.2 -- commands and errors the fake emits. */
constexpr std::uint8_t kCmdGetInfo = 0x04u;
constexpr std::uint8_t kCmdClientPin = 0x06u;
constexpr std::uint8_t kCmdReset = 0x07u;
constexpr std::uint8_t kErrInvalidParameter = 0x02u;
constexpr std::uint8_t kErrInvalidCbor = 0x12u;
constexpr std::uint8_t kErrMissingParameter = 0x14u;
constexpr std::uint8_t kErrOther = 0x7Fu;
constexpr std::int64_t kInfoVersions = 0x01;
constexpr std::int64_t kInfoExtensions = 0x02;
constexpr std::int64_t kInfoAaguid = 0x03;
constexpr std::int64_t kInfoOptions = 0x04;
constexpr std::int64_t kInfoMaxMsgSize = 0x05;
constexpr std::int64_t kInfoPinProtocols = 0x06;
constexpr std::size_t kAaguidLen = 16u;
constexpr std::uint8_t kAaguidFirstByte = 0xA0u;
constexpr std::int64_t kMaxMsgSize = 1200;
constexpr std::size_t kPinHashLen = 16u;
constexpr std::uint64_t kDefaultPinRetries = 8u;

/* Test fixtures. */
constexpr std::uint8_t kStatusUnset = 0xFFu;
constexpr std::uint8_t kPinProtocolUnsupported = 3u;
constexpr std::size_t kResponseChunkLen = 16u;
constexpr std::size_t kAesBlockLen = 16u;
constexpr std::uint8_t kIvFirstByte = 0x10u;
constexpr std::uint8_t kCborArrayOfOne = 0x81u;
/* One level deeper than the decoder's nesting limit. */
constexpr std::size_t kTooDeepNesting = 13u;
constexpr std::uint64_t kMinPinLength = 4u;
/* CTAP status-update keepalives the fake sends before the reset result. */
constexpr int kResetStatusUpdates = 3;

Bytes Hex(std::string_view text) {
  Bytes out;
  EXPECT_TRUE(nero_nfc::ParseHexBytes(text, out)) << text;
  return out;
}

Bytes Range(std::uint8_t first, std::size_t count) {
  Bytes out(count);
  for (std::size_t i = 0; i < count; ++i) {
    out.at(i) = static_cast<std::uint8_t>(first + i);
  }
  return out;
}

/* Minimal CTAP2-over-NFC authenticator behind an APDU transceiver. */
class FakeAuthenticator {
 public:
  std::vector<Bytes> apdus_;
  std::size_t chunk_size_{}; /* > 0: split responses with ISO 61xx chaining */
  int reset_status_updates_{};
  std::uint8_t reset_status_{nero_nfc::ctap::kStatusSuccess};
  std::uint16_t select_sw_{kSwSuccess};
  std::vector<std::uint64_t> pin_protocols_{ctap::kPinProtocolTwo,
                                            ctap::kPinProtocolOne};
  bool pin_set_{};
  std::string pin_;
  std::uint64_t retries_{kDefaultPinRetries};
  nero_nfc::ctap::EcdhKeyPair key_;
  std::deque<std::uint8_t> pending_;
  int pending_status_updates_{};

  nero_nfc::ctap::ApduTransceiver Transceiver() {
    return [this](const Bytes& capdu, Bytes& rapdu, std::string& err) {
      return Transceive(capdu, rapdu, err);
    };
  }

 private:
  bool Transceive(const Bytes& capdu, Bytes& rapdu, std::string& err) {
    apdus_.push_back(capdu);
    err.clear();
    if (IsCommand(capdu, kClaIso, kInsGetResponse)) {
      return SendChunk(rapdu);
    }
    if (IsCommand(capdu, kClaIso, kInsSelect)) {
      if (select_sw_ != kSwSuccess) {
        rapdu = {static_cast<std::uint8_t>(select_sw_ >> kByteBits),
                 static_cast<std::uint8_t>(select_sw_)};
        return true;
      }
      return Respond(Bytes{'F', 'I', 'D', 'O', '_', '2', '_', '0'}, rapdu);
    }
    if (IsCommand(capdu, kClaCtap, kInsCtapGetResponse)) {
      if (pending_status_updates_ > 0) {
        --pending_status_updates_;
        rapdu = {kCtapStatusProcessing, kSw1CtapStatusUpdate, 0x00u};
        return true;
      }
      return Respond(Bytes{reset_status_}, rapdu);
    }
    std::uint8_t cmd = 0u;
    Bytes cbor;
    if (!ParseCtapApdu(capdu, cmd, cbor)) {
      rapdu = {kSw1InsNotSupported, 0x00u};
      return true;
    }
    switch (cmd) {
      case kCmdGetInfo:
        return RespondCtap(nero_nfc::ctap::kStatusSuccess,
                           nero_nfc::cbor::Encode(InfoValue()), rapdu);
      case kCmdReset:
        if (reset_status_ == nero_nfc::ctap::kStatusSuccess) {
          pin_set_ = false;
          pin_.clear();
        }
        if (reset_status_updates_ > 0) {
          pending_status_updates_ = reset_status_updates_ - 1;
          rapdu = {kCtapStatusProcessing, kSw1CtapStatusUpdate, 0x00u};
          return true;
        }
        return Respond(Bytes{reset_status_}, rapdu);
      case kCmdClientPin:
        return HandleClientPin(cbor, rapdu);
      default:
        return RespondCtap(nero_nfc::ctap::kErrInvalidCommand, {}, rapdu);
    }
  }

  static bool IsCommand(const Bytes& apdu, std::uint8_t cla, std::uint8_t ins) {
    return apdu.size() >= kApduHeaderLen && apdu.at(0) == cla &&
           apdu.at(1) == ins;
  }

  static bool ParseCtapApdu(const Bytes& apdu, std::uint8_t& cmd, Bytes& cbor) {
    if (apdu.size() < kMinCtapApduLen ||
        !IsCommand(apdu, kClaCtap, kInsCtapMsg)) {
      return false;
    }
    std::size_t off = kShortDataOffset;
    std::size_t len = apdu.at(kShortLcOffset);
    if (len == 0u) {
      off = kExtDataOffset;
      len = (static_cast<std::size_t>(apdu.at(kExtLcHighOffset)) << kByteBits) |
            apdu.at(kExtLcLowOffset);
    }
    if (len == 0u || off + len > apdu.size()) {
      return false;
    }
    cmd = apdu.at(off);
    cbor.assign(apdu.begin() + static_cast<std::ptrdiff_t>(off + 1u),
                apdu.begin() + static_cast<std::ptrdiff_t>(off + len));
    return true;
  }

  [[nodiscard]] Value InfoValue() const {
    std::vector<Value> protocols;
    protocols.reserve(pin_protocols_.size());
    for (const std::uint64_t p : pin_protocols_) {
      protocols.push_back(Value::Int(static_cast<std::int64_t>(p)));
    }
    return Value::Map({
        {.key_ = Value::Int(kInfoVersions),
         .value_ = Value::Array({Value::Text("U2F_V2"), Value::Text("FIDO_2_0"),
                                 Value::Text("FIDO_2_1")})},
        {.key_ = Value::Int(kInfoExtensions),
         .value_ = Value::Array({Value::Text("hmac-secret")})},
        {.key_ = Value::Int(kInfoAaguid),
         .value_ = Value::Bytes(Range(kAaguidFirstByte, kAaguidLen))},
        {.key_ = Value::Int(kInfoOptions),
         .value_ = Value::Map(
             {{.key_ = Value::Text("clientPin"),
               .value_ = Value::Bool(pin_set_)},
              {.key_ = Value::Text("rk"), .value_ = Value::Bool(true)},
              {.key_ = Value::Text("plat"), .value_ = Value::Bool(false)}})},
        {.key_ = Value::Int(kInfoMaxMsgSize),
         .value_ = Value::Int(kMaxMsgSize)},
        {.key_ = Value::Int(kInfoPinProtocols),
         .value_ = Value::Array(std::move(protocols))},
    });
  }

  bool HandleClientPin(const Bytes& cbor, Bytes& rapdu) {
    Value params;
    std::string err;
    if (!nero_nfc::cbor::Decode(cbor, params, err)) {
      return RespondCtap(kErrInvalidCbor, {}, rapdu);
    }
    std::int64_t protocol = 0;
    std::int64_t sub = 0;
    const Value* const protocol_param = params.Find(ctap::kPinKeyProtocol);
    const Value* const sub_param = params.Find(ctap::kPinKeySubCommand);
    if (protocol_param == NERO_NFC_NULL || !protocol_param->AsInt(protocol) ||
        sub_param == NERO_NFC_NULL || !sub_param->AsInt(sub)) {
      return RespondCtap(kErrMissingParameter, {}, rapdu);
    }
    switch (sub) {
      case ctap::kPinSubGetRetries:
        return RespondCtap(
            nero_nfc::ctap::kStatusSuccess,
            nero_nfc::cbor::Encode(Value::Map(
                {{.key_ = Value::Int(ctap::kPinRespRetries),
                  .value_ = Value::Int(static_cast<std::int64_t>(retries_))}})),
            rapdu);
      case ctap::kPinSubGetKeyAgreement: {
        Value cose;
        EXPECT_TRUE(key_.Generate(err)) << err;
        EXPECT_TRUE(key_.CoseKey(cose, err)) << err;
        return RespondCtap(nero_nfc::ctap::kStatusSuccess,
                           nero_nfc::cbor::Encode(Value::Map(
                               {{.key_ = Value::Int(ctap::kPinRespKeyAgreement),
                                 .value_ = cose}})),
                           rapdu);
      }
      case ctap::kPinSubSetPin:
      case ctap::kPinSubChangePin:
        return RespondCtap(
            SetOrChangePin(static_cast<std::uint8_t>(protocol),
                           std::cmp_equal(sub, ctap::kPinSubChangePin), params),
            {}, rapdu);
      default:
        return RespondCtap(kErrInvalidParameter, {}, rapdu);
    }
  }

  std::uint8_t SetOrChangePin(std::uint8_t protocol, bool change,
                              const Value& params) {
    if (change != pin_set_) {
      return change ? nero_nfc::ctap::kErrPinNotSet
                    : nero_nfc::ctap::kErrNotAllowed;
    }
    const nero_nfc::ctap::PinUvAuthProtocol proto(protocol);
    std::string err;
    Bytes z;
    Bytes shared;
    const Value* const platform_key = params.Find(ctap::kPinKeyKeyAgreement);
    if (platform_key == NERO_NFC_NULL || !key_.Agree(*platform_key, z, err) ||
        !proto.Kdf(z, shared, err)) {
      ADD_FAILURE() << "key agreement failed: " << err;
      return kErrOther;
    }
    const Bytes& new_pin_enc = params.Find(ctap::kPinKeyNewPinEnc)->AsBytes();
    Bytes message = new_pin_enc;
    if (change) {
      const Bytes& hash_enc = params.Find(ctap::kPinKeyPinHashEnc)->AsBytes();
      message.insert(message.end(), hash_enc.begin(), hash_enc.end());
    }
    Bytes auth;
    EXPECT_TRUE(proto.Authenticate(shared, message, auth, err)) << err;
    if (auth != params.Find(ctap::kPinKeyAuthParam)->AsBytes()) {
      return nero_nfc::ctap::kErrPinAuthInvalid;
    }
    if (change) {
      Bytes hash;
      EXPECT_TRUE(proto.Decrypt(
          shared, params.Find(ctap::kPinKeyPinHashEnc)->AsBytes(), hash, err));
      if (hash != PinHash(pin_)) {
        --retries_;
        return nero_nfc::ctap::kErrPinInvalid;
      }
    }
    Bytes padded;
    EXPECT_TRUE(proto.Decrypt(shared, new_pin_enc, padded, err)) << err;
    EXPECT_EQ(padded.size(), nero_nfc::ctap::kPinPaddedLen);
    const auto nul = std::ranges::find(padded, 0u);
    pin_.assign(padded.begin(), nul);
    pin_set_ = true;
    return nero_nfc::ctap::kStatusSuccess;
  }

  static Bytes PinHash(const std::string& pin) {
    Bytes md(EVP_MAX_MD_SIZE);
    unsigned int len = 0u;
    EXPECT_EQ(EVP_Digest(pin.data(), pin.size(), md.data(), &len, EVP_sha256(),
                         NERO_NFC_NULL),
              1);
    md.resize(kPinHashLen);
    return md;
  }

  bool RespondCtap(std::uint8_t status, const Bytes& body, Bytes& rapdu) {
    Bytes data{status};
    data.insert(data.end(), body.begin(), body.end());
    return Respond(data, rapdu);
  }

  bool Respond(const Bytes& data, Bytes& rapdu) {
    pending_.assign(data.begin(), data.end());
    return SendChunk(rapdu);
  }

  bool SendChunk(Bytes& rapdu) {
    const std::size_t n = (chunk_size_ == 0u)
                              ? pending_.size()
                              : std::min(chunk_size_, pending_.size());
    rapdu.assign(pending_.begin(),
                 pending_.begin() + static_cast<std::ptrdiff_t>(n));
    pending_.erase(pending_.begin(),
                   pending_.begin() + static_cast<std::ptrdiff_t>(n));
    if (pending_.empty()) {
      rapdu.push_back(kSw1Success);
      rapdu.push_back(0x00u);
    } else {
      rapdu.push_back(kSw1MoreData);
      rapdu.push_back(static_cast<std::uint8_t>(
          std::min(pending_.size(), kSw2MaxRemaining)));
    }
    return true;
  }
};

nero_nfc::ctap::Client MakeClient(FakeAuthenticator& fake) {
  return nero_nfc::ctap::Client(fake.Transceiver(),
                                std::chrono::milliseconds(1));
}

}  // namespace

TEST(UserspaceCbor, EncodesMapsInCtap2CanonicalOrder) {
  const Value map = Value::Map({
      {.key_ = Value::Text("up"), .value_ = Value::Bool(true)},
      {.key_ = Value::Int(-3), .value_ = Value::Null()},
      {.key_ = Value::Int(3), .value_ = Value::Int(-25)},
      {.key_ = Value::Int(-1), .value_ = Value::Int(1)},
      {.key_ = Value::Int(1), .value_ = Value::Int(2)},
  });
  EXPECT_EQ(nero_nfc::cbor::Encode(map),
            Hex("A5 01 02 03 38 18 20 01 22 F6 62 75 70 F5"));
}

TEST(UserspaceCbor, EncodesIntegerAndLengthHeads) {
  EXPECT_EQ(nero_nfc::cbor::Encode(Value::Int(23)), Hex("17"));
  EXPECT_EQ(nero_nfc::cbor::Encode(Value::Int(24)), Hex("18 18"));
  EXPECT_EQ(nero_nfc::cbor::Encode(Value::Int(1200)), Hex("19 04 B0"));
  EXPECT_EQ(nero_nfc::cbor::Encode(Value::Int(-25)), Hex("38 18"));
  EXPECT_EQ(nero_nfc::cbor::Encode(Value::Bytes(Bytes(32u, 0u))).size(), 34u);
}

TEST(UserspaceCbor, RoundTripsNestedValues) {
  const Value in = Value::Map({
      {.key_ = Value::Int(1),
       .value_ = Value::Array({Value::Text("FIDO_2_0"), Value::Int(-7)})},
      {.key_ = Value::Int(4),
       .value_ = Value::Map(
           {{.key_ = Value::Text("rk"), .value_ = Value::Bool(false)}})},
      {.key_ = Value::Int(3), .value_ = Value::Bytes(Range(0u, 16u))},
  });
  Value out;
  std::string err;
  ASSERT_TRUE(nero_nfc::cbor::Decode(nero_nfc::cbor::Encode(in), out, err))
      << err;
  ASSERT_NE(out.Find(1), NERO_NFC_NULL);
  ASSERT_EQ(out.Find(1)->AsArray().size(), 2u);
  EXPECT_EQ(out.Find(1)->AsArray().at(0).AsText(), "FIDO_2_0");
  std::int64_t v = 0;
  ASSERT_TRUE(out.Find(1)->AsArray().at(1).AsInt(v));
  EXPECT_EQ(v, -7);
  ASSERT_NE(out.Find(4), NERO_NFC_NULL);
  ASSERT_NE(out.Find(4)->Find("rk"), NERO_NFC_NULL);
  EXPECT_FALSE(out.Find(4)->Find("rk")->AsBool());
  EXPECT_EQ(out.Find(3)->AsBytes(), Range(0u, 16u));
  EXPECT_EQ(out.Find(99), NERO_NFC_NULL);
}

TEST(UserspaceCbor, RejectsMalformedInput) {
  Value out;
  std::string err;
  EXPECT_FALSE(nero_nfc::cbor::Decode(Hex("A1 01"), out, err));
  EXPECT_FALSE(nero_nfc::cbor::Decode(Hex("01 02"), out, err));
  EXPECT_FALSE(nero_nfc::cbor::Decode(Hex("9F 01 FF"), out, err));
  EXPECT_FALSE(nero_nfc::cbor::Decode(Hex("5A FF FF FF FF 00"), out, err));
  EXPECT_FALSE(nero_nfc::cbor::Decode(Hex("9A FF FF FF FF"), out, err));
  EXPECT_FALSE(nero_nfc::cbor::Decode(Hex("C1 01"), out, err));
  EXPECT_FALSE(nero_nfc::cbor::Decode(Hex("F9 00 00"), out, err));
  EXPECT_FALSE(nero_nfc::cbor::Decode({}, out, err));
  Bytes deep(kTooDeepNesting, kCborArrayOfOne);
  deep.back() = 0x00u;
  EXPECT_FALSE(nero_nfc::cbor::Decode(deep, out, err));
}

TEST(UserspaceCbor, KeepsFull64BitIntegerRange) {
  Value out;
  std::string err;
  ASSERT_TRUE(
      nero_nfc::cbor::Decode(Hex("3B FF FF FF FF FF FF FF FF"), out, err));
  std::int64_t v = 0;
  EXPECT_FALSE(out.AsInt(v));
  EXPECT_EQ(nero_nfc::cbor::Encode(out), Hex("3B FF FF FF FF FF FF FF FF"));
}

TEST(UserspaceCtap, SelectsAndReadsInfoAcrossGetResponseChaining) {
  FakeAuthenticator fake;
  fake.chunk_size_ = kResponseChunkLen;
  auto client = MakeClient(fake);
  std::string version;
  std::string err;
  ASSERT_TRUE(client.Select(version, err)) << err;
  EXPECT_EQ(version, "FIDO_2_0");
  EXPECT_EQ(fake.apdus_.front(),
            Hex("00 A4 04 00 08 A0 00 00 06 47 2F 00 01 00"));

  nero_nfc::ctap::AuthenticatorInfo info;
  ASSERT_TRUE(client.GetInfo(info, err)) << err;
  EXPECT_EQ(info.versions_,
            (std::vector<std::string>{"U2F_V2", "FIDO_2_0", "FIDO_2_1"}));
  EXPECT_EQ(info.aaguid_, Range(0xA0u, 16u));
  EXPECT_EQ(info.Option("rk"), std::optional<bool>(true));
  EXPECT_EQ(info.Option("clientPin"), std::optional<bool>(false));
  EXPECT_EQ(info.Option("uv"), std::nullopt);
  EXPECT_EQ(info.max_msg_size_, std::optional<std::uint64_t>(1200u));
  EXPECT_EQ(nero_nfc::ctap::ChoosePinProtocol(info), ctap::kPinProtocolTwo);
  EXPECT_TRUE(std::ranges::any_of(fake.apdus_, [](const Bytes& a) {
    return a.size() == 5u && a.at(0) == 0x00u && a.at(1) == 0xC0u;
  }));
  EXPECT_EQ(fake.apdus_.at(1), Hex("80 10 80 00 01 04 00"));
}

TEST(UserspaceCtap, PollsStatusUpdatesUntilResetCompletes) {
  FakeAuthenticator fake;
  fake.reset_status_updates_ = kResetStatusUpdates;
  auto client = MakeClient(fake);
  std::uint8_t status = kStatusUnset;
  std::string err;
  ASSERT_TRUE(client.Reset(status, err)) << err;
  EXPECT_EQ(status, nero_nfc::ctap::kStatusSuccess);
  ASSERT_EQ(fake.apdus_.size(), 4u);
  EXPECT_EQ(fake.apdus_.at(0), Hex("80 10 80 00 01 07 00"));
  for (std::size_t i = 1u; i < fake.apdus_.size(); ++i) {
    EXPECT_EQ(fake.apdus_.at(i), Hex("80 11 00 00 00"));
  }
}

TEST(UserspaceCtap, ReportsCtapAndIsoErrors) {
  FakeAuthenticator fake;
  fake.reset_status_ = nero_nfc::ctap::kErrNotAllowed;
  auto client = MakeClient(fake);
  std::uint8_t status = 0u;
  std::string err;
  ASSERT_TRUE(client.Reset(status, err)) << err;
  EXPECT_EQ(status, nero_nfc::ctap::kErrNotAllowed);
  EXPECT_EQ(nero_nfc::ctap::StatusName(status), "CTAP2_ERR_NOT_ALLOWED (0x30)");

  FakeAuthenticator not_fido;
  not_fido.select_sw_ = kSwFileNotFound;
  auto other = MakeClient(not_fido);
  std::string version;
  EXPECT_FALSE(other.Select(version, err));
  EXPECT_NE(err.find("6A82"), std::string::npos);
}

TEST(UserspaceCtap, RefusedResetAsksForRetap) {
  FakeAuthenticator fake;
  fake.reset_status_ = nero_nfc::ctap::kErrNotAllowed;
  auto client = MakeClient(fake);
  nero_nfc::FidoTokenRequest request;
  request.reset_ = true;
  EXPECT_EQ(nero_nfc::RunFidoTokenOperations(client, request),
            nero_nfc::FidoTokenResult::kRetryReset);
}

TEST(UserspaceCtap, ChoosesPinProtocol) {
  nero_nfc::ctap::AuthenticatorInfo info;
  EXPECT_EQ(nero_nfc::ctap::ChoosePinProtocol(info), 1u);
  info.pin_protocols_ = {1u};
  EXPECT_EQ(nero_nfc::ctap::ChoosePinProtocol(info), 1u);
  info.pin_protocols_ = {ctap::kPinProtocolOne, ctap::kPinProtocolTwo};
  EXPECT_EQ(nero_nfc::ctap::ChoosePinProtocol(info), ctap::kPinProtocolTwo);
  info.pin_protocols_ = {kPinProtocolUnsupported};
  EXPECT_EQ(nero_nfc::ctap::ChoosePinProtocol(info), 0u);
}

TEST(UserspaceCtap, ValidatesNewPins) {
  std::string err;
  EXPECT_FALSE(nero_nfc::ctap::ValidateNewPin("123", 4u, err));
  EXPECT_TRUE(nero_nfc::ctap::ValidateNewPin("1234", 4u, err)) << err;
  EXPECT_TRUE(nero_nfc::ctap::ValidateNewPin(std::string(63u, 'a'), 4u, err));
  EXPECT_FALSE(nero_nfc::ctap::ValidateNewPin(std::string(64u, 'a'), 4u, err));
  EXPECT_FALSE(nero_nfc::ctap::ValidateNewPin(std::string("12\0"
                                                          "34",
                                                          5u),
                                              4u, err));
  EXPECT_FALSE(
      nero_nfc::ctap::ValidateNewPin("12\xFF"
                                     "34",
                                     4u, err));
  EXPECT_FALSE(
      nero_nfc::ctap::ValidateNewPin("\xC3\xA9\xC3\xA9\xC3\xA9", 4u, err));
  EXPECT_TRUE(nero_nfc::ctap::ValidateNewPin("\xC3\xA9\xC3\xA9\xC3\xA9\xC3\xA9",
                                             4u, err));
  EXPECT_FALSE(nero_nfc::ctap::ValidateNewPin("123456", 8u, err));
}

TEST(UserspaceCtap, FormatsAuthenticatorInfo) {
  nero_nfc::ctap::AuthenticatorInfo info;
  info.versions_ = {"FIDO_2_0", "FIDO_2_1"};
  info.options_ = {{"rk", true}, {"plat", false}, {"clientPin", true}};
  info.pin_protocols_ = {ctap::kPinProtocolTwo, ctap::kPinProtocolOne};
  info.min_pin_length_ = kMinPinLength;
  const std::string text = nero_nfc::FormatAuthenticatorInfo(info);
  EXPECT_NE(text.find("versions: FIDO_2_0, FIDO_2_1"), std::string::npos);
  EXPECT_NE(text.find("options: rk, noplat, clientPin"), std::string::npos);
  EXPECT_NE(text.find("pin protocols: 2, 1"), std::string::npos);
  EXPECT_NE(text.find("min pin length: 4"), std::string::npos);
}

/* Expected values computed independently with the openssl(1) CLI. */
TEST(UserspaceCtapPin, Protocol1MatchesKnownAnswers) {
  const nero_nfc::ctap::PinUvAuthProtocol proto(1u);
  const Bytes z = Range(0u, 32u);
  Bytes shared;
  Bytes out;
  std::string err;
  ASSERT_TRUE(proto.Kdf(z, shared, err)) << err;
  EXPECT_EQ(shared, Hex("630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8"
                        "581bd710dd"));
  ASSERT_TRUE(proto.Encrypt(Range(0u, 32u), Range(0u, 16u), out, err)) << err;
  EXPECT_EQ(out, Hex("5a6e045708fb7196f02e553d02c3a692"));
  Bytes plain;
  ASSERT_TRUE(proto.Decrypt(Range(0u, 32u), out, plain, err)) << err;
  EXPECT_EQ(plain, Range(0u, 16u));
  ASSERT_TRUE(
      proto.Authenticate(Range(0u, 32u), Bytes{'a', 'b', 'c'}, out, err))
      << err;
  EXPECT_EQ(out, Hex("F0133729C4163DEDE81E21CD47839256"));
}

TEST(UserspaceCtapPin, Protocol2MatchesKnownAnswers) {
  const nero_nfc::ctap::PinUvAuthProtocol proto(2u);
  Bytes shared;
  Bytes out;
  std::string err;
  ASSERT_TRUE(proto.Kdf(Range(0u, 32u), shared, err)) << err;
  EXPECT_EQ(shared,
            Hex("a689b3b92a6ebab91192408da9c4f05c674a2bc5f938d613077716c719a8"
                "df39"
                "0f6ff2ef211829c11638ef2893ea02edf195658c0572393e7680d93bc2b5"
                "8d44"));
  ASSERT_TRUE(proto.Authenticate(shared, Bytes{'a', 'b', 'c'}, out, err));
  EXPECT_EQ(out, Hex("7806F087D00656B3113CD046BC4E2EEB5B72D1A37C7263712C7AB6B"
                     "BE499CC7C"));
  Bytes iv_ct = Range(kIvFirstByte, kAesBlockLen);
  const Bytes ct = Hex("edd2a228b8f8bff62a65218eb24f786f");
  iv_ct.insert(iv_ct.end(), ct.begin(), ct.end());
  ASSERT_TRUE(proto.Decrypt(shared, iv_ct, out, err)) << err;
  EXPECT_EQ(out, Range(0u, kAesBlockLen));

  Bytes enc;
  ASSERT_TRUE(proto.Encrypt(shared, Range(0u, 64u), enc, err)) << err;
  EXPECT_EQ(enc.size(), 16u + 64u);
  ASSERT_TRUE(proto.Decrypt(shared, enc, out, err)) << err;
  EXPECT_EQ(out, Range(0u, 64u));
}

TEST(UserspaceCtapPin, RejectsInvalidPeerKey) {
  nero_nfc::ctap::EcdhKeyPair key;
  std::string err;
  ASSERT_TRUE(key.Generate(err)) << err;
  const Value off_curve = Value::Map({
      {.key_ = Value::Int(1), .value_ = Value::Int(2)},
      {.key_ = Value::Int(3), .value_ = Value::Int(-25)},
      {.key_ = Value::Int(-1), .value_ = Value::Int(1)},
      {.key_ = Value::Int(-2), .value_ = Value::Bytes(Range(1u, 32u))},
      {.key_ = Value::Int(-3), .value_ = Value::Bytes(Range(2u, 32u))},
  });
  Bytes z;
  EXPECT_FALSE(key.Agree(off_curve, z, err));
  EXPECT_TRUE(z.empty());
}

TEST(UserspaceCtapPin, SetsAndChangesPinWithBothProtocols) {
  for (const std::uint64_t protocol : {1u, 2u}) {
    SCOPED_TRACE(protocol);
    FakeAuthenticator fake;
    fake.pin_protocols_ = {protocol};
    auto client = MakeClient(fake);
    std::uint8_t status = kStatusUnset;
    std::string err;
    ASSERT_TRUE(nero_nfc::ctap::SetPin(
        client, static_cast<std::uint8_t>(protocol), "1234", status, err))
        << err;
    EXPECT_EQ(status, nero_nfc::ctap::kStatusSuccess);
    EXPECT_EQ(fake.pin_, "1234");

    ASSERT_TRUE(nero_nfc::ctap::ChangePin(client,
                                          static_cast<std::uint8_t>(protocol),
                                          "0000", "5678", status, err))
        << err;
    EXPECT_EQ(status, nero_nfc::ctap::kErrPinInvalid);
    EXPECT_EQ(fake.pin_, "1234");
    EXPECT_EQ(fake.retries_, 7u);

    ASSERT_TRUE(nero_nfc::ctap::ChangePin(client,
                                          static_cast<std::uint8_t>(protocol),
                                          "1234", "5678", status, err))
        << err;
    EXPECT_EQ(status, nero_nfc::ctap::kStatusSuccess);
    EXPECT_EQ(fake.pin_, "5678");
  }
}

TEST(UserspaceCtapPin, ResetThenSetPinEndToEnd) {
  FakeAuthenticator fake;
  fake.pin_set_ = true;
  fake.pin_ = "old-pin";
  fake.reset_status_updates_ = kResetStatusUpdates;
  auto client = MakeClient(fake);
  nero_nfc::FidoTokenRequest request;
  request.reset_ = true;
  request.set_pin_ = true;
  request.new_pin_ = "4321";
  EXPECT_EQ(nero_nfc::RunFidoTokenOperations(client, request),
            nero_nfc::FidoTokenResult::kOk);
  EXPECT_TRUE(fake.pin_set_);
  EXPECT_EQ(fake.pin_, "4321");
}

TEST(UserspaceCtapPin, SetPinRefusesWhenPinAlreadySet) {
  FakeAuthenticator fake;
  fake.pin_set_ = true;
  fake.pin_ = "1234";
  auto client = MakeClient(fake);
  nero_nfc::FidoTokenRequest request;
  request.set_pin_ = true;
  request.new_pin_ = "4321";
  EXPECT_EQ(nero_nfc::RunFidoTokenOperations(client, request),
            nero_nfc::FidoTokenResult::kFailed);
  EXPECT_EQ(fake.pin_, "1234");
}
