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

#include "nero_nfc_ctap_pin.hpp"

#include "nero_nfc_mem_util.h"
#include "nero_nfc_null.h"

#include <algorithm>
#include <array>
#include <format>
#include <iterator>
#include <limits>
#include <string>
#include <utility>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>

namespace nero_nfc::ctap {

namespace {

inline constexpr std::size_t kCoordLen = 32u;
/* SEC1 uncompressed point: 0x04 || X || Y. */
inline constexpr std::size_t kUncompressedPointLen = 1u + (2u * kCoordLen);
inline constexpr std::size_t kKeyLen = 32u;
inline constexpr std::size_t kAesBlockLen = 16u;
inline constexpr std::size_t kSharedLenV1 = kKeyLen;
inline constexpr std::size_t kSharedLenV2 = 2u * kKeyLen;
inline constexpr std::size_t kAuthLenV1 = 16u;
/* [CTAP2.3] section 6.5.5.6 -- pinHashEnc covers LEFT(SHA-256(curPin), 16). */
inline constexpr std::size_t kPinHashLen = 16u;

/* [CTAP2.3] section 6.5.6 -- COSE_Key for the platform key agreement. */
inline constexpr std::int64_t kCoseKty = 1;
inline constexpr std::int64_t kCoseAlg = 3;
inline constexpr std::int64_t kCoseCrv = -1;
inline constexpr std::int64_t kCoseX = -2;
inline constexpr std::int64_t kCoseY = -3;
inline constexpr std::int64_t kCoseKtyEc2 = 2;
inline constexpr std::int64_t kCoseAlgEcdhEsHkdf256 = -25;
inline constexpr std::int64_t kCoseCrvP256 = 1;

/* ERR_error_string_n() documents 256 bytes as sufficient. */
inline constexpr std::size_t kOpenSslErrLen = 256u;

/* [RFC3629] section 3 -- UTF-8 byte forms for PIN validation. */
inline constexpr std::uint8_t kUtf8ContMask = 0xC0u;
inline constexpr std::uint8_t kUtf8ContBits = 0x80u;
inline constexpr std::uint8_t kUtf8ContPayloadMask = 0x3Fu;
inline constexpr unsigned kUtf8ContPayloadBits = 6u;
inline constexpr std::uint8_t kUtf8AsciiEnd = 0x80u;
inline constexpr std::uint32_t kUnicodeMax = 0x10FFFFu;
inline constexpr std::uint32_t kSurrogateFirst = 0xD800u;
inline constexpr std::uint32_t kSurrogateLast = 0xDFFFu;

struct Utf8Lead {
  std::uint8_t mask_;
  std::uint8_t value_;
  std::uint8_t payload_mask_;
  std::size_t continuation_bytes_;
  std::uint32_t min_code_point_;
};

/* Multi-byte lead forms; min_code_point_ rejects overlong encodings. */
inline constexpr std::array<Utf8Lead, 3> kUtf8Leads{{
    {.mask_ = 0xE0u,
     .value_ = 0xC0u,
     .payload_mask_ = 0x1Fu,
     .continuation_bytes_ = 1u,
     .min_code_point_ = 0x80u},
    {.mask_ = 0xF0u,
     .value_ = 0xE0u,
     .payload_mask_ = 0x0Fu,
     .continuation_bytes_ = 2u,
     .min_code_point_ = 0x800u},
    {.mask_ = 0xF8u,
     .value_ = 0xF0u,
     .payload_mask_ = 0x07u,
     .continuation_bytes_ = 3u,
     .min_code_point_ = 0x10000u},
}};

bool ProtocolSupported(std::uint8_t version, std::string& err) {
  if (version == kPinProtocolOne || version == kPinProtocolTwo) {
    return true;
  }
  err = std::format("unsupported PIN/UV auth protocol {}", version);
  return false;
}

/* Well-formed UTF-8 per RFC 3629 (no overlongs, surrogates, or > U+10FFFF). */
bool IsValidUtf8(std::string_view s) {
  std::size_t i = 0u;
  while (i < s.size()) {
    const auto b0 = static_cast<std::uint8_t>(s.at(i));
    if (b0 < kUtf8AsciiEnd) {
      ++i;
      continue;
    }
    const auto* const lead =
        std::ranges::find_if(kUtf8Leads, [b0](const Utf8Lead& form) {
          return (b0 & form.mask_) == form.value_;
        });
    if (lead == kUtf8Leads.end()) {
      return false;
    }
    const std::size_t extra = lead->continuation_bytes_;
    auto cp = static_cast<std::uint32_t>(b0 & lead->payload_mask_);
    if (s.size() - i <= extra) {
      return false;
    }
    for (std::size_t k = 1u; k <= extra; ++k) {
      const auto b = static_cast<std::uint8_t>(s.at(i + k));
      if ((b & kUtf8ContMask) != kUtf8ContBits) {
        return false;
      }
      cp = (cp << kUtf8ContPayloadBits) |
           static_cast<std::uint32_t>(b & kUtf8ContPayloadMask);
    }
    if (cp < lead->min_code_point_ || cp > kUnicodeMax ||
        (cp >= kSurrogateFirst && cp <= kSurrogateLast)) {
      return false;
    }
    i += extra + 1u;
  }
  return true;
}

}  // namespace

std::size_t PinCodePointCount(std::string_view pin) {
  return static_cast<std::size_t>(std::ranges::count_if(pin, [](char c) {
    return (static_cast<std::uint8_t>(c) & kUtf8ContMask) != kUtf8ContBits;
  }));
}

bool ValidateNewPin(std::string_view pin, std::uint64_t min_length,
                    std::string& err) {
  if (pin.contains('\0')) {
    err = "PIN must not contain NUL characters";
    return false;
  }
  if (!IsValidUtf8(pin)) {
    err = "PIN must be valid UTF-8";
    return false;
  }
  if (pin.size() > kPinMaxBytes) {
    err = std::format("PIN must be at most {} bytes", kPinMaxBytes);
    return false;
  }
  if (PinCodePointCount(pin) < min_length) {
    err = std::format("PIN must be at least {} characters", min_length);
    return false;
  }
  err.clear();
  return true;
}

void SecureWipe(std::string& s) {
  nero_nfc_secure_clear(s.data(), s.size());
  s.clear();
}

void SecureWipe(std::vector<std::uint8_t>& v) {
  nero_nfc_secure_clear(v.data(), v.size());
  v.clear();
}

namespace {

struct PkeyFree {
  void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
struct PkeyCtxFree {
  void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); }
};
struct CipherCtxFree {
  void operator()(EVP_CIPHER_CTX* p) const { EVP_CIPHER_CTX_free(p); }
};
struct KdfFree {
  void operator()(EVP_KDF* p) const { EVP_KDF_free(p); }
};
struct KdfCtxFree {
  void operator()(EVP_KDF_CTX* p) const { EVP_KDF_CTX_free(p); }
};
struct ParamBldFree {
  void operator()(OSSL_PARAM_BLD* p) const { OSSL_PARAM_BLD_free(p); }
};
struct ParamFree {
  void operator()(OSSL_PARAM* p) const { OSSL_PARAM_free(p); }
};
struct BnFree {
  void operator()(BIGNUM* p) const { BN_free(p); }
};
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyFree>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, PkeyCtxFree>;
using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxFree>;
using KdfPtr = std::unique_ptr<EVP_KDF, KdfFree>;
using KdfCtxPtr = std::unique_ptr<EVP_KDF_CTX, KdfCtxFree>;
using ParamBldPtr = std::unique_ptr<OSSL_PARAM_BLD, ParamBldFree>;
using ParamPtr = std::unique_ptr<OSSL_PARAM, ParamFree>;
using BnPtr = std::unique_ptr<BIGNUM, BnFree>;

/* "P-256" is OpenSSL's NIST alias for prime256v1 / secp256r1. */
inline constexpr const char* kCurveName = "P-256";
inline constexpr std::uint8_t kSec1Uncompressed = 0x04u;

bool CryptoFail(std::string& err, std::string_view what) {
  const unsigned long code = ERR_get_error();
  ERR_clear_error();
  std::array<char, kOpenSslErrLen> buf{};
  if (code != 0u) {
    ERR_error_string_n(code, buf.data(), buf.size());
    err = std::format("{}: {}", what, buf.data());
  } else {
    err = std::string(what);
  }
  return false;
}

bool Sha256(std::span<const std::uint8_t> in, std::vector<std::uint8_t>& out,
            std::string& err) {
  out.assign(EVP_MAX_MD_SIZE, 0u);
  unsigned int len = 0u;
  if (EVP_Digest(in.data(), in.size(), out.data(), &len, EVP_sha256(),
                 NERO_NFC_NULL) != 1) {
    return CryptoFail(err, "SHA-256");
  }
  out.resize(len);
  return true;
}

bool HmacSha256(std::span<const std::uint8_t> key,
                std::span<const std::uint8_t> msg,
                std::vector<std::uint8_t>& out, std::string& err) {
  out.assign(EVP_MAX_MD_SIZE, 0u);
  std::size_t len = 0u;
  if (EVP_Q_mac(NERO_NFC_NULL, "HMAC", NERO_NFC_NULL, "SHA256", NERO_NFC_NULL,
                key.data(), key.size(), msg.data(), msg.size(), out.data(),
                out.size(), &len) == NERO_NFC_NULL) {
    return CryptoFail(err, "HMAC-SHA-256");
  }
  out.resize(len);
  return true;
}

bool HkdfSha256(std::span<const std::uint8_t> ikm, std::string_view info,
                std::size_t out_len, std::vector<std::uint8_t>& out,
                std::string& err) {
  const KdfPtr kdf(EVP_KDF_fetch(NERO_NFC_NULL, "HKDF", NERO_NFC_NULL));
  if (!kdf) {
    return CryptoFail(err, "HKDF fetch");
  }
  const KdfCtxPtr ctx(EVP_KDF_CTX_new(kdf.get()));
  if (!ctx) {
    return CryptoFail(err, "HKDF context");
  }
  /* OSSL_PARAM takes non-const buffers; hand it private copies. */
  std::string digest{"SHA256"};
  std::vector<std::uint8_t> key(ikm.begin(), ikm.end());
  std::vector<std::uint8_t> salt(kKeyLen, 0u);
  std::vector<std::uint8_t> info_bytes(info.begin(), info.end());
  const std::array params = {
      OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest.data(),
                                       0u),
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key.data(),
                                        key.size()),
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt.data(),
                                        salt.size()),
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info_bytes.data(),
                                        info_bytes.size()),
      OSSL_PARAM_construct_end(),
  };
  out.assign(out_len, 0u);
  const bool ok =
      EVP_KDF_derive(ctx.get(), out.data(), out.size(), params.data()) == 1;
  SecureWipe(key);
  if (!ok) {
    return CryptoFail(err, "HKDF derive");
  }
  return true;
}

bool AesCbc(bool encrypt, std::span<const std::uint8_t> key,
            std::span<const std::uint8_t> iv, std::span<const std::uint8_t> in,
            std::vector<std::uint8_t>& out, std::string& err) {
  if (key.size() != kKeyLen || iv.size() != kAesBlockLen ||
      (in.size() % kAesBlockLen) != 0u ||
      in.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    err = "AES-256-CBC: invalid key, IV, or block length";
    return false;
  }
  const CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
  if (!ctx) {
    return CryptoFail(err, "AES context");
  }
  if (EVP_CipherInit_ex2(ctx.get(), EVP_aes_256_cbc(), key.data(), iv.data(),
                         encrypt ? 1 : 0, NERO_NFC_NULL) != 1 ||
      EVP_CIPHER_CTX_set_padding(ctx.get(), 0) != 1) {
    return CryptoFail(err, "AES init");
  }
  out.assign(in.size() + kAesBlockLen, 0u);
  int len = 0;
  int final_len = 0;
  if (EVP_CipherUpdate(ctx.get(), out.data(), &len, in.data(),
                       static_cast<int>(in.size())) != 1 ||
      EVP_CipherFinal_ex(
          ctx.get(),
          std::span(out).subspan(static_cast<std::size_t>(len)).data(),
          &final_len) != 1) {
    return CryptoFail(err, "AES-256-CBC");
  }
  out.resize(static_cast<std::size_t>(len) +
             static_cast<std::size_t>(final_len));
  return true;
}

bool CoseCoordinate(const cbor::Value& key, std::int64_t label,
                    std::span<std::uint8_t> out, std::string& err) {
  const cbor::Value* v = key.Find(label);
  if (v == NERO_NFC_NULL || !v->IsBytes() ||
      v->AsBytes().size() != out.size()) {
    err = "authenticator key agreement has a malformed coordinate";
    return false;
  }
  std::ranges::copy(v->AsBytes(), out.begin());
  return true;
}

bool CoseIntEquals(const cbor::Value& key, std::int64_t label,
                   std::int64_t want) {
  const cbor::Value* v = key.Find(label);
  std::int64_t got = 0;
  return v != NERO_NFC_NULL && v->AsInt(got) && got == want;
}

bool PeerKeyFromCose(const cbor::Value& cose, PkeyPtr& out, std::string& err) {
  if (!cose.IsMap() || !CoseIntEquals(cose, kCoseKty, kCoseKtyEc2) ||
      !CoseIntEquals(cose, kCoseCrv, kCoseCrvP256)) {
    err = "authenticator key agreement is not an EC2 P-256 COSE key";
    return false;
  }
  std::array<std::uint8_t, kUncompressedPointLen> point{};
  point.at(0) = kSec1Uncompressed;
  const auto body = std::span(point).subspan(1u);
  if (!CoseCoordinate(cose, kCoseX, body.first(kCoordLen), err) ||
      !CoseCoordinate(cose, kCoseY, body.subspan(kCoordLen), err)) {
    return false;
  }
  const ParamBldPtr bld(OSSL_PARAM_BLD_new());
  if (!bld ||
      OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME,
                                      kCurveName, 0u) != 1 ||
      OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                       point.data(), point.size()) != 1) {
    return CryptoFail(err, "peer key params");
  }
  const ParamPtr params(OSSL_PARAM_BLD_to_param(bld.get()));
  const PkeyCtxPtr ctx(
      EVP_PKEY_CTX_new_from_name(NERO_NFC_NULL, "EC", NERO_NFC_NULL));
  if (!params || !ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1) {
    return CryptoFail(err, "peer key import");
  }
  EVP_PKEY* raw = NERO_NFC_NULL;
  if (EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_PUBLIC_KEY, params.get()) !=
      1) {
    return CryptoFail(err, "peer key import");
  }
  out.reset(raw);
  const PkeyCtxPtr check(
      EVP_PKEY_CTX_new_from_pkey(NERO_NFC_NULL, out.get(), NERO_NFC_NULL));
  if (!check || EVP_PKEY_public_check(check.get()) != 1) {
    return CryptoFail(err, "authenticator key agreement point is invalid");
  }
  return true;
}

}  // namespace

struct EcdhKeyPair::Impl {
  PkeyPtr key_;
};

EcdhKeyPair::EcdhKeyPair() : impl_(std::make_unique<Impl>()) {}
EcdhKeyPair::~EcdhKeyPair() = default;
EcdhKeyPair::EcdhKeyPair(EcdhKeyPair&&) noexcept = default;
EcdhKeyPair& EcdhKeyPair::operator=(EcdhKeyPair&&) noexcept = default;

bool EcdhKeyPair::Generate(std::string& err) {
  const PkeyCtxPtr ctx(
      EVP_PKEY_CTX_new_from_name(NERO_NFC_NULL, "EC", NERO_NFC_NULL));
  if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1 ||
      EVP_PKEY_CTX_set_group_name(ctx.get(), kCurveName) != 1) {
    return CryptoFail(err, "P-256 keygen init");
  }
  EVP_PKEY* raw = NERO_NFC_NULL;
  if (EVP_PKEY_generate(ctx.get(), &raw) != 1) {
    return CryptoFail(err, "P-256 keygen");
  }
  impl_->key_.reset(raw);
  return true;
}

bool EcdhKeyPair::CoseKey(cbor::Value& out, std::string& err) const {
  if (!impl_->key_) {
    err = "key pair not generated";
    return false;
  }
  std::array<std::uint8_t, kCoordLen> x{};
  std::array<std::uint8_t, kCoordLen> y{};
  BIGNUM* raw_x = NERO_NFC_NULL;
  BIGNUM* raw_y = NERO_NFC_NULL;
  const bool got_x =
      EVP_PKEY_get_bn_param(impl_->key_.get(), OSSL_PKEY_PARAM_EC_PUB_X,
                            &raw_x) == 1;
  const BnPtr bx(raw_x);
  const bool got_y =
      EVP_PKEY_get_bn_param(impl_->key_.get(), OSSL_PKEY_PARAM_EC_PUB_Y,
                            &raw_y) == 1;
  const BnPtr by(raw_y);
  if (!got_x || !got_y ||
      BN_bn2binpad(bx.get(), x.data(), static_cast<int>(x.size())) < 0 ||
      BN_bn2binpad(by.get(), y.data(), static_cast<int>(y.size())) < 0) {
    return CryptoFail(err, "P-256 public key export");
  }
  out = cbor::Value::Map({
      {.key_ = cbor::Value::Int(kCoseKty),
       .value_ = cbor::Value::Int(kCoseKtyEc2)},
      {.key_ = cbor::Value::Int(kCoseAlg),
       .value_ = cbor::Value::Int(kCoseAlgEcdhEsHkdf256)},
      {.key_ = cbor::Value::Int(kCoseCrv),
       .value_ = cbor::Value::Int(kCoseCrvP256)},
      {.key_ = cbor::Value::Int(kCoseX), .value_ = cbor::Value::Bytes(x)},
      {.key_ = cbor::Value::Int(kCoseY), .value_ = cbor::Value::Bytes(y)},
  });
  return true;
}

bool EcdhKeyPair::Agree(const cbor::Value& peer_cose_key,
                        std::vector<std::uint8_t>& z, std::string& err) const {
  z.clear();
  if (!impl_->key_) {
    err = "key pair not generated";
    return false;
  }
  PkeyPtr peer;
  if (!PeerKeyFromCose(peer_cose_key, peer, err)) {
    return false;
  }
  const PkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_pkey(
      NERO_NFC_NULL, impl_->key_.get(), NERO_NFC_NULL));
  std::size_t len = 0u;
  if (!ctx || EVP_PKEY_derive_init(ctx.get()) != 1 ||
      EVP_PKEY_derive_set_peer_ex(ctx.get(), peer.get(), 1) != 1 ||
      EVP_PKEY_derive(ctx.get(), NERO_NFC_NULL, &len) != 1 ||
      len != kCoordLen) {
    return CryptoFail(err, "ECDH");
  }
  z.assign(len, 0u);
  if (EVP_PKEY_derive(ctx.get(), z.data(), &len) != 1 || len != kCoordLen) {
    SecureWipe(z);
    return CryptoFail(err, "ECDH");
  }
  return true;
}

bool PinUvAuthProtocol::Kdf(std::span<const std::uint8_t> z,
                            std::vector<std::uint8_t>& shared,
                            std::string& err) const {
  shared.clear();
  if (!ProtocolSupported(version_, err)) {
    return false;
  }
  if (version_ == kPinProtocolOne) {
    return Sha256(z, shared, err);
  }
  std::vector<std::uint8_t> hmac_key;
  std::vector<std::uint8_t> aes_key;
  if (!HkdfSha256(z, "CTAP2 HMAC key", kKeyLen, hmac_key, err) ||
      !HkdfSha256(z, "CTAP2 AES key", kKeyLen, aes_key, err)) {
    SecureWipe(hmac_key);
    return false;
  }
  shared = std::move(hmac_key);
  shared.insert(shared.end(), aes_key.begin(), aes_key.end());
  SecureWipe(aes_key);
  return true;
}

bool PinUvAuthProtocol::Encrypt(std::span<const std::uint8_t> shared,
                                std::span<const std::uint8_t> plaintext,
                                std::vector<std::uint8_t>& out,
                                std::string& err) const {
  out.clear();
  if (!ProtocolSupported(version_, err)) {
    return false;
  }
  if (version_ == kPinProtocolOne) {
    if (shared.size() != kSharedLenV1) {
      err = "protocol 1 shared secret must be 32 bytes";
      return false;
    }
    const std::array<std::uint8_t, kAesBlockLen> iv{};
    return AesCbc(true, shared, iv, plaintext, out, err);
  }
  if (shared.size() != kSharedLenV2) {
    err = "protocol 2 shared secret must be 64 bytes";
    return false;
  }
  std::array<std::uint8_t, kAesBlockLen> iv{};
  if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1) {
    return CryptoFail(err, "random IV");
  }
  std::vector<std::uint8_t> ct;
  if (!AesCbc(true, shared.subspan(kKeyLen), iv, plaintext, ct, err)) {
    return false;
  }
  out.assign(iv.begin(), iv.end());
  std::ranges::copy(ct, std::back_inserter(out));
  return true;
}

bool PinUvAuthProtocol::Decrypt(std::span<const std::uint8_t> shared,
                                std::span<const std::uint8_t> ciphertext,
                                std::vector<std::uint8_t>& out,
                                std::string& err) const {
  out.clear();
  if (!ProtocolSupported(version_, err)) {
    return false;
  }
  if (version_ == kPinProtocolOne) {
    if (shared.size() != kSharedLenV1) {
      err = "protocol 1 shared secret must be 32 bytes";
      return false;
    }
    const std::array<std::uint8_t, kAesBlockLen> iv{};
    return AesCbc(false, shared, iv, ciphertext, out, err);
  }
  if (shared.size() != kSharedLenV2 || ciphertext.size() < kAesBlockLen) {
    err = "protocol 2 decrypt: bad shared secret or ciphertext length";
    return false;
  }
  return AesCbc(false, shared.subspan(kKeyLen), ciphertext.first(kAesBlockLen),
                ciphertext.subspan(kAesBlockLen), out, err);
}

bool PinUvAuthProtocol::Authenticate(std::span<const std::uint8_t> shared,
                                     std::span<const std::uint8_t> message,
                                     std::vector<std::uint8_t>& out,
                                     std::string& err) const {
  out.clear();
  if (!ProtocolSupported(version_, err)) {
    return false;
  }
  if (version_ == kPinProtocolOne) {
    if (shared.size() != kSharedLenV1) {
      err = "protocol 1 shared secret must be 32 bytes";
      return false;
    }
    if (!HmacSha256(shared, message, out, err)) {
      return false;
    }
    out.resize(kAuthLenV1);
    return true;
  }
  if (shared.size() != kSharedLenV2) {
    err = "protocol 2 shared secret must be 64 bytes";
    return false;
  }
  return HmacSha256(shared.first(kKeyLen), message, out, err);
}

namespace {

/* getKeyAgreement + ECDH + KDF. A CTAP error returns true with status set and
 * the outputs empty. */
bool EstablishSharedSecret(Client& client, const PinUvAuthProtocol& proto,
                           cbor::Value& platform_key,
                           std::vector<std::uint8_t>& shared,
                           std::uint8_t& status, std::string& err) {
  cbor::Value peer;
  if (!client.GetKeyAgreement(proto.Version(), peer, status, err)) {
    return false;
  }
  if (status != kStatusSuccess) {
    return true;
  }
  EcdhKeyPair ephemeral;
  std::vector<std::uint8_t> z;
  if (!ephemeral.Generate(err) || !ephemeral.CoseKey(platform_key, err) ||
      !ephemeral.Agree(peer, z, err)) {
    return false;
  }
  const bool ok = proto.Kdf(z, shared, err);
  SecureWipe(z);
  return ok;
}

bool EncryptPaddedPin(const PinUvAuthProtocol& proto,
                      std::span<const std::uint8_t> shared,
                      std::string_view pin, std::vector<std::uint8_t>& out,
                      std::string& err) {
  std::vector<std::uint8_t> padded(kPinPaddedLen, 0u);
  std::ranges::copy(pin, padded.begin());
  const bool ok = proto.Encrypt(shared, padded, out, err);
  SecureWipe(padded);
  return ok;
}

}  // namespace

bool SetPin(Client& client, std::uint8_t protocol, std::string_view new_pin,
            std::uint8_t& status, std::string& err) {
  status = kStatusSuccess;
  if (!ProtocolSupported(protocol, err) || !ValidateNewPin(new_pin, 1u, err)) {
    return false;
  }
  const PinUvAuthProtocol proto(protocol);
  cbor::Value platform_key;
  std::vector<std::uint8_t> shared;
  if (!EstablishSharedSecret(client, proto, platform_key, shared, status,
                             err)) {
    SecureWipe(shared);
    return false;
  }
  if (status != kStatusSuccess) {
    return true;
  }
  std::vector<std::uint8_t> new_pin_enc;
  std::vector<std::uint8_t> auth;
  const bool built =
      EncryptPaddedPin(proto, shared, new_pin, new_pin_enc, err) &&
      proto.Authenticate(shared, new_pin_enc, auth, err);
  SecureWipe(shared);
  if (!built) {
    return false;
  }
  const cbor::Value params = cbor::Value::Map({
      {.key_ = cbor::Value::Int(kPinKeyProtocol),
       .value_ = cbor::Value::Int(protocol)},
      {.key_ = cbor::Value::Int(kPinKeySubCommand),
       .value_ = cbor::Value::Int(kPinSubSetPin)},
      {.key_ = cbor::Value::Int(kPinKeyKeyAgreement), .value_ = platform_key},
      {.key_ = cbor::Value::Int(kPinKeyAuthParam),
       .value_ = cbor::Value::Bytes(auth)},
      {.key_ = cbor::Value::Int(kPinKeyNewPinEnc),
       .value_ = cbor::Value::Bytes(new_pin_enc)},
  });
  cbor::Value response;
  return client.ClientPin(params, status, response, err);
}

bool ChangePin(Client& client, std::uint8_t protocol,
               std::string_view current_pin, std::string_view new_pin,
               std::uint8_t& status, std::string& err) {
  status = kStatusSuccess;
  if (!ProtocolSupported(protocol, err) || !ValidateNewPin(new_pin, 1u, err)) {
    return false;
  }
  const PinUvAuthProtocol proto(protocol);
  cbor::Value platform_key;
  std::vector<std::uint8_t> shared;
  if (!EstablishSharedSecret(client, proto, platform_key, shared, status,
                             err)) {
    SecureWipe(shared);
    return false;
  }
  if (status != kStatusSuccess) {
    return true;
  }
  std::vector<std::uint8_t> new_pin_enc;
  std::vector<std::uint8_t> pin_hash;
  std::vector<std::uint8_t> pin_hash_enc;
  std::vector<std::uint8_t> auth;
  std::vector<std::uint8_t> current(current_pin.begin(), current_pin.end());
  bool built = EncryptPaddedPin(proto, shared, new_pin, new_pin_enc, err) &&
               Sha256(current, pin_hash, err);
  if (built) {
    pin_hash.resize(kPinHashLen);
    built = proto.Encrypt(shared, pin_hash, pin_hash_enc, err);
  }
  if (built) {
    std::vector<std::uint8_t> message = new_pin_enc;
    message.insert(message.end(), pin_hash_enc.begin(), pin_hash_enc.end());
    built = proto.Authenticate(shared, message, auth, err);
  }
  SecureWipe(current);
  SecureWipe(pin_hash);
  SecureWipe(shared);
  if (!built) {
    return false;
  }
  const cbor::Value params = cbor::Value::Map({
      {.key_ = cbor::Value::Int(kPinKeyProtocol),
       .value_ = cbor::Value::Int(protocol)},
      {.key_ = cbor::Value::Int(kPinKeySubCommand),
       .value_ = cbor::Value::Int(kPinSubChangePin)},
      {.key_ = cbor::Value::Int(kPinKeyKeyAgreement), .value_ = platform_key},
      {.key_ = cbor::Value::Int(kPinKeyAuthParam),
       .value_ = cbor::Value::Bytes(auth)},
      {.key_ = cbor::Value::Int(kPinKeyNewPinEnc),
       .value_ = cbor::Value::Bytes(new_pin_enc)},
      {.key_ = cbor::Value::Int(kPinKeyPinHashEnc),
       .value_ = cbor::Value::Bytes(pin_hash_enc)},
  });
  cbor::Value response;
  return client.ClientPin(params, status, response, err);
}

}  // namespace nero_nfc::ctap
