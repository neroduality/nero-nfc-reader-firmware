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
#include <gtest/gtest.h>

#include "nero_nfc_mem_util.h"
#include "writer_payload.h"
#include "writer_payload_utest_hook.h"

#include <cstdio>
#include <cstring>
#include <string>

namespace {

void poison_writer_kind(writer_payload_config_t *cfg, int bits) {
  static_assert(sizeof(cfg->kind) <= sizeof(bits));
  (void)nero_nfc_copy_bytes(&cfg->kind, sizeof(cfg->kind), 0u, &bits, sizeof(cfg->kind));
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((no_sanitize("undefined")))
#endif
static const char *
kind_name_from_raw_bits_for_test(unsigned bits) {
  writer_payload_kind_t k{};
  (void)nero_nfc_copy_bytes(&k, sizeof(k), 0u, &bits, sizeof(k));
  return writer_payload_kind_name(k);
}

} // namespace

static void FillChar(char *dest, size_t cap, char ch) {
  ASSERT_NE(dest, NERO_NFC_NULL);
  ASSERT_GE(cap, 2u);
  for (size_t i = 0u; i + 1u < cap; ++i) {
    dest[i] = ch;
  }
  dest[cap - 1u] = '\0';
}

static void SetUrlPayload(writer_payload_config_t *cfg, const char *value = "neroduality.com/contact/") {
  ASSERT_NE(cfg, NERO_NFC_NULL);
  cfg->kind = WRITER_PAYLOAD_URL_HTTPS;
  cfg->uri_id = 0x04u;
  (void)snprintf(cfg->str1, sizeof(cfg->str1), "%s", value);
}

TEST(WriterPayload, DefaultAndKindNames) {
  writer_payload_config_t cfg{};
  writer_payload_default(&cfg);
  EXPECT_EQ(cfg.kind, WRITER_PAYLOAD_NONE);
  EXPECT_STREQ(cfg.str1, "");
  EXPECT_FALSE(writer_payload_configured(&cfg));
  EXPECT_STREQ(writer_payload_kind_name(WRITER_PAYLOAD_NONE), "none");
  EXPECT_STREQ(writer_payload_kind_name(WRITER_PAYLOAD_URL_HTTPS), "url");
  EXPECT_STREQ(writer_payload_kind_name(WRITER_PAYLOAD_PLAIN_TEXT), "text");
  EXPECT_STREQ(writer_payload_kind_name(WRITER_PAYLOAD_SMS_URI), "sms");
  EXPECT_STREQ(writer_payload_kind_name(WRITER_PAYLOAD_MAILTO_URI), "mailto");
  EXPECT_STREQ(writer_payload_kind_name(WRITER_PAYLOAD_GEO_URI), "geo");
  EXPECT_STREQ(writer_payload_kind_name(WRITER_PAYLOAD_VCARD_MIME), "vcard");
  EXPECT_STREQ(writer_payload_kind_name(WRITER_PAYLOAD_WIFI_WSC), "wifi");
  EXPECT_STREQ(writer_payload_kind_name(WRITER_PAYLOAD_URI_RAW), "uri");
  EXPECT_STREQ(writer_payload_kind_name(WRITER_PAYLOAD_BT_OOB), "bt");
  EXPECT_STREQ(kind_name_from_raw_bits_for_test(999u), "?");
}

TEST(WriterPayload, NullArgsReturnZero) {
  writer_payload_config_t cfg{};
  writer_payload_default(&cfg);
  uint8_t out[32];
  EXPECT_EQ(writer_payload_ndef_len(NERO_NFC_NULL), 0u);
  EXPECT_EQ(writer_payload_build_tlv(NERO_NFC_NULL, out, sizeof(out)), 0u);
  EXPECT_EQ(writer_payload_build_tlv(&cfg, NERO_NFC_NULL, sizeof(out)), 0u);
  EXPECT_EQ(writer_payload_build_tlv(&cfg, out, 4u), 0u);
  EXPECT_EQ(writer_payload_build_ndef(NERO_NFC_NULL, out, sizeof(out)), 0u);
  EXPECT_EQ(writer_payload_build_ndef(&cfg, NERO_NFC_NULL, sizeof(out)), 0u);
  EXPECT_EQ(writer_payload_build_ndef(&cfg, out, 0u), 0u);
}

TEST(WriterPayload, UrlHttpsWellKnownTlv) {
  writer_payload_config_t cfg{};
  writer_payload_default(&cfg);
  SetUrlPayload(&cfg);
  uint8_t tlv[WRITER_NDEF_MAX_BYTES + 8];
  uint16_t n = writer_payload_build_tlv(&cfg, tlv, sizeof(tlv));
  ASSERT_GT(n, 0u);
  EXPECT_EQ(tlv[0], 0x03u);
  ASSERT_NE(tlv[1], 0xFFu);
  const uint8_t ndef_len = tlv[1];
  ASSERT_EQ(tlv[2u + ndef_len], 0xFEu);
  const uint8_t *ndef = &tlv[2];
  EXPECT_EQ(ndef[0], 0xD1u);
  EXPECT_EQ(ndef[1], 0x01u);
  EXPECT_EQ(ndef[3], 0x55u);
  EXPECT_EQ(ndef[4], 0x04u); /* https:// */
}

TEST(WriterPayload, PlainTextNdef) {
  writer_payload_config_t cfg{};
  writer_payload_default(&cfg);
  cfg.kind = WRITER_PAYLOAD_PLAIN_TEXT;
  (void)snprintf(cfg.str1, sizeof(cfg.str1), "%s", "hello");
  uint8_t ndef[64];
  uint16_t nl = writer_payload_build_ndef(&cfg, ndef, sizeof(ndef));
  ASSERT_GT(nl, 0u);
  EXPECT_EQ(ndef[0], 0xD1u);
  EXPECT_EQ(ndef[3], 0x54u);
  EXPECT_EQ(ndef[4], 0x02u);
}

TEST(WriterPayload, UriRawUsesIdentifier) {
  writer_payload_config_t cfg{};
  writer_payload_default(&cfg);
  cfg.kind = WRITER_PAYLOAD_URI_RAW;
  cfg.uri_id = 0x01u; /* http://www. */
  (void)snprintf(cfg.str1, sizeof(cfg.str1), "%s", "example.test/");
  uint8_t ndef[80];
  ASSERT_GT(writer_payload_build_ndef(&cfg, ndef, sizeof(ndef)), 0u);
  EXPECT_EQ(ndef[3], 0x55u);
  EXPECT_EQ(ndef[4], 0x01u);
}

TEST(WriterPayload, SmsWithAndWithoutBody) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_SMS_URI;
  (void)snprintf(cfg.str1, sizeof(cfg.str1), "%s", "+15551212");
  cfg.str2[0] = '\0';
  uint8_t a[160];
  ASSERT_GT(writer_payload_build_ndef(&cfg, a, sizeof(a)), 0u);
  (void)snprintf(cfg.str2, sizeof(cfg.str2), "%s", "ping");
  uint8_t b[200];
  ASSERT_GT(writer_payload_build_ndef(&cfg, b, sizeof(b)), 0u);
}

TEST(WriterPayload, MailtoSplitsSubjectBody) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_MAILTO_URI;
  (void)snprintf(cfg.str1, sizeof(cfg.str1), "%s", "dev@example.com");
  (void)snprintf(cfg.str2, sizeof(cfg.str2), "%s", "Hi|Please read");
  uint8_t out[240];
  ASSERT_GT(writer_payload_build_ndef(&cfg, out, sizeof(out)), 0u);
}

TEST(WriterPayload, GeoUri) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_GEO_URI;
  (void)snprintf(cfg.str1, sizeof(cfg.str1), "%s", "37.8,-122.4");
  uint8_t out[120];
  ASSERT_GT(writer_payload_build_ndef(&cfg, out, sizeof(out)), 0u);
}

TEST(WriterPayload, VcardMime) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_VCARD_MIME;
  (void)snprintf(cfg.str1, sizeof(cfg.str1), "%s", "Ada");
  (void)snprintf(cfg.str2, sizeof(cfg.str2), "%s", "+100|ada@example.com");
  uint8_t out[500];
  ASSERT_GT(writer_payload_build_ndef(&cfg, out, sizeof(out)), 0u);
  EXPECT_EQ(out[0], 0xD2u);
  ASSERT_GT(out[1], 0u);
  ASSERT_GT(out[2], 0u);
  const auto type_len = static_cast<size_t>(out[1]);
  const auto payload_len = static_cast<size_t>(out[2]);
  ASSERT_LT((3u + type_len + payload_len), sizeof(out));
  const std::string body(reinterpret_cast<const char *>(&out[3u + type_len]), payload_len);
  EXPECT_NE(body.find("VERSION:4.0"), std::string::npos);
}

TEST(WriterPayload, VcardRejectsControlCharInField) {
  /* [RFC6350] CR/LF in a field must be rejected (no property injection). */
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_VCARD_MIME;
  (void)snprintf(cfg.str1, sizeof(cfg.str1), "%s", "Ada\r\nFN:Eve");
  (void)snprintf(cfg.str2, sizeof(cfg.str2), "%s", "+100|ada@example.com");
  uint8_t out[500];
  EXPECT_EQ(writer_payload_build_ndef(&cfg, out, sizeof(out)), 0u);
}

TEST(WriterPayload, WifiWscHappyPath) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_WIFI_WSC;
  (void)snprintf(cfg.str1, sizeof(cfg.str1), "%s", "myssid");
  (void)snprintf(cfg.str2, sizeof(cfg.str2), "%s", "correct horse");
  uint8_t out[300];
  ASSERT_GT(writer_payload_build_ndef(&cfg, out, sizeof(out)), 0u);
}

TEST(WriterPayload, WifiWscEncodeRejectsUndersizedOutputBlob) {
  uint8_t tiny[24];
  uint16_t wlen = 0u;
  EXPECT_FALSE(writer_payload_utest_wifi_wsc_encode(tiny, sizeof(tiny), &wlen,
                                                    "myssid", "abcdefgh"));
}

TEST(WriterPayload, WifiWscEncodeAcceptsLargeEnoughBlob) {
  uint8_t blob[256];
  uint16_t wlen = 0u;
  ASSERT_TRUE(writer_payload_utest_wifi_wsc_encode(blob, sizeof(blob), &wlen,
                                                   "myssid", "abcdefgh"));
  EXPECT_GE(wlen, 40u);
  EXPECT_LE(wlen, 200u);
}

TEST(WriterPayload, WifiWscRejectsShortPsk) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_WIFI_WSC;
  (void)snprintf(cfg.str1, sizeof(cfg.str1), "%s", "myssid");
  (void)snprintf(cfg.str2, sizeof(cfg.str2), "%s", "short");
  EXPECT_EQ(writer_payload_build_ndef(&cfg, NERO_NFC_NULL, 0u), 0u);
}

TEST(WriterPayload, BtOobMacRoundTrip) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_BT_OOB;
  (void)snprintf(cfg.str1, sizeof(cfg.str1), "%s", "01:23:45:67:89:AB");
  uint8_t out[80];
  uint16_t n = writer_payload_build_ndef(&cfg, out, sizeof(out));
  ASSERT_GT(n, 0u);
  /* MIME payload begins after SR header: type length + 3. */
  size_t mime_type_len = out[1];
  size_t payload_len = out[2];
  ASSERT_EQ(payload_len, 8u);
  const uint8_t *payload = &out[3 + mime_type_len];
  /* [BT-OOB] 2-byte OOB Data Length (LSB first) then BD_ADDR LSB first. */
  EXPECT_EQ(payload[0], 0x08u);
  EXPECT_EQ(payload[1], 0x00u);
  EXPECT_EQ(payload[2], 0xABu);
  EXPECT_EQ(payload[7], 0x01u);
}

TEST(WriterPayload, BtOobRejectsBadMac) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_BT_OOB;
  (void)snprintf(cfg.str1, sizeof(cfg.str1), "%s", "GG:GG:GG:GG:GG:GG");
  uint8_t out[40];
  EXPECT_EQ(writer_payload_build_ndef(&cfg, out, sizeof(out)), 0u);
}

TEST(WriterPayload, LongNdefUsesLongTlvHeader) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_VCARD_MIME;
  /* SR-encoded MIME cannot exceed a 255-byte payload; size the FN so the vcard
   * is 242..255 bytes, yielding a total NDEF length just above the TLV short
   * length limit (254). */
  for (uint16_t i = 0u; i < 190u; ++i) {
    cfg.str1[i] = 'N';
  }
  cfg.str1[190u] = '\0';
  (void)snprintf(cfg.str2, sizeof(cfg.str2), "%s", "t|e");
  uint8_t tlv[WRITER_NDEF_MAX_BYTES + 16];
  uint16_t n = writer_payload_build_tlv(&cfg, tlv, sizeof(tlv));
  ASSERT_GT(n, 0u);
  EXPECT_EQ(tlv[0], 0x03u);
  ASSERT_EQ(tlv[1], 0xFFu)
      << "expected long TLV length form once NDEF exceeds 254 bytes";
  uint16_t inner = (uint16_t)(((uint16_t)tlv[2] << 8) | tlv[3]);
  EXPECT_GT(inner, 254u);
  EXPECT_EQ(tlv[4 + inner], 0xFEu);
}

TEST(WriterPayload, NdefRejectsOverlongUri) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_URI_RAW;
  cfg.uri_id = 0u;
  FillChar(cfg.str1, sizeof(cfg.str1), 'x');
  EXPECT_EQ(writer_payload_ndef_len(&cfg), 0u);
}

TEST(WriterPayload, NdefRejectsUnterminatedConfigStrings) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_URI_RAW;
  cfg.uri_id = 0u;
  FillChar(cfg.str1, sizeof(cfg.str1), 'u');
  cfg.str2[0] = '\0';

  EXPECT_EQ(writer_payload_ndef_len(&cfg), 0u);
}

TEST(WriterPayload, DefaultNullSafe) { writer_payload_default(NERO_NFC_NULL); }

TEST(WriterPayload, UriRawRejectsEmptyString) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_URI_RAW;
  cfg.uri_id = 0u;
  cfg.str1[0] = '\0';
  EXPECT_EQ(writer_payload_ndef_len(&cfg), 0u);
}

TEST(WriterPayload, TlvRejectsBufferTooSmallShortForm) {
  writer_payload_config_t cfg{};
  writer_payload_default(&cfg);
  SetUrlPayload(&cfg);
  uint8_t tlv[32];
  uint16_t need = writer_payload_build_tlv(&cfg, tlv, sizeof(tlv));
  ASSERT_GT(need, 0u);
  EXPECT_EQ(writer_payload_build_tlv(&cfg, tlv, (uint16_t)(need - 1u)), 0u);
}

TEST(WriterPayload, TlvRejectsBufferTooSmallLongForm) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_VCARD_MIME;
  for (uint16_t i = 0u; i < 190u; ++i) {
    cfg.str1[i] = 'N';
  }
  cfg.str1[190u] = '\0';
  (void)snprintf(cfg.str2, sizeof(cfg.str2), "%s", "t|e");
  uint8_t big[WRITER_NDEF_MAX_BYTES + 16];
  uint16_t need = writer_payload_build_tlv(&cfg, big, sizeof(big));
  ASSERT_GT(need, 0u);
  EXPECT_EQ(big[0], 0x03u);
  ASSERT_EQ(big[1], 0xFFu);
  EXPECT_EQ(writer_payload_build_tlv(&cfg, big, (uint16_t)(need - 1u)), 0u);
}

TEST(WriterPayload, PlainTextRejectsTooLong) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_PLAIN_TEXT;
  FillChar(cfg.str1, sizeof(cfg.str1), 't');
  /* 859 characters: strlen > 200 -> ndef_emit_text rejects */
  EXPECT_EQ(writer_payload_ndef_len(&cfg), 0u);
}

TEST(WriterPayload, PlainTextRejectsTinyNdefBuffer) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_PLAIN_TEXT;
  (void)snprintf(cfg.str1, sizeof(cfg.str1), "%s", "hi");
  uint8_t tiny[6];
  EXPECT_EQ(writer_payload_build_ndef(&cfg, tiny, sizeof(tiny)), 0u);
}

TEST(WriterPayload, UrlRejectsTinyNdefBuffer) {
  writer_payload_config_t cfg{};
  writer_payload_default(&cfg);
  SetUrlPayload(&cfg);
  uint8_t tiny[8];
  EXPECT_EQ(writer_payload_build_ndef(&cfg, tiny, sizeof(tiny)), 0u);
}

TEST(WriterPayload, MailtoSubjectOnly) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_MAILTO_URI;
  (void)snprintf(cfg.str1, sizeof(cfg.str1), "%s", "u@example.com");
  (void)snprintf(cfg.str2, sizeof(cfg.str2), "%s", "OnlySubject");
  uint8_t out[240];
  ASSERT_GT(writer_payload_build_ndef(&cfg, out, sizeof(out)), 0u);
}

TEST(WriterPayload, MailtoAddrOnly) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_MAILTO_URI;
  (void)snprintf(cfg.str1, sizeof(cfg.str1), "%s", "u@example.com");
  cfg.str2[0] = '\0';
  uint8_t out[120];
  ASSERT_GT(writer_payload_build_ndef(&cfg, out, sizeof(out)), 0u);
}

TEST(WriterPayload, VcardStr2WithoutSeparator) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_VCARD_MIME;
  (void)snprintf(cfg.str1, sizeof(cfg.str1), "%s", "Bob");
  (void)snprintf(cfg.str2, sizeof(cfg.str2), "%s", "+19995550000");
  uint8_t out[500];
  ASSERT_GT(writer_payload_build_ndef(&cfg, out, sizeof(out)), 0u);
}

TEST(WriterPayload, VcardRejectsOverlongMimePayload) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_VCARD_MIME;
  /* snprintf fits in vcard[400], but SR MIME record rejects payload_len > 380.
   */
  /* ~381 bytes of vCard payload once FN is 320 chars (see snprintf template in
   * writer). */
  for (uint16_t i = 0u; i < 320u; ++i) {
    cfg.str1[i] = 'V';
  }
  cfg.str1[320u] = '\0';
  (void)snprintf(cfg.str2, sizeof(cfg.str2), "%s", "t|e@x.test");
  EXPECT_EQ(writer_payload_ndef_len(&cfg), 0u);
}

TEST(WriterPayload, VcardRejectsSnprintfOverflow) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_VCARD_MIME;
  for (uint16_t i = 0u; i < 400u; ++i) {
    cfg.str1[i] = 'W';
  }
  cfg.str1[400u] = '\0';
  (void)snprintf(cfg.str2, sizeof(cfg.str2), "%s", "t|e");
  EXPECT_EQ(writer_payload_ndef_len(&cfg), 0u);
}

TEST(WriterPayload, TlvBuildFailsWhenNdefEncodesToZero) {
  writer_payload_config_t cfg{};
  poison_writer_kind(&cfg, 77);
  cfg.str1[0] = '\0';
  uint8_t out[64];
  EXPECT_EQ(writer_payload_build_tlv(&cfg, out, sizeof(out)), 0u);
}

TEST(WriterPayload, InvalidKindRejected) {
  writer_payload_config_t cfg{};
  poison_writer_kind(&cfg, 123);
  cfg.str1[0] = '\0';
  EXPECT_EQ(writer_payload_ndef_len(&cfg), 0u);
}

TEST(WriterPayload, WifiRejectsEmptySsid) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_WIFI_WSC;
  cfg.str1[0] = '\0';
  (void)snprintf(cfg.str2, sizeof(cfg.str2), "%s", "abcdefgh");
  uint8_t out[120];
  EXPECT_EQ(writer_payload_build_ndef(&cfg, out, sizeof(out)), 0u);
}

TEST(WriterPayload, WifiRejectsLongSsid) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_WIFI_WSC;
  (void)snprintf(cfg.str1, sizeof(cfg.str1), "%s",
                 "123456789012345678901234567890123"); /* 33 */
  (void)snprintf(cfg.str2, sizeof(cfg.str2), "%s", "abcdefgh");
  uint8_t out[120];
  EXPECT_EQ(writer_payload_build_ndef(&cfg, out, sizeof(out)), 0u);
}

TEST(WriterPayload, WifiRejectsShortPskLength) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_WIFI_WSC;
  (void)snprintf(cfg.str1, sizeof(cfg.str1), "%s", "ssid");
  (void)snprintf(cfg.str2, sizeof(cfg.str2), "%s", "1234567"); /* 7 chars */
  uint8_t out[120];
  EXPECT_EQ(writer_payload_build_ndef(&cfg, out, sizeof(out)), 0u);
}

TEST(WriterPayload, WifiRejectsLongPsk) {
  char psk[80];
  FillChar(psk, sizeof(psk), 'p');
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_WIFI_WSC;
  (void)snprintf(cfg.str1, sizeof(cfg.str1), "%s", "ssid");
  (void)snprintf(cfg.str2, sizeof(cfg.str2), "%s", psk); /* 79 chars */
  uint8_t out[300];
  EXPECT_EQ(writer_payload_build_ndef(&cfg, out, sizeof(out)), 0u);
}

TEST(WriterPayload, BtOobAcceptsLowercaseHex) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_BT_OOB;
  (void)snprintf(cfg.str1, sizeof(cfg.str1), "%s", "aa:bb:cc:dd:ee:ff");
  uint8_t out[80];
  ASSERT_GT(writer_payload_build_ndef(&cfg, out, sizeof(out)), 0u);
}

TEST(WriterPayload, BtOobRejectsWrongSeparator) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_BT_OOB;
  (void)snprintf(cfg.str1, sizeof(cfg.str1), "%s", "01-23-45-67-89-AB");
  uint8_t out[40];
  EXPECT_EQ(writer_payload_build_ndef(&cfg, out, sizeof(out)), 0u);
}

TEST(WriterPayload, BtOobRejectsTrailingCharacters) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_BT_OOB;
  (void)snprintf(cfg.str1, sizeof(cfg.str1), "%s", "01:23:45:67:89:AB:");
  uint8_t out[40];
  EXPECT_EQ(writer_payload_build_ndef(&cfg, out, sizeof(out)), 0u);
}

TEST(WriterPayload, MimeNdefRejectsSmallOutCap) {
  writer_payload_config_t cfg{};
  cfg.kind = WRITER_PAYLOAD_BT_OOB;
  (void)snprintf(cfg.str1, sizeof(cfg.str1), "%s", "01:23:45:67:89:AB");
  uint8_t tiny[20];
  EXPECT_EQ(writer_payload_build_ndef(&cfg, tiny, sizeof(tiny)), 0u);
}
