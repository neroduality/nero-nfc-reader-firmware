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

#include "reader_tags_ndef_decode.h"

namespace {
enum {
  kTestLit16 = 16,
  kTestLit32 = 32,
  kTestLit64 = 64,
  kTestLit9 = 9,
};
}  // namespace

#include <gtest/gtest.h>

#include <cstring>

TEST(ReaderTagsNdefDecode, UriHttpsPrefixCode) {
  static const uint8_t kPayload[] = {0x04u, 'e', 'x', 'a', 'm', 'p',
                                     'l',   'e', '.', 'c', 'o', 'm'};
  char out[kTestLit64]{};
  ASSERT_TRUE(reader_tags_decode_uri_payload(&kPayload[0], sizeof(kPayload),
                                             &out[0], sizeof(out)));
  EXPECT_STREQ(&out[0], "https://example.com");
}

TEST(ReaderTagsNdefDecode, UriRejectsUnsafeCharacter) {
  static const uint8_t kPayload[] = {0x00u, 'b', 'a', 'd', ' ', 'x'};
  char out[kTestLit32]{};
  EXPECT_FALSE(reader_tags_decode_uri_payload(&kPayload[0], sizeof(kPayload),
                                              &out[0], sizeof(out)));
}

TEST(ReaderTagsNdefDecode, UriRejectsBarePercentEscape) {
  /* [RFC3986] §2.1 — '%' must be followed by two hex digits. */
  static const uint8_t kBadTail[] = {0x00u, 'a', '%', '1'};
  static const uint8_t kBadNonhex[] = {0x00u, 'a', '%', 'g', '0'};
  static const uint8_t kOkTriplet[] = {0x00u, 'a', '%', '2', '0', 'b'};
  char out[kTestLit32]{};
  EXPECT_FALSE(reader_tags_decode_uri_payload(&kBadTail[0], sizeof(kBadTail),
                                              &out[0], sizeof(out)));
  EXPECT_FALSE(reader_tags_decode_uri_payload(
      &kBadNonhex[0], sizeof(kBadNonhex), &out[0], sizeof(out)));
  EXPECT_TRUE(reader_tags_decode_uri_payload(&kOkTriplet[0], sizeof(kOkTriplet),
                                             &out[0], sizeof(out)));
}

TEST(ReaderTagsNdefDecode, TextUtf8Payload) {
  static const uint8_t kPayload[] = {0x02u, 'e', 'n', 'h', 'i'};
  char out[kTestLit16]{};
  ASSERT_TRUE(reader_tags_decode_text_payload(&kPayload[0], sizeof(kPayload),
                                              &out[0], sizeof(out)));
  EXPECT_STREQ(&out[0], "hi");
}

TEST(ReaderTagsNdefDecode, TextUtf16Placeholder) {
  static const uint8_t kPayload[] = {0x80u, 0x02u, 'e', 'n'};
  char out[kTestLit64]{};
  ASSERT_TRUE(reader_tags_decode_text_payload(&kPayload[0], sizeof(kPayload),
                                              &out[0], sizeof(out)));
  EXPECT_STREQ(&out[0], "UTF-16 text record");
}

TEST(ReaderTagsNdefDecode, UriRejectsReservedPrefixCode) {
  static const uint8_t kPayload[] = {0x24u, 'e', 'x', 'a', 'm', 'p', 'l', 'e'};
  char out[kTestLit32]{};
  EXPECT_FALSE(reader_tags_decode_uri_payload(&kPayload[0], sizeof(kPayload),
                                              &out[0], sizeof(out)));
  EXPECT_STREQ(&out[0], "");
}

TEST(ReaderTagsNdefDecode, UriRejectsOutputAtCapacity) {
  static const uint8_t kPayload[] = {0x03u, 'h', 't', 't', 'p',
                                     ':',   '/', '/', 'a'};
  char out[kTestLit9]{};
  EXPECT_FALSE(reader_tags_decode_uri_payload(&kPayload[0], sizeof(kPayload),
                                              &out[0], sizeof(out)));
  EXPECT_STREQ(&out[0], "");
}

TEST(ReaderTagsNdefDecode, TextRejectsTruncatedLanguageCode) {
  static const uint8_t kPayload[] = {0x05u, 'e', 'n'};
  char out[kTestLit16]{};
  EXPECT_FALSE(reader_tags_decode_text_payload(&kPayload[0], sizeof(kPayload),
                                               &out[0], sizeof(out)));
  EXPECT_STREQ(&out[0], "");
}

TEST(ReaderTagsNdefDecode, UriRejectsEmbeddedNul) {
  static const uint8_t kPayload[] = {0x00u, 'o', 'k', '\0', 'x'};
  char out[kTestLit32]{};
  EXPECT_FALSE(reader_tags_decode_uri_payload(&kPayload[0], sizeof(kPayload),
                                              &out[0], sizeof(out)));
  EXPECT_STREQ(&out[0], "");
}

TEST(ReaderTagsNdefDecode, TextRejectsEmbeddedNul) {
  static const uint8_t kPayload[] = {0x02u, 'e', 'n', 'h', '\0', 'i'};
  char out[kTestLit16]{};
  EXPECT_FALSE(reader_tags_decode_text_payload(&kPayload[0], sizeof(kPayload),
                                               &out[0], sizeof(out)));
  EXPECT_STREQ(&out[0], "");
}

TEST(ReaderTagsNdefDecode, UriClearsOutputOnReject) {
  static const uint8_t kPayload[] = {0x24u, 'e', 'x', 'a', 'm', 'p', 'l', 'e'};
  char out[kTestLit32] = "keep";
  EXPECT_FALSE(reader_tags_decode_uri_payload(&kPayload[0], sizeof(kPayload),
                                              &out[0], sizeof(out)));
  EXPECT_STREQ(&out[0], "");
}
