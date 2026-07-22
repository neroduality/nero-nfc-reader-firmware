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

// Unit tests for nero_nfc_line_pump (line accumulator + browser trigger).
// These run on the host with GoogleTest; no hardware required.
//
#include "nero_nfc_line_pump.hpp"

namespace {
enum {
  kTestLit100 = 100,
  kTestLit3 = 3,
};
}  // namespace

#include <gtest/gtest.h>

using nero_nfc::ExtractBrowserUrl;
using nero_nfc::IsBrowserLine;
using nero_nfc::LinePump;
using nero_nfc::StripCr;

// ── strip_cr
// ──────────────────────────────────────────────────────────────────

TEST(StripCr, EmptyString) { EXPECT_EQ(StripCr(""), ""); }

TEST(StripCr, NoCarriageReturn) { EXPECT_EQ(StripCr("hello"), "hello"); }

TEST(StripCr, TrailingCrRemoved) { EXPECT_EQ(StripCr("hello\r"), "hello"); }

TEST(StripCr, MidCrUntouched) { EXPECT_EQ(StripCr("xyz\rlo"), "xyz\rlo"); }

// ── is_browser_line
// ───────────────────────────────────────────────────────────

TEST(IsBrowserLine, NotBrowserLine) {
  EXPECT_FALSE(IsBrowserLine("TAG:abcdef"));
}

TEST(IsBrowserLine, BrowserLine) {
  EXPECT_TRUE(IsBrowserLine("BROWSER_OPEN:https://example.com"));
}

TEST(IsBrowserLine, EmptyString) { EXPECT_FALSE(IsBrowserLine("")); }

// ── extract_browser_url
// ───────────────────────────────────────────────────────

TEST(ExtractBrowserUrl, ExtractsUrl) {
  EXPECT_EQ(ExtractBrowserUrl("BROWSER_OPEN:https://example.com"),
            "https://example.com");
}

TEST(ExtractBrowserUrl, NonBrowserLineReturnsEmpty) {
  EXPECT_EQ(ExtractBrowserUrl("TAG:abcdef"), "");
}

TEST(ExtractBrowserUrl, EmptyUrl) {
  EXPECT_EQ(ExtractBrowserUrl("BROWSER_OPEN:"), "");
}

// ── LinePump
// ──────────────────────────────────────────────────────────────────

TEST(LinePump, SingleLineLF) {
  std::vector<std::string> lines;
  LinePump pump([&](const std::string& l) { lines.push_back(l); });
  const char* data = "hello\n";
  pump.Feed(data, strlen(data));
  ASSERT_EQ(lines.size(), 1u);
  EXPECT_EQ(lines[0], "hello");
}

TEST(LinePump, CRLFStripped) {
  std::vector<std::string> lines;
  LinePump pump([&](const std::string& l) { lines.push_back(l); });
  const char* data = "hello\r\n";
  pump.Feed(data, strlen(data));
  ASSERT_EQ(lines.size(), 1u);
  EXPECT_EQ(lines[0], "hello");
}

TEST(LinePump, MultipleLines) {
  std::vector<std::string> lines;
  LinePump pump([&](const std::string& l) { lines.push_back(l); });
  const char* data = "line1\nline2\nline3\n";
  pump.Feed(data, strlen(data));
  ASSERT_EQ(lines.size(), 3u);
  EXPECT_EQ(lines[0], "line1");
  EXPECT_EQ(lines[1], "line2");
  EXPECT_EQ(lines[2], "line3");
}

TEST(LinePump, PartialLinesAcrossFeeds) {
  std::vector<std::string> lines;
  LinePump pump([&](const std::string& l) { lines.push_back(l); });
  pump.Feed("abc", kTestLit3);
  EXPECT_TRUE(lines.empty());
  pump.Feed("de\n", kTestLit3);
  ASSERT_EQ(lines.size(), 1u);
  EXPECT_EQ(lines[0], "abcde");
}

TEST(LinePump, BrowserLineDetectedInCallback) {
  std::vector<std::string> browser_urls;
  LinePump pump([&](const std::string& l) {
    if (IsBrowserLine(l)) {
      browser_urls.push_back(ExtractBrowserUrl(l));
    }
  });
  const char* data = "BROWSER_OPEN:https://auth.example.com/login\n";
  pump.Feed(data, strlen(data));
  ASSERT_EQ(browser_urls.size(), 1u);
  EXPECT_EQ(browser_urls[0], "https://auth.example.com/login");
}

TEST(LinePump, OverflowDropsExcessBytes) {
  std::vector<std::string> lines;
  LinePump pump([&](const std::string& l) { lines.push_back(l); });
  // Feed kMaxBufBytes + 100 bytes without a newline, then a newline.
  std::string overflow(LinePump::kMaxBufBytes + kTestLit100, 'A');
  overflow.push_back('\n');
  pump.Feed(overflow.data(), overflow.size());
  // Oversized lines are dropped entirely (not truncated and emitted).
  EXPECT_TRUE(lines.empty());
  EXPECT_EQ(pump.PendingBytes(), 0u);

  // A subsequent in-budget line must still be delivered.
  pump.Feed("ok\n", kTestLit3);
  ASSERT_EQ(lines.size(), 1u);
  EXPECT_EQ(lines[0], "ok");
}

TEST(LinePump, NoPendingBytesAfterFullLine) {
  LinePump pump([](const std::string&) {});
  const char* data = "abc\n";
  pump.Feed(data, strlen(data));
  EXPECT_EQ(pump.PendingBytes(), 0u);
}

TEST(LinePump, PendingBytesAfterPartialLine) {
  LinePump pump([](const std::string&) {});
  pump.Feed("abc", kTestLit3);
  EXPECT_EQ(pump.PendingBytes(), 3u);
}
