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
#include "nero_nfc_line_pump.h"

#include <gtest/gtest.h>

using nero_nfc::extract_browser_url;
using nero_nfc::is_browser_line;
using nero_nfc::LinePump;
using nero_nfc::strip_cr;

// ── strip_cr
// ──────────────────────────────────────────────────────────────────

TEST(StripCr, EmptyString) { EXPECT_EQ(strip_cr(""), ""); }

TEST(StripCr, NoCarriageReturn) { EXPECT_EQ(strip_cr("hello"), "hello"); }

TEST(StripCr, TrailingCrRemoved) { EXPECT_EQ(strip_cr("hello\r"), "hello"); }

TEST(StripCr, MidCrUntouched) { EXPECT_EQ(strip_cr("hel\rlo"), "hel\rlo"); }

// ── is_browser_line
// ───────────────────────────────────────────────────────────

TEST(IsBrowserLine, NotBrowserLine) {
  EXPECT_FALSE(is_browser_line("TAG:abcdef"));
}

TEST(IsBrowserLine, BrowserLine) {
  EXPECT_TRUE(is_browser_line("BROWSER_OPEN:https://example.com"));
}

TEST(IsBrowserLine, EmptyString) { EXPECT_FALSE(is_browser_line("")); }

// ── extract_browser_url
// ───────────────────────────────────────────────────────

TEST(ExtractBrowserUrl, ExtractsUrl) {
  EXPECT_EQ(extract_browser_url("BROWSER_OPEN:https://example.com"),
            "https://example.com");
}

TEST(ExtractBrowserUrl, NonBrowserLineReturnsEmpty) {
  EXPECT_EQ(extract_browser_url("TAG:abcdef"), "");
}

TEST(ExtractBrowserUrl, EmptyUrl) {
  EXPECT_EQ(extract_browser_url("BROWSER_OPEN:"), "");
}

// ── LinePump
// ──────────────────────────────────────────────────────────────────

TEST(LinePump, SingleLineLF) {
  std::vector<std::string> lines;
  LinePump pump([&](const std::string &l) { lines.push_back(l); });
  const char *data = "hello\n";
  pump.feed(data, strlen(data));
  ASSERT_EQ(lines.size(), 1u);
  EXPECT_EQ(lines[0], "hello");
}

TEST(LinePump, CRLFStripped) {
  std::vector<std::string> lines;
  LinePump pump([&](const std::string &l) { lines.push_back(l); });
  const char *data = "hello\r\n";
  pump.feed(data, strlen(data));
  ASSERT_EQ(lines.size(), 1u);
  EXPECT_EQ(lines[0], "hello");
}

TEST(LinePump, MultipleLines) {
  std::vector<std::string> lines;
  LinePump pump([&](const std::string &l) { lines.push_back(l); });
  const char *data = "line1\nline2\nline3\n";
  pump.feed(data, strlen(data));
  ASSERT_EQ(lines.size(), 3u);
  EXPECT_EQ(lines[0], "line1");
  EXPECT_EQ(lines[1], "line2");
  EXPECT_EQ(lines[2], "line3");
}

TEST(LinePump, PartialLinesAcrossFeeds) {
  std::vector<std::string> lines;
  LinePump pump([&](const std::string &l) { lines.push_back(l); });
  pump.feed("hel", 3);
  EXPECT_TRUE(lines.empty());
  pump.feed("lo\n", 3);
  ASSERT_EQ(lines.size(), 1u);
  EXPECT_EQ(lines[0], "hello");
}

TEST(LinePump, BrowserLineDetectedInCallback) {
  std::vector<std::string> browser_urls;
  LinePump pump([&](const std::string &l) {
    if (is_browser_line(l)) {
      browser_urls.push_back(extract_browser_url(l));
    }
  });
  const char *data = "BROWSER_OPEN:https://auth.example.com/login\n";
  pump.feed(data, strlen(data));
  ASSERT_EQ(browser_urls.size(), 1u);
  EXPECT_EQ(browser_urls[0], "https://auth.example.com/login");
}

TEST(LinePump, OverflowDropsExcessBytes) {
  std::vector<std::string> lines;
  LinePump pump([&](const std::string &l) { lines.push_back(l); });
  // Feed kMaxBufBytes + 100 bytes without a newline, then a newline.
  std::string overflow(LinePump::kMaxBufBytes + 100, 'A');
  overflow.push_back('\n');
  pump.feed(overflow.data(), overflow.size());
  // One line emitted, capped at kMaxBufBytes characters.
  ASSERT_EQ(lines.size(), 1u);
  EXPECT_EQ(lines[0].size(), LinePump::kMaxBufBytes);
}

TEST(LinePump, NoPendingBytesAfterFullLine) {
  LinePump pump([](const std::string &) {});
  const char *data = "abc\n";
  pump.feed(data, strlen(data));
  EXPECT_EQ(pump.pendingBytes(), 0u);
}

TEST(LinePump, PendingBytesAfterPartialLine) {
  LinePump pump([](const std::string &) {});
  pump.feed("abc", 3);
  EXPECT_EQ(pump.pendingBytes(), 3u);
}
