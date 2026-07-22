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
#include "writer_serial_cli.h"

#include "writer_hal.h"

#include "nfc_runtime_mode_poll.h"
#include "nfc_hex.h"
#include "nfc_ndef_record_decode.h"
#include "nero_nfc_mem_util.h"

#include <ctype.h>
#include <stdarg.h>
#include <string.h>

#include "nero_nfc_format.h"
#include "nero_nfc_log.h"

#include "writer_payload.h"
#include "writer_context.h"

enum {
  WRITER_CLI_HEX_NIBBLE_SHIFT = 4u,
  WRITER_CLI_LONG_OPT_PREFIX_LEN = 2u,
};

#if defined(__GNUC__) || defined(__clang__)
#define CLI_PRINTF_LIKE __attribute__((format(printf, 2, 3)))
#else
#define CLI_PRINTF_LIKE
#endif

static char* writer_serial_cli_line_buf(void) {
  writer_context_t* ctx = writer_context_active();
  return (ctx == NERO_NFC_NULL) ? NERO_NFC_NULL : ctx->cli_line;
}

static bool writer_serial_cli_snprintf_buf(char* dst, size_t dst_cap,
                                           const char* fmt, ...) {
  va_list ap;
  int n;
  if ((dst == NERO_NFC_NULL) || (dst_cap == 0u)) {
    return false;
  }
  va_start(ap, fmt);
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
#endif
  n = nero_nfc_vsnprintf(dst, dst_cap, fmt, ap);
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
  va_end(ap);
  if ((n < 0) || ((size_t)(n) >= dst_cap)) {
    if (!nero_nfc_store_u8((uint8_t*)(dst), dst_cap, (size_t)(0),
                           (uint8_t)('\0'))) {
      return false;
    }
    return false;
  }
  return true;
}

static void trim(char* s, size_t cap) {
  const char* p = s;
  size_t n = 0u;

  if ((s == NERO_NFC_NULL) || (cap == 0u) ||
      !nero_nfc_bounded_strlen(s, cap, &n)) {
    return;
  }
  while ((*p != '\0') && ((unsigned char)(*p) <= ' ')) {
    p++;
  }
  if (p != s) {
    size_t consumed = (size_t)(p - s);
    (void)nero_nfc_move_bytes(s, cap, 0u, p, n - consumed + 1u);
    n -= consumed;
  }
  while ((n > 0u) && nero_nfc_span_ok(n - 1u, 1u, cap) &&
         ((unsigned char)(s[n - 1u]) <= ' ')) {
    n--;
    if (!nero_nfc_store_u8((uint8_t*)(s), cap, n, (uint8_t)('\0'))) {
      return;
    }
  }
}

static bool starts_ci(const char* s, const char* pfx) {
  while (*pfx != '\0') {
    char a = *s++;
    char b = *pfx++;
    if (a == '\0') {
      return false;
    }
    if (tolower((unsigned char)(a)) != tolower((unsigned char)(b))) {
      return false;
    }
  }
  return true;
}

static char* skip_ws(char* s) {
  while ((*s != '\0') && ((unsigned char)(*s) <= ' ')) {
    s++;
  }
  return s;
}

static bool split_pipe(char* rest, char** first, char** second, char** third) {
  *first = rest;
  *second = NERO_NFC_NULL;
  *third = NERO_NFC_NULL;
  char* p = strchr(rest, '|');
  if (p == NERO_NFC_NULL) {
    return true;
  }
  *p++ = '\0';
  *second = p;
  p = strchr(p, '|');
  if (p != NERO_NFC_NULL) {
    *p++ = '\0';
    *third = p;
  }
  return true;
}

static bool copy_field(char* dst, size_t dst_sz, const char* src) {
  size_t n = 0u;

  if ((dst == NERO_NFC_NULL) || (dst_sz == 0u)) {
    return false;
  }
  if (src == NERO_NFC_NULL) {
    if (!nero_nfc_store_u8((uint8_t*)(dst), dst_sz, 0u, (uint8_t)('\0'))) {
      return false;
    }
    return true;
  }
  if (!nero_nfc_bounded_strlen(src, WRITER_CLI_LINE_CAP, &n)) {
    if (!nero_nfc_store_u8((uint8_t*)(dst), dst_sz, 0u, (uint8_t)('\0'))) {
      return false;
    }
    return false;
  }
  if (n >= dst_sz) {
    n = dst_sz - 1u;
  }
  if (!nero_nfc_copy_bytes(dst, dst_sz, 0u, src, n)) {
    if (!nero_nfc_store_u8((uint8_t*)(dst), dst_sz, 0u, (uint8_t)('\0'))) {
      return false;
    }
    return false;
  }
  if (!nero_nfc_store_u8((uint8_t*)(dst), dst_sz, n, (uint8_t)('\0'))) {
    return false;
  }
  trim(dst, dst_sz);
  return dst[0] != '\0';
}

static void strip_https_prefix(char* s) {
  static const char HTTPS_PREFIX[] = "https://";
  enum { HTTPS_PREFIX_LEN = (int)(sizeof(HTTPS_PREFIX) - 1u) };
  if (starts_ci(s, HTTPS_PREFIX)) {
    size_t n = 0u;
    if (nero_nfc_bounded_strlen(s, WRITER_STR1_MAX, &n) &&
        (n >= (size_t)HTTPS_PREFIX_LEN)) {
      (void)nero_nfc_move_bytes(s, WRITER_STR1_MAX, 0u, s + HTTPS_PREFIX_LEN,
                                n - (size_t)HTTPS_PREFIX_LEN + 1u);
    }
  }
}

static void print_help(void) {
  nero_nfc_log_write(
      "\r\n"
      "-- NFC writer commands (serial, line oriented) --\r\n"
      "  help              This list\r\n"
      "  show              Current payload\r\n"
      "  url <host/path>   HTTPS URI (prefix stored as NDEF id 04h)\r\n"
      "  --uri=<uri>       Raw URI record (same as uri <uri>)\r\n"
      "  --text=<msg>      Plain text (same as text <msg>)\r\n"
      "  --ndef-hex=<hex>  Raw NDEF bytes\r\n"
      "  text <msg>        Plain text (RTD Text)\r\n"
      "  sms <num>|<body>  sms: URI (?body=)\r\n"
      "  mailto <addr>|<subject>|<body>\r\n"
      "  geo <lat>,<lon>   geo: URI\r\n"
      "  vcard <fn>|<tel>|<email>\r\n"
      "  wifi <ssid>|<psk> WPA2-Personal (MIME vendor WFA WSC)\r\n"
      "  bt <MAC>          Bluetooth EP OOB (AA:BB:CC:DD:EE:FF)\r\n"
      "  uri <string>      Raw URI record (no scheme abbreviation)\r\n"
      "  launch <uri>      Same as uri (e.g. Android intent:/App links)\r\n"
      "  ndef-hex <hex>    Raw NDEF message bytes (same payload as "
      "--ndef-hex)\r\n"
      "\r\n");
}

static void print_show(const writer_payload_config_t* cfg) {
  nero_nfc_log_write("  Active payload: ");
  nero_nfc_log_write(writer_payload_kind_name(cfg->kind));
  if (!writer_payload_configured(cfg)) {
    nero_nfc_log_write("\r\n  Payload not set.\r\n");
    return;
  }
  if ((cfg->kind == WRITER_PAYLOAD_RAW_NDEF) &&
      (cfg->raw_ndef != NERO_NFC_NULL)) {
    nero_nfc_log_write("\r\n  NDEF bytes: ");
    {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                              (unsigned)((uint32_t)(cfg->raw_ndef_len)));
      nero_nfc_log_write(ndc);
    }
    nero_nfc_log_write("\r\n");
    return;
  }
  if (cfg->str1[0] != '\0') {
    nero_nfc_log_write("\r\n  Value: ");
    nero_nfc_log_write(cfg->str1);
  }
  if (cfg->str2[0] != '\0') {
    nero_nfc_log_write("\r\n  Extra: ");
    nero_nfc_log_write(cfg->str2);
  }
  nero_nfc_log_write("\r\n");
}

static bool line_eq_ci(const char* s, const char* want) {
  while (*want != '\0') {
    if (tolower((unsigned char)(*s)) != tolower((unsigned char)(*want))) {
      return false;
    }
    if (*s == '\0') {
      return false;
    }
    s++;
    want++;
  }
  return *s == '\0';
}

static void clear_raw_ndef(writer_payload_config_t* cfg) {
  if ((cfg != NERO_NFC_NULL) && (cfg->raw_ndef != NERO_NFC_NULL)) {
    nero_nfc_secure_clear(cfg->raw_ndef, cfg->raw_ndef_len);
    cfg->raw_ndef = NERO_NFC_NULL;
  }
  if (cfg != NERO_NFC_NULL) {
    cfg->raw_ndef_len = 0u;
  }
}

static bool hex_nibble(char c, uint8_t* out) {
  if (out == NERO_NFC_NULL) {
    return false;
  }
  const int v = nfc_hex_nibble((uint8_t)(c));
  if (v < 0) {
    return false;
  }
  *out = (uint8_t)(v);
  return true;
}

static bool parse_hex_bytes(const char* text, uint8_t* out, uint16_t out_cap,
                            uint16_t* out_len) {
  uint16_t n = 0u;
  uint8_t hi = 0u;
  bool have_hi = false;

  if (out_len != NERO_NFC_NULL) {
    *out_len = 0u;
  }
  if ((text == NERO_NFC_NULL) || (out_len == NERO_NFC_NULL) ||
      (out_cap == 0u)) {
    return false;
  }
  for (const char* p = text; *p != '\0'; ++p) {
    if ((*p == ' ') || (*p == ':') || (*p == '-') || (*p == '_')) {
      continue;
    }
    uint8_t v = 0u;
    if (!hex_nibble(*p, &v)) {
      if (out != NERO_NFC_NULL) {
        nero_nfc_secure_clear(out, n);
      }
      return false;
    }
    if (!have_hi) {
      hi = v;
      have_hi = true;
      continue;
    }
    if (n >= out_cap) {
      return false;
    }
    if (out != NERO_NFC_NULL) {
      if (!nero_nfc_store_u8(
              out, (size_t)(out_cap), (size_t)(n),
              (uint8_t)((hi << WRITER_CLI_HEX_NIBBLE_SHIFT) | v))) {
        return false;
      }
    }
    n++;
    have_hi = false;
  }
  if (have_hi || n == 0u) {
    if (out != NERO_NFC_NULL) {
      nero_nfc_secure_clear(out, n);
    }
    return false;
  }
  *out_len = n;
  return true;
}

static bool writer_cli_apply_command(writer_payload_config_t* cfg,
                                     const char* cmd, char* rest) {
  writer_context_t* ctx = writer_context_active();
  bool updated = true;

  if (ctx == NERO_NFC_NULL) {
    return false;
  }

  if (starts_ci(cmd, "url")) {
    cfg->uri_id = (uint8_t)(NFC_NDEF_URI_PREFIX_HTTPS);
    if (!copy_field(cfg->str1, sizeof(cfg->str1), rest)) {
      nero_nfc_log_write("  url: missing path/host\r\n");
      updated = false;
    } else {
      strip_https_prefix(cfg->str1);
      cfg->str2[0] = '\0';
      cfg->kind = WRITER_PAYLOAD_URL_HTTPS;
    }
  } else if (starts_ci(cmd, "text") || starts_ci(cmd, "data")) {
    cfg->uri_id = 0u;
    if (!copy_field(cfg->str1, sizeof(cfg->str1), rest)) {
      nero_nfc_log_write("  text: missing message\r\n");
      updated = false;
    } else {
      cfg->str2[0] = '\0';
      cfg->kind = WRITER_PAYLOAD_PLAIN_TEXT;
    }
  } else if (starts_ci(cmd, "phone") || starts_ci(cmd, "phone-number")) {
    cfg->uri_id = 0u;
    char uri[WRITER_STR1_MAX];
    if (rest[0] == '\0' ||
        !writer_serial_cli_snprintf_buf(uri, sizeof(uri), "tel:%s", rest) ||
        !copy_field(cfg->str1, sizeof(cfg->str1), uri)) {
      nero_nfc_log_write("  phone: missing number\r\n");
      updated = false;
    } else {
      cfg->str2[0] = '\0';
      cfg->kind = WRITER_PAYLOAD_URI_RAW;
    }
  } else if (starts_ci(cmd, "sms")) {
    cfg->uri_id = 0u;
    char* a = NERO_NFC_NULL;
    char* b = NERO_NFC_NULL;
    char* c = NERO_NFC_NULL;
    (void)split_pipe(rest, &a, &b, &c);
    (void)c;
    if (!copy_field(cfg->str1, sizeof(cfg->str1), a)) {
      nero_nfc_log_write("  sms: missing number\r\n");
      updated = false;
    } else {
      (void)copy_field(cfg->str2, sizeof(cfg->str2),
                       (b != NERO_NFC_NULL) ? b : "");
      cfg->kind = WRITER_PAYLOAD_SMS_URI;
    }
  } else if (starts_ci(cmd, "mailto") || starts_ci(cmd, "mail")) {
    cfg->uri_id = 0u;
    char* addr = NERO_NFC_NULL;
    char* subj = NERO_NFC_NULL;
    char* body = NERO_NFC_NULL;
    (void)split_pipe(rest, &addr, &subj, &body);
    if (!copy_field(cfg->str1, sizeof(cfg->str1), addr)) {
      nero_nfc_log_write("  mailto: missing address\r\n");
      updated = false;
    } else {
      char combined[WRITER_STR2_MAX];
      combined[0] = '\0';
      if ((subj != NERO_NFC_NULL) && (body != NERO_NFC_NULL)) {
        (void)writer_serial_cli_snprintf_buf(combined, sizeof(combined),
                                             "%s|%s", subj, body);
      } else if (subj != NERO_NFC_NULL) {
        (void)writer_serial_cli_snprintf_buf(combined, sizeof(combined), "%s",
                                             subj);
      }
      (void)copy_field(cfg->str2, sizeof(cfg->str2), combined);
      cfg->kind = WRITER_PAYLOAD_MAILTO_URI;
    }
  } else if (starts_ci(cmd, "geo") || starts_ci(cmd, "location") ||
             starts_ci(cmd, "custom-location")) {
    cfg->uri_id = 0u;
    if (!copy_field(cfg->str1, sizeof(cfg->str1), rest)) {
      nero_nfc_log_write("  geo: missing coordinates\r\n");
      updated = false;
    } else {
      cfg->str2[0] = '\0';
      cfg->kind = WRITER_PAYLOAD_GEO_URI;
    }
  } else if (starts_ci(cmd, "vcard") || starts_ci(cmd, "contact")) {
    cfg->uri_id = 0u;
    char* fn = NERO_NFC_NULL;
    char* tel = NERO_NFC_NULL;
    char* email = NERO_NFC_NULL;
    (void)split_pipe(rest, &fn, &tel, &email);
    if (!copy_field(cfg->str1, sizeof(cfg->str1), fn)) {
      nero_nfc_log_write("  vcard: missing display name\r\n");
      updated = false;
    } else {
      char combo[WRITER_STR2_MAX];
      combo[0] = '\0';
      if ((tel != NERO_NFC_NULL) && (email != NERO_NFC_NULL)) {
        (void)writer_serial_cli_snprintf_buf(combo, sizeof(combo), "%s|%s", tel,
                                             email);
      } else if (tel != NERO_NFC_NULL) {
        (void)writer_serial_cli_snprintf_buf(combo, sizeof(combo), "%s", tel);
      }
      if (!copy_field(cfg->str2, sizeof(cfg->str2), combo)) {
        nero_nfc_log_write("  vcard: missing tel (use name|tel|email)\r\n");
        updated = false;
      } else {
        cfg->kind = WRITER_PAYLOAD_VCARD_MIME;
      }
    }
  } else if (starts_ci(cmd, "wifi")) {
    cfg->uri_id = 0u;
    char* ssid = NERO_NFC_NULL;
    char* psk = NERO_NFC_NULL;
    char* z = NERO_NFC_NULL;
    (void)split_pipe(rest, &ssid, &psk, &z);
    (void)z;
    if (!copy_field(cfg->str1, sizeof(cfg->str1), ssid) ||
        !copy_field(cfg->str2, sizeof(cfg->str2), psk)) {
      nero_nfc_log_write("  wifi: need ssid|psk (WPA2 PSK 8..63 chars)\r\n");
      updated = false;
    } else {
      cfg->kind = WRITER_PAYLOAD_WIFI_WSC;
    }
  } else if (starts_ci(cmd, "bt") || starts_ci(cmd, "bluetooth")) {
    cfg->uri_id = 0u;
    if (!copy_field(cfg->str1, sizeof(cfg->str1), rest)) {
      nero_nfc_log_write("  bt: missing AA:BB:CC:DD:EE:FF\r\n");
      updated = false;
    } else {
      cfg->str2[0] = '\0';
      cfg->kind = WRITER_PAYLOAD_BT_OOB;
    }
  } else if (starts_ci(cmd, "search")) {
    cfg->uri_id = 0x00u;
    char uri[WRITER_STR1_MAX];
    if (rest[0] == '\0' ||
        !writer_serial_cli_snprintf_buf(
            uri, sizeof(uri), "https://www.google.com/search?q=%s", rest) ||
        !copy_field(cfg->str1, sizeof(cfg->str1), uri)) {
      nero_nfc_log_write("  search: missing query\r\n");
      updated = false;
    } else {
      cfg->str2[0] = '\0';
      cfg->kind = WRITER_PAYLOAD_URI_RAW;
    }
  } else if (starts_ci(cmd, "address") ||
             starts_ci(cmd, "destination-address")) {
    cfg->uri_id = 0x00u;
    char uri[WRITER_STR1_MAX];
    const char* pfx =
        starts_ci(cmd, "destination-address")
            ? "https://www.google.com/maps/dir/?api=1&destination="
            : "https://www.google.com/maps/search/?api=1&query=";
    if (rest[0] == '\0' ||
        !writer_serial_cli_snprintf_buf(uri, sizeof(uri), "%s%s", pfx, rest) ||
        !copy_field(cfg->str1, sizeof(cfg->str1), uri)) {
      nero_nfc_log_write("  address: missing text\r\n");
      updated = false;
    } else {
      cfg->str2[0] = '\0';
      cfg->kind = WRITER_PAYLOAD_URI_RAW;
    }
  } else if (starts_ci(cmd, "launch") || starts_ci(cmd, "uri") ||
             starts_ci(cmd, "link") || starts_ci(cmd, "unit-link") ||
             starts_ci(cmd, "social") || starts_ci(cmd, "video") ||
             starts_ci(cmd, "file") || starts_ci(cmd, "application")) {
    cfg->uri_id = 0x00u;
    if (!copy_field(cfg->str1, sizeof(cfg->str1), rest)) {
      nero_nfc_log_write("  uri: missing string\r\n");
      updated = false;
    } else {
      cfg->str2[0] = '\0';
      cfg->kind = WRITER_PAYLOAD_URI_RAW;
    }
  } else if (starts_ci(cmd, "ndef-hex")) {
    uint16_t raw_len = 0u;
    if (!parse_hex_bytes(rest, NERO_NFC_NULL, (uint16_t)(sizeof(ctx->raw_ndef)),
                         &raw_len) ||
        !parse_hex_bytes(rest, ctx->raw_ndef, (uint16_t)(sizeof(ctx->raw_ndef)),
                         &raw_len)) {
      nero_nfc_log_write(
          "  ndef-hex: invalid or oversized hex NDEF message\r\n");
      updated = false;
    } else {
      cfg->raw_ndef = ctx->raw_ndef;
      cfg->raw_ndef_len = raw_len;
      cfg->str1[0] = '\0';
      cfg->str2[0] = '\0';
      cfg->kind = WRITER_PAYLOAD_RAW_NDEF;
    }
  } else {
    nero_nfc_log_write("  Unknown command (try help)\r\n");
    updated = false;
  }

  return updated;
}

static bool handle_line(writer_payload_config_t* cfg, char* line) {
  trim(line, WRITER_CLI_LINE_CAP);
  if (nero_nfc_u8_at((const uint8_t*)(line), (size_t)(WRITER_CLI_LINE_CAP),
                     0u) == (uint8_t)('\0')) {
    return false;
  }
  if ((nero_nfc_u8_at((const uint8_t*)(line), (size_t)(WRITER_CLI_LINE_CAP),
                      0u) == (uint8_t)('-')) &&
      (nero_nfc_u8_at((const uint8_t*)(line), (size_t)(WRITER_CLI_LINE_CAP),
                      1u) == (uint8_t)('-'))) {
    line += WRITER_CLI_LONG_OPT_PREFIX_LEN;
    char* eq = strchr(line, '=');
    if (eq != NERO_NFC_NULL) {
      *eq = ' ';
    }
  }

  /* Host `reader` / `writer` launchers probe combined mode over UART — ignore
   * on standalone. */
  if (line_eq_ci(line, "mode reader") || line_eq_ci(line, "mode writer")) {
    return false;
  }

  char* cmd = line;
  char* rest = line;
  while (*rest > ' ') {
    rest++;
  }
  if (*rest != '\0') {
    *rest++ = '\0';
    rest = skip_ws(rest);
  }
  trim(cmd, WRITER_CLI_LINE_CAP);

  if (starts_ci(cmd, "help") || starts_ci(cmd, "?")) {
    print_help();
    return false;
  }
  if (starts_ci(cmd, "show")) {
    print_show(cfg);
    return false;
  }

  bool updated = writer_cli_apply_command(cfg, cmd, rest);

  if (updated) {
    if (cfg->kind != WRITER_PAYLOAD_RAW_NDEF) {
      clear_raw_ndef(cfg);
    }
    uint16_t nl = writer_payload_ndef_len(cfg);
    if (nl == 0u) {
      nero_nfc_log_write("  ERROR: payload does not fit encoder rules\r\n");
      updated = false;
    }
  }

  return updated;
}

void writer_serial_cli_init(void) {
  writer_context_t* ctx = writer_context_active();
  char* line = writer_serial_cli_line_buf();
  if (ctx == NERO_NFC_NULL) {
    return;
  }
  ctx->cli_line_len = 0u;
  ctx->cli_line_overflow = false;
#if defined(NERO_RAM_CONSTRAINED)
  if (line != NERO_NFC_NULL) {
    if (!nero_nfc_store_u8((uint8_t*)(line), (size_t)(WRITER_CLI_LINE_CAP), 0u,
                           (uint8_t)('\0'))) {
      return;
    }
  }
#else
  if (!nero_nfc_store_u8((uint8_t*)(line), (size_t)(WRITER_CLI_LINE_CAP), 0u,
                         (uint8_t)('\0'))) {
    return;
  }
#endif
}

bool writer_serial_cli_poll(writer_payload_config_t* cfg) {
  writer_context_t* ctx = writer_context_active();
  bool changed = false;
  char* line = writer_serial_cli_line_buf();

#if defined(NERO_RAM_CONSTRAINED)
  if ((ctx == NERO_NFC_NULL) || (cfg == NERO_NFC_NULL) ||
      (line == NERO_NFC_NULL)) {
    return false;
  }
#else
  if ((ctx == NERO_NFC_NULL) || (cfg == NERO_NFC_NULL)) {
    return false;
  }
#endif
  if (nfc_app_poll_mode_switch()) {
    return changed;
  }
  /*
   * One byte per call: combined firmware (`nfc.ino`) runs `nfc_app_loop()` →
   * preload + `scan_mode_switch()` before this. If we drain the whole RX ring
   * in one pass, we can swallow a "mode reader" / "mode writer" line that
   * follows stray bytes the scanner returned to the buffer (prefix mismatch) in
   * the same iteration — a standalone `mode …` send then appears to do nothing.
   */
  if (!writer_hal_serial_available()) {
    return changed;
  }
  int c = writer_hal_serial_read_byte();
  if (c < 0) {
    return changed;
  }
  char ch = (char)(c);
  if ((ch == '\r') || (ch == '\n')) {
    if (ctx->cli_line_overflow) {
      nero_nfc_log_write("  ERROR: serial command too long; discarded.\r\n");
      ctx->cli_line_overflow = false;
      ctx->cli_line_len = 0u;
      return changed;
    }
    if (ctx->cli_line_len > 0u) {
      line[ctx->cli_line_len] = '\0';
      if (handle_line(cfg, line)) {
        nero_nfc_log_write("  OK — payload updated; tap tag to write.\r\n");
        print_show(cfg);
        changed = true;
      }
      ctx->cli_line_len = 0u;
    }
    return changed;
  }
  if ((unsigned char)(ch) < ' ') {
    return changed;
  }
  if (ctx->cli_line_len < (WRITER_CLI_LINE_CAP - 1u)) {
    line[ctx->cli_line_len++] = ch;
  } else {
    ctx->cli_line_overflow = true;
  }
  return changed;
}

/* Device CCID is reader-only: omit writer TU bodies so UNO RAM fits.
 * CDC keeps identical library commands; host tests keep writer bodies. */
#if !defined(NERO_CCID_USB_BUILD) || defined(NERO_HOST_UNIT_TEST_HOOKS)

#endif /* !CCID device || host tests */
