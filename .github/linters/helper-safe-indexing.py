#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2026 Nero Duality, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Safe indexing policy — checked helpers for external buffers (firmware/userspace/tests).

This is an ADDITIONAL anti-drift / defense-in-depth gate layered on top of the real
memory-safety controls (the nero_nfc_span_ok / try_add_* / nero_nfc_copy_bytes helpers,
ASan/UBSan/TSan/Valgrind in `make verify`, clang-tidy bounds + cppcheck, and the host
unit tests). It is a regex heuristic, NOT a sound bounds verifier — see Limitations.

Rules:
  1. No variable subscript / deep literal subscript on external wire buffers unless the
     enclosing function uses a checked helper, an explicit length/cap guard, a bounded
     loop, or the file is a canonical wire-format parser.
     (Raw memcpy/memmove/memset + heap: see helper-unsafe-memory.py.)
  2. No unchecked ``&apdu[n]`` / ``buf + n`` data pointers without span_ok or ISO7816 helper.
  3. Variable-index writes (``buf[pos++] = …``) require span_ok / try_add_* / safe_copy in
     the same function unless canonical.

Limitations (by construction — do not treat a green result as a proof of bounds safety):
  * Guard detection is function-WIDE, not variable/flow-sensitive: any recognized guard
    token anywhere in a function clears every subscript in that function.
  * External-buffer recognition is a curated identifier list (EXTERNAL_BUFFER_IDS);
    buffers named outside that list are not inspected.
  * A literal index within the ISO7816 header window is always allowed.
  These gaps are accepted because real bounds safety is enforced by the helpers, the
  sanitizer/Valgrind profiles, and clang-tidy/cppcheck — this gate only catches drift.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

_LINT_DIR = Path(__file__).resolve().parent
if str(_LINT_DIR) not in sys.path:
    sys.path.insert(0, str(_LINT_DIR))

from nero_lint_policy import (
    CANONICAL_INDEX_FILES,
    FIDO_APP_AID_DRIFT_ALLOW,
    SKIP_DIR_NAMES,
    SOURCE_SUFFIXES,
    is_canonical_index_file,
    is_test_file,
    iter_scan_root_files,
    strip_comments_and_strings,
)

MEM_UTIL_FILE = "nero_nfc_mem_util.h"
ISO7816_HEADER_MAX = 4

GUARD_TOKENS = (
    "nero_nfc_span_ok(",
    "nero_nfc_copy_bytes(",
    "nero_nfc_move_bytes(",
    "nero_nfc_try_add_size(",
    "nero_nfc_try_add_u16(",
    "nero_nfc_try_sub_size(",
    "nfc_iso7816_apdu_min_len(",
    "nfc_iso7816_apdu_lc(",
    "nfc_iso7816_apdu_lc_body_ok(",
    "nfc_iso7816_apdu_lc_body_with_le_ok(",
    "nfc_iso7816_apdu_data_ptr(",
    "nfc_iso7816_apdu_read_binary(",
    "nfc_iso7816_apdu_update_binary(",
    "nfc_iso7816_append_sw(",
    "nfc_iso7816_response_sw(",
    "nfc_iso7816_response_sw_ok(",
    "nfc_iso7816_response_wrong_length(",
    "nfc_iso7816_response_more_data(",
    "nfc_pcsc_build_select_aid_apdu(",
    "nfc_ndef_record_next(",
    "nfc_tag_type4_apply_cc(",
    "nfc_ndef_tlv_next(",
    "nfc_ndef_find_message_tlv(",
    "nfc_ndef_build_message_tlv(",
    "nfc_ccid_frame_",
    "reader_ccid_append_status(",
)

GUARD_REGEXES = (
    re.compile(r"\b(?:\w*len|\w*cap|rlen|count|size|total|need|end_offset|declared_total|"
               r"response_len|rsp_need|max_storage_len|pos|nstd|hdr_skip|nad_idx)\s*[<>!=]=\s*"),
    re.compile(r"\b(?:apdu_len|frame_len|buf_len|data_len|rsp_len|dst_cap|rsp_cap|buf_cap|"
               r"dst_len|src_len)\s*[<>!=]=\s*"),
    re.compile(r"for\s*\([^;]*;\s*[^;]*<\s*(?:len|n|cap|\w+_len|\w+_cap|sizeof\s*\()"),
    re.compile(r"while\s*\(\s*\w+\s*<\s*(?:len|cap|\w+_len|\w+_cap|sizeof\s*\()"),
    re.compile(r"\bstd::min\s*\("),
    re.compile(r"\b(?:sizeof|static_cast<unsigned>\(sizeof)\s*\("),
    # C++ container bounds guard (e.g. `if (pos + 2u >= atr.size())`, `uid.size() == 8u`).
    re.compile(r"\.size\s*\(\s*\)"),
)

EXTERNAL_BUFFER_IDS = (
    "apdu",
    "capdu",
    "rapdu",
    "rsp",
    "resp",
    "frame",
    "cmd",
    "raw",
    "data",
    "buf",
    "cc",
    "dst",
    "src",
    "payload",
    "ndef",
    "tlv",
    "rx",
    "tx",
    "atr",
    "g_storage_ndef_cache",
)

RAW_MEM = re.compile(r"(?:::)?\b(memcpy|memmove)\s*\(")
SAFE_INDEX_SKIP_DIR_NAMES = SKIP_DIR_NAMES - frozenset({"st25r3916"})

ARRAY_DECL = re.compile(
    rf"\b(?:static\s+)?(?:const\s+)?"
    rf"(?:std::)?(?:u?int(?:8|16|32|64)_t|byte|char|unsigned\s+char)\s+"
    rf"(?:{'|'.join(EXTERNAL_BUFFER_IDS)})\s*\[[^\]]+\]\s*(?:[=;])"
)
SUBSCRIPT = re.compile(
    rf"\b(?:{'|'.join(EXTERNAL_BUFFER_IDS)})\[([^\]]+)\]"
)
DATA_PTR = re.compile(
    rf"(?:&(?:{'|'.join(EXTERNAL_BUFFER_IDS)})\[(\d+[uU]?)\]|"
    rf"(?:{'|'.join(EXTERNAL_BUFFER_IDS)})\s*\+\s*(\d+[uU]?))"
)
LITERAL_INDEX = re.compile(r"^(\d+)[uU]?$")
LOOP_INDEX = re.compile(r"for\s*\(\s*(?:uint\d+_t\s+)?(\w+)\s*=")
BOUNDED_LOOP = re.compile(
    rf"for\s*\(\s*(?:uint\d+_t\s+)?(\w+)\s*=\s*[^;]*;\s*\1\s*<\s*([^;)]+)"
)
WRITE_SUBSCRIPT = re.compile(
    rf"\b(?:{'|'.join(EXTERNAL_BUFFER_IDS)})\[([^\]]+)\]\s*(?:\+\+|--)?\s*="
)

# Anti-drift: app code must use shared ISO7816 / APDU helpers instead of re-learning wire layout.
RESP_SW_DRIFT = re.compile(r"\bresp\[(?:rlen|total|normalized_len)\s*-\s*[12]\]")
APDU_LC_ASSIGN_DRIFT = re.compile(r"\bapdu\[4\]\s*=(?!=)")
NDEF_WALK_DRIFT = re.compile(r"\(\s*hdr\s*&\s*0x10u\s*\)")
NDEF_APP_AID_V0_DRIFT = re.compile(r"\bNFC_PCSC_NDEF_APP_AID_V0\b")
FIDO_APP_AID_DRIFT = re.compile(r"\bNFC_CTAP_FIDO_AID\b")


def is_canonical(path: Path) -> bool:
    return is_canonical_index_file(path)


def should_skip_safe_indexing(path: Path) -> bool:
    return any(part in SAFE_INDEX_SKIP_DIR_NAMES for part in path.parts)


def function_bounds(lines: list[str], line_idx: int) -> tuple[int, int]:
    depth = 0
    func_start = 0
    for i in range(line_idx, -1, -1):
        opens = lines[i].count("{")
        closes = lines[i].count("}")
        if i == line_idx:
            # On the access line, cancel balanced inline braces (e.g. a `= {...}`
            # initializer) and ignore only unmatched opener(s) that introduce a scope
            # continuing BELOW the access (e.g. `switch (buf[i]) {`); those must not end
            # the upward search early, or guards at function scope above are missed.
            net = closes - opens
            depth += max(net, 0)
        else:
            depth += closes - opens
        if depth < 0:
            func_start = i
            break
    else:
        func_start = 0

    depth = 0
    func_end = len(lines) - 1
    for i in range(func_start, len(lines)):
        depth += lines[i].count("{")
        depth -= lines[i].count("}")
        if depth == 0 and i >= func_start:
            func_end = i
            break
    return func_start, func_end


def function_body(lines: list[str], line_idx: int) -> str:
    start, end = function_bounds(lines, line_idx)
    return "\n".join(lines[start : end + 1])


def function_has_guard(lines: list[str], line_idx: int) -> bool:
    body = function_body(lines, line_idx)
    if any(token in body for token in GUARD_TOKENS):
        return True
    return any(rx.search(body) for rx in GUARD_REGEXES)


def literal_index_value(index_expr: str) -> int | None:
    m = LITERAL_INDEX.match(index_expr.strip())
    if not m:
        return None
    return int(m.group(1))


def function_has_output_cap_for_literal(lines: list[str], line_idx: int, lit: int) -> bool:
    body = function_body(lines, line_idx)
    need = lit + 1
    cap_patterns = (
        rf"\b(?:cap|dst_cap|rsp_cap|buf_cap|apdu_cap|dst_len|buf_len)\s*<\s*{need}\b",
        rf"\b(?:cap|dst_cap|rsp_cap|buf_cap|apdu_cap|dst_len|buf_len)\s*<=\s*{lit}\b",
        rf"\b(?:cap|dst_cap|rsp_cap|buf_cap|apdu_cap|dst_len|buf_len)\s*>=\s*{need}\b",
        rf"\b(?:cap|dst_cap|rsp_cap|buf_cap|apdu_cap|dst_len|buf_len)\s*>\s*{lit}\b",
    )
    return any(re.search(p, body) for p in cap_patterns)


def function_has_loop_bound_for_index(lines: list[str], line_idx: int, index_expr: str) -> bool:
    body = function_body(lines, line_idx)
    idx = index_expr.strip()
    if idx in {"i", "n", "pos"}:
        for m in BOUNDED_LOOP.finditer(body):
            if m.group(1) == idx:
                return True
    for m in LOOP_INDEX.finditer(body):
        if m.group(1) == idx:
            if re.search(rf"for\s*\([^;]*;\s*{re.escape(idx)}\s*<\s*", body):
                return True
    return False


def function_has_length_guard_for_expr(lines: list[str], line_idx: int, index_expr: str) -> bool:
    body = function_body(lines, line_idx)
    expr = index_expr.strip()

    def len_minus_guard(var: str, minus_lit: int) -> bool:
        need = minus_lit + 1
        return bool(
            re.search(rf"\b{re.escape(var)}\s*<\s*{need}[uU]?\b", body)
            or re.search(rf"\b{re.escape(var)}\s*>=\s*{need}[uU]?\b", body)
        )

    m = re.fullmatch(r"(\w+)\s*-\s*(\d+)[uU]?", expr)
    if m:
        return len_minus_guard(m.group(1), int(m.group(2)))
    if re.search(rf"\(\s*5\s*[uU]?\s*\+\s*lc\s*\)", body) and "apdu_len" in body:
        if expr in {"4", "5", "5u", "5u + lc", "5 + lc", "(uint8_t)(5 + lc)"}:
            return True
        if re.search(r"lc", expr):
            return True
    if re.search(rf"\(\s*6\s*[uU]?\s*\+\s*lc\s*\)", body) and "apdu_len" in body:
        if "lc" in expr or expr.startswith("5"):
            return True
    return False


def subscript_allowed(lines: list[str], line_idx: int, index_expr: str, *, is_write: bool) -> bool:
    lit = literal_index_value(index_expr)
    if lit is not None and lit <= ISO7816_HEADER_MAX:
        return True
    if lit is not None and function_has_output_cap_for_literal(lines, line_idx, lit):
        return True
    if function_has_loop_bound_for_index(lines, line_idx, index_expr):
        return True
    if function_has_length_guard_for_expr(lines, line_idx, index_expr):
        return True
    if function_has_guard(lines, line_idx):
        return True
    if is_write and not function_has_guard(lines, line_idx):
        return False
    return False


def scan_subscripts(path: Path, lines: list[str]) -> list[str]:
    if is_canonical(path) or is_test_file(path):
        return []
    issues: list[str] = []
    for i, line in enumerate(lines):
        if ARRAY_DECL.search(line):
            continue
        is_write = WRITE_SUBSCRIPT.search(line) is not None
        for m in SUBSCRIPT.finditer(line):
            idx_expr = m.group(1).strip()
            if subscript_allowed(lines, i, idx_expr, is_write=is_write):
                continue
            kind = "write to" if is_write else "unchecked subscript"
            issues.append(
                f"{path}:{i + 1}: {kind} [{idx_expr}] on external buffer "
                f"(use nero_nfc_span_ok / nero_nfc_copy_bytes or canonical parser helper)"
            )
    return issues


def scan_data_ptrs(path: Path, lines: list[str]) -> list[str]:
    if is_canonical(path):
        return []
    if is_test_file(path):
        return []
    issues: list[str] = []
    for i, line in enumerate(lines):
        m = DATA_PTR.search(line)
        if not m:
            continue
        off = m.group(1) or m.group(2)
        lit = literal_index_value(off or "")
        if lit is not None and lit <= ISO7816_HEADER_MAX:
            continue
        if function_has_guard(lines, i):
            continue
        if function_has_length_guard_for_expr(lines, i, off or ""):
            continue
        issues.append(
            f"{path}:{i + 1}: unchecked buffer data pointer at offset {off} "
            f"(use nfc_iso7816_apdu_data_ptr or nero_nfc_span_ok)"
        )
    return issues


def scan_drift_patterns(path: Path, lines: list[str]) -> list[str]:
    if is_canonical(path) or is_test_file(path):
        return []
    issues: list[str] = []
    for i, line in enumerate(lines):
        if RESP_SW_DRIFT.search(line):
            issues.append(
                f"{path}:{i + 1}: manual response SW subscript "
                f"(use nfc_iso7816_response_sw / nfc_iso7816_response_sw_ok)"
            )
        if APDU_LC_ASSIGN_DRIFT.search(line):
            issues.append(
                f"{path}:{i + 1}: manual APDU Lc assignment "
                f"(use nfc_pcsc_build_* or nfc_iso7816_apdu_lc)"
            )
        if NDEF_WALK_DRIFT.search(line):
            issues.append(
                f"{path}:{i + 1}: hand-rolled NDEF record walk "
                f"(use nfc_ndef_record_next)"
            )
        if NDEF_APP_AID_V0_DRIFT.search(line) and "nfc_pcsc_ndef_app_select_variant" not in line:
            issues.append(
                f"{path}:{i + 1}: direct NFC_PCSC_NDEF_APP_AID_V0 use "
                f"(use nfc_pcsc_ndef_app_select_variant policy table)"
            )
        if FIDO_APP_AID_DRIFT.search(line) and not any(token in line for token in FIDO_APP_AID_DRIFT_ALLOW):
            issues.append(
                f"{path}:{i + 1}: direct NFC_CTAP_FIDO_AID use "
                f"(use nfc_ctap_fido_app_select_variant policy table)"
            )
    return issues


def scan_file(path: Path) -> list[str]:
    text = strip_comments_and_strings(path.read_text(encoding="utf-8", errors="replace"))
    lines = text.splitlines()
    issues: list[str] = []
    issues.extend(scan_subscripts(path, lines))
    issues.extend(scan_data_ptrs(path, lines))
    issues.extend(scan_drift_patterns(path, lines))
    return issues


def scan_repo(repo_root: Path) -> list[str]:
    errors: list[str] = []
    for path in iter_scan_root_files(
        repo_root, skip_dir_names=SAFE_INDEX_SKIP_DIR_NAMES
    ):
        if should_skip_safe_indexing(path):
            continue
        errors.extend(scan_file(path))
    return errors


def run_self_test() -> int:
    cases = {
        "safe_copy_ok.c": (
            "#include \"nero_nfc_mem_util.h\"\n"
            "bool g(uint8_t *d, const uint8_t *s) { return nero_nfc_copy_bytes(d, 8, 0, s, 4); }\n",
            set(),
        ),
        "literal_header_ok.c": (
            "bool h(const uint8_t *apdu, uint16_t n) {\n"
            "  if (n < 5u) return false;\n"
            "  return apdu[0] == 0x00u && apdu[4] == 3u;\n"
            "}\n",
            set(),
        ),
        "deep_literal_bad.c": (
            "bool h(const uint8_t *resp, int n) {\n"
            "  (void)n;\n"
            "  return resp[14] == 0;\n"
            "}\n",
            {"deep_literal_bad.c"},
        ),
        "inline_deep_literal_bad.c": (
            "bool h(const uint8_t *apdu) { return apdu[5] == 0; }\n",
            {"inline_deep_literal_bad.c"},
        ),
        "local_array_decl_ok.c": (
            "void h(void) { uint8_t apdu[5]; (void)apdu; }\n",
            set(),
        ),
        "switch_size_guard_ok.cpp": (
            "void f(std::vector<uint8_t> resp) {\n"
            "  size_t pos = 0;\n"
            "  if (pos + 2u >= resp.size()) { return; }\n"
            "  switch (resp[pos]) {\n"
            "  default: break;\n"
            "  }\n"
            "}\n",
            set(),
        ),
        "switch_noguard_bad.cpp": (
            "void f(const uint8_t *resp, int n) {\n"
            "  (void)n;\n"
            "  switch (resp[7]) {\n"
            "  default: break;\n"
            "  }\n"
            "}\n",
            {"switch_noguard_bad.cpp"},
        ),
        "guarded_var_ok.c": (
            "bool h(const uint8_t *apdu, uint16_t apdu_len, uint8_t lc) {\n"
            "  if (!nero_nfc_span_ok(5u, lc, apdu_len)) return false;\n"
            "  return apdu[5] == 0;\n"
            "}\n",
            set(),
        ),
        "loop_bound_ok.c": (
            "uint16_t crc(const uint8_t *buf, uint16_t len) {\n"
            "  uint16_t c = 0;\n"
            "  for (uint16_t i = 0u; i < len; i++) { c ^= buf[i]; }\n"
            "  return c;\n"
            "}\n",
            set(),
        ),
        "len_minus_ok.c": (
            "bool ok(const uint8_t *frame, uint16_t len) {\n"
            "  if (len < 3u) return false;\n"
            "  return frame[len - 2u] == 0;\n"
            "}\n",
            set(),
        ),
        "cap_literal_ok.c": (
            "bool fill(uint8_t *parm, unsigned cap) {\n"
            "  if (cap < 5u) return false;\n"
            "  parm[4] = 0;\n"
            "  return true;\n"
            "}\n",
            set(),
        ),
        "data_ptr_bad.c": (
            "bool w(const uint8_t *apdu, uint16_t apdu_len) {\n"
            "  (void)apdu_len;\n"
            "  return reader_tags_type2_write_page(4, &apdu[5]);\n"
            "}\n",
            {"data_ptr_bad.c"},
        ),
        "pos_write_bad.c": (
            "bool w(uint8_t *buf, size_t cap) {\n"
            "  size_t pos = 0;\n"
            "  buf[pos++] = 1;\n"
            "  return true;\n"
            "}\n",
            {"pos_write_bad.c"},
        ),
        "sw_drift_bad.c": (
            "void f(const uint8_t *resp, int rlen) {\n"
            "  if (rlen >= 2) { (void)resp[rlen - 2]; }\n"
            "}\n",
            {"sw_drift_bad.c"},
        ),
        "apdu_lc_drift_bad.c": (
            "bool b(uint8_t *apdu, uint8_t lc) { apdu[4] = lc; return true; }\n",
            {"apdu_lc_drift_bad.c"},
        ),
        "ndef_walk_drift_bad.c": (
            "void w(const uint8_t *data, uint16_t len) {\n"
            "  uint8_t hdr = data[0];\n"
            "  bool sr = (hdr & 0x10u) != 0u;\n"
            "  (void)sr; (void)len;\n"
            "}\n",
            {"ndef_walk_drift_bad.c"},
        ),
        "ndef_app_aid_v0_drift_bad.c": (
            "bool s(void) { return NFC_PCSC_NDEF_APP_AID_V0[0] == 0xD2u; }\n",
            {"ndef_app_aid_v0_drift_bad.c"},
        ),
        "fido_app_aid_drift_bad.c": (
            "bool s(void) { return NFC_CTAP_FIDO_AID[0] == 0xA0u; }\n",
            {"fido_app_aid_drift_bad.c"},
        ),
    }

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "firmware" / "nfc_core" / "common"
        root.mkdir(parents=True)
        (root / "nfc_pcsc_contactless.h").write_text(
            "bool h(const uint8_t *resp) { return resp[14] == 0; }\n", encoding="utf-8"
        )
        probe = Path(tmp) / "firmware" / "probe"
        probe.mkdir(parents=True)
        st25_probe = Path(tmp) / "firmware" / "nfc_core" / "frontends" / "st25r3916"
        st25_probe.mkdir(parents=True)
        for name, (content, _) in cases.items():
            (probe / name).write_text(content, encoding="utf-8")
        (st25_probe / "st25_unchecked_index.c").write_text(
            "bool h(const uint8_t *resp, int n) { (void)n; return resp[14] == 0; }\n",
            encoding="utf-8",
        )

        errors = scan_repo(Path(tmp))
        reported = {Path(err.split(":", 2)[0]).name for err in errors}

        failed = False
        for name, (_, expected) in cases.items():
            if expected and name not in reported:
                print(f"self-test miss: expected violation in {name}", file=sys.stderr)
                failed = True
            if not expected and name in reported:
                print(f"self-test false positive: {name}", file=sys.stderr)
                failed = True
        if "st25_unchecked_index.c" not in reported:
            print("self-test miss: expected safe-indexing violation in st25r3916 tree", file=sys.stderr)
            failed = True

        if failed:
            print("reported:", sorted(reported), file=sys.stderr)
            return 1

    print("self-test: OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    errors = scan_repo(args.repo_root.resolve())
    if errors:
        print("error: safe-indexing policy violations:", file=sys.stderr)
        for err in errors:
            print(f"  {err}", file=sys.stderr)
        print(
            "Use nero_nfc_span_ok / nero_nfc_copy_bytes for external buffers; "
            "centralize wire parsing in nfc_core/common.",
            file=sys.stderr,
        )
        return 1

    print(
        "safe-indexing policy: OK "
        "(supplementary anti-drift gate; bounds safety is enforced by the helpers, "
        "sanitizer/Valgrind profiles, and clang-tidy/cppcheck)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
