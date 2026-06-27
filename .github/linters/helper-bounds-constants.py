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

"""Require named constants and bounds in firmware/userspace C/C++.

Scans ``firmware/`` and ``userspace/`` (``.c``, ``.cpp``, ``.h``, ``.hpp``, ``.ino``).

Bare numeric literals (except ``0``, ``1``, ``0u``, and ``1u``) must not appear in live code — use a named
``#define``, ``enum``, or ``static constexpr`` instead. Shared caps live in canonical
headers (``nero_nfc_limits.h``, ``nfc_pcsc_contactless.h``, …); file-local values belong
at the top of the ``.c`` / ``.cpp``.

Also enforces:
  * Cross-TU / header placement for numeric constants.
  * Tier-1 protocol bound hints (240, 254, 832, …).
  * Stack arrays ``char`` / ``uint8_t[N]`` with ``N >= 100`` must use named caps.
  * Direct self-recursion unless annotated ``NERO_NFC_BOUNDED_RECURSION``.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

_LINT_DIR = Path(__file__).resolve().parent
if str(_LINT_DIR) not in sys.path:
    sys.path.insert(0, str(_LINT_DIR))

from nero_lint_policy import (
    CANONICAL_BOUNDS_HEADERS,
    MAGIC_LITERAL_SCAN_ROOTS,
    MAGIC_LITERAL_SHARED_HEADER_BASENAMES,
    SOURCE_SUFFIXES,
    iter_scan_root_files,
    should_skip,
)

LIMIT_TEST_SUFFIXES = (
    "test_nero_nfc_limits.cpp",
    "test_nfc_pcsc_contactless.cpp",
    "test_nfc_ctap_codec.cpp",
    "test_nfc_ndef_tlv.cpp",
    "test_nfc_ccid_frame.cpp",
    "test_reader_ram_constrained.cpp",
)

# Literal token -> required constant name (Tier 1: always enforced in .c/.cpp).
TIER1_NAKED = {
    240: "NFC_PCSC_T4_UPDATE_BINARY_DATA_MAX",
    254: "NFC_PCSC_T4_READ_BINARY_DATA_MAX",
    832: "NFC_ISO_DEP_IBLOCK_TX_BUF_LEN",
    1024: "NERO_NFC_READER_NDEF_BUF_MAX or WAUTH_CBOR_BUF_MAX",
    2048: "NERO_NFC_CCID_STORAGE_NDEF_BUF_MAX",
    8192: "NERO_NFC_HOST_SERIAL_LINE_MAX",
    65536: "NERO_NFC_PCSC_APDU_RX_MAX or NERO_NFC_NDEF_MAX_TOTAL_BYTES",
}

FILE_LOCAL_HEADER_LINES = 150

LOCAL_DECL = re.compile(
    r"(?:#define\s+\w+|enum\s*\{|(?:static\s+)?(?:inline\s+)?constexpr\s+\w+|NERO_NFC_STATIC_ASSERT\s*\()"
)
STACK_ARRAY_DECL_RE = re.compile(
    r"\b(?:char|uint8_t|unsigned char)\s+(\w+)\s*\[\s*(\d+)u?\s*\]"
)

CANONICAL_INCLUDES = (
    "nero_nfc_limits.h",
    "nfc_pcsc_contactless.h",
    "nfc_ctap_codec.h",
    "nfc_ccid_frame.h",
    "nfc_frontend.h",
)

CANONICAL_HEADERS = CANONICAL_BOUNDS_HEADERS

# Tier-2: numeric stack-array bounds in these trees must use named caps (not char x[400]).
NAKED_STACK_ARRAY_ROOTS = (
    "firmware/writer/src",
    "firmware/reader/src",
    "userspace/app",
)
NAKED_STACK_ARRAY_MIN = 100

BOUNDED_RECURSION_ANNOTATION = "NERO_NFC_BOUNDED_RECURSION"
CONTROL_CALL_NAMES = frozenset(
    {
        "catch",
        "for",
        "if",
        "return",
        "sizeof",
        "switch",
        "while",
    }
)
CALL_NAME_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")

IDENTITY_LITERAL_VALUES = frozenset({0, 1})  # allows 0, 1, 0u, 1u, 0x0, 0x1, …
HEADER_SUFFIXES = frozenset({".h", ".hpp"})
TU_SUFFIXES = frozenset({".c", ".cpp", ".cc", ".cxx", ".ino"})
STATIC_ASSERT_LITERAL_RE = re.compile(r"\b(?:NERO_NFC_STATIC_ASSERT|static_assert)\s*\(")
STATIC_CXX_CONST_LITERAL_RE = re.compile(
    r"^\s*(?:static\s+)?(?:inline\s+)?constexpr\b[^;{}]*=\s*[^{};]+;"
)
INT_LITERAL_RE = re.compile(r"(?<![\w.])(0[xX][0-9a-fA-F]+|\d+)([uUlLzZ]*)\b")
NUMERIC_LITERAL_RE = re.compile(r"(?<![\w.])(0[xX][0-9a-fA-F]+|\d+)[uUlLzZ]*\b")
HEADER_DEFINE_LITERAL_RE = re.compile(r"^\s*#\s*define\s+([A-Z_][A-Z0-9_]*)\b")
ENUM_MEMBER_LITERAL_RE = re.compile(
    r"\b([A-Z_][A-Z0-9_]*)\s*=\s*(?:0[xX][0-9a-fA-F]+|\d+)[uUlLzZ]*"
)
HEADER_CONST_LITERAL_RE = re.compile(
    r"^\s*(?:static\s+)?(?:inline\s+)?constexpr\s+[\w:<>,\s*&]+\s+([A-Z_][A-Z0-9_]*)\s*="
)
ENUM_OPEN_LITERAL_RE = re.compile(r"\benum\b(?:\s+(?:class|struct)\b)?[^{};(]*\{")


@dataclass(frozen=True)
class LiteralHit:
    label: str
    lineno: int
    token: str
    value: int
    raw: str
    lit_end: int


@dataclass(frozen=True)
class HeaderConstant:
    label: str
    lineno: int
    name: str


def _blank_all_comments(text: str) -> str:
    def _blank(match: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    text = re.sub(r"/\*.*?\*/", _blank, text, flags=re.DOTALL)
    out: list[str] = []
    for line in text.splitlines(keepends=True):
        newline = "\n" if line.endswith("\n") else ""
        body = line[: len(line) - len(newline)]
        body = re.sub(r"//.*", lambda m: " " * len(m.group(0)), body)
        body = re.sub(
            r'"([^"\\]|\\.)*"',
            lambda m: '"' + " " * (len(m.group(0)) - 2) + '"',
            body,
        )
        body = re.sub(
            r"'([^'\\]|\\.)*'",
            lambda m: "'" + " " * (len(m.group(0)) - 2) + "'",
            body,
        )
        out.append(body + newline)
    return "".join(out)


def _brace_spans(blanked: str, open_re: re.Pattern[str]) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for match in open_re.finditer(blanked):
        brace = blanked.find("{", match.start())
        if brace < 0:
            continue
        depth = 0
        i = brace
        while i < len(blanked):
            ch = blanked[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        spans.append((match.start(), i))
    return spans


def _enum_body_line_set(text: str) -> frozenset[int]:
    blanked = _blank_all_comments(text)
    lines: set[int] = set()
    for start, end in _brace_spans(blanked, ENUM_OPEN_LITERAL_RE):
        first = text.count("\n", 0, start) + 1
        last = text.count("\n", 0, end) + 1
        lines.update(range(first, last + 1))
    return frozenset(lines)


def _literal_value(token: str) -> int:
    base = token.rstrip("uUlLzZ")
    return int(base, 16) if base[:2].lower() == "0x" else int(base)


def _literal_key(value: int, token: str) -> str:
    if token[:2].lower() == "0x" or value > 9:
        return f"0x{value:X}"
    return str(value)


def _strip_for_literal_scan(raw: str) -> str:
    line = re.sub(r"/\*.*?\*/", "", raw, flags=re.DOTALL)
    line = re.sub(r'"([^"\\]|\\.)*"', '""', line)
    line = re.sub(r"'([^'\\]|\\.)*'", "''", line)
    line = re.sub(r"//.*", "", line)
    return line


def _is_function_macro(line: str) -> bool:
    return bool(re.match(r"^\s*#\s*define\s+[A-Za-z_]\w*\s*\(", line))


def _line_has_numeric_value(line: str) -> bool:
    return bool(NUMERIC_LITERAL_RE.search(_strip_for_literal_scan(line)))


def _is_shared_constant_header(path: Path) -> bool:
    return path.name in MAGIC_LITERAL_SHARED_HEADER_BASENAMES


def _is_header_path(path: Path) -> bool:
    return path.suffix in HEADER_SUFFIXES


def _is_translation_unit_path(path: Path) -> bool:
    return path.suffix in TU_SUFFIXES


def _literal_placement_hint(*, multi_file: bool, is_header: bool) -> str:
    if multi_file:
        return "; define once in a shared .h/.hpp for multi-file use"
    if is_header:
        return "; move logic/value to a .c/.cpp if only one translation unit needs it"
    return "; define as static/file-local constexpr or #define at the top of this .c/.cpp"


def _literal_issue(hit: LiteralHit, *, multi_file: bool, is_header: bool) -> str:
    if hit.value in TIER1_NAKED:
        hint = f"; prefer {TIER1_NAKED[hit.value]}"
    else:
        hint = _literal_placement_hint(multi_file=multi_file, is_header=is_header)
    return (
        f"{hit.label}:{hit.lineno}: bare numeric literal {hit.token} "
        f"(use a named constant{hint})"
    )


def scan_bare_literals(text: str, label: str) -> list[LiteralHit]:
    blanked = _blank_all_comments(text)
    raw_lines = text.splitlines()
    code_lines = blanked.splitlines()
    if len(code_lines) < len(raw_lines):
        code_lines.extend([""] * (len(raw_lines) - len(code_lines)))
    enum_lines = _enum_body_line_set(text)
    hits: list[LiteralHit] = []
    static_const_depth = 0
    pending_static_const = False
    for lineno, raw in enumerate(raw_lines, 1):
        code = code_lines[lineno - 1] if lineno <= len(code_lines) else ""

        if static_const_depth > 0:
            static_const_depth += code.count("{") - code.count("}")
            continue
        if pending_static_const:
            if "{" in code:
                static_const_depth = max(0, code.count("{") - code.count("}"))
                pending_static_const = False
                continue
            if ";" in code:
                pending_static_const = False
            else:
                continue
        elif re.search(r"\bstatic\s+const\b", code):
            if "{" in code:
                static_const_depth = max(0, code.count("{") - code.count("}"))
                continue
            if "=" in code and ";" not in code:
                pending_static_const = True
                continue

        if lineno in enum_lines:
            continue

        stripped = code.lstrip()
        if stripped.startswith("#"):
            continue
        if STATIC_ASSERT_LITERAL_RE.search(code):
            continue
        if STATIC_CXX_CONST_LITERAL_RE.match(code):
            continue

        for match in INT_LITERAL_RE.finditer(code):
            value = _literal_value(match.group(0))
            if value in IDENTITY_LITERAL_VALUES:
                continue
            hits.append(LiteralHit(label, lineno, match.group(0), value, raw, match.end()))
    return hits


def build_literal_issues(hits: list[LiteralHit], path_for_label: dict[str, Path]) -> list[str]:
    grouped: dict[str, set[str]] = {}
    for hit in hits:
        grouped.setdefault(_literal_key(hit.value, hit.token), set()).add(hit.label)

    issues: list[str] = []
    for hit in hits:
        path = path_for_label.get(hit.label)
        multi_file = len(grouped.get(_literal_key(hit.value, hit.token), {hit.label})) > 1
        is_header = path is not None and _is_header_path(path)
        issues.append(_literal_issue(hit, multi_file=multi_file, is_header=is_header))
    return issues


def extract_header_constants(text: str, label: str) -> list[HeaderConstant]:
    constants: list[HeaderConstant] = []
    enum_lines = _enum_body_line_set(text)
    for lineno, raw in enumerate(text.splitlines(), 1):
        if lineno not in enum_lines:
            continue
        for match in ENUM_MEMBER_LITERAL_RE.finditer(raw):
            constants.append(HeaderConstant(label, lineno, match.group(1)))

    for lineno, raw in enumerate(text.splitlines(), 1):
        if lineno in enum_lines:
            continue
        if _is_function_macro(raw):
            continue
        define_match = HEADER_DEFINE_LITERAL_RE.match(raw)
        if define_match and _line_has_numeric_value(raw):
            constants.append(HeaderConstant(label, lineno, define_match.group(1)))
            continue
        const_match = HEADER_CONST_LITERAL_RE.match(raw.strip())
        if const_match and _line_has_numeric_value(raw):
            constants.append(HeaderConstant(label, lineno, const_match.group(1)))
    return constants


def translation_units_referencing(symbol: str, tu_texts: dict[Path, str]) -> set[Path]:
    pattern = re.compile(r"\b" + re.escape(symbol) + r"\b")
    return {path for path, text in tu_texts.items() if pattern.search(text)}


def scan_header_constant_placement(
    header_constants: list[HeaderConstant],
    header_paths: dict[str, Path],
    tu_texts: dict[Path, str],
) -> list[str]:
    issues: list[str] = []
    for constant in header_constants:
        path = header_paths.get(constant.label)
        if path is None or _is_shared_constant_header(path):
            continue
        users = translation_units_referencing(constant.name, tu_texts)
        if len(users) != 1:
            continue
        only_tu = next(iter(users)).as_posix()
        issues.append(
            f"{constant.label}:{constant.lineno}: header constant {constant.name} is only "
            f"referenced from {only_tu} (move to that .c/.cpp as static/file-local constexpr "
            f"instead of exposing it in a header)"
        )
    return issues


def scan_bare_literals_and_placement(repo_root: Path) -> list[str]:
    repo_root = repo_root.resolve()
    paths: list[Path] = []
    for path in iter_scan_root_files(repo_root, scan_roots=MAGIC_LITERAL_SCAN_ROOTS):
        if should_skip(path):
            continue
        if path.name in CANONICAL_HEADERS:
            continue
        paths.append(path)

    texts: dict[Path, str] = {}
    labels: dict[Path, str] = {}
    path_for_label: dict[str, Path] = {}
    for path in paths:
        texts[path] = path.read_text(encoding="utf-8", errors="replace")
        labels[path] = str(path)
        path_for_label[labels[path]] = path

    tu_texts = {path: text for path, text in texts.items() if _is_translation_unit_path(path)}

    literal_hits: list[LiteralHit] = []
    header_constants: list[HeaderConstant] = []
    header_paths: dict[str, Path] = {}

    for path in paths:
        label = labels[path]
        literal_hits.extend(scan_bare_literals(texts[path], label))
        if _is_header_path(path):
            header_paths[label] = path
            header_constants.extend(extract_header_constants(texts[path], label))

    errors: list[str] = []
    errors.extend(build_literal_issues(literal_hits, path_for_label))
    errors.extend(scan_header_constant_placement(header_constants, header_paths, tu_texts))
    return errors


def strip_comments_and_strings(line: str) -> str:
    line = re.sub(r"//.*", "", line)
    line = re.sub(r"/\*.*?\*/", "", line)
    line = re.sub(r'"([^"\\]|\\.)*"', '""', line)
    line = re.sub(r"'([^'\\]|\\.)*'", "''", line)
    return line


def strip_block_comments_preserve_lines(text: str) -> str:
    return re.sub(
        r"/\*.*?\*/",
        lambda match: "\n" * match.group(0).count("\n"),
        text,
        flags=re.DOTALL,
    )


def paren_content(text: str, open_pos: int) -> str | None:
    depth = 0
    start = open_pos + 1
    for pos in range(open_pos, len(text)):
        char = text[pos]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[start:pos]
    return None


def count_call_args(args: str) -> int:
    stripped = args.strip()
    if not stripped or stripped == "void":
        return 0
    depth = 0
    count = 1
    for char in stripped:
        if char in "([{<":
            depth += 1
        elif char in ")]}>":
            depth = max(depth - 1, 0)
        elif char == "," and depth == 0:
            count += 1
    return count


def file_has_canonical_include(text: str) -> bool:
    return any(f'#include "{h}"' in text for h in CANONICAL_INCLUDES)


def file_header_has_local_decl(text: str) -> bool:
    head = "\n".join(text.splitlines()[:FILE_LOCAL_HEADER_LINES])
    return bool(LOCAL_DECL.search(head))


def is_limit_test(path: Path) -> bool:
    return path.name in LIMIT_TEST_SUFFIXES


def scan_file_local_bounds(path: Path) -> list[str]:
    """Non-canonical .c/.cpp using Tier-1 literals must declare/include bounds at top."""
    if path.suffix not in {".c", ".cpp"}:
        return []
    if path.name in CANONICAL_HEADERS or is_limit_test(path):
        return []
    if "tests" in path.parts:
        return []

    text = path.read_text(encoding="utf-8", errors="replace")
    if file_has_canonical_include(text) or file_header_has_local_decl(text):
        return []

    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
            continue
        code = strip_comments_and_strings(line)
        if not code.strip():
            continue
        for literal in TIER1_NAKED:
            if re.search(rf"\b{literal}u?\b", code):
                return [
                    f"{path}:{i}: bound literal {literal} without canonical include "
                    f"or file-local #define/enum/constexpr in first {FILE_LOCAL_HEADER_LINES} lines"
                ]
    return []


def scan_naked_stack_arrays(path: Path, repo_root: Path) -> list[str]:
    """Flag char/uint8_t stack arrays with numeric bounds >= NAKED_STACK_ARRAY_MIN."""
    if path.suffix not in {".c", ".cpp"}:
        return []
    if is_limit_test(path) or "tests" in path.parts:
        return []

    rel = path.relative_to(repo_root).as_posix()
    if not any(rel.startswith(root + "/") or rel == root for root in NAKED_STACK_ARRAY_ROOTS):
        return []

    issues: list[str] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
            continue
        code = strip_comments_and_strings(line)
        for _name, size_s in STACK_ARRAY_DECL_RE.findall(code):
            size = int(size_s)
            if size < NAKED_STACK_ARRAY_MIN:
                continue
            issues.append(
                f"{path}:{i}: naked stack array bound {size} "
                f"(use a named #define/enum cap, e.g. writer_payload.h)"
            )
    return issues


def function_info_from_signature(signature: str) -> tuple[str, int] | None:
    """Best-effort C/C++ function name extraction for lint, not compilation."""
    before_body = signature.split("{", 1)[0]
    if before_body.lstrip().startswith("#") or ";" in before_body:
        return None
    match = CALL_NAME_RE.search(before_body)
    if match is None:
        return None
    name = match.group(1)
    if name in CONTROL_CALL_NAMES:
        return None
    args = paren_content(before_body, match.end() - 1)
    if args is None:
        return None
    return name, count_call_args(args)


def scan_direct_recursion(path: Path) -> list[str]:
    """Flag direct self-calls unless bounded recursion is explicitly annotated."""
    if path.suffix not in SOURCE_SUFFIXES:
        return []
    if is_limit_test(path) or "tests" in path.parts:
        return []

    raw_text = path.read_text(encoding="utf-8", errors="replace")
    raw_lines = raw_text.splitlines()
    code_text = strip_block_comments_preserve_lines(raw_text)
    code_lines = [strip_comments_and_strings(line) for line in code_text.splitlines()]
    issues: list[str] = []
    index = 0
    signature_parts: list[str] = []

    while index < len(code_lines):
        code = code_lines[index]
        stripped = code.strip()
        if not stripped or stripped.startswith("#"):
            signature_parts.clear()
            index += 1
            continue

        signature_parts.append(code)
        signature = " ".join(signature_parts)
        open_pos = signature.find("{")
        semicolon_pos = signature.find(";")
        if semicolon_pos != -1 and (open_pos == -1 or semicolon_pos < open_pos):
            signature_parts.clear()
            index += 1
            continue
        if open_pos == -1:
            if len(signature_parts) > 8:
                signature_parts.clear()
            index += 1
            continue

        function_info = function_info_from_signature(signature)
        signature_parts.clear()
        if function_info is None:
            index += 1
            continue
        name, param_count = function_info

        depth = 0
        body_code: list[tuple[int, str]] = []
        body_raw: list[str] = []
        first_body_line = True
        while index < len(code_lines):
            code_line = code_lines[index]
            raw_line = raw_lines[index]
            if first_body_line:
                fragment = code_line.split("{", 1)[1]
                raw_fragment = raw_line.split("{", 1)[1] if "{" in raw_line else raw_line
                first_body_line = False
            else:
                fragment = code_line
                raw_fragment = raw_line
            depth += code_line.count("{")
            depth -= code_line.count("}")
            body_code.append((index + 1, fragment))
            body_raw.append(raw_fragment)
            index += 1
            if depth <= 0:
                break

        if BOUNDED_RECURSION_ANNOTATION in "\n".join(body_raw):
            continue
        call_re = re.compile(rf"\b{re.escape(name)}\s*\(")
        for line_no, body_line in body_code:
            for match in call_re.finditer(body_line):
                args = paren_content(body_line, match.end() - 1)
                if args is None or count_call_args(args) != param_count:
                    continue
                issues.append(
                    f"{path}:{line_no}: direct recursion in {name}() "
                    f"(replace with an iterative bounded loop or annotate "
                    f"{BOUNDED_RECURSION_ANNOTATION} with the maximum depth)"
                )
                break
            else:
                continue
            break

    return issues


def scan_repo(repo_root: Path) -> list[str]:
    errors: list[str] = []
    errors.extend(scan_bare_literals_and_placement(repo_root))
    for path in iter_scan_root_files(repo_root, scan_roots=MAGIC_LITERAL_SCAN_ROOTS):
        if should_skip(path):
            continue
        if path.name in CANONICAL_HEADERS:
            continue
        errors.extend(scan_file_local_bounds(path))
        errors.extend(scan_naked_stack_arrays(path, repo_root))
        errors.extend(scan_direct_recursion(path))
    return sorted(set(errors))


def run_self_test() -> int:
    cases = {
        "bad_type4.cpp": (
            "void f(){ uint16_t c = 240; (void)c; }\n",
            {"bad_type4.cpp"},
        ),
        "good_type4.cpp": (
            '#include "nfc_pcsc_contactless.h"\nvoid f(){ uint16_t c = NFC_PCSC_T4_UPDATE_BINARY_DATA_MAX; (void)c; }\n',
            set(),
        ),
        "local_define.cpp": (
            "#define CHUNK_MAX 240u\nvoid f(){ uint8_t n = CHUNK_MAX; (void)n; }\n",
            set(),
        ),
        "limit_test.cpp": (
            "TEST(X,Y){ EXPECT_EQ(NFC_PCSC_T4_READ_BINARY_DATA_MAX, 254u); }\n",
            set(),
        ),
        "bad_stack.cpp": (
            "void f(){ char vcard[400]; vcard[0]=0; (void)vcard; }\n",
            {"bad_stack.cpp"},
        ),
        "good_stack.cpp": (
            '#include "writer_payload.h"\nvoid f(){ char vcard[WRITER_VCARD_TEXT_MAX]; vcard[0]=0; (void)vcard; }\n',
            set(),
        ),
        "bad_recursion.cpp": (
            "static bool walk(unsigned depth) { return depth == 0u ? true : walk(depth - 1u); }\n",
            {"bad_recursion.cpp"},
        ),
        "good_loop.cpp": (
            "void loop(void) { poll_one_cycle(); }\n",
            set(),
        ),
        "bad_loop_bound.cpp": (
            "void scan(void) { for (int depth = 0; depth < 8; ++depth) { step(); } }\n",
            {"bad_loop_bound.cpp"},
        ),
        "good_loop_bound.cpp": (
            "enum { SCAN_DEPTH_MAX = 8u }; void scan(void) { for (int depth = 0; depth < SCAN_DEPTH_MAX; ++depth) { step(); } }\n",
            set(),
        ),
        "good_bounded_recursion.cpp": (
            "static bool walk(unsigned depth) { /* NERO_NFC_BOUNDED_RECURSION max depth: 2 */ return depth == 0u ? true : walk(depth - 1u); }\n",
            set(),
        ),
        "bad_plain_decimal.cpp": (
            "int f(int x){ if (x <= 225) { return 42; } return 0; }\n",
            {"bad_plain_decimal.cpp"},
        ),
        "bad_hex.cpp": (
            "void g(void){ uint8_t c = 0xFFu; (void)c; }\n",
            {"bad_hex.cpp"},
        ),
        "good_constexpr.cpp": (
            "static constexpr unsigned kValue = 0x22u;\nvoid f(void){ (void)kValue; }\n",
            set(),
        ),
        "identity_literals_ok.cpp": (
            "void f(int x){ if (x <= 0) { (void)x; } if (x == 1u) { return; } }\n",
            set(),
        ),
        "comments_strings_ok.cpp": (
            'void f(void){ const char *s = "240 0xFF"; /* 400 */ (void)s; }\n',
            set(),
        ),
        "single_use_header_cap.h": (
            "#define NFC_LOCAL_HEADER_CAP 7u\n",
            {"single_use_header_cap.h"},
        ),
        "uses_single_header.cpp": (
            '#include "single_use_header_cap.h"\nint f(void){ return NFC_LOCAL_HEADER_CAP; }\n',
            set(),
        ),
        "shared_header_cap.h": (
            "#define NFC_SHARED_HEADER_CAP 8u\n",
            set(),
        ),
        "uses_shared_header_a.cpp": (
            '#include "shared_header_cap.h"\nint a(void){ return NFC_SHARED_HEADER_CAP; }\n',
            set(),
        ),
        "uses_shared_header_b.cpp": (
            '#include "shared_header_cap.h"\nint b(void){ return NFC_SHARED_HEADER_CAP; }\n',
            set(),
        ),
    }

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "firmware" / "writer" / "src"
        root.mkdir(parents=True)
        tests = Path(tmp) / "tests" / "firmware"
        tests.mkdir(parents=True)
        canon = Path(tmp) / "firmware" / "nfc_core" / "common"
        canon.mkdir(parents=True)
        (canon / "nfc_pcsc_contactless.h").write_text(
            "enum { NFC_PCSC_T4_UPDATE_BINARY_DATA_MAX = 240u };\n", encoding="utf-8"
        )
        (canon / "writer_payload.h").write_text(
            "#define WRITER_VCARD_TEXT_MAX 1166u\n", encoding="utf-8"
        )
        (root / "bad_type4.cpp").write_text(cases["bad_type4.cpp"][0], encoding="utf-8")
        (root / "good_type4.cpp").write_text(cases["good_type4.cpp"][0], encoding="utf-8")
        (root / "local_define.cpp").write_text(cases["local_define.cpp"][0], encoding="utf-8")
        (root / "bad_stack.cpp").write_text(cases["bad_stack.cpp"][0], encoding="utf-8")
        (root / "good_stack.cpp").write_text(cases["good_stack.cpp"][0], encoding="utf-8")
        (root / "bad_recursion.cpp").write_text(
            cases["bad_recursion.cpp"][0], encoding="utf-8"
        )
        (root / "good_loop.cpp").write_text(cases["good_loop.cpp"][0], encoding="utf-8")
        (root / "bad_loop_bound.cpp").write_text(
            cases["bad_loop_bound.cpp"][0], encoding="utf-8"
        )
        (root / "good_loop_bound.cpp").write_text(
            cases["good_loop_bound.cpp"][0], encoding="utf-8"
        )
        (root / "good_bounded_recursion.cpp").write_text(
            cases["good_bounded_recursion.cpp"][0], encoding="utf-8"
        )
        (root / "bad_plain_decimal.cpp").write_text(
            cases["bad_plain_decimal.cpp"][0], encoding="utf-8"
        )
        (root / "bad_hex.cpp").write_text(cases["bad_hex.cpp"][0], encoding="utf-8")
        (root / "good_constexpr.cpp").write_text(
            cases["good_constexpr.cpp"][0], encoding="utf-8"
        )
        (root / "identity_literals_ok.cpp").write_text(
            cases["identity_literals_ok.cpp"][0], encoding="utf-8"
        )
        (root / "comments_strings_ok.cpp").write_text(
            cases["comments_strings_ok.cpp"][0], encoding="utf-8"
        )
        (root / "single_use_header_cap.h").write_text(
            cases["single_use_header_cap.h"][0], encoding="utf-8"
        )
        (root / "uses_single_header.cpp").write_text(
            cases["uses_single_header.cpp"][0], encoding="utf-8"
        )
        (root / "shared_header_cap.h").write_text(
            cases["shared_header_cap.h"][0], encoding="utf-8"
        )
        (root / "uses_shared_header_a.cpp").write_text(
            cases["uses_shared_header_a.cpp"][0], encoding="utf-8"
        )
        (root / "uses_shared_header_b.cpp").write_text(
            cases["uses_shared_header_b.cpp"][0], encoding="utf-8"
        )
        (tests / "test_nero_nfc_limits.cpp").write_text(
            cases["limit_test.cpp"][0], encoding="utf-8"
        )

        errors = scan_repo(Path(tmp))
        reported = {Path(err.split(":", 2)[0]).name for err in errors}

        failed = False
        for name, (_, expected) in cases.items():
            probe_name = (
                "test_nero_nfc_limits.cpp" if name == "limit_test.cpp" else name
            )
            if expected and probe_name not in reported and name not in reported:
                print(f"self-test miss: expected violation in {name}", file=sys.stderr)
                failed = True
            if not expected and (probe_name in reported or name in reported):
                print(f"self-test false positive: {name}", file=sys.stderr)
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
        print("error: named constants/bounds policy violations:", file=sys.stderr)
        for err in errors:
            print(f"  {err}", file=sys.stderr)
        print(
            "Replace bare numeric literals with named constants (0, 1, 0u, and 1u are allowed); "
            "shared caps belong in canonical headers, file-local caps at the top of the .c/.cpp.",
            file=sys.stderr,
        )
        return 1

    roots = ", ".join(MAGIC_LITERAL_SCAN_ROOTS)
    print(f"named constants/bounds policy: OK (scan roots: {roots})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
