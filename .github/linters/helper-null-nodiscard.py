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

"""Guard NERO_NFC_NODISCARD and NERO_NFC_NULL policy in project code.

Null-pointer policy (firmware/userspace/tests):
  - Use NERO_NFC_NULL for every null pointer literal — never raw NULL, legacy
    NFC_NULL, (const T*)0, or nullptr.
  - The only raw NULL/nullptr tokens live in firmware/nfc_core/common/nero_nfc_null.h
    on #define NERO_NFC_NULL lines.
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
    CANONICAL_NULL_HEADER,
    SKIP_DIR_NAMES,
    SOURCE_SUFFIXES,
    iter_scan_root_files,
)

BOOL_HEAD = re.compile(
    r"^(?:\s*(?:NERO_NFC_NODISCARD|\[\[nodiscard\]\])\s+)?"
    r"(?:static\s+inline\s+)?bool\s*$"
)
BOOL_DECL = re.compile(
    r"(?:NERO_NFC_NODISCARD|\[\[nodiscard\]\])\s+"
    r"(?:static\s+inline\s+)?bool\s+\w+\s*\("
    r"|"
    r"(?:static\s+inline\s+)?bool\s+\w+\s*\(",
    re.MULTILINE,
)
RAW_NULL = re.compile(r"\bNULL\b")
LEGACY_NFC_NULL = re.compile(r"(?<![A-Z_])NFC_NULL\b")
CAST_NULL = re.compile(r"\(\s*const\s+[^)]+\*\s*\)\s*0\b")
STANDALONE_NULLPTR = re.compile(r"\bnullptr\b")
NODISCARD_ON_FIELD = re.compile(
    r"NERO_NFC_NODISCARD\s+(?:bool|\[\[nodiscard\]\]\s+bool)\s+\w+\s*\{"
)
NERO_NFC_NULL_DEFINE = re.compile(r"#define\s+NERO_NFC_NULL\s+nullptr\b")
NERO_NFC_NULL_DEFINE_NULL = re.compile(r"#define\s+NERO_NFC_NULL\s+NULL\b")
NERO_NFC_NULL_TOKEN = re.compile(r"\bNERO_NFC_NULL\b")
NULL_INCLUDE_HEADERS = (
    CANONICAL_NULL_HEADER,
    "nero_nfc_attrs.h",
    "nero_nfc_mem_util.h",
)
NULL_POLICY_SKIP_DIR_NAMES = SKIP_DIR_NAMES - frozenset({"st25r3916"})


def strip_comments_and_strings(line: str) -> str:
    line = re.sub(r"//.*", "", line)
    line = re.sub(r"/\*.*?\*/", "", line)
    line = re.sub(r'"([^"\\]|\\.)*"', '""', line)
    line = re.sub(r"'([^'\\]|\\.)*'", "''", line)
    return line


def should_skip_null_policy(path: Path) -> bool:
    return any(part in NULL_POLICY_SKIP_DIR_NAMES for part in path.parts)


def canonical_null_define_allowed(path: Path, line: str) -> bool:
    if path.name != CANONICAL_NULL_HEADER:
        return False
    stripped = strip_comments_and_strings(line)
    return bool(
        NERO_NFC_NULL_DEFINE.search(stripped)
        or NERO_NFC_NULL_DEFINE_NULL.search(stripped)
    )


def merge_bool_decl_lines(lines: list[str]) -> list[tuple[int, str]]:
    """Join split bool declarations; return (1-based start line, merged text)."""
    merged: list[tuple[int, str]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if BOOL_HEAD.match(line.rstrip()):
            start = i + 1
            parts = [line.strip()]
            j = i + 1
            while j < len(lines):
                parts.append(lines[j].strip())
                if ";" in lines[j] or "{" in lines[j]:
                    break
                j += 1
            merged.append((start, " ".join(parts)))
            i = j + 1
            continue
        merged.append((i + 1, line))
        i += 1
    return merged


def is_struct_or_field(decl: str) -> bool:
    if "(" not in decl and ";" in decl:
        return True
    if re.search(r"\bbool\s+\w+\s*\{", decl):
        return True
    return False


def has_nodiscard(decl: str) -> bool:
    return "NERO_NFC_NODISCARD" in decl or "[[nodiscard]]" in decl


def scan_nodiscard_header(path: Path) -> list[str]:
    issues: list[str] = []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for start_line, decl in merge_bool_decl_lines(lines):
        if re.search(r"\bstatic\s+bool\s+\w+\s*\(", decl) and "inline" not in decl:
            continue
        if not re.search(r"\bbool\s+\w+\s*\(", decl):
            continue
        if is_struct_or_field(decl):
            continue
        if "operator" in decl:
            continue
        if not has_nodiscard(decl):
            issues.append(
                f"{path}:{start_line}: fallible bool API missing NERO_NFC_NODISCARD"
            )
    return issues


def scan_null_tokens(path: Path) -> list[str]:
    issues: list[str] = []
    for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if canonical_null_define_allowed(path, line):
            continue
        code = strip_comments_and_strings(line)
        if RAW_NULL.search(code):
            issues.append(f"{path}:{i}: raw NULL (use NERO_NFC_NULL)")
        if LEGACY_NFC_NULL.search(code):
            issues.append(f"{path}:{i}: legacy NFC_NULL (use NERO_NFC_NULL)")
        if CAST_NULL.search(code):
            issues.append(f"{path}:{i}: (const T*)0 cast (use NERO_NFC_NULL)")
    return issues


def has_null_include(text: str) -> bool:
    return any(f'#include "{header}"' in text for header in NULL_INCLUDE_HEADERS)


def scan_nero_nfc_null_include(path: Path) -> list[str]:
    if path.name == CANONICAL_NULL_HEADER:
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    code = "\n".join(strip_comments_and_strings(line) for line in text.splitlines())
    if not NERO_NFC_NULL_TOKEN.search(code):
        return []
    if has_null_include(text):
        return []
    return [
        f"{path}: missing #include \"{CANONICAL_NULL_HEADER}\" "
        f"(or nero_nfc_attrs.h / nero_nfc_mem_util.h) for NERO_NFC_NULL"
    ]


def scan_standalone_nullptr(path: Path) -> list[str]:
    issues: list[str] = []
    for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if canonical_null_define_allowed(path, line):
            continue
        code = strip_comments_and_strings(line)
        if STANDALONE_NULLPTR.search(code):
            issues.append(f"{path}:{i}: standalone nullptr (use NERO_NFC_NULL)")
    return issues


def scan_nodiscard_on_fields(path: Path) -> list[str]:
    if path.suffix not in {".h", ".hpp"}:
        return []
    issues: list[str] = []
    for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if NODISCARD_ON_FIELD.search(line):
            issues.append(f"{path}:{i}: NERO_NFC_NODISCARD on data member (functions only)")
    return issues


def scan_repo(repo_root: Path) -> list[str]:
    errors: list[str] = []
    for path in iter_scan_root_files(
        repo_root, skip_dir_names=NULL_POLICY_SKIP_DIR_NAMES
    ):
        if should_skip_null_policy(path):
            continue
        if path.suffix in {".h", ".hpp"}:
            errors.extend(scan_nodiscard_header(path))
            errors.extend(scan_nodiscard_on_fields(path))
        errors.extend(scan_null_tokens(path))
        errors.extend(scan_standalone_nullptr(path))
        errors.extend(scan_nero_nfc_null_include(path))
    return errors


def run_self_test() -> int:
    cases = {
        "missing_nodiscard.h": (
            "#pragma once\nbool probe_no_nodiscard(void);\n",
            {"missing_nodiscard.h"},
        ),
        "multiline_nodiscard_ok.h": (
            "#pragma once\nNERO_NFC_NODISCARD bool\nprobe_ok(void);\n",
            set(),
        ),
        "multiline_nodiscard_bad.h": (
            "#pragma once\nbool\nprobe_bad(void);\n",
            {"multiline_nodiscard_bad.h"},
        ),
        "raw_null.c": (
            "void f(void* p) { if (p == NULL) {} }\n",
            {"raw_null.c"},
        ),
        "legacy_nfc_null.c": (
            "void f(void* p) { if (p == NFC_NULL) {} }\n",
            {"legacy_nfc_null.c"},
        ),
        "cast_null.c": (
            "const void* p = (const uint8_t*)0;\n",
            {"cast_null.c"},
        ),
        "header_nullptr.h": (
            "#pragma once\nvoid f(const char* s) { if (s == nullptr) {} }\n",
            {"header_nullptr.h"},
        ),
        "source_nullptr.cpp": (
            "void f(const char* s) { if (s == nullptr) {} }\n",
            {"source_nullptr.cpp"},
        ),
        "header_default_nullptr_bad.h": (
            "#pragma once\nvoid f(uint8_t* p = nullptr);\n",
            {"header_default_nullptr_bad.h"},
        ),
        "nodiscard_field.h": (
            "struct S { NERO_NFC_NODISCARD bool flag{}; };\n",
            {"nodiscard_field.h"},
        ),
        "struct_field_ok.h": (
            "struct S { bool flag{}; };\n",
            set(),
        ),
        "static_internal_ok.h": (
            "static bool helper(void) { return false; }\n",
            set(),
        ),
        "comment_null.c": (
            "/* NULL is bad in code */ void f(void) {}\n",
            set(),
        ),
        "comment_nullptr.c": (
            "/* nullptr is bad in code */ void f(void) {}\n",
            set(),
        ),
        "comment_nero_nfc_null.c": (
            "/* NERO_NFC_NULL is the canonical token. */ void f(void) {}\n",
            set(),
        ),
        "nero_nfc_null_define_ok.h": (
            "#define NERO_NFC_NULL nullptr\n",
            {"nero_nfc_null_define_ok.h"},
        ),
        "missing_null_include.c": (
            "void f(void* p) { if (p == NERO_NFC_NULL) {} }\n",
            {"missing_null_include.c"},
        ),
        "null_include_ok.c": (
            '#include "nero_nfc_null.h"\nvoid f(void* p) { if (p == NERO_NFC_NULL) {} }\n',
            set(),
        ),
    }

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "firmware" / "probe"
        root.mkdir(parents=True)
        st25_root = Path(tmp) / "firmware" / "nfc_core" / "frontends" / "st25r3916"
        st25_root.mkdir(parents=True)
        canonical = Path(tmp) / "firmware" / "nfc_core" / "common"
        canonical.mkdir(parents=True)
        (canonical / CANONICAL_NULL_HEADER).write_text(
            "#if defined(__cplusplus)\n"
            "#define NERO_NFC_NULL nullptr\n"
            "#else\n"
            "#define NERO_NFC_NULL NULL\n"
            "#endif\n",
            encoding="utf-8",
        )
        for name, (content, _) in cases.items():
            (root / name).write_text(content, encoding="utf-8")
        (st25_root / "raw_null_st25.c").write_text(
            "void f(void* p) { if (p == NULL) {} }\n",
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

        canonical_errors = [
            err
            for err in errors
            if CANONICAL_NULL_HEADER in err.split(":", 1)[0]
        ]
        if canonical_errors:
            print(
                f"self-test false positive in canonical header: {canonical_errors}",
                file=sys.stderr,
            )
            failed = True
        if "raw_null_st25.c" not in reported:
            print("self-test miss: expected violation in st25r3916 tree", file=sys.stderr)
            failed = True

        if failed:
            print("reported:", sorted(reported), file=sys.stderr)
            return 1

    print("self-test: OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run built-in regression cases and exit",
    )
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    errors = scan_repo(args.repo_root.resolve())
    if errors:
        print("error: null/nodiscard policy violations:", file=sys.stderr)
        for err in errors:
            print(f"  {err}", file=sys.stderr)
        print(
            "Use NERO_NFC_NODISCARD on fallible bool APIs and NERO_NFC_NULL for null checks.",
            file=sys.stderr,
        )
        return 1

    print("null/nodiscard policy: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
