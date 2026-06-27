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

"""Duplicate #include and header pragma-once guard for firmware/userspace/tests.

Complements compile-DB / clang-tidy coverage with a cheap structural gate:
each translation unit must not repeat the same include (by header path or macro
token). Mixed ``#include <foo.h>`` / ``#include "foo.h"`` counts as duplicate.
Headers (``.h`` / ``.hpp``) must have ``#pragma once`` as the first
non-comment, non-blank directive/code line.
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
    iter_scan_root_files,
    should_skip,
)

INCLUDE_LITERAL = re.compile(r'^\s*#\s*include\s+(?:"([^"]+)"|<([^>]+)>)')
INCLUDE_MACRO = re.compile(r'^\s*#\s*include\s+([A-Za-z_][A-Za-z0-9_]*)')
INCLUDE_LINE = re.compile(r'^\s*#\s*include\b')
PRAGMA_ONCE = re.compile(r"^\s*#\s*pragma\s+once\b")
HEADER_SUFFIXES = frozenset({".h", ".hpp"})


def strip_block_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)


def strip_line_for_include_scan(line: str) -> str:
    line = re.sub(r"//.*", "", line)
    if INCLUDE_LINE.match(line):
        return line.rstrip()
    line = re.sub(r'"([^"\\]|\\.)*"', '""', line)
    line = re.sub(r"'([^'\\]|\\.)*'", "''", line)
    return line.rstrip()


def parse_include(code_line: str) -> tuple[str, str] | None:
    """Return (kind, key) for a preprocessed code line, or None."""
    m = INCLUDE_LITERAL.match(code_line)
    if m:
        path = m.group(1) or m.group(2)
        return ("path", path)
    m = INCLUDE_MACRO.match(code_line)
    if m:
        return ("macro", m.group(1))
    return None


def format_include(kind: str, key: str) -> str:
    if kind == "macro":
        return f"#include {key}"
    return f'#include "{key}"'


def scan_file(path: Path) -> list[str]:
    raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    without_blocks = strip_block_comments("\n".join(raw_lines)).splitlines()
    code_lines = [strip_line_for_include_scan(line) for line in without_blocks]
    seen: dict[tuple[str, str], int] = {}
    issues: list[str] = []

    if path.suffix in HEADER_SUFFIXES:
        issues.extend(scan_header_pragma_once(path, code_lines))

    for line_no, (raw_line, code_line) in enumerate(zip(raw_lines, code_lines, strict=False), 1):
        parsed = parse_include(code_line)
        if parsed is None:
            continue
        first = seen.get(parsed)
        if first is not None:
            kind, key = parsed
            issues.append(
                f"{path}:{line_no}: duplicate {format_include(kind, key)} "
                f"(first at line {first})"
            )
            continue
        seen[parsed] = line_no

    return issues


def scan_header_pragma_once(path: Path, code_lines: list[str]) -> list[str]:
    for line_no, code_line in enumerate(code_lines, 1):
        stripped = code_line.strip()
        if not stripped:
            continue
        if PRAGMA_ONCE.match(code_line):
            return []
        return [
            f"{path}:{line_no}: header must start with #pragma once "
            "(first non-comment, non-blank directive/code line)"
        ]
    return [f"{path}:1: header must start with #pragma once"]


def scan_repo(repo_root: Path) -> list[str]:
    errors: list[str] = []
    for path in iter_scan_root_files(repo_root):
        if should_skip(path):
            continue
        errors.extend(scan_file(path))
    return errors


def run_self_test() -> int:
    cases = {
        "unique_ok.c": (
            '#include "a.h"\n#include "b.h"\n',
            set(),
        ),
        "pragma_once_ok.h": (
            "// license comment\n\n#pragma once\n#include \"a.h\"\n",
            set(),
        ),
        "pragma_once_after_include_bad.h": (
            '#include "a.h"\n#pragma once\n',
            {"pragma_once_after_include_bad.h"},
        ),
        "pragma_once_missing_bad.hpp": (
            "// license comment\nint f(void);\n",
            {"pragma_once_missing_bad.hpp"},
        ),
        "pragma_once_in_block_comment_bad.h": (
            "/* #pragma once */\nint f(void);\n",
            {"pragma_once_in_block_comment_bad.h"},
        ),
        "dup_literal.c": (
            '#include "foo.h"\n#include "foo.h"\n',
            {"dup_literal.c"},
        ),
        "dup_mixed.c": (
            "#include <foo.h>\n#include \"foo.h\"\n",
            {"dup_mixed.c"},
        ),
        "dup_macro.c": (
            "#include CONFIG_HEADER\n#include CONFIG_HEADER\n",
            {"dup_macro.c"},
        ),
        "comment_ok.c": (
            '/* duplicate mention: #include "foo.h" */\n#include "foo.h"\n',
            set(),
        ),
        "string_ok.c": (
            'const char *s = "#include \\"foo.h\\"";\n#include "foo.h"\n',
            set(),
        ),
        "nolint_bad.c": (
            '#include "foo.h"\n#include "foo.h" // NOLINT duplicate-includes\n',
            {"nolint_bad.c"},
        ),
    }

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "firmware" / "app"
        root.mkdir(parents=True)
        for name, (content, _) in cases.items():
            (root / name).write_text(content, encoding="utf-8")

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
        print("error: duplicate #include violations:", file=sys.stderr)
        for err in errors:
            print(f"  {err}", file=sys.stderr)
        print("Remove repeated includes; keep one include per header per file.", file=sys.stderr)
        return 1

    print("duplicate includes: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
