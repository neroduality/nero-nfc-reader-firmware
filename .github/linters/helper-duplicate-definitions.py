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

"""Enforce one authoritative definition per spec constant.

A numeric ``NFC_*`` / ``ISO15693_*`` / ``ST25_*`` constant defined (via an
object-like ``#define``, an ``enum`` enumerator, or a ``constexpr`` / ``const``
definition) in more than one production file is almost always an accidental
shadow copy. The classic failure mode is a helper/tutorial header
re-``define``-ing a name that is already an ``enum`` constant in a canonical
header: the values happen to match so it compiles, but there is no longer a
single source of truth and a later edit to one copy drifts silently.

This gate flags any such constant defined in more than one production file,
including two file-local ``.c``/``.cpp`` copies. Non-numeric ``#define`` aliases
(e.g. ``#define ISO15693_CMD_x RFAL_...``) are ignored — only numeric literals
participate, so vendor-library HAL bindings are unaffected.

Scope: production trees only (``firmware/``, ``userspace/``). Host-test mirrors
under ``tests/`` are intentional and excluded.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

_LINT_DIR = Path(__file__).resolve().parent
if str(_LINT_DIR) not in sys.path:
    sys.path.insert(0, str(_LINT_DIR))

from nero_lint_policy import walk_tree

SYMBOL_PREFIXES = ("NFC_", "ISO15693_", "ST25_")
NUMERIC_RE = re.compile(r"^(0[xX][0-9A-Fa-f]+|\d+)[uUlL]*$")
DEFINE_RE = re.compile(
    r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]+(.+?)[ \t]*(?:/\*|//|$)",
    re.MULTILINE,
)
CONST_RE = re.compile(
    r"^\s*(?:static\s+)?(?:inline\s+)?(?:constexpr|const)\s+"
    r"[\w:<>,\s*&]+?\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*\[[^\]]*\])?\s*=\s*(.+?)(?:\s*/\*|\s*//|\s*;)",
    re.MULTILINE,
)
# Enum-definition opening brace (multi-line aware; excludes '(' so a function
# returning an enum type is not mistaken for an enum body).
ENUM_OPEN_RE = re.compile(r"\benum\b(?:\s+(?:class|struct)\b)?[^{};(]*\{")
SCAN_DIRS = ("firmware", "userspace")
SCAN_SUFFIXES = (".h", ".hpp", ".c", ".cpp", ".cc", ".ino")
SKIP_DIR_PARTS = {"build", "build-scan", "third-party", "tests"}


def is_numeric(token: str) -> bool:
    return bool(NUMERIC_RE.match(token.strip()))


def wanted(symbol: str) -> bool:
    return symbol.startswith(SYMBOL_PREFIXES)


def _iter_enum_members(text: str):
    """Yield (name, value_str) for explicitly-valued enum members.

    Brace-aware and multi-line tolerant so single-line ``enum { NAME = N };`` and
    brace-on-next-line bodies are covered (the previous line-anchored regex
    silently excluded single-line enums)."""

    def _blank(match: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    blanked = re.sub(r"/\*.*?\*/", _blank, text, flags=re.DOTALL)
    blanked = "\n".join(re.sub(r"//.*", "", line) for line in blanked.splitlines())
    for match in ENUM_OPEN_RE.finditer(blanked):
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
        body = blanked[brace + 1 : i]
        seg_start = 0
        pdepth = 0
        segments: list[str] = []
        for idx, ch in enumerate(body):
            if ch in "([":
                pdepth += 1
            elif ch in ")]":
                pdepth -= 1
            elif ch == "," and pdepth == 0:
                segments.append(body[seg_start:idx])
                seg_start = idx + 1
        segments.append(body[seg_start:])
        for seg in segments:
            m = re.match(r"\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.+)\s*$", seg, re.DOTALL)
            if m:
                yield m.group(1), m.group(2).strip()


def collect_definitions(text: str) -> dict[str, str]:
    """Return {symbol: numeric_literal} for numeric #define / enum / constexpr definitions."""
    out: dict[str, str] = {}
    for match in DEFINE_RE.finditer(text):
        name, value = match.group(1), match.group(2).strip()
        if wanted(name) and is_numeric(value):
            out[name] = value
    for name, value in _iter_enum_members(text):
        if wanted(name) and is_numeric(value):
            out.setdefault(name, value)
    for match in CONST_RE.finditer(text):
        name, value = match.group(1), match.group(2).strip()
        if wanted(name) and is_numeric(value):
            out.setdefault(name, value)
    return out


def iter_source_files(repo_root: Path):
    for top in SCAN_DIRS:
        base = repo_root / top
        if not base.is_dir():
            continue
        for path in walk_tree(base, frozenset(SKIP_DIR_PARTS)):
            if path.suffix not in SCAN_SUFFIXES:
                continue
            yield path


def audit(repo_root: Path) -> list[str]:
    sites: dict[str, set[str]] = defaultdict(set)
    for path in iter_source_files(repo_root):
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = path.relative_to(repo_root).as_posix()
        for symbol in collect_definitions(text):
            sites[symbol].add(rel)

    errors: list[str] = []
    for symbol, files_for_symbol in sorted(sites.items()):
        files = sorted(files_for_symbol)
        if len(files) < 2:
            continue
        errors.append(f"{symbol}: defined in {len(files)} files: {', '.join(files)}")
    return errors


def self_test() -> int:
    canonical = "enum {\n  NFC_FOO = 0xA4u,\n  NFC_BAR = 7,\n};\n"
    shadow = "#define NFC_FOO 0xA4u  /* duplicate of the enum above */\n"
    alias = "#define ISO15693_CMD RFAL_NFCV_CMD_X\n"  # non-numeric, must be ignored
    unique = "#define NFC_UNIQUE 5u\n"
    const = "static constexpr unsigned NFC_CONST = 6u;\n"

    c = collect_definitions(canonical)
    assert c == {"NFC_FOO": "0xA4u", "NFC_BAR": "7"}, c
    # Single-line enum members must also be discovered (previously excluded).
    single = collect_definitions("enum { NFC_SINGLE = 240u };\n")
    assert single == {"NFC_SINGLE": "240u"}, single
    nextline = collect_definitions("typedef enum\n{\n  NFC_NL = 0x6Du,\n} t;\n")
    assert nextline == {"NFC_NL": "0x6Du"}, nextline
    s = collect_definitions(shadow)
    assert s == {"NFC_FOO": "0xA4u"}, s
    a = collect_definitions(alias)
    assert a == {}, a  # alias value is non-numeric -> ignored
    u = collect_definitions(unique)
    assert u == {"NFC_UNIQUE": "5u"}, u
    k = collect_definitions(const)
    assert k == {"NFC_CONST": "6u"}, k

    assert is_numeric("0xFF") and is_numeric("12u") and is_numeric("255")
    assert not is_numeric("RFAL_X") and not is_numeric("(A | B)")
    assert wanted("NFC_X") and wanted("ST25_X") and not wanted("RFAL_X")

    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        common = repo / "firmware" / "nfc_core" / "common"
        reader = repo / "firmware" / "reader" / "src"
        userspace = repo / "userspace" / "app"
        tests = repo / "tests" / "firmware"
        common.mkdir(parents=True)
        reader.mkdir(parents=True)
        userspace.mkdir(parents=True)
        tests.mkdir(parents=True)

        (common / "canonical.h").write_text("enum { NFC_DUP = 0x23u };\n", encoding="utf-8")
        (reader / "shadow.h").write_text("#define NFC_DUP 0x23u\n", encoding="utf-8")
        errors = audit(repo)
        assert any("NFC_DUP" in err for err in errors), errors

        (reader / "shadow.h").write_text("#define ISO15693_CMD RFAL_NFCV_CMD_X\n", encoding="utf-8")
        (tests / "mirror.h").write_text("#define NFC_DUP 0x23u\n", encoding="utf-8")
        errors = audit(repo)
        assert errors == [], errors

        (reader / "local_a.cpp").write_text("#define NFC_LOCAL_ONLY 7u\n", encoding="utf-8")
        (userspace / "local_b.cpp").write_text("#define NFC_LOCAL_ONLY 7u\n", encoding="utf-8")
        errors = audit(repo)
        assert any("NFC_LOCAL_ONLY" in err for err in errors), errors

    print("helper-duplicate-definitions self-test: OK")
    return 0


def main() -> int:
    script_dir = Path(__file__).resolve().parent
    repo_root_default = script_dir.parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=repo_root_default)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    errors = audit(args.repo_root.resolve())
    if errors:
        print("duplicate spec-constant definitions:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        print(
            "\nEach shared spec constant must have exactly one authoritative "
            "definition (one #define, enum, or constexpr/const symbol). Remove the "
            "shadow copies and include the canonical header, or keep a genuinely "
            "file-local value under a unique file-local name.",
            file=sys.stderr,
        )
        return 1

    print("duplicate definitions: OK (one authoritative definition per spec constant)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
