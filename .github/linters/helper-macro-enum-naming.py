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

"""Enforce macro names and C/C++ constant naming policy.

Scope (clearly bounded):
  * ``#define NAME`` macros in project C/C++ source roots.
  * Enum constants of plain / anonymous ``enum { NAME = N }`` (C-visible) in
    shared C/C++ headers.
  * C++ implementation-file enum constants and file-local constants.

Naming rule (Google C++ Style §"Macro Names" / §"Enumerator Names"):
  * Macros, when used, are ``ALL_CAPS_WITH_UNDERSCORES``.
  * Google names enumerators like constants (``kCamelCase``). This project
    deliberately deviates for *shared C-ABI headers*: enumerators there must be
    ``ALL_CAPS`` because MCU **C** code includes the same headers and the project
    spec-traceability manifest maps normative literals to these ALL_CAPS symbols.
  * C++ ``.cpp`` / ``.hpp`` enum constants and compile-time constants must be
    ``kCamelCase``.

Complements clang-tidy MacroDefinitionCase (C++ TUs) by scanning all project
source roots for macro names and shared `.h` homes for C-visible enum constants.
HAL alias shims (`g_*`, `nfc_frontend_*`) are ignored.
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
    MAGIC_LITERAL_SHARED_HEADER_BASENAMES,
    SKIP_DIR_NAMES,
    iter_scan_root_files,
    should_skip,
    walk_tree,
)

SHARED_HEADER_DIRS = (
    "firmware/nfc_core/common",
    "firmware/nfc_core/frontends",
)

DEFINE_RE = re.compile(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)")
VALID_MACRO_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
VALID_K_CAMEL_RE = re.compile(r"^k[A-Z][A-Za-z0-9]*(?:_[0-9]+)*$")
IGNORED_MACRO_RE = re.compile(r"^(g_.*|nfc_frontend_.*)$")
CXX_SUFFIXES = frozenset({".cpp", ".hpp", ".cc", ".cxx"})
CXX_CONST_RE = re.compile(
    r"^\s*(?:(?:static\s+)(?:inline\s+)?(?:constexpr|const)|(?:inline\s+)?constexpr)\s+"
    r"[\w:<>,\s*&]+?\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*\[[^\]]*\])?\s*="
)
# enum / typedef enum / enum NAME with an opening brace (possibly on a later line);
# the capture group is non-None only for C++ scoped enums (`enum class|struct`).
ENUM_OPEN_RE = re.compile(r"\benum\b(\s+(?:class|struct)\b)?[^{};]*\{")


def _blank_comments(text: str) -> str:
    """Replace comment bodies with spaces, preserving line structure/offsets."""

    def _blank(match: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    text = re.sub(r"/\*.*?\*/", _blank, text, flags=re.DOTALL)
    out_lines = []
    for line in text.splitlines(keepends=True):
        newline = "\n" if line.endswith("\n") else ""
        body = line[: len(line) - len(newline)]
        body = re.sub(r"//.*", lambda m: " " * len(m.group(0)), body)
        out_lines.append(body + newline)
    return "".join(out_lines)


def _iter_enum_enumerator_names(body: str, base: int):
    """Yield (name, absolute_offset) for each top-level enumerator in an enum body."""
    depth = 0
    expect_name = True
    i = 0
    n = len(body)
    while i < n:
        c = body[i]
        if c in "([{":
            depth += 1
            i += 1
            continue
        if c in ")]}":
            depth -= 1
            i += 1
            continue
        if depth == 0 and c == ",":
            expect_name = True
            i += 1
            continue
        if expect_name and (c.isalpha() or c == "_"):
            j = i
            while j < n and (body[j].isalnum() or body[j] == "_"):
                j += 1
            yield body[i:j], base + i
            expect_name = False
            i = j
            continue
        if expect_name and not c.isspace():
            expect_name = False
        i += 1


def _scan_enum_names(
    path: Path,
    text: str,
    *,
    valid_name_re: re.Pattern[str],
    style_name: str,
    skip_scoped: bool,
) -> list[str]:
    errors: list[str] = []
    blanked = _blank_comments(text)
    for match in ENUM_OPEN_RE.finditer(blanked):
        if skip_scoped and match.group(1) is not None:
            continue
        brace = blanked.find("{", match.start())
        if brace < 0:
            continue
        depth = 0
        end = brace
        while end < len(blanked):
            if blanked[end] == "{":
                depth += 1
            elif blanked[end] == "}":
                depth -= 1
                if depth == 0:
                    break
            end += 1
        body = blanked[brace + 1 : end]
        for name, offset in _iter_enum_enumerator_names(body, brace + 1):
            if IGNORED_MACRO_RE.match(name):
                continue
            if valid_name_re.match(name):
                continue
            lineno = blanked.count("\n", 0, offset) + 1
            errors.append(
                f"{path}:{lineno}: enum constant {name} must be {style_name}",
            )
    return errors


def header_files_under(root: Path) -> list[Path]:
    return sorted(path for path in walk_tree(root, SKIP_DIR_NAMES) if path.suffix == ".h")


def shared_header_paths(repo_root: Path) -> list[Path]:
    out: list[Path] = []
    seen: set[Path] = set()

    for rel_dir in SHARED_HEADER_DIRS:
        root = repo_root / rel_dir
        if not root.is_dir():
            continue
        for path in header_files_under(root):
            if should_skip(path):
                continue
            resolved = path.resolve()
            if resolved not in seen:
                seen.add(resolved)
                out.append(path)

    firmware_root = repo_root / "firmware"
    for path in header_files_under(firmware_root):
        if path.name not in MAGIC_LITERAL_SHARED_HEADER_BASENAMES:
            continue
        if should_skip(path):
            continue
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            out.append(path)

    return out


def scan_macro_names(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [f"{path}: read failed: {exc}"]

    lines = text.splitlines()
    for index, line in enumerate(lines, start=1):
        if line.lstrip().startswith("//"):
            continue
        match = DEFINE_RE.match(line)
        if not match:
            continue
        name = match.group(1)
        if IGNORED_MACRO_RE.match(name):
            continue
        if VALID_MACRO_RE.match(name):
            continue
        errors.append(
            f"{path}:{index}: #define {name} must be ALL_CAPS (^[A-Z][A-Z0-9_]*$)",
        )

    return errors


def scan_shared_header_enum_names(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [f"{path}: read failed: {exc}"]

    errors.extend(
        _scan_enum_names(
            path,
            text,
            valid_name_re=VALID_MACRO_RE,
            style_name="ALL_CAPS (^[A-Z][A-Z0-9_]*$)",
            skip_scoped=True,
        )
    )
    return errors


def scan_cxx_constant_names(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [f"{path}: read failed: {exc}"]

    errors.extend(
        _scan_enum_names(
            path,
            text,
            valid_name_re=VALID_K_CAMEL_RE,
            style_name="kCamelCase (^k[A-Z][A-Za-z0-9]*(?:_[0-9]+)*$)",
            skip_scoped=False,
        )
    )
    for index, line in enumerate(text.splitlines(), start=1):
        match = CXX_CONST_RE.match(line)
        if not match:
            continue
        name = match.group(1)
        if VALID_K_CAMEL_RE.match(name):
            continue
        errors.append(
            f"{path}:{index}: C++ constant {name} must be kCamelCase "
            "(^k[A-Z][A-Za-z0-9]*(?:_[0-9]+)*$)",
        )
    return errors


def scan_repo(repo_root: Path) -> list[str]:
    errors: list[str] = []
    for path in iter_scan_root_files(repo_root):
        if should_skip(path):
            continue
        errors.extend(scan_macro_names(path))
        if path.suffix in CXX_SUFFIXES:
            errors.extend(scan_cxx_constant_names(path))
    for path in shared_header_paths(repo_root):
        errors.extend(scan_shared_header_enum_names(path))
    return sorted(set(errors))


def run_self_test() -> int:
    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        good = root / "firmware/nfc_core/common/good.h"
        bad = root / "firmware/nfc_core/common/bad.h"
        alias = root / "firmware/nfc_core/frontends/alias.h"
        local_cpp = root / "firmware/reader/src/local.cpp"
        enums = root / "firmware/nfc_core/common/enums.h"
        good.parent.mkdir(parents=True)
        alias.parent.mkdir(parents=True)
        local_cpp.parent.mkdir(parents=True)
        good.write_text("#define NFC_TAG_PAGE_SIZE 4u\n", encoding="utf-8")
        bad.write_text("#define kBadMacro 1\n", encoding="utf-8")
        alias.write_text("#define nfc_frontend_bus_write st25_bus_write\n", encoding="utf-8")
        local_cpp.write_text(
            "#define kBadLocalMacro 2u\n"
            "enum { BAD_LOCAL_ENUM = 2u, kGoodLocalEnum = 3u };\n"
            "enum class Mode { BadScoped = 0, kGoodScoped = 1 };\n"
            "static constexpr unsigned BAD_LOCAL_CONST = 4u;\n",
            encoding="utf-8",
        )
        # Shared-header ALL_CAPS enums (anonymous + named + brace-on-next-line)
        # must pass; lowercase/kCamelCase plain-enum members must fail there.
        # C++ implementation-file enum constants must use kCamelCase.
        enums.write_text(
            "enum { NFC_OK = 0u, NFC_FAIL = 1u };\n"
            "typedef enum\n{\n  NFC_STATE_IDLE = 0,\n  kBadState = 1,\n} nfc_state_t;\n"
            "enum class Kind : uint8_t { kIdle = 0, kActive = 1 };\n"
            "enum nfc_mask_t { NFC_MASK_A = (1u << 2), nfc_bad = 3u };\n",
            encoding="utf-8",
        )

        errors = scan_repo(root)
        expected = {
            f"{bad}:1: #define kBadMacro must be ALL_CAPS (^[A-Z][A-Z0-9_]*$)",
            f"{local_cpp}:1: #define kBadLocalMacro must be ALL_CAPS (^[A-Z][A-Z0-9_]*$)",
            f"{local_cpp}:2: enum constant BAD_LOCAL_ENUM must be kCamelCase (^k[A-Z][A-Za-z0-9]*(?:_[0-9]+)*$)",
            f"{local_cpp}:3: enum constant BadScoped must be kCamelCase (^k[A-Z][A-Za-z0-9]*(?:_[0-9]+)*$)",
            f"{local_cpp}:4: C++ constant BAD_LOCAL_CONST must be kCamelCase (^k[A-Z][A-Za-z0-9]*(?:_[0-9]+)*$)",
            f"{enums}:5: enum constant kBadState must be ALL_CAPS (^[A-Z][A-Z0-9_]*$)",
            f"{enums}:8: enum constant nfc_bad must be ALL_CAPS (^[A-Z][A-Z0-9_]*$)",
        }
        if set(errors) != expected:
            print("self-test FAIL: unexpected errors", file=sys.stderr)
            for err in sorted(set(errors) ^ expected):
                print(f"  diff: {err}", file=sys.stderr)
            ok = False

    if ok:
        print("self-test: OK")
        return 0
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    repo_root = args.repo_root.resolve()
    errors = scan_repo(repo_root)
    if errors:
        print("macro/enum naming errors:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        print(
            "\nAll #define macros must be ALL_CAPS; shared-header plain/anonymous "
            "enum constants must be ALL_CAPS; C++ enum constants and compile-time "
            "constants must be kCamelCase.",
            file=sys.stderr,
        )
        return 1

    macro_files = [path for path in iter_scan_root_files(repo_root) if not should_skip(path)]
    print(
        "macro/enum naming: "
        f"{len(macro_files)} source files + {len(shared_header_paths(repo_root))} shared headers OK"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
