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

"""Verify manifest symbols exist in source and spec_value matches the live literal."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print(
        "error: PyYAML is required (install python3-yaml or pip install pyyaml)",
        file=sys.stderr,
    )
    sys.exit(2)

DEFINE_RE = re.compile(
    r"^#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\s+(.+?)(?:\s*/\*|\s*$)",
    re.MULTILINE,
)
# Enum-definition opening brace (multi-line aware; excludes '(' so a function
# returning an enum type is not mistaken for an enum body).
ENUM_OPEN_RE = re.compile(r"\benum\b(?:\s+(?:class|struct)\b)?[^{};(]*\{")
NUMERIC_RE = re.compile(r"^(0[xX][0-9A-Fa-f]+|\d+)")
IMPL_POLICY_PREFIX = "IMPL-POLICY"
IMPL_POLICY_SYMBOL_RE = re.compile(r"(?:SETTLE|RETRY|ATTEMPTS|BUDGET)")
IMPL_POLICY_COMMENT_RE = re.compile(r"\b(?:implementation|policy|non[- ]normative|tuning)\b", re.I)


def _blank_block_comments(text: str) -> str:
    def _blank(match: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    return re.sub(r"/\*.*?\*/", _blank, text, flags=re.DOTALL)


def _iter_enum_members(text: str):
    """Yield (name, value_str) for every explicitly-valued enum member.

    Handles single-line ``enum { NAME = N };`` and multi-line bodies (brace on a
    later line), including members anywhere on a line, which the previous
    line-anchored regex missed (single-line enums were silently excluded).
    """
    blanked = _blank_block_comments(text)
    # Drop // comments per line (block comments already blanked, newlines kept).
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
        # Split into top-level (paren-aware) enumerator segments.
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
            m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)\s*$", seg, re.DOTALL)
            if m:
                yield m.group(1), m.group(2).strip()


CONST_RE = re.compile(
    r"^\s*(?:static\s+)?(?:inline\s+)?(?:constexpr|const)\s+"
    r"[\w:<>,\s*&]+?\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*\[[^\]]*\])?\s*=\s*(.+?)(?:\s*/\*|\s*//|\s*;)",
    re.MULTILINE,
)


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent.parent
    parser = argparse.ArgumentParser(
        description=(
            "Validate docs/spec-traceability.yaml: each symbol must exist as a "
            "#define, enum constant, or constexpr/const symbol in source and "
            "spec_value must match the live literal."
        ),
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=repo_root,
        help="Repository root",
    )
    parser.add_argument(
        "--traceability",
        type=Path,
        default=repo_root / "docs" / "spec-traceability.yaml",
        help="Authoritative spec traceability manifest",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run internal parser regression checks and exit",
    )
    return parser.parse_args()


def parse_int(token: str) -> int | None:
    token = token.strip().rstrip("uUlLzZ")
    if not token:
        return None
    if token.lower().startswith("0x"):
        try:
            return int(token, 16)
        except ValueError:
            return None
    if token.isdigit():
        return int(token)
    return None


def normalize_value(raw: str) -> tuple[int | None, str]:
    raw = raw.strip()
    raw = raw.split("/*", 1)[0].strip()
    raw = raw.split("//", 1)[0].strip()
    match = NUMERIC_RE.match(raw)
    if not match:
        return None, raw
    token = match.group(1)
    return parse_int(token), token


def load_defines(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    text = path.read_text(encoding="utf-8", errors="replace")
    return _load_defines_from_text(text)


def _load_defines_from_text(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    # Enum constants first; #define macros override on the rare collision so an
    # explicit macro literal always wins over an enumerator of the same name.
    for name, value in _iter_enum_members(text):
        out[name] = value
    for match in CONST_RE.finditer(text):
        out[match.group(1)] = match.group(2).strip()
    for match in DEFINE_RE.finditer(text):
        out[match.group(1)] = match.group(2).strip()
    return out


def source_comment_window(text: str, symbol: str) -> str:
    """Return nearby source/comment text used to sanity-check trace wording."""
    lines = text.splitlines()
    symbol_re = re.compile(rf"\b{re.escape(symbol)}\b")
    for index, line in enumerate(lines):
        if symbol_re.search(line):
            start = max(0, index - 6)
            end = min(len(lines), index + 2)
            return "\n".join(lines[start:end])
    return ""


def symbol_needs_impl_policy(symbol: str) -> bool:
    return IMPL_POLICY_SYMBOL_RE.search(symbol) is not None


def validate_policy_comment(
    spec_prefix: str,
    symbol: str,
    ref: object,
    source_text: str,
    errors: list[str],
) -> None:
    ref_text = str(ref or "")
    nearby = source_comment_window(source_text, symbol)
    policy_text = f"{ref_text}\n{nearby}"

    if spec_prefix == IMPL_POLICY_PREFIX:
        if not IMPL_POLICY_COMMENT_RE.search(policy_text):
            errors.append(
                f"[{spec_prefix}] {symbol}: implementation-policy entries must say "
                "implementation/policy/non-normative/tuning in ref or nearby source comment"
            )
        return

    if symbol_needs_impl_policy(symbol):
        errors.append(
            f"[{spec_prefix}] {symbol}: retry/settle/attempt constants are implementation "
            f"policy; use {IMPL_POLICY_PREFIX} unless the symbol is a normative protocol value"
        )


def validate_source_traceability(
    spec_prefix: str,
    symbol: str,
    ref: object,
    source: str,
    source_text: str,
    errors: list[str],
) -> None:
    ref_text = str(ref or "").strip()
    if not ref_text:
        errors.append(f"[{spec_prefix}] {symbol}: ref must be non-empty in manifest")
    if spec_prefix == IMPL_POLICY_PREFIX:
        return
    if spec_prefix not in source_text:
        errors.append(
            f"[{spec_prefix}] {symbol}: spec_prefix is not cited in source file {source}",
        )


def self_test() -> int:
    sample = (
        "#define NFC_HEX 0x6Du  /* trailing comment */\n"
        "#define NFC_DEC 23u\n"
        "#define NFC_WRAPPED                         \\\n"
        "  128u\n"
        "enum {\n"
        "  NFC_ENUM_HEX = 0xA4u,\n"
        "  NFC_ENUM_DEC = 5,\n"
        "  kEnumCamel = 6u,\n"
        "};\n"
        "enum { NFC_ENUM_SINGLE = 240u };\n"
        "typedef enum\n{\n  NFC_ENUM_NEXTLINE = 256u,\n} nfc_x_t;\n"
        "enum nfc_mask_t { NFC_MASK = (1u << 2) };\n"
        "static constexpr unsigned kConstHex = 0x77u;\n"
        "static const uint8_t kConstDec = 42u;\n"
    )
    defs = _load_defines_from_text(sample)
    assert defs["NFC_HEX"] == "0x6Du", defs
    assert defs["NFC_DEC"] == "23u", defs
    assert defs["NFC_ENUM_HEX"] == "0xA4u", defs
    assert defs["NFC_ENUM_DEC"] == "5", defs
    assert defs["kEnumCamel"] == "6u", defs
    # Single-line and brace-on-next-line enum members must be discovered too.
    assert defs["NFC_ENUM_SINGLE"] == "240u", defs
    assert defs["NFC_ENUM_NEXTLINE"] == "256u", defs
    assert defs["NFC_MASK"] == "(1u << 2)", defs
    assert defs["kConstHex"] == "0x77u", defs
    assert defs["kConstDec"] == "42u", defs
    # Wrapped macro: captured value is a bare line continuation, flagged by main().
    assert defs["NFC_WRAPPED"].endswith("\\"), defs

    assert normalize_value("0x6Du") == (0x6D, "0x6D"), normalize_value("0x6Du")
    assert normalize_value("23u") == (23, "23"), normalize_value("23u")
    assert normalize_value("0xFF /* c */")[0] == 0xFF
    assert parse_int("0x10") == 16 and parse_int("16") == 16
    assert parse_int("FF") is None  # bare hex without 0x prefix is not numeric
    source_errors: list[str] = []
    validate_source_traceability(
        "ISO14443-3",
        "NFC_ENUM_DEC",
        "section 1",
        "sample.h",
        "/* [ISO14443-3] section 1 */\n" + sample,
        source_errors,
    )
    assert source_errors == [], source_errors
    validate_source_traceability(
        "ISO14443-4",
        "NFC_ENUM_DEC",
        "",
        "sample.h",
        sample,
        source_errors,
    )
    assert any("ref must be non-empty" in err for err in source_errors), source_errors
    assert any("spec_prefix is not cited" in err for err in source_errors), source_errors
    print("helper-spec-traceability-check self-test: OK")
    return 0


def main() -> int:
    args = parse_args()
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    manifest_path = args.traceability.resolve()

    with manifest_path.open(encoding="utf-8") as handle:
        manifest = yaml.safe_load(handle) or {}

    constants = manifest.get("constants")
    if not isinstance(constants, list) or not constants:
        print("error: constants must be a non-empty list", file=sys.stderr)
        return 2

    define_cache: dict[str, dict[str, str]] = {}
    source_text_cache: dict[str, str] = {}
    errors: list[str] = []

    for index, entry in enumerate(constants):
        if not isinstance(entry, dict):
            errors.append(f"constants[{index}]: expected mapping")
            continue

        symbol = entry.get("symbol")
        spec_value_raw = entry.get("spec_value")
        source = entry.get("source")
        spec_prefix = entry.get("spec_prefix", "?")

        if not isinstance(symbol, str) or not symbol.strip():
            errors.append(f"constants[{index}]: symbol must be a non-empty string")
            continue
        if spec_value_raw is None or (
            not isinstance(spec_value_raw, (str, int))
            and not isinstance(spec_value_raw, float)
        ):
            errors.append(f"constants[{index}] {symbol}: spec_value must be a string or number")
            continue
        spec_value = str(spec_value_raw).strip()
        if not spec_value:
            errors.append(f"constants[{index}] {symbol}: spec_value must be non-empty")
            continue
        if not isinstance(source, str) or not source.strip():
            errors.append(f"constants[{index}] {symbol}: source must be a non-empty string")
            continue

        source_path = repo_root / source
        if not source_path.is_file():
            errors.append(f"[{spec_prefix}] {symbol}: source missing: {source}")
            continue

        rel = source_path.as_posix()
        if rel not in define_cache:
            define_cache[rel] = load_defines(source_path)
        if rel not in source_text_cache:
            source_text_cache[rel] = source_path.read_text(encoding="utf-8", errors="replace")

        live_raw = define_cache[rel].get(symbol)
        if live_raw is None:
            errors.append(f"[{spec_prefix}] {symbol}: source literal not found in {source}")
            continue

        # A manifest macro that wraps across lines (clang-format may do this when a
        # trailing citation comment pushes the line past the column limit) leaves a
        # bare backslash as the captured value. Report it clearly instead of as a
        # cryptic "non-numeric live value '\\'".
        if live_raw.endswith("\\"):
            errors.append(
                f"[{spec_prefix}] {symbol}: definition spans multiple lines in "
                f"{source} (line continuation). Manifest constants must be a "
                f"single-line #define, enum, or constexpr/const literal — move any trailing comment "
                f"to its own line above the definition.",
            )
            continue

        expected_int, expected_display = normalize_value(spec_value)
        live_int, live_display = normalize_value(live_raw)

        if expected_int is None:
            errors.append(
                f"[{spec_prefix}] {symbol}: invalid spec_value in manifest: {spec_value!r}",
            )
            continue
        if live_int is None:
            errors.append(
                f"[{spec_prefix}] {symbol}: non-numeric live value in {source}: {live_raw!r}",
            )
            continue
        if expected_int != live_int:
            errors.append(
                f"[{spec_prefix}] {symbol}: spec={expected_display} code={live_display} ({source})",
            )

        validate_policy_comment(
            str(spec_prefix),
            symbol,
            entry.get("ref"),
            source_text_cache[rel],
            errors,
        )
        validate_source_traceability(
            str(spec_prefix),
            symbol,
            entry.get("ref"),
            source,
            source_text_cache[rel],
            errors,
        )

    if errors:
        print("spec traceability errors:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        print(
            "\nEach manifest entry must have a matching #define, enum constant, "
            "or constexpr/const symbol in source "
            "(missing symbol) and the same numeric literal as spec_value "
            "(value mismatch). Update docs/spec-traceability.yaml when "
            "normative values change, or fix/rename the firmware symbol.",
            file=sys.stderr,
        )
        return 1

    print(f"spec traceability: {len(constants)} constants OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
