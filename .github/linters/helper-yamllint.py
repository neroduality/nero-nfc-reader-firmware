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

"""Yamllint: validate and format docs/spec-traceability.yaml.

Entries are sorted by ``spec_prefix`` (case-insensitive), then ``symbol``.
Symbol presence and spec_value vs #define/enum/constexpr checks live in
helper-spec-traceability-check.py.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("error: PyYAML is required (install python3-yaml or pip install pyyaml)", file=sys.stderr)
    sys.exit(2)

REQUIRED_FIELDS = ("spec_prefix", "symbol", "spec_value", "ref", "source")
OPTIONAL_FIELDS: tuple[str, ...] = ()
ENTRY_FIELD_ORDER = REQUIRED_FIELDS[:3] + OPTIONAL_FIELDS + REQUIRED_FIELDS[3:]
ENTRY_BLOCK_RE = re.compile(r"^  - spec_prefix:", re.MULTILINE)
SPEC_PREFIX_LINE_RE = re.compile(r"^  - spec_prefix: (?P<value>.+)$", re.MULTILINE)
FIELD_LINE_RE = re.compile(r"^    (?P<field>[a-z_]+): (?P<value>.+)$", re.MULTILINE)


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent.parent
    default_manifest = repo_root / "docs" / "spec-traceability.yaml"

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=default_manifest,
        help=f"Manifest to validate (default: {default_manifest})",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=repo_root,
        help="Repository root (reserved for symmetry with helper-spec-traceability-check.py)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if manifest schema or sort order is not canonical",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Rewrite manifest in canonical sort order when it differs",
    )
    parser.add_argument(
        "--fail-on-change",
        action="store_true",
        help="Rewrite manifest in canonical order AND fail if it needed changes "
        "(mirrors helper-license-headers.py --fail-on-change for CI gating)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run internal schema-validation regression checks and exit",
    )
    return parser.parse_args()


def sort_constants(constants: list[dict]) -> list[dict]:
    return sorted(
        constants,
        key=lambda entry: (
            str(entry["spec_prefix"]).casefold(),
            str(entry["symbol"]),
        ),
    )


def unquote_yaml_scalar(raw: str) -> str:
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        quote = value[0]
        inner = value[1:-1]
        if quote == '"':
            inner = inner.replace("\\\"", '"').replace("\\\\", "\\")
        return inner
    return value


def quoted_scalar(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def yaml_scalar(value: str) -> str:
    if not value:
        return '""'
    if any(ch in value for ch in ':#[]{},"\'&*!?|>@%`') or value != value.strip():
        return quoted_scalar(value)
    return value


def render_entry(entry: dict) -> str:
    lines = ["  - spec_prefix: " + yaml_scalar(str(entry["spec_prefix"]))]
    for field in ENTRY_FIELD_ORDER[1:]:
        if field not in entry:
            continue
        value = entry[field]
        if value is None or (isinstance(value, str) and not value.strip()):
            continue
        rendered = quoted_scalar(str(value)) if field in {"spec_value", "ref"} else yaml_scalar(str(value))
        lines.append(f"    {field}: {rendered}")
    return "\n".join(lines)


def render_manifest(preamble: str, constants: list[dict]) -> str:
    body = "\n\n".join(render_entry(entry) for entry in constants)
    if preamble and not preamble.endswith("\n"):
        preamble += "\n"
    return f"{preamble}constants:\n\n{body}\n"


def split_preamble(raw: str) -> tuple[str, str]:
    marker = "constants:"
    idx = raw.find(marker)
    if idx < 0:
        return raw, ""
    return raw[:idx], raw[idx:]


def parse_constants_body(body: str) -> list[dict]:
    matches = list(ENTRY_BLOCK_RE.finditer(body))
    constants: list[dict] = []
    for index, match in enumerate(matches):
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        block = body[start:end]
        entry: dict[str, str] = {}
        prefix_match = SPEC_PREFIX_LINE_RE.search(block)
        if prefix_match:
            entry["spec_prefix"] = unquote_yaml_scalar(prefix_match.group("value"))
        for field_match in FIELD_LINE_RE.finditer(block):
            field = field_match.group("field")
            if field not in ENTRY_FIELD_ORDER and field not in OPTIONAL_FIELDS:
                continue
            entry[field] = unquote_yaml_scalar(field_match.group("value"))
        if entry:
            constants.append(entry)
    return constants


def load_manifest(path: Path) -> tuple[str, dict]:
    raw = path.read_text(encoding="utf-8")
    preamble, body = split_preamble(raw)
    if not body.strip():
        raise ValueError("missing constants: section")

    constants = parse_constants_body(body)
    if not constants:
        raise ValueError("constants list is empty")

    try:
        yaml_data = yaml.safe_load(body)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML: {exc}") from exc

    if not isinstance(yaml_data, dict):
        raise ValueError("manifest root must be a mapping")

    yaml_constants = yaml_data.get("constants")
    if not isinstance(yaml_constants, list) or len(yaml_constants) != len(constants):
        raise ValueError("parsed entry count does not match YAML loader")

    return preamble, {"constants": constants}


def self_test() -> int:
    good = {
        "constants": [
            {
                "spec_prefix": "T2T-ISO14443-A",
                "symbol": "NFC_X",
                "spec_value": "0x04",
                "ref": "section 1",
                "source": "a.h",
            },
        ]
    }
    assert validate_manifest(good) == [], validate_manifest(good)

    missing_field = {"constants": [{"spec_prefix": "P", "symbol": "NFC_X", "source": "a.h"}]}
    assert any("spec_value" in e for e in validate_manifest(missing_field)), missing_field

    empty_field = {
        "constants": [
            {"spec_prefix": "P", "symbol": "  ", "spec_value": "1", "ref": "section 1", "source": "a.h"},
        ]
    }
    assert any("symbol" in e for e in validate_manifest(empty_field)), empty_field

    assert validate_manifest({"constants": []}) == ["constants must be a non-empty list"]
    assert validate_manifest({}) == ["constants must be a non-empty list"]

    unsorted = {
        "constants": [
            {"spec_prefix": "Z", "symbol": "B", "spec_value": "1", "ref": "section 1", "source": "a.h"},
            {"spec_prefix": "A", "symbol": "C", "spec_value": "2", "ref": "section 2", "source": "b.h"},
            {"spec_prefix": "A", "symbol": "A", "spec_value": "3", "ref": "section 3", "source": "c.h"},
        ]
    }
    sorted_entries = sort_constants(unsorted["constants"])
    assert [e["symbol"] for e in sorted_entries] == ["A", "C", "B"]
    rendered = render_manifest("", sorted_entries)
    assert "spec_value: \"1\"" in rendered
    assert rendered.index("spec_prefix: A") < rendered.index("spec_prefix: Z")

    raw_block = """
constants:

  - spec_prefix: CCID1.10
    symbol: NFC_X
    spec_value: "0x61"
    ref: "section 6.1"
    source: firmware/x.h
"""
    parsed = parse_constants_body(raw_block)
    assert parsed[0]["spec_value"] == "0x61"
    roundtrip = render_manifest("", parsed)
    assert "spec_value: \"0x61\"" in roundtrip
    assert load_manifest_from_text(raw_block)[1]["constants"][0]["spec_value"] == "0x61"

    print("helper-yamllint self-test: OK")
    return 0


def load_manifest_from_text(raw: str) -> tuple[str, dict]:
    preamble, body = split_preamble(raw)
    constants = parse_constants_body(body)
    return preamble, {"constants": constants}


def validate_manifest(data: dict) -> list[str]:
    errors: list[str] = []
    constants = data.get("constants")
    if not isinstance(constants, list) or not constants:
        errors.append("constants must be a non-empty list")
        return errors

    for index, entry in enumerate(constants):
        if not isinstance(entry, dict):
            errors.append(f"constants[{index}]: expected mapping")
            continue
        for field in REQUIRED_FIELDS:
            value = entry.get(field)
            if value is None or (isinstance(value, str) and not value.strip()):
                errors.append(f"constants[{index}]: missing or empty {field}")
    return errors


def canonical_text(preamble: str, data: dict) -> str:
    constants = sort_constants(list(data["constants"]))
    return render_manifest(preamble, constants)


def main() -> int:
    args = parse_args()
    if args.self_test:
        return self_test()

    manifest_path = args.manifest.resolve()
    if not manifest_path.is_file():
        print(f"error: manifest not found: {manifest_path}", file=sys.stderr)
        return 1

    try:
        preamble, data = load_manifest(manifest_path)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    errors = validate_manifest(data)
    if errors:
        print(f"error: {manifest_path} schema invalid", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    formatted = canonical_text(preamble, data)
    current = manifest_path.read_text(encoding="utf-8")
    if current == formatted:
        if args.fail_on_change:
            print("yamllint: OK")
        elif args.write:
            print(f"yamllint: {manifest_path} (already canonical)")
        return 0

    if args.check:
        print(f"error: {manifest_path} is not canonically sorted/formatted", file=sys.stderr)
        print("  run: python3 .github/linters/helper-yamllint.py --write", file=sys.stderr)
        return 1

    if args.fail_on_change:
        manifest_path.write_text(formatted, encoding="utf-8")
        print(
            f"error: rewrote {manifest_path} into canonical sort/format "
            f"({len(data['constants'])} entries); commit the updates and re-run",
            file=sys.stderr,
        )
        return 1

    if args.write:
        manifest_path.write_text(formatted, encoding="utf-8")
        print(f"yamllint: rewrote {manifest_path} ({len(data['constants'])} entries)")
        return 0

    print(f"error: {manifest_path} is not canonical (pass --check, --write or --fail-on-change)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
