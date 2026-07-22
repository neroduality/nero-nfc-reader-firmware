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


"""Strict compile-database and link-map ownership checks for all firmware profiles."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

PROFILES = (
    ("arduino_uno_r4wifi", "reader", "cdc"),
    ("arduino_uno_r4wifi", "writer", "cdc"),
    ("arduino_uno_r4wifi", "nfc", "cdc"),
    ("arduino_uno_r4wifi", "reader", "ccid"),
    ("nucleo_wba65ri", "reader", "cdc"),
    ("nucleo_wba65ri", "writer", "cdc"),
    ("nucleo_wba65ri", "nfc", "cdc"),
    ("nucleo_wba65ri", "reader", "ccid"),
)
IMPLEMENTATION_SUFFIXES = {".c", ".cc", ".cpp", ".cxx"}


def owned_library_implementations(root: Path) -> list[Path]:
    library_root = root / "firmware/libraries"
    return sorted(
        path.resolve()
        for path in library_root.glob("*/src/**/*")
        if path.is_file() and path.suffix.lower() in IMPLEMENTATION_SUFFIXES
    )


def applicable_implementations(root: Path, product: str) -> list[Path]:
    return [
        *owned_library_implementations(root),
        (root / "firmware" / product / f"{product}.ino").resolve(),
    ]


def all_owned_implementations(root: Path) -> set[Path]:
    return {
        *owned_library_implementations(root),
        *((root / "firmware" / product / f"{product}.ino").resolve()
          for product in ("reader", "writer", "nfc")),
    }


def resolved_entry_file(entry: object, index: int) -> Path:
    if not isinstance(entry, dict) or not isinstance(entry.get("file"), str):
        raise ValueError(f"entry {index}: expected an object with a string 'file'")
    source = Path(entry["file"])
    if source.is_absolute():
        return source.resolve()
    directory = entry.get("directory")
    if not isinstance(directory, str):
        raise ValueError(f"entry {index}: relative 'file' requires a string 'directory'")
    return (Path(directory) / source).resolve()


def check_compile_database(
    database: Path, expected: list[Path], all_owned: set[Path]
) -> list[str]:
    try:
        data = json.loads(database.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{database}: invalid compile database: {exc}"]
    if not isinstance(data, list):
        return [f"{database}: expected a JSON array"]

    counts: Counter[Path] = Counter()
    try:
        for index, entry in enumerate(data):
            source = resolved_entry_file(entry, index)
            if source in all_owned:
                counts[source] += 1
    except ValueError as exc:
        return [f"{database}: {exc}"]

    expected_set = set(expected)
    errors = [
        f"{database}: owned implementation {source} occurs {counts[source]} times (expected 1)"
        for source in expected
        if counts[source] != 1
    ]
    errors.extend(
        f"{database}: non-applicable owned implementation {source} occurs {counts[source]} times"
        for source in sorted(set(counts) - expected_set)
        if counts[source] != 0
    )
    return errors


def object_pattern(root: Path, source: Path) -> re.Pattern[str]:
    rel = source.resolve().relative_to(root.resolve())
    if rel.parts[:3] == ("firmware", "libraries", "NeroNfc"):
        tail = Path(*rel.parts[4:])
        prefix = rf"libraries/NeroNfc/{re.escape(tail.parent.as_posix())}/"
    elif rel.parts[:3] == ("firmware", "libraries", "NeroNfcArduino"):
        tail = Path(*rel.parts[4:])
        prefix = rf"libraries/NeroNfcArduino/{re.escape(tail.parent.as_posix())}/"
    else:
        tail = Path(f"{source.name}.cpp")
        prefix = r"sketch/"
    if tail.parent == Path("."):
        prefix = prefix.replace(r"\./", "")
    return re.compile(
        rf"(?:^|/){prefix}(?:objs\.a\()?{re.escape(tail.name)}\.o\)?$"
    )


def link_input_objects(text: str) -> list[str]:
    preamble = text.split("Discarded input sections", 1)[0]
    objects: list[str] = []
    for raw_line in preamble.splitlines():
        line = raw_line.strip()
        if ".a(" in line and re.search(r"\.o\)$", line):
            objects.append(line)
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("LOAD ") and re.search(r"\.o$", line):
            objects.append(line[5:])
    return objects


def check_link_map_text(
    text: str, link_map: Path, root: Path, expected: list[Path], all_owned: set[Path]
) -> list[str]:
    inputs = link_input_objects(text)
    errors: list[str] = []
    expected_set = set(expected)
    for source in sorted(all_owned):
        count = sum(bool(object_pattern(root, source).search(item)) for item in inputs)
        wanted = 1 if source in expected_set else 0
        if count != wanted:
            qualifier = "owned implementation" if wanted else "non-applicable owned implementation"
            errors.append(
                f"{link_map}: {qualifier} {source} occurs {count} times (expected {wanted})"
            )
    return errors


def check_profile_artifacts(
    root: Path, board: str, product: str, usb: str, all_owned: set[Path]
) -> list[str]:
    label = f"{board}/{product}/{usb}"
    database = root / "build/lint/firmware" / board / product / usb / "compile_commands.json"
    link_map = root / "build/firmware" / board / product / usb / f"{product}.ino.map"
    expected = applicable_implementations(root, product)
    errors: list[str] = []
    if database.is_file():
        errors.extend(check_compile_database(database, expected, all_owned))
    else:
        errors.append(f"{label}: required artifact missing: {database}")
    if link_map.is_file():
        errors.extend(
            check_link_map_text(
                link_map.read_text(encoding="utf-8", errors="replace"),
                link_map,
                root,
                expected,
                all_owned,
            )
        )
    else:
        errors.append(f"{label}: required artifact missing: {link_map}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    root = args.repo_root.resolve()
    all_owned = all_owned_implementations(root)
    errors: list[str] = []

    for board, product, usb in PROFILES:
        errors.extend(check_profile_artifacts(root, board, product, usb, all_owned))

    wba_archive_check = subprocess.run(
        [
            sys.executable,
            str(root / "scripts/check-wba-tinyusb-artifacts.py"),
            "--repo-root",
            str(root),
            "--require-link-map",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if wba_archive_check.returncode != 0:
        errors.append(wba_archive_check.stderr.strip())

    if errors:
        print("Strict firmware artifact check failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(f"── strict firmware artifact check OK ({len(PROFILES)} profiles) ──")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
