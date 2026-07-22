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

"""Fail-closed uniqueness checks for the WBA TinyUSB vendor archive."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path, PurePosixPath

EXPECTED = {
    "tusb.o": "tusb.c",
    "tusb_fifo.o": "common/tusb_fifo.c",
    "usbd.o": "device/usbd.c",
    "usbd_control.o": "device/usbd_control.c",
    "dwc2_common.o": "portable/synopsys/dwc2/dwc2_common.c",
    "dcd_dwc2.o": "portable/synopsys/dwc2/dcd_dwc2.c",
}
TINYUSB_OBJECT_RE = re.compile(
    r"(?i)(?:^|[/\(])"
    r"(?:tusb(?:_fifo)?|usbd(?:_control)?|dwc2_common|dcd_dwc2)(?:\.c)?\.o\)"
)
ARCHIVE_REL = PurePosixPath("build/vendor/tinyusb/wba65/libtinyusb_wba65.a")


def check_archive_members(members: list[str], label: str) -> list[str]:
    errors: list[str] = []
    counts = Counter(member.strip() for member in members if member.strip())
    for member in EXPECTED:
        if counts[member] != 1:
            errors.append(f"{label}: archive member {member} occurs {counts[member]} times")
    unexpected = sorted(set(counts) - set(EXPECTED))
    if unexpected:
        errors.append(f"{label}: unexpected archive members: {', '.join(unexpected)}")
    return errors


def resolved_entry_file(entry: object, database: Path, index: int) -> Path:
    if not isinstance(entry, dict) or not isinstance(entry.get("file"), str):
        raise ValueError(f"entry {index}: expected an object with a string 'file'")
    source = Path(entry["file"])
    if source.is_absolute():
        return source.resolve()
    directory = entry.get("directory")
    if not isinstance(directory, str):
        raise ValueError(f"entry {index}: relative 'file' requires a string 'directory'")
    return (Path(directory) / source).resolve()


def tinyusb_src_relative(path: Path) -> PurePosixPath | None:
    """Return path relative to .../tinyusb/src/, if present (bind-mount safe)."""
    parts = PurePosixPath(path.as_posix()).parts
    for index, part in enumerate(parts):
        if part == "tinyusb" and index + 1 < len(parts) and parts[index + 1] == "src":
            rel = parts[index + 2 :]
            return PurePosixPath(*rel) if rel else PurePosixPath(".")
    return None


def paths_equivalent(left: Path, right: Path) -> bool:
    try:
        if left.resolve() == right.resolve():
            return True
    except OSError:
        pass
    try:
        if left.exists() and right.exists() and left.samefile(right):
            return True
    except OSError:
        pass
    left_posix = PurePosixPath(left.as_posix())
    right_posix = PurePosixPath(right.as_posix())
    if left_posix.name != right_posix.name:
        return False
    left_parts = left_posix.parts
    right_parts = right_posix.parts
    marker = ARCHIVE_REL.parts
    return (
        len(left_parts) >= len(marker)
        and len(right_parts) >= len(marker)
        and left_parts[-len(marker) :] == marker
        and right_parts[-len(marker) :] == marker
    )


def line_references_archive(line: str, archive: Path) -> bool:
    text = line.strip()
    archive_text = str(archive.resolve())
    if archive_text in text:
        return True
    marker = f"/{ARCHIVE_REL.as_posix()}"
    if marker not in text.replace("\\", "/"):
        return False
    # Bind-mount dual paths: accept any absolute path ending at the vendor archive.
    normalized = text.replace("\\", "/")
    end = normalized.find(marker)
    if end < 0:
        return False
    candidate = Path(normalized[: end + len(marker)])
    return paths_equivalent(candidate, archive)


def check_compile_db(database: Path, tinyusb_src: Path) -> list[str]:
    try:
        data = json.loads(database.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{database}: invalid compile database: {exc}"]
    if not isinstance(data, list):
        return [f"{database}: expected a JSON array"]

    counts: Counter[PurePosixPath] = Counter()
    try:
        for index, entry in enumerate(data):
            rel = tinyusb_src_relative(resolved_entry_file(entry, database, index))
            if rel is not None:
                counts[rel] += 1
    except ValueError as exc:
        return [f"{database}: {exc}"]

    errors: list[str] = []
    expected_rels = {PurePosixPath(suffix) for suffix in EXPECTED.values()}
    for rel in sorted(expected_rels):
        source = (tinyusb_src / Path(rel)).resolve()
        if counts[rel] != 1:
            errors.append(f"{database}: TinyUSB source {source} occurs {counts[rel]} times")
    return errors


def check_link_map_text(text: str, link_map: Path, archive: Path) -> list[str]:
    errors: list[str] = []
    archive_resolved = archive.resolve()
    preamble = text.split("Discarded input sections", 1)[0]
    for member in EXPECTED:
        token_suffix = f"({member})"
        count = 0
        for line in preamble.splitlines():
            stripped = line.strip()
            if not stripped.endswith(token_suffix):
                continue
            if line_references_archive(stripped[: -len(token_suffix)], archive_resolved):
                count += 1
        if count != 1:
            errors.append(f"{link_map}: linked archive member {member} occurs {count} times")

    load_count = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("LOAD "):
            continue
        candidate = Path(stripped[5:].strip())
        if paths_equivalent(candidate, archive_resolved):
            load_count += 1
    if load_count != 1:
        errors.append(f"{link_map}: TinyUSB archive LOAD occurs {load_count} times")

    duplicates = sorted(
        {
            line.strip()
            for line in preamble.splitlines()
            if TINYUSB_OBJECT_RE.search(line)
            and not line_references_archive(line, archive_resolved)
        }
    )
    if duplicates:
        errors.append(
            f"{link_map}: board-core/non-vendor TinyUSB objects also linked: "
            + ", ".join(duplicates)
        )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--compile-db", action="append", type=Path, default=None)
    parser.add_argument("--link-map", action="append", type=Path, default=None)
    parser.add_argument("--ar", default="ar")
    parser.add_argument("--require-link-map", action="store_true")
    args = parser.parse_args()

    root = args.repo_root.resolve()
    archive = (args.archive or root / "build/vendor/tinyusb/wba65/libtinyusb_wba65.a").resolve()
    tinyusb_src = root / "third-party/tinyusb/src"

    # None => use defaults / auto-discover. Explicit empty append list is unused;
    # callers either omit the flag or pass one or more paths.
    if args.compile_db is None and args.link_map is None:
        compile_dbs = [
            root / "build/vendor/tinyusb/wba65/compile_commands.json",
            root / "build/lint/firmware/nucleo_wba65ri/reader/ccid/compile_commands.json",
        ]
        map_root = root / "build/firmware/nucleo_wba65ri/reader/ccid"
        link_maps = sorted(map_root.glob("*.map")) if map_root.is_dir() else []
    else:
        compile_dbs = list(args.compile_db or [])
        link_maps = list(args.link_map or [])

    errors: list[str] = []
    checked = 0
    if archive.exists():
        proc = subprocess.run(
            [args.ar, "t", str(archive)], capture_output=True, text=True, check=False
        )
        if proc.returncode != 0:
            errors.append(f"{archive}: cannot list archive members: {proc.stderr.strip()}")
        else:
            errors.extend(check_archive_members(proc.stdout.splitlines(), str(archive)))
        checked += 1
    elif args.require_link_map:
        errors.append(f"{archive}: required archive does not exist")

    for database in compile_dbs:
        database = database.resolve()
        if database.exists():
            errors.extend(check_compile_db(database, tinyusb_src))
            checked += 1

    existing_maps = [path.resolve() for path in link_maps if path.exists()]
    if args.require_link_map and not existing_maps:
        errors.append("required WBA CCID link map does not exist")
    for link_map in existing_maps:
        errors.extend(
            check_link_map_text(
                link_map.read_text(encoding="utf-8", errors="replace"), link_map, archive
            )
        )
        checked += 1

    if errors:
        print("WBA TinyUSB artifact check failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(f"── WBA TinyUSB artifact check OK ({checked} artifacts) ──")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
