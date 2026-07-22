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

# Merge compile_commands.json fragments, rejecting duplicate source provenance.

from __future__ import annotations

import argparse
import json
from pathlib import Path


def load_entries(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise SystemExit(f"{path}: expected a JSON array")
    return data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("databases", nargs="+", type=Path)
    args = parser.parse_args()

    by_file: dict[str, tuple[Path, int, dict]] = {}
    order: list[str] = []
    for db in args.databases:
        for index, entry in enumerate(load_entries(db)):
            if not isinstance(entry, dict) or not isinstance(entry.get("file"), str):
                raise SystemExit(f"{db}: entry {index}: expected an object with a string 'file'")
            source = Path(entry["file"])
            if not source.is_absolute():
                directory = entry.get("directory")
                if not isinstance(directory, str):
                    raise SystemExit(
                        f"{db}: entry {index}: relative 'file' requires a string 'directory'"
                    )
                source = Path(directory) / source
            file_path = str(source.resolve())
            if file_path in by_file:
                first_db, first_index, _ = by_file[file_path]
                raise SystemExit(
                    f"duplicate compile source {file_path}: "
                    f"{first_db} entry {first_index} and {db} entry {index}"
                )
            order.append(file_path)
            entry = dict(entry)
            entry["file"] = file_path
            by_file[file_path] = (db, index, entry)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    merged = [by_file[path][2] for path in order]
    args.out.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
    print(f"── merged compile DB ({len(merged)} entries) → {args.out} ──")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
