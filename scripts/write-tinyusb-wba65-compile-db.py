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

# Write a compile_commands.json fragment for the WBA65 TinyUSB vendor archive.

from __future__ import annotations

import argparse
import json
import shlex
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--gcc", required=True)
    parser.add_argument("--cflags", required=True)
    parser.add_argument("--obj-dir", required=True, type=Path)
    parser.add_argument("sources", nargs="+", type=Path)
    args = parser.parse_args()

    flag_args = shlex.split(args.cflags)
    repo = args.repo_root.resolve()
    entries = []
    for src in args.sources:
        src = src.resolve()
        obj = (args.obj_dir / (src.stem + ".o")).resolve()
        entries.append(
            {
                "directory": str(repo),
                "file": str(src),
                "arguments": [args.gcc, *flag_args, "-c", str(src), "-o", str(obj)],
                "output": str(obj),
            }
        )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
    print(f"── TinyUSB WBA65 compile DB → {args.out} ──")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
