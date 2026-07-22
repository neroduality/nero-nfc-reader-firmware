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

# Hash TinyUSB pin, source list, flags, and toolchain identity for the WBA65
# vendor archive (§6).

from __future__ import annotations

import argparse
import hashlib
import subprocess
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--pin-stamp", required=True, type=Path)
    parser.add_argument("--gcc", required=True)
    parser.add_argument("--cflags", required=True)
    parser.add_argument("sources", nargs="+", type=Path)
    args = parser.parse_args()

    pin = args.pin_stamp.read_text(encoding="utf-8").strip()
    gcc_version = subprocess.check_output(
        [args.gcc, "-dumpversion"], text=True
    ).strip()
    gcc_machine = subprocess.check_output(
        [args.gcc, "-dumpmachine"], text=True
    ).strip()
    src_lines = "\n".join(str(s.resolve()) for s in args.sources)
    payload = "\n".join(
        [
            f"pin={pin}",
            f"gcc={args.gcc}",
            f"gcc_version={gcc_version}",
            f"gcc_machine={gcc_machine}",
            "cflags:",
            args.cflags.strip(),
            "sources:",
            src_lines,
            "",
        ]
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(digest + "\n" + payload, encoding="utf-8")
    print(f"── TinyUSB WBA65 identity → {args.out} ──")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
