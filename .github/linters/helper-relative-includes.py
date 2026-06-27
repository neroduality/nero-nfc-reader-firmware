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

"""Reject parent-directory traversals in C/C++ include directives."""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

_LINT_DIR = Path(__file__).resolve().parent
if str(_LINT_DIR) not in sys.path:
    sys.path.insert(0, str(_LINT_DIR))

from nero_lint_policy import iter_scan_root_files, should_skip

INCLUDE_LITERAL = re.compile(r'^\s*#\s*include\s+(?:"([^"]+)"|<([^>]+)>)')


def strip_block_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)


def scan_file(path: Path) -> list[str]:
    raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    code_lines = strip_block_comments("\n".join(raw_lines)).splitlines()
    issues: list[str] = []

    for line_no, (raw_line, code_line) in enumerate(zip(raw_lines, code_lines, strict=False), 1):
        code_line = re.sub(r"//.*", "", code_line)
        match = INCLUDE_LITERAL.match(code_line)
        if not match:
            continue
        include_path = match.group(1) or match.group(2)
        if "../" in include_path:
            issues.append(
                f"{path}:{line_no}: relative parent include banned: {include_path}"
            )

    return issues


def scan_repo(repo_root: Path) -> list[str]:
    errors: list[str] = []
    for path in iter_scan_root_files(repo_root):
        if should_skip(path):
            continue
        errors.extend(scan_file(path))
    return errors


def run_self_test() -> int:
    cases = {
        "ok.c": ('#include "nfc_pcsc_contactless.h"\n', set()),
        "bad.c": ('#include "../common/foo.h"\n', {"bad.c"}),
        "angle_bad.cpp": ("#include <../foo.h>\n", {"angle_bad.cpp"}),
        "comment_ok.c": ('/* #include "../bad.h" */\n#include "ok.h"\n', set()),
        "nolint_bad.c": ('#include "../generated.h" // NOLINT relative include\n', {"nolint_bad.c"}),
    }

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "firmware" / "app"
        root.mkdir(parents=True)
        for name, (content, _) in cases.items():
            (root / name).write_text(content, encoding="utf-8")

        errors = scan_repo(Path(tmp))
        reported = {Path(err.split(":", 2)[0]).name for err in errors}

    expected = {name for name, (_, names) in cases.items() if name in names}
    if reported != expected:
        print(
            f"helper-relative-includes self-test failed: got {reported}, expected {expected}",
            file=sys.stderr,
        )
        return 1
    print("helper-relative-includes self-test: OK")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent.parent,
        help="Repository root",
    )
    parser.add_argument("--self-test", action="store_true", help="run self-test and exit")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        return run_self_test()

    errors = scan_repo(args.repo_root.resolve())
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
