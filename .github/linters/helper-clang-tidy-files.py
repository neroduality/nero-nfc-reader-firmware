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

"""List project sources from compile_commands.json for clang-tidy."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_LINT_DIR = Path(__file__).resolve().parent
if str(_LINT_DIR) not in sys.path:
    sys.path.insert(0, str(_LINT_DIR))

from nero_lint_policy import SKIP_DIR_NAMES, SOURCE_SUFFIXES, is_firmware_bounds_tu

# Top-level directories that anchor a repo-relative source path.
_REPO_TOP_DIRS = ("firmware", "userspace", "tests")


def _repo_relative(src: Path, repo_root: Path) -> Path | None:
    """Repo-relative path for a compile-database source.

    Fast path: ``src`` lives under ``repo_root``. Fallback: the compile database
    was produced under a different absolute prefix than ``repo_root`` (e.g. a
    container/Lima bind mount such as ``/src``), so recover the repo-relative
    path from the first top-level project directory. Scanning left-to-right
    keeps ``tests/firmware/...`` anchored at ``tests`` (not the nested
    ``firmware``), so test sources stay excluded from the firmware trees.
    """
    try:
        return src.relative_to(repo_root)
    except ValueError:
        pass
    for index, part in enumerate(src.parts):
        if part in _REPO_TOP_DIRS:
            return Path(*src.parts[index:])
    return None


def project_sources(repo_root: Path, compile_db: Path, tree: str) -> list[Path]:
    repo_root = repo_root.resolve()
    data = json.loads(compile_db.read_text(encoding="utf-8"))
    out: list[Path] = []
    for entry in data:
        src = Path(entry["file"]).resolve()
        if src.suffix not in SOURCE_SUFFIXES:
            continue
        rel = _repo_relative(src, repo_root)
        if rel is None:
            continue
        rel_posix = rel.as_posix()
        if rel.parts[0] != "firmware" and tree.startswith("firmware"):
            continue
        if rel.parts[0] != "userspace" and tree == "userspace":
            continue
        if any(part in SKIP_DIR_NAMES for part in rel.parts):
            continue

        bounds = is_firmware_bounds_tu(rel_posix)
        if tree == "firmware-bounds" and not bounds:
            continue
        if tree == "firmware-base" and bounds:
            continue
        if tree == "firmware" and rel.parts[0] != "firmware":
            continue

        out.append(src)
    return sorted(set(out))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--repo-root", type=Path)
    parser.add_argument("--compile-db", type=Path)
    parser.add_argument(
        "tree",
        nargs="?",
        choices=("firmware", "firmware-base", "firmware-bounds", "userspace"),
    )
    args = parser.parse_args()
    if args.self_test:
        return run_self_test()
    if args.repo_root is None or args.compile_db is None or args.tree is None:
        parser.error("--repo-root, --compile-db and tree are required")
    for path in project_sources(args.repo_root, args.compile_db, args.tree):
        print(path)
    return 0


def run_self_test() -> int:
    """Regression checks for repo-relative recovery across build prefixes."""
    repo = Path("/home/ci/nero-nfc-reader-firmware")
    cases = [
        # Build under repo_root (host): straightforward relative path.
        (Path("/home/ci/nero-nfc-reader-firmware/userspace/app/x.cpp"), "userspace/app/x.cpp"),
        # Build under a different prefix (container/Lima bind mount such as /src).
        (Path("/src/userspace/app/x.cpp"), "userspace/app/x.cpp"),
        (Path("/src/firmware/reader/src/x.cpp"), "firmware/reader/src/x.cpp"),
        # tests/firmware must anchor at tests, not the nested firmware dir.
        (Path("/src/tests/firmware/test_x.cpp"), "tests/firmware/test_x.cpp"),
        # No project dir in the path: unmapped.
        (Path("/opt/vendor/lib/x.cpp"), None),
    ]
    ok = True
    for src, expected in cases:
        rel = _repo_relative(src, repo)
        actual = rel.as_posix() if rel is not None else None
        if actual != expected:
            print(f"self-test FAIL: {src} -> {actual} (expected {expected})", file=sys.stderr)
            ok = False
    if ok:
        print("self-test: OK")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
