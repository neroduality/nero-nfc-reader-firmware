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

"""Rewrite arduino-cli sketch build-dir paths in a compile DB back to real sources.

arduino-cli copies the sketch into <build>/sketch/ and records the copies in
compile_commands.json. The org lint kit matches entries by real source path under
scan.source_roots, so rewrite <build>/sketch/<rel> -> <repo>/<sketch_rel>/<rel>
(and the generated <name>.ino.cpp -> <name>.ino) in both `file` and the compile
command. Symlinked sketch TUs resolve to their canonical targets. Core/library
entries (outside the sketch) are kept unchanged as cross templates.

Usage: rewrite-arduino-compile-db.py DB_JSON BUILD_ROOT REPO_ROOT SKETCH_REL
"""

import json
import os
import sys


def main() -> int:
    if len(sys.argv) != 5:
        sys.stderr.write(
            "usage: rewrite-arduino-compile-db.py DB_JSON BUILD_ROOT REPO_ROOT SKETCH_REL\n"
        )
        return 2
    db_path, build_root, repo_root, sketch_rel = sys.argv[1:5]
    build_root = os.path.realpath(build_root)
    repo_root = os.path.realpath(repo_root)
    sketch_prefix = os.path.join(build_root, "sketch") + os.sep
    sketch_abs = os.path.join(repo_root, sketch_rel)

    with open(db_path, encoding="utf-8") as handle:
        entries = json.load(handle)

    out = []
    for entry in entries:
        raw = entry.get("file", "")
        cwd = entry.get("directory", repo_root)
        abs_file = raw if os.path.isabs(raw) else os.path.normpath(os.path.join(cwd, raw))
        if not abs_file.startswith(sketch_prefix):
            out.append(entry)  # core/library template — leave untouched
            continue
        rel = abs_file[len(sketch_prefix):]
        real = os.path.join(sketch_abs, rel)
        if not os.path.exists(real) and rel.endswith(".ino.cpp"):
            real = os.path.join(sketch_abs, rel[: -len(".cpp")])  # foo.ino.cpp -> foo.ino
        if not os.path.exists(real):
            continue  # generated wrapper with no real source — drop
        # Prefer the canonical target when the sketch path is a symlink (§7).
        real = os.path.realpath(real)
        for key in ("command",):
            if key in entry and isinstance(entry[key], str):
                entry[key] = entry[key].replace(abs_file, real)
        if "arguments" in entry and isinstance(entry["arguments"], list):
            entry["arguments"] = [
                real if arg == abs_file else arg for arg in entry["arguments"]
            ]
        entry["file"] = real
        out.append(entry)

    with open(db_path, "w", encoding="utf-8") as handle:
        json.dump(out, handle, indent=1)
        handle.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
