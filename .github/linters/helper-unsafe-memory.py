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

"""Unsafe memory and heap policy for firmware/userspace/tests (repo-wide).

Complements clang-tidy/cppcheck with a nullptr-style Python gate that survives
compile-DB gaps and Arduino-only sources.

Rules:
  1. Raw memcpy/memmove/memset (incl. std::*) only in nero_nfc_mem_util.h implementations.
  2. No heap: malloc/calloc/realloc/aligned_alloc/free, C++ new/delete.

Banned string/shell C APIs are enforced by helper-unsafe-api.py.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

_LINT_DIR = Path(__file__).resolve().parent
if str(_LINT_DIR) not in sys.path:
    sys.path.insert(0, str(_LINT_DIR))

from nero_lint_policy import (
    CANONICAL_MEMORY_IMPL_FILES,
    SKIP_DIR_NAMES,
    iter_scan_root_files,
    blank_comments_and_strings,
    is_preprocessor_at,
    line_number_at,
)

RAW_MEM = re.compile(r"(?:::std::)?\b(memcpy|memmove)\s*\(")
RAW_MEMSET = re.compile(r"(?:::std::)?\bmemset\s*\(")
HEAP_C = re.compile(r"\b(aligned_alloc|calloc|free|malloc|realloc)\s*\(")
HEAP_CXX_DELETE = re.compile(r"\bdelete\s*(\[\])?\s*(?:[\w:]|::)")
HEAP_CXX_NEW = re.compile(
    r"(?<![A-Za-z0-9_])new\s*\[|"
    r"(?<![A-Za-z0-9_])new\s+"
    r"(?:const\s+|volatile\s+|unsigned\s+|signed\s+|auto\s+|std::[\w:]+\s*|\[\[nodiscard\]\]\s*)?"
    r"(?:[A-Za-z_][\w:]*|\*)"
)
DEFINE_LINE = re.compile(r"^\s*#\s*define\b")
UNSAFE_MEMORY_SKIP_DIR_NAMES = SKIP_DIR_NAMES - frozenset({"st25r3916"})


def is_canonical_memory_impl(path: Path) -> bool:
    return path.name in CANONICAL_MEMORY_IMPL_FILES


def should_skip_unsafe_memory(path: Path) -> bool:
    return any(part in UNSAFE_MEMORY_SKIP_DIR_NAMES for part in path.parts)


def scan_match(path: Path, text: str, match: re.Match[str], message: str) -> str | None:
    if is_canonical_memory_impl(path):
        return None
    if is_preprocessor_at(text, match.start()):
        return None
    line_no = line_number_at(text, match.start())
    return f"{path}:{line_no}: {message}"


def scan_file(path: Path) -> list[str]:
    issues: list[str] = []
    raw_text = path.read_text(encoding="utf-8", errors="replace")
    text = blank_comments_and_strings(raw_text)
    checks = (
        (
            RAW_MEM,
            "raw memcpy/memmove (use nero_nfc_copy_bytes / nero_nfc_move_bytes / "
            "nero_nfc_zero_bytes)",
        ),
        (
            RAW_MEMSET,
            "raw memset (use nero_nfc_zero_bytes for zero-fill or nero_nfc_secure_clear "
            "for secrets)",
        ),
        (HEAP_C, "heap C API (use stack/static buffers; heap is forbidden in project code)"),
        (HEAP_CXX_NEW, "C++ heap allocation (use stack/static buffers; new is forbidden in project code)"),
        (HEAP_CXX_DELETE, "C++ heap delete (use stack/static buffers; delete is forbidden in project code)"),
    )
    for regex, message in checks:
        for match in regex.finditer(text):
            issue = scan_match(path, text, match, message)
            if issue is not None:
                issues.append(issue)
    return sorted(set(issues))


def scan_repo(repo_root: Path) -> list[str]:
    errors: list[str] = []
    for path in iter_scan_root_files(
        repo_root, skip_dir_names=UNSAFE_MEMORY_SKIP_DIR_NAMES
    ):
        if should_skip_unsafe_memory(path):
            continue
        errors.extend(scan_file(path))
    return errors


def run_self_test() -> int:
    canonical = Path("firmware/nfc_core/common/nero_nfc_mem_util.h")
    cases = {
        "raw_memcpy_app.c": (
            "void f(uint8_t *d,const uint8_t *s){memcpy(d,s,4);}\n",
            {"raw_memcpy_app.c"},
        ),
        "std_memcpy_app.cpp": (
            "void f(uint8_t *d,const uint8_t *s){std::memcpy(d,s,4);}\n",
            {"std_memcpy_app.cpp"},
        ),
        "raw_memset_app.c": (
            "void f(uint8_t *p){memset(p,0,8);}\n",
            {"raw_memset_app.c"},
        ),
        "raw_memmove_app.c": (
            "void f(uint8_t *d,const uint8_t *s){memmove(d,s,4);}\n",
            {"raw_memmove_app.c"},
        ),
        "heap_malloc.c": (
            "void *p=malloc(16); free(p);\n",
            {"heap_malloc.c"},
        ),
        "heap_calloc.c": (
            "void *p=calloc(4,4); free(p);\n",
            {"heap_calloc.c"},
        ),
        "heap_realloc.c": (
            "void *p=realloc(0,16); free(p);\n",
            {"heap_realloc.c"},
        ),
        "heap_aligned.c": (
            "void *p=aligned_alloc(16,64); free(p);\n",
            {"heap_aligned.c"},
        ),
        "heap_new.cpp": (
            "struct S{}; void f(){auto*p=new S; delete p;}\n",
            {"heap_new.cpp"},
        ),
        "heap_new_array.cpp": (
            "void f(){auto*p=new int[4]; delete[] p;}\n",
            {"heap_new_array.cpp"},
        ),
        "safe_copy_ok.c": (
            '#include "nero_nfc_mem_util.h"\n'
            "bool g(uint8_t*d,const uint8_t*s){return nero_nfc_copy_bytes(d,8,0,s,4);}\n",
            set(),
        ),
        "zero_bytes_ok.c": (
            '#include "nero_nfc_mem_util.h"\n'
            "void z(void*p){nero_nfc_zero_bytes(p,4);}\n",
            set(),
        ),
        "comment_memcpy.c": (
            "/* memcpy is banned at call sites */ void f(void){}\n",
            set(),
        ),
        "nolint_memcpy.c": (
            "void f(uint8_t*d,const uint8_t*s){memcpy(d,s,4);} // NOLINT unsafe-memory\n",
            {"nolint_memcpy.c"},
        ),
        "split_memcpy.c": (
            "void f(uint8_t*d,const uint8_t*s){memcpy\n(d,s,4);}\n",
            {"split_memcpy.c"},
        ),
        "canonical_impl.h": (
            "static inline void impl(void*d,const void*s){memcpy(d,s,4);}\n",
            set(),
        ),
        "brace_init_ok.cpp": (
            "struct S{int x;}; void f(){S s{}; (void)s;}\n",
            set(),
        ),
        "param_new_mode.cpp": (
            "enum E{A,B}; void f(E new_mode){(void)new_mode; g_mode=new_mode;}\n",
            set(),
        ),
        "comment_newline.h": (
            "/* Stateful parser for newline-terminated lines matching exactly "
            '"mode reader" */\n',
            set(),
        ),
    }

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "firmware" / "app").mkdir(parents=True)
        (root / "firmware" / "nfc_core" / "common").mkdir(parents=True)
        (root / "firmware" / "nfc_core" / "frontends" / "st25r3916").mkdir(parents=True)
        (root / canonical).write_text(
            "static inline void impl(void*d,const void*s,size_t n){memcpy(d,s,n);}\n",
            encoding="utf-8",
        )
        for name, (content, _) in cases.items():
            if name == "canonical_impl.h":
                (root / canonical).write_text(content, encoding="utf-8")
            else:
                (root / "firmware" / "app" / name).write_text(content, encoding="utf-8")
        (root / "firmware" / "nfc_core" / "frontends" / "st25r3916" / "st25_memcpy_bad.c").write_text(
            "void f(uint8_t *d,const uint8_t *s){memcpy(d,s,4);}\n",
            encoding="utf-8",
        )

        errors = scan_repo(root)
        reported = {Path(err.split(":", 2)[0]).name for err in errors}

        failed = False
        for name, (_, expected) in cases.items():
            if name == "canonical_impl.h":
                continue
            if expected and name not in reported:
                print(f"self-test miss: expected violation in {name}", file=sys.stderr)
                failed = True
            if not expected and name in reported:
                print(f"self-test false positive: {name}", file=sys.stderr)
                failed = True

        canonical_hits = [err for err in errors if canonical.name in err]
        if canonical_hits:
            print(f"self-test false positive in canonical header: {canonical_hits}", file=sys.stderr)
            failed = True
        if "st25_memcpy_bad.c" not in reported:
            print("self-test miss: expected unsafe-memory violation in st25r3916 tree", file=sys.stderr)
            failed = True

        if failed:
            print("reported:", sorted(reported), file=sys.stderr)
            return 1

    print("self-test: OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    errors = scan_repo(args.repo_root.resolve())
    if errors:
        print("error: unsafe memory / heap policy violations:", file=sys.stderr)
        for err in errors:
            print(f"  {err}", file=sys.stderr)
        print(
            "Use nero_nfc_copy_bytes, nero_nfc_move_bytes, nero_nfc_zero_bytes; "
            "no heap or raw libc memory APIs outside nero_nfc_mem_util.h.",
            file=sys.stderr,
        )
        return 1

    print("unsafe memory / heap policy: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
