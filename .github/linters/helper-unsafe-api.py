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

"""Banned upstream libc APIs for firmware/userspace/tests.

Two policy groups, one scan:
  1. Unbounded string/shell/parse C APIs (cppcheck-nero-forbidden.cfg) — repo-wide except
     nero_nfc_parse.c/h canonical wrappers.
  2. Raw terminal/format I/O (printf, puts, std::println, Serial.*, …) — repo-wide
     except allowed sink files (nero_nfc_io.cpp, HAL boards, nero_nfc_format.*).
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
    BANNED_C_API_CALL,
    BANNED_C_API_NAMES,
    CANONICAL_PARSE_IMPL_FILES,
    OUTPUT_C_API_NAMES,
    RAW_OUTPUT_ALLOWED_BASENAMES,
    SKIP_DIR_NAMES,
    SOURCE_SUFFIXES,
    blank_comments_and_strings,
    is_preprocessor_at,
    is_test_file,
    iter_scan_root_files,
    line_number_at,
)

OUTPUT_C_CALL_RE = re.compile(
    r"\b(" + "|".join(sorted(OUTPUT_C_API_NAMES, key=len, reverse=True)) + r")\s*\("
)

UPSTREAM_PATTERN_RES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            "|".join(
                (
                    r"std::println\s*\(",
                    r"std::print\s*\(",
                    r"std::cout\s*<<",
                    r"std::cerr\s*<<",
                    r"std::clog\s*<<",
                    r"std::wcout\s*<<",
                    r"std::wcerr\s*<<",
                    r"std::wclog\s*<<",
                    r"\bSerial\.(?:print|println|write)\s*\(",
                )
            )
        ),
        "raw stream/terminal output",
    ),
    (
        re.compile(r"\bwrite\s*\(\s*(?:1|2|STDOUT_FILENO|STDERR_FILENO)\b"),
        "raw stream/terminal output",
    ),
)


def _is_likely_macro(name: str) -> bool:
    body = name.replace("_", "")
    return len(body) > 1 and body.isupper()


def scan_banned_c_api(path: Path, blanked: str, text: str) -> list[str]:
    if path.name in CANONICAL_PARSE_IMPL_FILES:
        return []

    issues: list[str] = []
    for match in BANNED_C_API_CALL.finditer(blanked):
        if is_preprocessor_at(blanked, match.start()):
            continue
        api = match.group(1)
        line_no = line_number_at(text, match.start())
        issues.append(
            f"{path}:{line_no}: banned C API {api}() "
            f"(use bounded helpers; see cppcheck-nero-forbidden.cfg / .clang-tidy)"
        )
    return issues


def scan_raw_terminal_output(path: Path, blanked: str, text: str) -> list[str]:
    if is_test_file(path) or path.name in RAW_OUTPUT_ALLOWED_BASENAMES:
        return []

    issues: list[str] = []
    for pattern, detail in UPSTREAM_PATTERN_RES:
        for match in pattern.finditer(blanked):
            if is_preprocessor_at(blanked, match.start()):
                continue
            line_no = line_number_at(text, match.start())
            issues.append(
                f"{path}:{line_no}: output must use nero_nfc_* wrappers ({detail})"
            )

    for match in OUTPUT_C_CALL_RE.finditer(blanked):
        if is_preprocessor_at(blanked, match.start()):
            continue
        name = match.group(1)
        if _is_likely_macro(name):
            continue
        line_no = line_number_at(text, match.start())
        issues.append(
            f"{path}:{line_no}: output must use nero_nfc_* wrappers (found {name}())"
        )
    return issues


def scan_file(path: Path) -> list[str]:
    if path.suffix not in SOURCE_SUFFIXES:
        return []

    text = path.read_text(encoding="utf-8", errors="replace")
    blanked = blank_comments_and_strings(text)
    issues = scan_banned_c_api(path, blanked, text)
    issues.extend(scan_raw_terminal_output(path, blanked, text))
    return sorted(set(issues))


def scan_repo(repo_root: Path) -> list[str]:
    issues: list[str] = []
    for path in iter_scan_root_files(repo_root, skip_dir_names=SKIP_DIR_NAMES):
        issues.extend(scan_file(path))
    return issues


def run_self_test() -> int:
    cases: dict[str, tuple[str, set[str]]] = {
        "good.c": ("void f(void){}\n", set()),
        "comment_ok.c": ("/* strcpy(d,s) */ void f(void){}\n", set()),
        "good_io.cpp": ('void f(){ nero_nfc::nero_nfc_stderr_line("x"); }\n', set()),
        "good_format.h": (
            "int nero_nfc_snprintf(char *buf, size_t cap, const char *fmt, ...);\n",
            set(),
        ),
        "good_fd_write.cpp": ("void f(){ write(fd, buf, n); }\n", set()),
        "nero_nfc_format.c": (
            "int nero_nfc_vsnprintf(char *buf, size_t cap, const char *fmt, va_list args) {\n"
            "  return vsnprintf(buf, cap, fmt, args);\n"
            "}\n",
            set(),
        ),
        "reader_hal_board.cpp": (
            "void reader_hal_serial_write_char(char c) {\n"
            "  Serial.write(static_cast<uint8_t>(c));\n"
            "}\n",
            set(),
        ),
        "nero_nfc_io.cpp": (
            "namespace nero_nfc {\n"
            "void nero_nfc_stdout_line(const char *s) {\n"
            "  std::println(\"{}\", s);\n"
            "  std::fflush(stdout);\n"
            "}\n"
            "}\n",
            set(),
        ),
        "bad_println.cpp": ('void f(){ std::println("x"); }\n', {"bad_println.cpp"}),
        "bad_raw_fd.cpp": ("void f(){ write(1, buf, n); }\n", {"bad_raw_fd.cpp"}),
    }
    for api in BANNED_C_API_NAMES:
        cases[f"bad_{api}.c"] = (f"void f(void){{{api}(a,b);}}\n", {f"bad_{api}.c"})
        cases[f"bad_split_{api}.ino"] = (
            f"void f(void){{{api}\n(a,b);}}\n",
            {f"bad_split_{api}.ino"},
        )
    for func in OUTPUT_C_API_NAMES:
        name = f"bad_out_{func}.c"
        cases[name] = (f"void f(void) {{ {func}(x); }}\n", {name})

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "firmware" / "app").mkdir(parents=True)
        (root / "firmware" / "writer").mkdir(parents=True)
        for name, (content, _) in cases.items():
            dest = root / "firmware" / ("writer" if name.endswith(".ino") else "app") / name
            dest.write_text(content, encoding="utf-8")

        reported = {Path(err.split(":", 2)[0]).name for err in scan_repo(root)}
        for name, (_, expected) in cases.items():
            if expected and name not in reported:
                print(f"self-test miss: expected violation in {name}", file=sys.stderr)
                return 1
            if not expected and name in reported:
                print(f"self-test false positive: {name}", file=sys.stderr)
                return 1

    print("self-test: OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return run_self_test()
    if args.repo_root is None:
        parser.error("--repo-root is required unless --self-test")
    issues = scan_repo(args.repo_root.resolve())
    if issues:
        print("error: unsafe API policy violations:", file=sys.stderr)
        for issue in issues:
            print(f"  {issue}", file=sys.stderr)
        print(
            "Use bounded project helpers and nero_nfc_* output wrappers "
            "(see cppcheck-nero-forbidden.cfg / .clang-tidy).",
            file=sys.stderr,
        )
        return 1
    print("unsafe API policy: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
