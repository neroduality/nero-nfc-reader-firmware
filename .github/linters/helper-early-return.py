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

"""Guard early-return / guard-clause style in fallible bool functions.

Policy (firmware/userspace/tests):
  - Reject invalid input with guard clauses at function entry (return false / -1).
  - Do not wrap the entire happy path in a positive ``if (ok) { … return true; }``.
  - Do not use ``if (ok) { return true; } else { return false; }`` — invert the guard.
  - Enum/tag dispatch chains (separate ``if (kind == X) { … return true; }`` plus a final
    default ``return false``) and classification ladders (digit range checks) are OK.
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

from nero_lint_policy import iter_scan_root_files, should_skip

FUNC_START = re.compile(
    r"^(?:static\s+)?(?:inline\s+)?(?:NERO_NFC_NODISCARD\s+)?bool\s+\w+\s*\("
)
IF_POSITIVE = re.compile(r"^\s*if\s*\((.+)\)\s*\{?\s*$")
RETURN_TRUE = re.compile(r"^\s*return\s+true\s*;\s*$")
RETURN_FALSE = re.compile(r"^\s*return\s+false\s*;\s*$")
ELSE_FALSE = re.compile(r"^\s*\}\s*else\s*\{\s*$")
CLOSE_BRACE = re.compile(r"^\s*\}\s*$")
ELSE_IF = re.compile(r"^\s*\}\s*else\s+if\s*\(")


def strip_comments_and_strings(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    lines: list[str] = []
    for line in text.splitlines():
        line = re.sub(r"//.*", "", line)
        line = re.sub(r'"([^"\\]|\\.)*"', '""', line)
        line = re.sub(r"'([^'\\]|\\.)*'", "''", line)
        lines.append(line)
    return "\n".join(lines)


def find_matching_brace(lines: list[str], open_idx: int) -> int:
    depth = 0
    for i in range(open_idx, len(lines)):
        depth += lines[i].count("{")
        depth -= lines[i].count("}")
        if depth == 0 and i > open_idx:
            return i
    return -1


def condition_looks_inverted(cond: str) -> bool:
    stripped = cond.strip()
    if stripped.startswith("!"):
        return True
    if re.search(r"\b(!=|>=|<=|>|<)\b", stripped):
        return True
    if "||" in stripped:
        return True
    return False


def find_block_open_for_close(lines: list[str], close_idx: int) -> int:
    depth = 0
    for i in range(close_idx, -1, -1):
        depth -= lines[i].count("{")
        depth += lines[i].count("}")
        if depth == 0 and i < close_idx:
            return i
    return -1


def preceding_if_sibling(lines: list[str], if_idx: int) -> bool:
    """True when this ``if`` immediately follows another ``if { … return true; }``."""
    j = if_idx - 1
    while j >= 0 and not lines[j].strip():
        j -= 1
    if j < 0 or not CLOSE_BRACE.match(lines[j]):
        return False
    prev_open = find_block_open_for_close(lines, j)
    if prev_open < 0:
        return False
    if j <= prev_open:
        return False
    if not RETURN_TRUE.match(lines[j - 1]):
        return False
    return IF_POSITIVE.match(lines[prev_open]) is not None


def is_dispatch_or_classification(lines: list[str], if_idx: int, close_idx: int) -> bool:
    """Allow multi-branch dispatch and range/classification ladders."""
    if if_idx > 0 and ELSE_IF.match(lines[if_idx - 1]):
        return True
    if preceding_if_sibling(lines, if_idx):
        return True
    j = close_idx + 1
    while j < len(lines):
        line = lines[j]
        if not line.strip():
            j += 1
            continue
        if ELSE_IF.match(line) or IF_POSITIVE.match(line):
            return True
        if RETURN_FALSE.match(line):
            return False
        break
    body = lines[if_idx + 1 : close_idx]
    positive_if_returns = 0
    for k, body_line in enumerate(body):
        if IF_POSITIVE.match(body_line):
            sub_close = find_matching_brace(lines, if_idx + 1 + k)
            if sub_close >= 0:
                for inner in lines[if_idx + 2 + k : sub_close]:
                    if RETURN_TRUE.match(inner):
                        positive_if_returns += 1
                        break
    return positive_if_returns >= 1


def iter_bool_function_bodies(lines: list[str]) -> list[tuple[int, int]]:
    """Return (open_brace_idx, close_brace_idx) for each bool function body."""
    bodies: list[tuple[int, int]] = []
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if FUNC_START.match(stripped) or (stripped.startswith("bool ") and "(" in stripped):
            j = i
            while j < len(lines) and "{" not in lines[j]:
                j += 1
            if j >= len(lines):
                break
            end = find_matching_brace(lines, j)
            if end >= 0:
                bodies.append((j, end))
                i = end + 1
                continue
        i += 1
    return bodies


def scan_wrapped_success_in_body(
    lines: list[str], path: Path, open_idx: int, close_idx: int
) -> list[str]:
    issues: list[str] = []
    for i in range(open_idx + 1, close_idx):
        m = IF_POSITIVE.match(lines[i])
        if not m:
            continue
        cond = m.group(1)
        if condition_looks_inverted(cond):
            continue
        block_close = find_matching_brace(lines, i)
        if block_close < 0 or block_close > close_idx:
            continue
        if not RETURN_TRUE.match(lines[block_close - 1]):
            continue
        if block_close + 1 >= len(lines):
            continue
        if not RETURN_FALSE.match(lines[block_close + 1]):
            continue
        if is_dispatch_or_classification(lines, i, block_close):
            continue
        issues.append(
            f"{path}:{i + 1}: wrap happy path in positive if/return-true; "
            f"use guard clause and fall-through return true"
        )
    return issues


def scan_else_return_false(lines: list[str], path: Path) -> list[str]:
    issues: list[str] = []
    for i in range(len(lines) - 2):
        if not RETURN_TRUE.match(lines[i]):
            continue
        if not CLOSE_BRACE.match(lines[i + 1]) and not lines[i + 1].strip().startswith("}"):
            continue
        if not ELSE_FALSE.match(lines[i + 1]):
            if not re.match(r"^\s*\}\s*else\s*\{\s*$", lines[i + 1]):
                continue
        if i + 2 >= len(lines):
            continue
        if not RETURN_FALSE.match(lines[i + 2]):
            continue
        if i > 0 and ELSE_IF.match(lines[i - 1]):
            continue
        issues.append(
            f"{path}:{i + 2}: if/else return true/false; invert guard and early-return false"
        )
    return issues


def scan_file(path: Path) -> list[str]:
    raw = path.read_text(encoding="utf-8", errors="replace")
    text = strip_comments_and_strings(raw)
    lines = text.splitlines()
    issues: list[str] = []
    issues.extend(scan_else_return_false(lines, path))
    seen: set[str] = set()
    for open_idx, close_idx in iter_bool_function_bodies(lines):
        for issue in scan_wrapped_success_in_body(lines, path, open_idx, close_idx):
            if issue not in seen:
                seen.add(issue)
                issues.append(issue)
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
        "wrapped_bad.c": (
            "static bool wrapped_bad(int x) {\n"
            "  if (x > 0) {\n"
            "    do_work();\n"
            "    return true;\n"
            "  }\n"
            "  return false;\n"
            "}\n",
            {"wrapped_bad.c"},
        ),
        "guard_ok.c": (
            "static bool guard_ok(int x) {\n"
            "  if (x <= 0) {\n"
            "    return false;\n"
            "  }\n"
            "  do_work();\n"
            "  return true;\n"
            "}\n",
            set(),
        ),
        "dispatch_ok.c": (
            "static bool dispatch_ok(int k) {\n"
            "  if (k == 1) {\n"
            "    return true;\n"
            "  }\n"
            "  if (k == 2) {\n"
            "    return true;\n"
            "  }\n"
            "  return false;\n"
            "}\n",
            set(),
        ),
        "classify_ok.c": (
            "static bool classify_ok(char c) {\n"
            "  if (c >= '0' && c <= '9') {\n"
            "    return true;\n"
            "  }\n"
            "  if (c >= 'a' && c <= 'f') {\n"
            "    return true;\n"
            "  }\n"
            "  return false;\n"
            "}\n",
            set(),
        ),
        "else_bad.c": (
            "static bool else_bad(int x) {\n"
            "  if (x > 0) {\n"
            "    return true;\n"
            "  } else {\n"
            "    return false;\n"
            "  }\n"
            "}\n",
            {"else_bad.c"},
        ),
        "else_if_dispatch_ok.c": (
            "static bool chain_ok(int k) {\n"
            "  if (k == 1) {\n"
            "    return true;\n"
            "  } else if (k == 2) {\n"
            "    return true;\n"
            "  } else {\n"
            "    return false;\n"
            "  }\n"
            "}\n",
            set(),
        ),
    }

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "firmware" / "probe"
        root.mkdir(parents=True)
        for name, (content, _) in cases.items():
            (root / name).write_text(content, encoding="utf-8")

        errors = scan_repo(Path(tmp))
        reported = {Path(err.split(":", 2)[0]).name for err in errors}

        failed = False
        for name, (_, expected) in cases.items():
            if expected and name not in reported:
                print(f"self-test miss: expected violation in {name}", file=sys.stderr)
                failed = True
            if not expected and name in reported:
                print(f"self-test false positive: {name}", file=sys.stderr)
                failed = True

        if failed:
            print("reported:", sorted(reported), file=sys.stderr)
            return 1

    print("self-test: OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run built-in regression cases and exit",
    )
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    errors = scan_repo(args.repo_root.resolve())
    if errors:
        print("error: early-return style violations:", file=sys.stderr)
        for err in errors:
            print(f"  {err}", file=sys.stderr)
        print(
            "Use guard clauses (early return false) instead of positive if/return-true wrappers.",
            file=sys.stderr,
        )
        return 1

    print("early-return style: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
