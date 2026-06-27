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

"""Resource lifetime policy — RAII for C/C++ acquire/release API pairs.

Applies to all project sources under ``firmware/``, ``userspace/``, and ``tests/``
(``.c``, ``.cpp``, ``.h``, ``.hpp``, ``.ino``). C and C++ share one policy table.

Project code must not manually pair libc/platform acquire/release calls at arbitrary
call sites. Each pair is listed in ``RESOURCE_LIFETIME_PAIRS`` (nero_lint_policy.py);
raw calls are allowed only inside that pair's canonical RAII implementation file(s).

Notes (examples, not an exhaustive list):
  - glob/globfree → GlobResult (nero_nfc_glob_raii.h)
  - fopen/fclose → FileHandle (nero_nfc_file_raii.h)
  - opendir/closedir → DirHandle (nero_nfc_dir_raii.h)
  - dlopen/dlclose → DlHandle (nero_nfc_dl_raii.h)
  - open/close → serial_open helpers (nero_nfc_serial.cpp)
  - SCard* context/card/transaction → PcscCard (nero_nfc_pcsc_connect.cpp)
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
    RESOURCE_LIFETIME_PAIRS,
    is_preprocessor_at,
    is_test_file,
    iter_scan_root_files,
    line_number_at,
    should_skip,
    strip_comments_and_strings,
)

DEFINE_LINE = re.compile(r"^\s*#\s*define\b")

_COMPILED_PAIRS: list[dict[str, object]] = []


def compiled_pairs() -> list[dict[str, object]]:
    if _COMPILED_PAIRS:
        return _COMPILED_PAIRS
    for pair in RESOURCE_LIFETIME_PAIRS:
        _COMPILED_PAIRS.append(
            {
                **pair,
                "acquire_rx": tuple(re.compile(p) for p in pair["acquire"]),
                "release_rx": tuple(re.compile(p) for p in pair["release"]),
            }
        )
    return _COMPILED_PAIRS


def pair_allowed_in_file(path: Path, pair: dict[str, object]) -> bool:
    canonical = pair["canonical_files"]
    assert isinstance(canonical, frozenset)
    return path.name in canonical


def scan_text(path: Path, code: str) -> list[str]:
    issues: list[str] = []
    for pair in compiled_pairs():
        if pair_allowed_in_file(path, pair):
            continue
        label = pair["label"]
        hint = pair["hint"]
        for rx in pair["acquire_rx"]:
            for match in rx.finditer(code):
                if is_preprocessor_at(code, match.start()):
                    continue
                line_no = line_number_at(code, match.start())
                issues.append(
                    f"{path}:{line_no}: manual {label} acquire "
                    f"(use RAII; {hint})"
                )
        for rx in pair["release_rx"]:
            for match in rx.finditer(code):
                if is_preprocessor_at(code, match.start()):
                    continue
                line_no = line_number_at(code, match.start())
                issues.append(
                    f"{path}:{line_no}: manual {label} release "
                    f"(use RAII; {hint})"
                )
    return sorted(set(issues))


def scan_file(path: Path) -> list[str]:
    if is_test_file(path):
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    code = strip_comments_and_strings(text)
    return scan_text(path, code)


def scan_repo(repo_root: Path) -> list[str]:
    errors: list[str] = []
    for path in iter_scan_root_files(repo_root):
        if should_skip(path):
            continue
        errors.extend(scan_file(path))
    return errors


def run_self_test() -> int:
    glob_canonical = "nero_nfc_glob_raii.h"
    file_canonical = "nero_nfc_file_raii.h"
    dir_canonical = "nero_nfc_dir_raii.h"
    dl_canonical = "nero_nfc_dl_raii.h"
    pcsc_canonical = "nero_nfc_pcsc_connect.cpp"
    serial_canonical = "nero_nfc_serial.cpp"
    cases = {
        "glob_ok.cpp": (
            '#include "nero_nfc_glob_raii.h"\n'
            "void f(){ nero_nfc::GlobResult gr; (void)gr.match(\"/dev/tty*\"); }\n",
            set(),
        ),
        "glob_bad.cpp": (
            "#include <glob.h>\n"
            "void f(){ glob_t g{}; (void)glob(\"/dev/tty*\",0,0,&g); globfree(&g); }\n",
            {"glob_bad.cpp"},
        ),
        "fopen_bad.c": (
            "void f(void){ FILE *fp=fopen(\"/tmp/x\",\"r\"); if(fp){fclose(fp);} }\n",
            {"fopen_bad.c"},
        ),
        "fopen_ok.cpp": (
            '#include "nero_nfc_file_raii.h"\n'
            "void f(){ nero_nfc::FileHandle fh; (void)fh.open(\"/tmp/x\", \"r\"); }\n",
            set(),
        ),
        "opendir_bad.c": (
            "void f(void){ DIR *d=opendir(\"/tmp\"); if(d){closedir(d);} }\n",
            {"opendir_bad.c"},
        ),
        "dlopen_bad.cpp": (
            "void f(){ void *h=dlopen(\"libm.so\",0); if(h){dlclose(h);} }\n",
            {"dlopen_bad.cpp"},
        ),
        "pcsc_bad.cpp": (
            "void f(){ SCARDCONTEXT ctx{}; "
            "(void)SCardEstablishContext(0,0,0,&ctx); "
            "(void)SCardReleaseContext(ctx); }\n",
            {"pcsc_bad.cpp"},
        ),
        "open_bad.cpp": (
            "#include <fcntl.h>\n"
            "void f(){ int fd=open(\"/dev/null\",O_RDONLY); close(fd); }\n",
            {"open_bad.cpp"},
        ),
        "comment_ok.c": (
            "/* glob(pattern, 0, NULL, &g) then globfree(&g) */ void f(void){}\n",
            set(),
        ),
        "nolint_ok.c": (
            "void f(){ glob_t g{}; glob(\"/dev/tty*\",0,0,&g); } // NOLINT resource-lifetime\n",
            {"nolint_ok.c"},
        ),
        "split_glob_bad.c": (
            "void f(){ glob_t g{}; glob\n(\"/dev/tty*\",0,0,&g); }\n",
            {"split_glob_bad.c"},
        ),
    }

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        app = root / "userspace" / "app"
        app.mkdir(parents=True)
        (app / glob_canonical).write_text(
            "class GlobResult{~GlobResult(){globfree(&g_);} "
            "int match(const char*p){return glob(p,0,0,&g_);} glob_t g_;};\n",
            encoding="utf-8",
        )
        (app / file_canonical).write_text(
            "class FileHandle{~FileHandle(){if(fp_)fclose(fp_);} "
            "FILE*open(const char*p,const char*m){return fp_=fopen(p,m);} FILE*fp_;};\n",
            encoding="utf-8",
        )
        (app / dir_canonical).write_text(
            "class DirHandle{~DirHandle(){if(dir_)closedir(dir_);} "
            "DIR*open(const char*p){return dir_=opendir(p);} DIR*dir_;};\n",
            encoding="utf-8",
        )
        (app / dl_canonical).write_text(
            "class DlHandle{~DlHandle(){if(h_)dlclose(h_);} "
            "void*open(const char*p,int f){return h_=dlopen(p,f);} void*h_;};\n",
            encoding="utf-8",
        )
        (app / pcsc_canonical).write_text(
            "void list_readers_impl(){ SCARDCONTEXT ctx{}; "
            "SCardEstablishContext(0,0,0,&ctx); SCardReleaseContext(ctx); }\n",
            encoding="utf-8",
        )
        (app / serial_canonical).write_text(
            "int serial_open(const char*p){ int fd=open(p,O_RDONLY); "
            "if(fd<0)return fd; close(fd); return fd; }\n",
            encoding="utf-8",
        )
        for name, (content, _) in cases.items():
            (app / name).write_text(content, encoding="utf-8")

        errors = scan_repo(root)
        reported = {Path(err.split(":", 2)[0]).name for err in errors}

        failed = False
        for name, (_, expected) in cases.items():
            if expected and name not in reported:
                print(f"self-test miss: expected violation in {name}", file=sys.stderr)
                failed = True
            if not expected and name in reported:
                print(f"self-test false positive: {name}", file=sys.stderr)
                failed = True

        for canonical in (
            glob_canonical,
            file_canonical,
            dir_canonical,
            dl_canonical,
            pcsc_canonical,
            serial_canonical,
        ):
            canonical_hits = [
                err for err in errors if Path(err.split(":", 1)[0]).name == canonical
            ]
            if canonical_hits:
                print(
                    f"self-test false positive in canonical file {canonical}: "
                    f"{canonical_hits}",
                    file=sys.stderr,
                )
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
        print("error: resource lifetime policy violations:", file=sys.stderr)
        for err in errors:
            print(f"  {err}", file=sys.stderr)
        print(
            "Use project RAII wrappers for C acquire/release pairs; see "
            "RESOURCE_LIFETIME_PAIRS in nero_lint_policy.py.",
            file=sys.stderr,
        )
        return 1

    print("resource lifetime policy: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
