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

"""Shared scan roots and canonical-file policy for custom Python linters."""

from __future__ import annotations

import os
import re
from pathlib import Path

# Directory basenames pruned by walk_tree() under SCAN_ROOTS (firmware/, userspace/, tests/).
# Repo-root trees such as third-party/ and patches/ lie outside those roots; dot-dirs are
# handled in prune_walk_dirnames() (.github/ is kept).
SKIP_DIR_NAMES = frozenset(
    {
        "st25r3916",  # firmware/nfc_core/frontends/st25r3916 (some linters opt back in)
        "build",  # tests/build, nested CMake trees, coverage-html/, etc.
        "build-codeql",  # tests/build-codeql (CodeQL configure)
        "build-scan",  # tests/build-scan (scan-build)
        "scan-build-report",  # tests/scan-build-report
        "_deps",  # CMake FetchContent (e.g. tests/build/_deps)
    }
)
SCAN_ROOTS = ("firmware", "userspace", "tests")
SOURCE_SUFFIXES = {".h", ".hpp", ".c", ".cpp", ".ino"}

# C/C++ scan roots for named-constant policy (helper-bounds-constants.py).
MAGIC_LITERAL_SCAN_ROOTS: tuple[str, ...] = ("firmware", "userspace")

CANONICAL_INDEX_FILES = frozenset(
    {
        "nero_nfc_mem_util.h",
        "nfc_ndef_tlv.h",
        "nfc_pcsc_contactless.h",
        "nfc_tag_info.h",
        "nfc_ccid_frame.h",
        "nfc_ccid_frame.c",
        "nfc_ctap_codec.h",
        "nfc_ctap_codec.c",
        "nfc_ndef_record_decode.c",
        "nfc_ndef_record_decode.h",
        "nfc_mode_line_scan.c",
        "nfc_mode_line_scan.h",
        "nfc_ndef_record_build.h",
        "nfc_writer_payload_common.c",
        "nfc_writer_payload_common.h",
        "nero_nfc_hex.c",
        "nero_nfc_hex.h",
        "st25r3916_iso15693.h",
        "reader_iso_dep_frame.h",
        "reader_iso_dep_apdu_relay.h",
        "reader_ccid_bulk_codec.h",
        "reader_ccid_protocol.h",
        "reader_security_key_ccid_codec.h",
        "reader_cbor.cpp",
    }
)

CANONICAL_BOUNDS_HEADERS = frozenset(
    {
        "nero_nfc_limits.h",
        "nfc_pcsc_contactless.h",
        "nfc_ctap_codec.h",
        "nfc_ccid_frame.h",
        "nfc_frontend.h",
        "nfc_tag_info.h",
        "writer_payload.h",
        "reader_tags_internal.h",
        "reader_context.h",
        "reader_ccid_internal.h",
        "reader_tags_internal.h",
        "ccid_usb_desc.h",
    }
)

# Headers exempt from the single-TU placement rule (shared constant homes by design).
MAGIC_LITERAL_SHARED_HEADER_BASENAMES = frozenset({"nfc_tag_geometry_limits.h"}) | {
    name for name in CANONICAL_INDEX_FILES if name.endswith((".h", ".hpp"))
} | CANONICAL_BOUNDS_HEADERS

CANONICAL_NULL_HEADER = "nero_nfc_null.h"

# Only file that may call raw memcpy/memmove/memset (bounded helpers + secure clear).
CANONICAL_MEMORY_IMPL_FILES = frozenset({"nero_nfc_mem_util.h"})

# C-style acquire/release API pairs — raw calls allowed only in ``canonical_files``.
# Extend when adding RAII wrappers; enforced by helper-resource-lifetime.py.
RESOURCE_LIFETIME_PAIRS: tuple[dict[str, object], ...] = (
    {
        "label": "glob/globfree",
        "acquire": (r"\bglob\s*\(",),
        "release": (r"\bglobfree\s*\(",),
        "canonical_files": frozenset({"nero_nfc_glob_raii.h"}),
        "hint": "GlobResult (nero_nfc_glob_raii.h)",
    },
    {
        "label": "fopen/fclose",
        "acquire": (r"\bfopen\s*\(",),
        "release": (r"\bfclose\s*\(",),
        "canonical_files": frozenset({"nero_nfc_file_raii.h"}),
        "hint": "FileHandle (nero_nfc_file_raii.h)",
    },
    {
        "label": "opendir/closedir",
        "acquire": (r"\bopendir\s*\(",),
        "release": (r"\bclosedir\s*\(",),
        "canonical_files": frozenset({"nero_nfc_dir_raii.h"}),
        "hint": "DirHandle (nero_nfc_dir_raii.h)",
    },
    {
        "label": "dlopen/dlclose",
        "acquire": (r"\bdlopen\s*\(",),
        "release": (r"\bdlclose\s*\(",),
        "canonical_files": frozenset({"nero_nfc_dl_raii.h"}),
        "hint": "DlHandle (nero_nfc_dl_raii.h)",
    },
    {
        "label": "open/close (fd)",
        "acquire": (r"(?<![:\w])open\s*\([^;)]*,\s*O_[A-Z_]",),
        "release": (r"\bclose\s*\(\s*[^)\s]",),
        "canonical_files": frozenset({"nero_nfc_serial.cpp"}),
        "hint": "serial_open / serial helpers (nero_nfc_serial.cpp)",
    },
    {
        "label": "SCardEstablishContext/SCardReleaseContext",
        "acquire": (r"\bSCardEstablishContext\s*\(",),
        "release": (r"\bSCardReleaseContext\s*\(",),
        "canonical_files": frozenset({"nero_nfc_pcsc_connect.cpp"}),
        "hint": "PcscCard / list_readers_impl (nero_nfc_pcsc_connect.cpp)",
    },
    {
        "label": "SCardConnect/SCardDisconnect",
        "acquire": (r"\bSCardConnect\s*\(",),
        "release": (r"\bSCardDisconnect\s*\(",),
        "canonical_files": frozenset({"nero_nfc_pcsc_connect.cpp"}),
        "hint": "PcscCard (nero_nfc_pcsc_connect.cpp)",
    },
    {
        "label": "SCardBeginTransaction/SCardEndTransaction",
        "acquire": (r"\bSCardBeginTransaction\s*\(",),
        "release": (r"\bSCardEndTransaction\s*\(",),
        "canonical_files": frozenset({"nero_nfc_pcsc_connect.cpp"}),
        "hint": "PcscCard transaction methods (nero_nfc_pcsc_connect.cpp)",
    },
)

# Host compile-DB TUs that get the firmware bounds clang-tidy overlay
# (.github/linters/.clang-tidy-firmware-bounds). Prefix match on repo-relative POSIX paths.
FIRMWARE_BOUNDS_TU_PREFIXES = (
    "firmware/nfc_core/common/",
    "firmware/reader/src/reader_security_key_",
    "firmware/reader/src/reader_wauth.",
    "firmware/reader/src/reader_security_key",
    "firmware/reader/src/reader_tags",
    "firmware/reader/src/reader_cbor.",
    "firmware/reader/src/reader_ccid",
    "firmware/writer/src/writer_payload.",
    "firmware/writer/src/writer_tag_write",
    "firmware/writer/src/writer_serial_cli.",
)


def is_firmware_bounds_tu(rel_posix: str) -> bool:
    return rel_posix.startswith(FIRMWARE_BOUNDS_TU_PREFIXES)

FIDO_APP_AID_DRIFT_ALLOW = (
    "nfc_ctap_fido_app_select_variant",
    "nfc_ctap_fido_app_select_variant_match",
    "nfc_ctap_pack_select_fido_apdu",
    "reader_security_key_select_fido_probe",
    "writer_iso_dep_select_fido_app_probe",
)

BANNED_C_API_NAMES = (
    "strcpy",
    "strcat",
    "sprintf",
    "vsprintf",
    "gets",
    "scanf",
    "sscanf",
    "fscanf",
    "popen",
    "system",
    "atoi",
    "atol",
    "atoll",
    "strtol",
    "strtoll",
    "strtoul",
    "strtoull",
    "strtoimax",
    "strtoumax",
)
BANNED_C_API_CALL = re.compile(
    r"\b(" + "|".join(sorted(BANNED_C_API_NAMES, key=len, reverse=True)) + r")\s*\("
)

# Only files that may call raw atoi/strtol-family parsers (bounded wrappers inside).
CANONICAL_PARSE_IMPL_FILES = frozenset({"nero_nfc_parse.c", "nero_nfc_parse.h"})

# Upstream terminal/format I/O — banned outside RAW_OUTPUT_ALLOWED_BASENAMES sink files.
# Overlap with BANNED_C_API_NAMES (sprintf/vsprintf) is scanned once via BANNED_C_API_CALL.
UPSTREAM_OUTPUT_FUNCS = frozenset(
    {
        "printf",
        "fprintf",
        "dprintf",
        "sprintf",
        "snprintf",
        "vsnprintf",
        "vprintf",
        "vfprintf",
        "vdprintf",
        "vsprintf",
        "wprintf",
        "fwprintf",
        "vwprintf",
        "vfwprintf",
        "puts",
        "fputs",
        "fputc",
        "putc",
        "putchar",
        "putwchar",
        "fputwc",
        "fputws",
        "perror",
        "fwrite",
        "fflush",
    }
)
OUTPUT_C_API_NAMES = UPSTREAM_OUTPUT_FUNCS - frozenset(BANNED_C_API_NAMES)
RAW_OUTPUT_ALLOWED_BASENAMES = frozenset(
    {
        "nero_nfc_io.cpp",
        "nero_nfc_format.c",
        "nero_nfc_format.h",
        "reader_hal_board.cpp",
        "writer_hal_board.cpp",
        "nfc_hal_board.cpp",
    }
)


def prune_walk_dirnames(dirnames: list[str], skip_dir_names: frozenset[str]) -> None:
    dirnames[:] = [
        name
        for name in dirnames
        if name not in skip_dir_names
        and not (name.startswith(".") and name != ".github")
    ]


def walk_tree(root: Path, skip_dir_names: frozenset[str]) -> list[Path]:
    """List files under root without descending into skip_dir_names (or dot-dirs except .github).

    ``Path.rglob`` still enters skipped directories before post-filters run; on Lima's
    virtio-fs ``/src`` mount that makes large trees like ``third-party/`` appear hung.
    """
    root = root.resolve()
    if not root.exists():
        return []
    if root.is_file():
        return [root]
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        prune_walk_dirnames(dirnames, skip_dir_names)
        base = Path(dirpath)
        files.extend(base / name for name in filenames)
    return files


def iter_scan_root_files(
    repo_root: Path,
    *,
    scan_roots: tuple[str, ...] = SCAN_ROOTS,
    skip_dir_names: frozenset[str] = SKIP_DIR_NAMES,
    suffixes: frozenset[str] = SOURCE_SUFFIXES,
) -> list[Path]:
    """Pruned file list under scan_roots (default: firmware/userspace/tests)."""
    paths: list[Path] = []
    for root_name in scan_roots:
        root = repo_root / root_name
        if not root.is_dir():
            continue
        for path in walk_tree(root, skip_dir_names):
            if path.suffix not in suffixes:
                continue
            paths.append(path)
    return sorted(paths)


def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIR_NAMES for part in path.parts)


def is_test_file(path: Path) -> bool:
    return "tests" in path.parts


def is_canonical_index_file(path: Path) -> bool:
    return path.name in CANONICAL_INDEX_FILES


def strip_comments_and_strings(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    lines: list[str] = []
    for line in text.splitlines():
        line = re.sub(r"//.*", "", line)
        line = re.sub(r'"([^"\\]|\\.)*"', '""', line)
        line = re.sub(r"'([^'\\]|\\.)*'", "''", line)
        lines.append(line)
    return "\n".join(lines)


def blank_comments_and_strings(text: str) -> str:
    """Blank comments and string/char literal bodies while preserving offsets."""

    def blank(match: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    text = re.sub(r"/\*.*?\*/", blank, text, flags=re.DOTALL)
    out: list[str] = []
    for line in text.splitlines(keepends=True):
        newline = "\n" if line.endswith("\n") else ""
        body = line[: len(line) - len(newline)]
        body = re.sub(r"//.*", lambda match: " " * len(match.group(0)), body)
        body = re.sub(
            r'"([^"\\]|\\.)*"',
            lambda match: '"' + " " * (len(match.group(0)) - 2) + '"',
            body,
        )
        body = re.sub(
            r"'([^'\\]|\\.)*'",
            lambda match: "'" + " " * (len(match.group(0)) - 2) + "'",
            body,
        )
        out.append(body + newline)
    return "".join(out)


def line_number_at(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def is_preprocessor_at(text: str, pos: int) -> bool:
    line_start = text.rfind("\n", 0, pos) + 1
    return text[line_start:pos].lstrip().startswith("#")


def iter_policy_sources(repo_root: Path) -> list[Path]:
    return [path for path in iter_scan_root_files(repo_root) if not should_skip(path)]
