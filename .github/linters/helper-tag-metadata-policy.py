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

"""Require shared NFC tag metadata parsers instead of local byte fingerprints."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

_LINT_DIR = Path(__file__).resolve().parent
if str(_LINT_DIR) not in sys.path:
    sys.path.insert(0, str(_LINT_DIR))

from nero_lint_policy import SOURCE_SUFFIXES, iter_scan_root_files


NTAG_FINGERPRINT_TOKENS = frozenset(
    {
        "NFC_TAG_NTAG_VER_FIXED_HEADER",
        "NFC_TAG_NTAG_VER_PRODUCT_NTAG",
        "NFC_TAG_NTAG_VER_SUBTYPE",
        "NFC_TAG_NTAG_VER_PROTO_14443",
        "NFC_TAG_NTAG_VER_PRODUCT_BYTE_INDEX",
        "NFC_TAG_NTAG_VER_SUBTYPE_BYTE_INDEX",
        "NFC_TAG_NTAG_VER_PROTO_BYTE_INDEX",
    }
)
NTAG_FINGERPRINT_ALLOWED = frozenset(
    {
        "firmware/nfc_core/common/nfc_tag_geometry_limits.h",
        "firmware/nfc_core/common/nfc_tag_info.h",
    }
)

TYPE5_OVERFLOW_TOKENS = frozenset(
    {
        "NFC_TAG_T5T_CC_FLAGS_BYTE_INDEX",
        "NFC_TAG_T5T_CC_MLEN_OVERFLOW",
        "NFC_TAG_T5T_CC_MLEN_OVERFLOW_CC3_FLAG",
    }
)
TYPE5_OVERFLOW_ALLOWED = frozenset(
    {
        "firmware/nfc_core/common/nfc_byte_tutorial.h",
        "firmware/nfc_core/common/nfc_tag_geometry_limits.h",
        "firmware/nfc_core/common/nfc_tag_info.h",
    }
)

TYPE5_DECLARED_LEN_ALLOWED = frozenset(
    {
        "firmware/nfc_core/common/nfc_byte_tutorial.h",
        "firmware/nfc_core/common/nfc_storage_ndef.h",
        "firmware/nfc_core/common/nfc_tag_geometry_limits.h",
        "firmware/nfc_core/common/nfc_tag_info.h",
    }
)

DETAILS_REQUIRED_CALLS = (
    "nfc_tag_type2_apply_version",
    "nfc_tag_type2_apply_cc",
    "nfc_tag_type4_apply_cc",
    "nfc_tag_type5_apply_cc",
    "nfc_tag_type5_apply_system_info",
    "nfc_tag_type5_apply_system_info_ext",
    "nfc_ndef_tlv_max_payload_for_data_area",
    "nfc_pcsc_type4_max_message_size",
    "nfc_tag_type5_cc_signals_mlen_overflow",
)
TYPE5_STORAGE_REQUIRED_CALLS = (
    "nfc_storage_type5_declared_cc_len_from_first_block",
    "nfc_tag_type5_cc_signals_mlen_overflow",
)
READER_TAGS_REQUIRED_CALLS = (
    "nfc_storage_type5_declared_cc_len_from_first_block",
    "nfc_tag_type5_cc_signals_mlen_overflow",
)

LINE_COMMENT_RE = re.compile(r"//.*")
BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


def strip_comments(text: str) -> str:
    without_blocks = BLOCK_COMMENT_RE.sub(lambda match: "\n" * match.group(0).count("\n"), text)
    return "\n".join(LINE_COMMENT_RE.sub("", line) for line in without_blocks.splitlines())


def _contains_any(text: str, tokens: frozenset[str]) -> list[str]:
    return sorted(token for token in tokens if token in text)


def _line_hits(text: str, token: str, relation_re: re.Pattern[str]) -> list[int]:
    hits: list[int] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if token in line and relation_re.search(line):
            hits.append(lineno)
    return hits


def validate_text(rel: str, text: str) -> list[str]:
    code = strip_comments(text)
    errors: list[str] = []

    if rel not in NTAG_FINGERPRINT_ALLOWED:
        for token in _contains_any(code, NTAG_FINGERPRINT_TOKENS):
            errors.append(
                f"{rel}: direct NTAG GET_VERSION fingerprint token {token}; "
                "use nfc_tag_type2_apply_version() and inspect nfc_tag_type2_info_t"
            )

    if rel not in TYPE5_OVERFLOW_ALLOWED:
        for token in _contains_any(code, TYPE5_OVERFLOW_TOKENS):
            errors.append(
                f"{rel}: direct Type 5 MLEN-overflow token {token}; "
                "use nfc_tag_type5_cc_signals_mlen_overflow()"
            )

    if rel not in TYPE5_DECLARED_LEN_ALLOWED:
        relation = re.compile(r"==\s*(?:0|0u|NFC_ISO7816_SW2_SUCCESS)\b|!=\s*(?:0|0u)\b")
        for lineno in _line_hits(code, "NFC_TAG_T5T_CC_MLEN_BYTE_INDEX", relation):
            errors.append(
                f"{rel}:{lineno}: direct Type 5 CC MLEN length test; "
                "use nfc_storage_type5_declared_cc_len_from_first_block()"
            )

    required_by_file = {
        "userspace/app/nero_nfc_pcsc_tag_details.cpp": DETAILS_REQUIRED_CALLS,
        "userspace/app/nero_nfc_pcsc_storage_type5.cpp": TYPE5_STORAGE_REQUIRED_CALLS,
        "firmware/reader/src/reader_tags.cpp": READER_TAGS_REQUIRED_CALLS,
    }
    for call in required_by_file.get(rel, ()):
        if call not in code:
            errors.append(f"{rel}: expected shared metadata helper call {call}()")

    return errors


def scan_repo(repo_root: Path) -> list[str]:
    errors: list[str] = []
    for path in iter_scan_root_files(repo_root, suffixes=SOURCE_SUFFIXES):
        rel = path.relative_to(repo_root).as_posix()
        errors.extend(validate_text(rel, path.read_text(encoding="utf-8", errors="replace")))
    return errors


def self_test() -> int:
    good_details = "\n".join(DETAILS_REQUIRED_CALLS) + "\n"
    assert validate_text("userspace/app/nero_nfc_pcsc_tag_details.cpp", good_details) == []

    bad_ntag = (
        "bool x(const uint8_t *version) {\n"
        "  return version[NFC_TAG_NTAG_VER_PRODUCT_BYTE_INDEX] == NFC_TAG_NTAG_VER_PRODUCT_NTAG;\n"
        "}\n"
    )
    assert any(
        "nfc_tag_type2_apply_version" in error
        for error in validate_text("userspace/app/bad.cpp", bad_ntag)
    )

    bad_type5_overflow = (
        "bool x(const nfc_tag_type5_info_t &info) {\n"
        "  return (info.cc[NFC_TAG_T5T_CC_FLAGS_BYTE_INDEX] & NFC_TAG_T5T_CC_MLEN_OVERFLOW_CC3_FLAG) != 0u;\n"
        "}\n"
    )
    assert any(
        "nfc_tag_type5_cc_signals_mlen_overflow" in error
        for error in validate_text("userspace/app/bad.cpp", bad_type5_overflow)
    )

    bad_declared_len = (
        "bool x(const uint8_t *cc) {\n"
        "  return cc[NFC_TAG_T5T_CC_MLEN_BYTE_INDEX] == 0u;\n"
        "}\n"
    )
    assert any(
        "nfc_storage_type5_declared_cc_len_from_first_block" in error
        for error in validate_text("firmware/reader/src/bad.cpp", bad_declared_len)
    )
    assert (
        validate_text("firmware/nfc_core/common/nfc_storage_ndef.h", bad_declared_len) == []
    )

    print("helper-tag-metadata-policy self-test: OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    errors = scan_repo(args.repo_root.resolve())
    if errors:
        print("tag metadata policy errors:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        print(
            "\nRoute tag metadata interpretation through nfc_tag_info.h / "
            "nfc_storage_ndef.h helpers. Keep local code to transport, "
            "presentation, or tested shared adapters.",
            file=sys.stderr,
        )
        return 1
    print("tag metadata policy: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
