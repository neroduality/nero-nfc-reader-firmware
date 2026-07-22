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

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, ClassVar

REPO = Path(__file__).resolve().parents[1]
MERGE = REPO / "scripts/merge-compile-commands.py"
CHECKER = REPO / "scripts/check-wba-tinyusb-artifacts.py"
ARCHITECTURE = REPO / "scripts/check-firmware-architecture.py"
ARTIFACTS = REPO / "scripts/check-firmware-artifacts.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MergeCompileCommandsTests(unittest.TestCase):
    def run_merge(self, fragments: list[list[dict]]) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = []
            for index, entries in enumerate(fragments):
                path = root / f"fragment-{index}.json"
                path.write_text(json.dumps(entries), encoding="utf-8")
                paths.append(path)
            return subprocess.run(
                [sys.executable, str(MERGE), "--out", str(root / "out.json"), *map(str, paths)],
                capture_output=True,
                text=True,
                check=False,
            )

    def test_rejects_duplicate_within_fragment(self) -> None:
        entry = {"directory": "/tmp", "file": "same.c", "command": "cc same.c"}
        proc = self.run_merge([[entry, entry]])
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("duplicate compile source /tmp/same.c", proc.stderr)

    def test_rejects_duplicate_across_fragments_after_resolution(self) -> None:
        proc = self.run_merge(
            [
                [{"directory": "/tmp", "file": "same.c", "command": "cc same.c"}],
                [{"directory": "/", "file": "tmp/./same.c", "command": "cc same.c"}],
            ]
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("fragment-0.json entry 0", proc.stderr)
        self.assertIn("fragment-1.json entry 0", proc.stderr)


class WbaTinyUsbCheckerTests(unittest.TestCase):
    checker: ClassVar[Any]

    @classmethod
    def setUpClass(cls) -> None:
        cls.checker = load_module("wba_checker", CHECKER)

    def test_archive_requires_each_expected_member_once(self) -> None:
        members = list(self.checker.EXPECTED)
        self.assertEqual(self.checker.check_archive_members(members, "archive"), [])
        errors = self.checker.check_archive_members([*members, "tusb.o"], "archive")
        self.assertIn("archive member tusb.o occurs 2 times", errors[0])

    def test_link_map_rejects_board_core_tinyusb_duplicate(self) -> None:
        archive = Path("/tmp/libtinyusb_wba65.a")
        lines = [
            *(f"{archive.resolve()}({member})" for member in self.checker.EXPECTED),
            "/tmp/core/core.a(tusb.c.o)",
            "Discarded input sections",
            f"LOAD {archive.resolve()}",
        ]
        errors = self.checker.check_link_map_text(
            "\n".join(lines), Path("/tmp/firmware.map"), archive
        )
        self.assertTrue(any("non-vendor TinyUSB objects" in error for error in errors))

    def test_compile_db_matches_tinyusb_sources_across_bind_mount_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            tinyusb_src = root / "third-party/tinyusb/src"
            other_root = Path("/src")
            entries = []
            for suffix in self.checker.EXPECTED.values():
                (tinyusb_src / suffix).parent.mkdir(parents=True, exist_ok=True)
                (tinyusb_src / suffix).write_text("/* stub */\n", encoding="utf-8")
                # Simulate a vendor DB written on the host path while lint runs as /src.
                entries.append(
                    {
                        "directory": str(other_root),
                        "file": str(other_root / "third-party/tinyusb/src" / suffix),
                        "command": "cc",
                    }
                )
            database = root / "compile_commands.json"
            database.write_text(json.dumps(entries), encoding="utf-8")
            self.assertEqual(self.checker.check_compile_db(database, tinyusb_src), [])

    def test_link_map_accepts_vendor_archive_under_alternate_absolute_root(self) -> None:
        host_archive = Path(
            "/home/ci/nero-nfc-reader-firmware/build/vendor/tinyusb/wba65/libtinyusb_wba65.a"
        )
        container_archive = Path("/src/build/vendor/tinyusb/wba65/libtinyusb_wba65.a")
        lines = [
            *(f"{host_archive}({member})" for member in self.checker.EXPECTED),
            "Discarded input sections",
            f"LOAD {host_archive}",
        ]
        errors = self.checker.check_link_map_text(
            "\n".join(lines), Path("/tmp/firmware.map"), container_archive
        )
        self.assertEqual(errors, [])


class FirmwareArchitectureCheckerTests(unittest.TestCase):
    checker: ClassVar[Any]

    @classmethod
    def setUpClass(cls) -> None:
        cls.checker = load_module("architecture_checker", ARCHITECTURE)

    def test_multiline_mutable_globals_are_detected(self) -> None:
        text = """
static reader_context_t *
    g_active =
        NERO_NFC_NULL;
static uint8_t
    multiline_buffer[32] = {
        0u,
    };
static void (*
    multiline_callback)(void);
static const uint8_t immutable_table[] = {1u};
"""
        self.assertEqual(
            self.checker.mutable_file_scope_names(text),
            ["g_active", "multiline_buffer", "multiline_callback"],
        )

    def test_general_active_pointer_is_not_whitelisted(self) -> None:
        self.assertNotIn(
            (
                Path("firmware/libraries/NeroNfc/src/core/nero_nfc_app.c"),
                "g_active",
            ),
            self.checker.ALLOWED_MUTABLE_GLOBALS,
        )
        self.assertIn(
            (
                Path(
                    "firmware/libraries/NeroNfc/src/usb/"
                    "nero_nfc_tinyusb_active.c"
                ),
                "g_tinyusb_active_instance",
            ),
            self.checker.ALLOWED_MUTABLE_GLOBALS,
        )


class FirmwareArtifactCheckerTests(unittest.TestCase):
    checker: ClassVar[Any]

    @classmethod
    def setUpClass(cls) -> None:
        cls.checker = load_module("firmware_artifact_checker", ARTIFACTS)

    def test_profile_check_rejects_missing_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            errors = self.checker.check_profile_artifacts(
                root, "test_board", "reader", "cdc", set()
            )
            self.assertEqual(len(errors), 2)
            self.assertTrue(all("required artifact missing" in error for error in errors))
            self.assertTrue(any("compile_commands.json" in error for error in errors))
            self.assertTrue(any("reader.ino.map" in error for error in errors))

    def test_compile_database_rejects_missing_and_duplicate_owned_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = (root / "firmware/libraries/NeroNfc/src/core/first.c").resolve()
            second = (root / "firmware/libraries/NeroNfc/src/core/second.c").resolve()
            database = root / "compile_commands.json"
            database.write_text(
                json.dumps(
                    [
                        {"directory": str(root), "file": str(first), "command": "cc first.c"},
                        {"directory": str(root), "file": str(first), "command": "cc first.c"},
                    ]
                ),
                encoding="utf-8",
            )
            errors = self.checker.check_compile_database(
                database, [first, second], {first, second}
            )
            self.assertTrue(any(f"{first} occurs 2 times" in error for error in errors))
            self.assertTrue(any(f"{second} occurs 0 times" in error for error in errors))

    def test_link_map_rejects_missing_and_duplicate_owned_objects(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            first = root / "firmware/libraries/NeroNfc/src/core/first.c"
            second = root / "firmware/libraries/NeroNfc/src/core/second.c"
            text = "\n".join(
                [
                    f"LOAD {root}/build/libraries/NeroNfc/core/first.c.o",
                    f"LOAD {root}/other/libraries/NeroNfc/core/first.c.o",
                ]
            )
            errors = self.checker.check_link_map_text(
                text, root / "firmware.map", root, [first, second], {first, second}
            )
            self.assertTrue(any(f"{first} occurs 2 times" in error for error in errors))
            self.assertTrue(any(f"{second} occurs 0 times" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
