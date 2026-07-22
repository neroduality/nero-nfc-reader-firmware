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

# Repository architecture gates for the NFC firmware migration (§9).

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path


def shutil_which(name: str) -> str | None:
    return shutil.which(name)


REPO_FIRMWARE = Path("firmware")
ADAPTER_CPP = Path("firmware/libraries/NeroNfcArduino/src/nero_nfc_arduino_port.cpp")
ALLOWED_OWNED_CPP = {
    ADAPTER_CPP,
}
ARDUINO_SPI_ALLOW = {
    Path("firmware/libraries/NeroNfcArduino/src/NeroNfcArduino.hpp"),
    Path("firmware/libraries/NeroNfcArduino/src/nero_nfc_arduino_port.cpp"),
    Path("firmware/reader/reader.ino"),
    Path("firmware/writer/writer.ino"),
    Path("firmware/nfc/nfc.ino"),
}

INCLUDE_SRC_RE = re.compile(
    r'^\s*#\s*include\s*[<"]([^>"]+\.(?:c|cc|cpp|cxx))[>"]',
    re.IGNORECASE | re.MULTILINE,
)
INCLUDE_HPP_RE = re.compile(
    r'^\s*#\s*include\s*[<"]([^>"]+\.hpp)[>"]', re.IGNORECASE | re.MULTILINE
)
ARDUINO_SPI_RE = re.compile(
    r'^\s*#\s*include\s*[<"]((?:Arduino|SPI|Wire)\.h)[>"]', re.MULTILINE
)
IMPL_NAME_RE = re.compile(r"(_impl\.[^.]+|_arduino\.c)$", re.IGNORECASE)
ALLOWED_MUTABLE_GLOBALS = {
    (
        Path("firmware/libraries/NeroNfc/src/core/stack_protector.c"),
        "nero_stack_chk_guard",
    ),
    (
        Path("firmware/libraries/NeroNfc/src/usb/nero_nfc_tinyusb_active.c"),
        "g_tinyusb_active_instance",
    ),
    (
        Path("firmware/libraries/NeroNfc/src/usb/ccid_usb_tinyusb.c"),
        "g_ccid_usb_runtime",
    ),
    (
        Path("firmware/libraries/NeroNfc/src/usb/ccid_usb_stm32_descriptors.c"),
        "g_ccid_usb_stm32_descriptor_runtime",
    ),
    (
        Path("firmware/libraries/NeroNfc/src/usb/ccid_usb_stm32_tinyusb.c"),
        "s_stm32_usb_started",
    ),
}
VALID_FIRMWARE_PROFILES = (
    ("arduino_uno_r4wifi", "reader", "cdc"),
    ("arduino_uno_r4wifi", "writer", "cdc"),
    ("arduino_uno_r4wifi", "nfc", "cdc"),
    ("arduino_uno_r4wifi", "reader", "ccid"),
    ("nucleo_wba65ri", "reader", "cdc"),
    ("nucleo_wba65ri", "writer", "cdc"),
    ("nucleo_wba65ri", "nfc", "cdc"),
    ("nucleo_wba65ri", "reader", "ccid"),
)


def iter_owned_sources(root: Path) -> list[Path]:
    out: list[Path] = []
    for path in (root / "firmware").rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(root)
        parts = rel.parts
        if "third-party" in parts or "build" in parts:
            continue
        if path.suffix.lower() in {
            ".c",
            ".cc",
            ".cpp",
            ".cxx",
            ".h",
            ".hh",
            ".hpp",
            ".hxx",
            ".ino",
        }:
            out.append(rel)
    return sorted(out)


def strip_c_comments_and_literals(text: str) -> str:
    clean = re.sub(
        r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*.*?\*/',
        lambda match: "\n" * match.group(0).count("\n"),
        text,
        flags=re.DOTALL,
    )
    lines: list[str] = []
    in_directive = False
    for line in clean.splitlines(keepends=True):
        if in_directive or line.lstrip().startswith("#"):
            in_directive = line.rstrip().endswith("\\")
            lines.append("\n" if line.endswith("\n") else "")
        else:
            lines.append(line)
    return "".join(lines)


def file_scope_statements(text: str) -> list[str]:
    clean = strip_c_comments_and_literals(text)
    statements: list[str] = []
    current: list[str] = []
    brace_depth = 0
    function_body = False
    for char in clean:
        if char == "{":
            prefix = "".join(current)
            if brace_depth == 0 and ")" in prefix and "=" not in prefix:
                function_body = True
                current.clear()
            elif not function_body:
                current.append(char)
            brace_depth += 1
            continue
        if char == "}":
            brace_depth = max(0, brace_depth - 1)
            if function_body and brace_depth == 0:
                function_body = False
            elif not function_body:
                current.append(char)
            continue
        if function_body:
            continue
        current.append(char)
        if char == ";" and brace_depth == 0:
            statement = " ".join("".join(current).split())
            if statement:
                statements.append(statement)
            current.clear()
    return statements


def mutable_file_scope_names(text: str) -> list[str]:
    names: list[str] = []
    for statement in file_scope_statements(text):
        if statement.startswith(
            ("typedef ", "extern ", "_Static_assert", "static_assert")
        ):
            continue
        if re.match(r"^(?:struct|union|enum)\b.*\}", statement):
            continue
        declaration = statement.split("=", 1)[0].rstrip(" ;")
        function_pointer = re.search(
            r"\(\s*\*\s*((?:const\s+)?)" r"([A-Za-z_][A-Za-z0-9_]*)\s*\)",
            declaration,
        )
        if function_pointer is not None:
            if not function_pointer.group(1):
                names.append(function_pointer.group(2))
            continue
        if "(" in declaration:
            continue
        declaration = re.sub(r"\[[^\]]*\]\s*$", "", declaration).rstrip()
        match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)$", declaration)
        if match is None:
            continue
        name = match.group(1)
        before_name = declaration[: match.start()]
        if "*" in before_name:
            immutable = bool(re.search(r"\bconst\b", before_name.rsplit("*", 1)[1]))
        else:
            immutable = bool(re.search(r"\bconst\b", before_name))
        if not immutable:
            names.append(name)
    return names


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    root = args.repo_root.resolve()
    errors: list[str] = []

    sources = iter_owned_sources(root)
    for rel in sources:
        text = (root / rel).read_text(encoding="utf-8", errors="replace")
        for match in INCLUDE_SRC_RE.finditer(text):
            errors.append(f"{rel}: source-inclusion of {match.group(1)}")
        if rel.suffix.lower() == ".c":
            for match in INCLUDE_HPP_RE.finditer(text):
                errors.append(f"{rel}: C includes C++ header {match.group(1)}")
        if ARDUINO_SPI_RE.search(text) and rel not in ARDUINO_SPI_ALLOW:
            errors.append(f"{rel}: Arduino/SPI/Wire include outside adapter/sketches")
        if IMPL_NAME_RE.search(rel.name):
            errors.append(f"{rel}: forbidden *_impl.* / *_arduino.c name")
        if rel.suffix.lower() == ".c":
            for name in mutable_file_scope_names(text):
                if (rel, name) not in ALLOWED_MUTABLE_GLOBALS:
                    errors.append(f"{rel}: mutable file-scope state {name}")

    for rel in sources:
        if rel.suffix.lower() != ".cpp":
            continue
        if (
            rel.parts[:2] == ("firmware", "libraries")
            and "NeroNfcArduino" not in rel.parts
        ):
            # NeroNfc must stay C-only.
            errors.append(f"{rel}: owned production .cpp outside NeroNfcArduino")
            continue
        if "tests" in rel.parts:
            continue
        if rel not in ALLOWED_OWNED_CPP and rel.parts[0] == "firmware":
            # Allow only adapter + documented ST25 binding.
            if "NeroNfcArduino" in rel.parts and rel.name != ADAPTER_CPP.name:
                errors.append(
                    f"{rel}: NeroNfcArduino must contain only the adapter .cpp"
                )
            elif "NeroNfcArduino" not in rel.parts and rel not in ALLOWED_OWNED_CPP:
                errors.append(
                    f"{rel}: owned production .cpp outside adapter (and ST25 bind)"
                )

    # Runtime board configuration is authoritative after app initialization.
    runtime_board_consumers = {
        Path("firmware/libraries/NeroNfc/src/reader/reader_app.c"): (
            "NFC_BOARD_CS_PIN",
            "NFC_BOARD_IRQ_PIN",
            "NFC_BOARD_LED_PIN",
            "NFC_HOST_SERIAL_BAUD",
            "NFC_HOST_BOARD_NAME",
        ),
        Path("firmware/libraries/NeroNfc/src/writer/writer_app.c"): (
            "NFC_BOARD_CS_PIN",
            "NFC_BOARD_IRQ_PIN",
            "NFC_BOARD_LED_PIN",
            "NFC_HOST_SERIAL_BAUD",
            "NFC_HOST_BOARD_NAME",
        ),
        Path(
            "firmware/libraries/NeroNfc/src/frontend/st25r3916/nero_nfc_st25_frontend.c"
        ): (
            "NFC_BOARD_CS_PIN",
            "NFC_BOARD_IRQ_PIN",
        ),
        Path("firmware/libraries/NeroNfc/src/app/nfc_app.c"): ("NFC_HOST_SERIAL_BAUD",),
    }
    for rel, forbidden_tokens in runtime_board_consumers.items():
        text = (root / rel).read_text(encoding="utf-8")
        for token in forbidden_tokens:
            if token in text:
                errors.append(f"{rel}: runtime board consumer still uses {token}")

    for rel in (
        Path("firmware/reader/reader.ino"),
        Path("firmware/writer/writer.ino"),
        Path("firmware/nfc/nfc.ino"),
    ):
        text = (root / rel).read_text(encoding="utf-8")
        if "g_port.SetSpiClockHz(board.spi_clock_hz);" not in text:
            errors.append(f"{rel}: runtime SPI clock is not applied to Arduino port")

    parity_contracts = {
        Path("firmware/libraries/NeroNfc/src/runtime/nfc_hal_board.c"): (
            "nero_nfc_log_set_sink(&writer_hal_serial_write_char);",
        ),
        Path("firmware/libraries/NeroNfc/src/core/nero_nfc_app.c"): (
            "#if defined(NERO_CCID_ONLY_BUILD)\n  return product == NERO_NFC_PRODUCT_READER;",
            "impl->st25.initialized &&",
            "nero_nfc_tinyusb_active_get() != app",
        ),
        Path("firmware/libraries/NeroNfc/src/writer/writer_app.c"): (
            "(nfc_frontend_t*)context, tx, tx_len, rx, rx_max",
        ),
        Path("firmware/libraries/NeroNfc/src/usb/ccid_usb_tinyusb.c"): (
            "static bool ccid_usb_context_ready(void)",
            "if (!ccid_usb_context_ready() || (desc_itf == NERO_NFC_NULL))",
            "if (!ccid_usb_context_ready() || (request == NERO_NFC_NULL))",
        ),
    }
    for rel, required_fragments in parity_contracts.items():
        text = (root / rel).read_text(encoding="utf-8")
        for fragment in required_fragments:
            if fragment not in text:
                errors.append(f"{rel}: missing parity contract: {fragment}")

    # Invalid product/USB combinations must fail closed in Make.
    for product, usb, label in (
        ("writer", "ccid", "writer-ccid"),
        ("nfc", "ccid", "nfc-ccid"),
    ):
        proc = subprocess.run(
            [
                "make",
                "-n",
                f"FIRMWARE_PRODUCT={product}",
                f"NFC_USB_MODE={usb}",
                "firmware",
            ],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            errors.append(
                f"make FIRMWARE_PRODUCT={product} NFC_USB_MODE={usb} firmware should fail ({label})"
            )
        # Still failed; when the combo token is absent, ensure an invalid-combo diagnostic.
        elif label.split("-")[0] not in (proc.stderr + proc.stdout) and "invalid" not in (
            proc.stderr + proc.stdout
        ).lower():
            errors.append(f"{label}: make failed without invalid-combo diagnostic")

    # The default runtime mode is consumed by C code, so the build define must
    # reach both language command lines for the combined sketch.
    proc = subprocess.run(
        [
            "make",
            "-n",
            "TARGET=arduino_uno_r4wifi",
            "FIRMWARE_PRODUCT=nfc",
            "NFC_USB_MODE=cdc",
            "NFC_MODE=writer",
            "firmware",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    dry_run = proc.stdout + proc.stderr
    if proc.returncode != 0:
        errors.append(f"default-writer dry run failed: {proc.stderr.strip()}")
    for language in ("c", "cpp"):
        pattern = rf'compiler\.{language}\.extra_flags="[^"]*-DNFC_DEFAULT_WRITER=1'
        if re.search(pattern, dry_run) is None:
            errors.append(
                f"NFC_DEFAULT_WRITER missing from compiler.{language}.extra_flags"
            )

    # Every valid build must select exactly its own checked-in hardening profile.
    for target, product, usb in VALID_FIRMWARE_PROFILES:
        expected = f"{target}/{product}/{usb}"
        slug = (
            f"build__lint__firmware__{target}__{product}__{usb}"
            "__compile_commands_json"
        )
        for suffix in (".cmake", ".mk"):
            prefix = "Hardening.by-" if suffix == ".cmake" else "Hardening.flags.by-"
            fragment_path = root / "cmake" / f"{prefix}{slug}{suffix}"
            if not fragment_path.is_file():
                errors.append(
                    f"missing hardening fragment: {fragment_path.relative_to(root)}"
                )
        proc = subprocess.run(
            [
                "make",
                "-s",
                "--no-print-directory",
                f"TARGET={target}",
                f"FIRMWARE_PRODUCT={product}",
                f"NFC_USB_MODE={usb}",
                "print-hardening-profile",
            ],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        selected = proc.stdout.split()
        if proc.returncode != 0:
            errors.append(
                f"{expected}: hardening profile query failed: {proc.stderr.strip()}"
            )
        elif selected != [expected]:
            errors.append(
                f"{expected}: expected exactly one matching hardening profile, got {selected}"
            )

    # Every C header directly under src/ is public and must compile on its own.
    public_root = root / "firmware/libraries/NeroNfc/src"
    include_dirs = [
        public_root,
        public_root / "core",
        public_root / "reader",
        public_root / "writer",
        public_root / "protocol",
        public_root / "usb",
        public_root / "port",
        public_root / "app",
        public_root / "runtime",
        public_root / "frontend",
        public_root / "frontend" / "st25r3916",
    ]
    headers = sorted(public_root.glob("*.h"))
    gcc = shutil_which("gcc")
    if gcc:
        for header in sorted(set(headers)):
            cmd = [
                gcc,
                "-std=gnu11",
                "-fsyntax-only",
                "-x",
                "c",
                "-DNERO_NFC_HOST_TEST=1",
                *[f"-I{d}" for d in include_dirs if d.is_dir()],
                str(header),
            ]
            proc = subprocess.run(
                cmd, cwd=root, capture_output=True, text=True, check=False
            )
            if proc.returncode != 0:
                errors.append(
                    f"public header compile-only failed: "
                    f"{header.relative_to(root)}\n{proc.stderr.strip()}"
                )
    else:
        errors.append("gcc not found; cannot compile-check public C headers")

    if errors:
        print("Architecture check failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print(f"── architecture check OK ({len(sources)} owned sources) ──")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
