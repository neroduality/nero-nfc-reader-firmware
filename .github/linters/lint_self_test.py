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

"""Strict simulated unit tests for custom linter helpers.

The individual helpers keep small parser self-tests close to the code they test.
This suite is the broader CI-facing gate: every helper script must run its own
``--self-test``, and every linter job gets an independent temporary-repo
simulation that proves the main scan path catches representative bad input and
does not flag canonical/good input.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from types import ModuleType


LINT_DIR = Path(__file__).resolve().parent
REPO_ROOT = LINT_DIR.parent.parent
HELPER_SCRIPTS = tuple(sorted(LINT_DIR.glob("helper-*.py")))
SHELL_LINTER_SCRIPTS = frozenset(script.name for script in LINT_DIR.glob("*.sh"))
SIMULATED_PYTHON_HELPERS = frozenset(
    {
        "helper-bounds-constants.py",
        "helper-clang-tidy-files.py",
        "helper-duplicate-definitions.py",
        "helper-duplicate-includes.py",
        "helper-early-return.py",
        "helper-license-headers.py",
        "helper-macro-enum-naming.py",
        "helper-null-nodiscard.py",
        "helper-relative-includes.py",
        "helper-resource-lifetime.py",
        "helper-safe-indexing.py",
        "helper-spec-traceability-check.py",
        "helper-tag-metadata-policy.py",
        "helper-yamllint.py",
        "helper-unsafe-api.py",
        "helper-unsafe-memory.py",
    }
)
SIMULATED_SHELL_LINTER_SCRIPTS = frozenset(
    {
        "ci-lint.sh",
        "helper-clang-tidy.sh",
        "helper-codespell.sh",
        "helper-cppcheck.sh",
        "helper-markdownlint.sh",
        "helper-spec-traceability.sh",
    }
)


def load_helper(script_name: str) -> ModuleType:
    module_name = script_name.replace("-", "_").removesuffix(".py")
    spec = importlib.util.spec_from_file_location(module_name, LINT_DIR / script_name)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def reported_basenames(errors: list[str]) -> set[str]:
    return {Path(error.split(":", 2)[0]).name for error in errors}


def run_checked(
    args: list[str],
    *,
    cwd: Path = REPO_ROOT,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"command failed ({result.returncode}): {args}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result


def make_fake_executable(directory: Path, name: str, body: str) -> Path:
    path = directory / name
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


class NumberedTextTestResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._test_number = 0

    def startTest(self, test):
        unittest.TestResult.startTest(self, test)
        self._test_number += 1
        if self.showAll:
            self.stream.write(f"{self._test_number:>2}. {self.getDescription(test)}")
            self.stream.write(" ... ")
            self.stream.flush()
            self._newline = False
        elif self.dots:
            self.stream.write(".")
            self.stream.flush()


class NumberedTextTestRunner(unittest.TextTestRunner):
    resultclass = NumberedTextTestResult


class EmbeddedSelfTests(unittest.TestCase):
    def test_every_helper_self_test_passes(self) -> None:
        self.assertGreaterEqual(len(HELPER_SCRIPTS), 1)
        for script in HELPER_SCRIPTS:
            with self.subTest(script=script.name):
                result = subprocess.run(
                    [sys.executable, str(script), "--self-test"],
                    cwd=REPO_ROOT,
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertEqual(
                    result.returncode,
                    0,
                    msg=result.stdout + result.stderr,
                )


class LintStepCoverage(unittest.TestCase):
    def test_every_python_helper_has_independent_simulation(self) -> None:
        helper_names = frozenset(script.name for script in HELPER_SCRIPTS)
        self.assertEqual(helper_names, SIMULATED_PYTHON_HELPERS)

    def test_every_linter_shell_script_has_unit_coverage(self) -> None:
        self.assertEqual(SHELL_LINTER_SCRIPTS, SIMULATED_SHELL_LINTER_SCRIPTS)

    def test_ci_lint_python_helper_steps_are_covered(self) -> None:
        ci_text = (LINT_DIR / "ci-lint.sh").read_text(encoding="utf-8")
        wrapper_text = (LINT_DIR / "helper-spec-traceability.sh").read_text(encoding="utf-8")
        referenced = frozenset(re.findall(r"\bhelper-[A-Za-z0-9-]+\.py\b", ci_text + wrapper_text))
        self.assertTrue(referenced)
        self.assertTrue(referenced <= SIMULATED_PYTHON_HELPERS, sorted(referenced - SIMULATED_PYTHON_HELPERS))

    def test_ci_lint_argument_parser_help_and_unknown_arg(self) -> None:
        help_result = run_checked(["bash", str(LINT_DIR / "ci-lint.sh"), "--help"])
        self.assertIn("--strict-tools", help_result.stdout)
        self.assertIn("--custom-lints-only", help_result.stdout)

        bad_result = subprocess.run(
            ["bash", str(LINT_DIR / "ci-lint.sh"), "--definitely-not-a-real-flag"],
            cwd=REPO_ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(bad_result.returncode, 2)
        self.assertIn("unknown argument", bad_result.stderr)

    def test_cppcheck_forbidden_library_is_parseable_and_complete(self) -> None:
        from nero_lint_policy import BANNED_C_API_NAMES

        root = ET.parse(LINT_DIR / "cppcheck-nero-forbidden.cfg").getroot()
        functions = {node.attrib["name"] for node in root.findall("function")}
        self.assertEqual(frozenset(BANNED_C_API_NAMES), functions)

    def test_codespell_helper_config_uses_multiline_and_noise_filters(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fakebin = Path(tmp)
            make_fake_executable(
                fakebin,
                "codespell",
                "#!/usr/bin/env bash\n"
                "if [[ ${1:-} == '--help' ]]; then echo 'codespell --ignore-multiline-regex'; exit 0; fi\n"
                "if [[ ${1:-} == '--version' ]]; then echo 'codespell 2.4.2'; exit 0; fi\n"
                "exit 0\n",
            )
            env = {**os.environ, "PATH": f"{fakebin}:{os.environ['PATH']}"}
            result = run_checked(
                ["bash", str(LINT_DIR / "helper-codespell.sh"), "--check-config", "docs/example.md"],
                env=env,
            )
        self.assertIn("--ignore-multiline-regex", result.stdout)
        self.assertIn("--ignore-regex", result.stdout)
        self.assertIn("docs/example.md", result.stdout)

    def test_markdownlint_collect_targets_finds_repo_markdown_excluding_vendor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "README.md", "# ok\n")
            write(root / "INSTALLATION.md", "# ok\n")
            write(root / "docs/CCID.md", "# ok\n")
            write(root / "third-party/vendor/IGNORE.md", "# skip\n")
            write(root / "build/out/IGNORE.md", "# skip\n")
            script = (
                f"source {str(LINT_DIR / 'helper-markdownlint.sh')!r}; "
                f"mapfile -t targets < <(nero_nfc_markdownlint_collect_targets {str(root)!r}); "
                'printf "%s\n" "${targets[@]}"'
            )
            result = run_checked(["bash", "-c", script])
            lines = set(result.stdout.strip().splitlines())
            self.assertEqual(
                {
                    "README.md",
                    "INSTALLATION.md",
                    "docs/CCID.md",
                },
                lines,
            )

    def test_markdownlint_fail_on_change_rewrites_then_requires_rerun(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            md = write(root / "README.md", "# Title\n\nExtra line   \n")
            script = (
                f"source {str(LINT_DIR / 'helper-markdownlint.sh')!r}; "
                "if ! nero_nfc_ensure_markdownlint; then echo skip; exit 0; fi; "
                f"cd {str(root)!r}; "
                "set +e; "
                f"nero_nfc_markdownlint_fail_on_change {str(LINT_DIR / '.markdownlint.json')!r} README.md; "
                "ec=$?; "
                "nero_nfc_markdownlint_fail_on_change "
                f"{str(LINT_DIR / '.markdownlint.json')!r} README.md; "
                "ec2=$?; "
                "set -e; "
                '[[ $ec -eq 1 && $ec2 -eq 0 ]]'
            )
            result = run_checked(["bash", "-c", script])
        if result.stdout.strip() == "skip":
            self.skipTest("markdownlint not installed")
        self.assertIn("markdownlint: OK", result.stdout)

    def test_markdownlint_helper_version_parsing_and_comparison(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fakebin = Path(tmp)
            make_fake_executable(
                fakebin,
                "markdownlint",
                "#!/usr/bin/env bash\n"
                "if [[ ${1:-} == '--version' ]]; then echo '0.49.0'; exit 0; fi\n"
                "exit 0\n",
            )
            env = {**os.environ, "PATH": f"{fakebin}:{os.environ['PATH']}"}
            script = (
                f"source {str(LINT_DIR / 'helper-markdownlint.sh')!r}; "
                "got=$(nero_nfc_markdownlint_version_raw); "
                "[[ $got == 0.49.0 ]]; "
                "nero_nfc_markdownlint_version_ge 0.48.0; "
                "if nero_nfc_markdownlint_version_ge 1.0.0; then exit 9; fi"
            )
            run_checked(["bash", "-c", script], env=env)

    def test_clang_tidy_helper_selects_new_enough_tidy_format_and_runner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fakebin = Path(tmp)
            make_fake_executable(
                fakebin,
                "clang-tidy",
                "#!/usr/bin/env bash\n"
                "if [[ ${1:-} == '--version' ]]; then echo 'LLVM version 99.0.0'; exit 0; fi\n"
                "exit 0\n",
            )
            make_fake_executable(fakebin, "run-clang-tidy", "#!/usr/bin/env bash\nexit 0\n")
            make_fake_executable(
                fakebin,
                "clang-format",
                "#!/usr/bin/env bash\n"
                "if [[ ${1:-} == '--version' ]]; then echo 'clang-format version 99.0.0'; exit 0; fi\n"
                "exit 0\n",
            )
            env = {**os.environ, "PATH": f"{fakebin}:{os.environ['PATH']}"}
            script = (
                f"source {str(LINT_DIR / 'helper-clang-tidy.sh')!r}; "
                "tidy=$(nero_nfc_find_clang_tidy); [[ $tidy == */clang-tidy ]]; "
                "runner=$(nero_nfc_find_run_clang_tidy \"$tidy\"); [[ $runner == */run-clang-tidy ]]; "
                "fmt=$(nero_nfc_find_clang_format); [[ $fmt == */clang-format ]]; "
                "nero_nfc_clang_tidy_version_ge 21.0.0 \"$(nero_nfc_clang_tidy_version_raw \"$tidy\")\"; "
                "nero_nfc_clang_format_version_ge 20.0.0 \"$(nero_nfc_clang_format_version_raw \"$fmt\")\""
            )
            run_checked(["bash", "-c", script], env=env)

    def test_clang_tidy_helper_persists_shim_dir_for_github_actions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fakebin = Path(tmp) / "fakebin"
            github_path = Path(tmp) / "github-path"
            fakebin.mkdir()
            make_fake_executable(
                fakebin,
                "clang-format-21",
                "#!/usr/bin/env bash\n"
                "if [[ ${1:-} == '--version' ]]; then echo 'clang-format version 21.0.0'; exit 0; fi\n"
                "exit 0\n",
            )
            env = {
                **os.environ,
                "GITHUB_PATH": str(github_path),
                "HOME": str(Path(tmp) / "home"),
                "PATH": f"{fakebin}:{os.environ['PATH']}",
            }
            script = (
                f"source {str(LINT_DIR / 'helper-clang-tidy.sh')!r}; "
                "nero_nfc_ensure_clang_format; "
                "shim=$(nero_nfc_clang_tidy_install_dir); "
                "fmt=$(nero_nfc_find_clang_format); [[ -x \"$fmt\" ]]; "
                "[[ $(grep -Fx \"$shim\" \"$GITHUB_PATH\" | wc -l) -eq 1 ]]; "
                "nero_nfc_ensure_clang_format; "
                "[[ $(grep -Fx \"$shim\" \"$GITHUB_PATH\" | wc -l) -eq 1 ]]"
            )
            run_checked(["bash", "-c", script], env=env)

    def test_ci_lint_invokes_resolved_llvm_tool_binaries(self) -> None:
        ci_text = (LINT_DIR / "ci-lint.sh").read_text(encoding="utf-8")
        ci_code = "\n".join(
            line for line in ci_text.splitlines() if not line.lstrip().startswith("#")
        )
        self.assertIn('clang_tidy_bin="$(nero_nfc_find_clang_tidy)"', ci_text)
        self.assertIn('clang_format_bin="$(nero_nfc_find_clang_format)"', ci_text)
        self.assertNotRegex(ci_code, r"(?m)^\s*(run\s+)?clang-tidy(\s|$)")
        self.assertNotRegex(ci_code, r"(?m)^\s*(run\s+)?clang-format(\s|$)")
        self.assertIn('"$clang_tidy_bin" --verify-config', ci_text)
        self.assertIn('"$clang_tidy_bin" --quiet', ci_text)
        self.assertIn('"$clang_format_bin" -i', ci_text)
        self.assertIn('run "$clang_format_bin" --dry-run', ci_text)

    def test_cppcheck_helper_version_gate_accepts_required_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fakebin = Path(tmp)
            make_fake_executable(
                fakebin,
                "cppcheck",
                "#!/usr/bin/env bash\n"
                "if [[ ${1:-} == '--version' ]]; then echo 'Cppcheck 2.19.1'; exit 0; fi\n"
                "exit 0\n",
            )
            env = {**os.environ, "PATH": f"{fakebin}:{os.environ['PATH']}"}
            script = (
                f"source {str(LINT_DIR / 'helper-cppcheck.sh')!r}; "
                "got=$(nero_nfc_cppcheck_version_raw); [[ $got == 2.19.1 ]]; "
                "nero_nfc_cppcheck_version_ge 2.19.1; "
                "if nero_nfc_cppcheck_version_ge 2.20.0; then exit 9; fi"
            )
            run_checked(["bash", "-c", script], env=env)

    def test_spec_traceability_wrapper_has_self_test_mode(self) -> None:
        result = run_checked(["bash", str(LINT_DIR / "helper-spec-traceability.sh"), "--self-test"])
        self.assertIn("helper-spec-traceability-check self-test: OK", result.stdout)
        self.assertNotIn("helper-yamllint self-test: OK", result.stdout)

    def test_custom_lints_only_runs_spec_traceability_before_exit(self) -> None:
        script = (LINT_DIR / "ci-lint.sh").read_text(encoding="utf-8")
        self.assertLess(
            script.index('section "Verify spec traceability manifest"'),
            script.index("if ((custom_lints_only == 1))"),
        )

    def test_clang_tidy_configs_treat_naming_as_error(self) -> None:
        for rel in (".github/linters/.clang-tidy-firmware-base",
                    ".github/linters/.clang-tidy-userspace",
                    ".github/linters/.clang-tidy-firmware-bounds"):
            text = (REPO_ROOT / rel).read_text(encoding="utf-8")
            self.assertIn('WarningsAsErrors: "readability-identifier-naming"', text)


class PolicyLinterSimulations(unittest.TestCase):
    def test_bounds_constants_flags_plain_literals_and_loop_bounds(self) -> None:
        helper = load_helper("helper-bounds-constants.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / "userspace/app/bad.cpp",
                "void f(void) {\n"
                "  for (int depth = 0; depth < 8; ++depth) {}\n"
                "  if (x <= 225) { (void)x; }\n"
                "}\n",
            )
            write(
                root / "userspace/app/good.cpp",
                "static constexpr int kProbeDepthMax = 8;\n"
                "void f(void) {\n"
                "  for (int depth = 0; depth < kProbeDepthMax; ++depth) {}\n"
                "}\n",
            )
            write(root / "firmware/app/bad_hex.cpp", "void f(void) { unsigned x = 0x22u; (void)x; }\n")
            write(
                root / "firmware/app/good_const.cpp",
                "static constexpr unsigned kValue = 0x22u;\nvoid f(void) { (void)kValue; }\n",
            )
            write(root / "firmware/app/solo.h", "#define SOLO_ONLY 99u\n")
            write(
                root / "firmware/app/solo.cpp",
                '#include "solo.h"\nvoid f(void) { (void)SOLO_ONLY; }\n',
            )
            errors = helper.scan_repo(root)
            reported = reported_basenames(errors)
        self.assertIn("bad.cpp", reported)
        self.assertIn("bad_hex.cpp", reported)
        self.assertNotIn("good.cpp", reported)
        self.assertNotIn("good_const.cpp", reported)
        self.assertTrue(any("SOLO_ONLY" in error and "move to that .c/.cpp" in error for error in errors), errors)

    def test_clang_tidy_file_filter_handles_repo_and_container_paths(self) -> None:
        helper = load_helper("helper-clang-tidy-files.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            compile_db = root / "compile_commands.json"
            compile_db.write_text(
                json.dumps(
                    [
                        {"directory": str(root), "command": "c++ -c", "file": str(root / "userspace/app/x.cpp")},
                        {"directory": "/src", "command": "c++ -c", "file": "/src/firmware/reader/src/reader_tags.cpp"},
                        {"directory": "/src", "command": "c++ -c", "file": "/src/tests/firmware/test_x.cpp"},
                    ]
                ),
                encoding="utf-8",
            )
            userspace = {path.as_posix() for path in helper.project_sources(root, compile_db, "userspace")}
            bounds = {path.as_posix() for path in helper.project_sources(root, compile_db, "firmware-bounds")}
        self.assertTrue(any(path.endswith("userspace/app/x.cpp") for path in userspace))
        self.assertTrue(any(path.endswith("firmware/reader/src/reader_tags.cpp") for path in bounds))
        self.assertFalse(any("/tests/" in path for path in bounds))

    def test_duplicate_definitions_flags_header_exposed_shadow_constant(self) -> None:
        helper = load_helper("helper-duplicate-definitions.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "firmware/nfc_core/common/canonical.h", "enum { NFC_FOO = 0xA4u };\n")
            write(root / "userspace/app/shadow.cpp", "#define NFC_FOO 0xA4u\n")
            write(root / "userspace/app/local_a.cpp", "#define NFC_LOCAL 5u\n")
            write(root / "userspace/app/local_b.cpp", "#define NFC_LOCAL 5u\n")
            errors = helper.audit(root)
        self.assertTrue(any("NFC_FOO" in error for error in errors), errors)
        self.assertTrue(any("NFC_LOCAL" in error for error in errors), errors)

    def test_duplicate_includes_catches_mixed_and_nolint_duplicates(self) -> None:
        helper = load_helper("helper-duplicate-includes.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "firmware/app/bad.c", '#include <foo.h>\n#include "foo.h" // NOLINT\n')
            write(root / "firmware/app/good.c", 'const char *s = "#include \\"foo.h\\"";\n#include "foo.h"\n')
            write(root / "firmware/app/good.h", "// license\n\n#pragma once\n#include \"foo.h\"\n")
            write(root / "firmware/app/missing_pragma.h", "#include \"foo.h\"\n")
            reported = reported_basenames(helper.scan_repo(root))
        self.assertIn("bad.c", reported)
        self.assertNotIn("good.c", reported)
        self.assertNotIn("good.h", reported)
        self.assertIn("missing_pragma.h", reported)

    def test_early_return_flags_wrapped_success_but_allows_dispatch(self) -> None:
        helper = load_helper("helper-early-return.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / "firmware/app/bad.c",
                "static bool f(int x) {\n"
                "  if (x > 0) {\n"
                "    return true;\n"
                "  }\n"
                "  return false;\n"
                "}\n",
            )
            write(
                root / "firmware/app/good.c",
                "static bool f(int k) {\n"
                "  if (k == 1) { return true; }\n"
                "  if (k == 2) { return true; }\n"
                "  return false;\n"
                "}\n",
            )
            reported = reported_basenames(helper.scan_repo(root))
        self.assertIn("bad.c", reported)
        self.assertNotIn("good.c", reported)

    def test_unsafe_api_flags_each_upstream_output_func(self) -> None:
        helper = load_helper("helper-unsafe-api.py")
        from nero_lint_policy import BANNED_C_API_NAMES, OUTPUT_C_API_NAMES, UPSTREAM_OUTPUT_FUNCS

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for func in OUTPUT_C_API_NAMES:
                write(root / "firmware/writer/src" / f"bad_{func}.c", f"void f(void) {{ {func}(x); }}\n")
            write(
                root / "userspace/app/nero_nfc_io.cpp",
                "namespace nero_nfc { void nero_nfc_stdout_line(const char *) {} }\n",
            )
            reported = reported_basenames(helper.scan_repo(root))
        for func in OUTPUT_C_API_NAMES:
            self.assertIn(f"bad_{func}.c", reported, func)
        self.assertNotIn("nero_nfc_io.cpp", reported)
        self.assertEqual(OUTPUT_C_API_NAMES, UPSTREAM_OUTPUT_FUNCS - frozenset(BANNED_C_API_NAMES))

    def test_unsafe_api_allows_only_wrapper_sink_files(self) -> None:
        helper = load_helper("helper-unsafe-api.py")
        bad = "void f(void) { std::println(\"x\"); }\n"
        allowed = "void f(void) { std::println(\"{}\", s); std::fflush(stdout); }\n"
        self.assertTrue(helper.scan_file(write(Path(tempfile.mkdtemp()) / "bad.cpp", bad)))
        self.assertFalse(helper.scan_file(write(Path(tempfile.mkdtemp()) / "nero_nfc_io.cpp", allowed)))

    def test_unsafe_api_flags_integer_parse_and_ignores_comments_and_canonical_impl(self) -> None:
        helper = load_helper("helper-unsafe-api.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bad = write(
                root / "firmware/app/bad.cpp",
                "void f(const char *s) { (void)strtol\n(s, 0, 10); }\n",
            )
            good = write(root / "firmware/app/good.cpp", "/* strtol(s, 0, 10) */ void f(void) {}\n")
            canonical = write(
                root / "firmware/app/nero_nfc_parse.c",
                "long f(const char *s) { return strtol(s, 0, 10); }\n",
            )
            self.assertTrue(helper.scan_file(bad))
            self.assertFalse(helper.scan_file(good))
            self.assertFalse(helper.scan_file(canonical))

    def test_license_header_repair_is_idempotent_and_prunes_vendor_dirs(self) -> None:
        helper = load_helper("helper-license-headers.py")
        repaired, changed = helper.repair_hash("#!/usr/bin/env bash\necho ok\n", 2026)
        self.assertTrue(changed)
        self.assertTrue(repaired.startswith("#!/usr/bin/env bash\n# SPDX-License-Identifier: Apache-2.0"))
        rerepaired, changed_again = helper.repair_hash(repaired, 2026)
        self.assertFalse(changed_again)
        self.assertEqual(repaired, rerepaired)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "third-party/vendor.c", "int vendor;\n")
            write(root / "src.c", "int project;\n")
            targets = {path.relative_to(root).as_posix() for path in helper.iter_targets(root, helper.SKIP_DIR_NAMES)}
        self.assertIn("src.c", targets)
        self.assertNotIn("third-party/vendor.c", targets)

    def test_macro_enum_naming_scans_macros_shared_enums_and_cpp_constants(self) -> None:
        helper = load_helper("helper-macro-enum-naming.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "firmware/nfc_core/common/bad.h", "#define kBadMacro 1\n")
            write(root / "firmware/nfc_core/common/enums.h", "enum { kBadShared = 1, NFC_GOOD = 2 };\n")
            write(root / "userspace/app/local.cpp", "static constexpr unsigned BAD_LOCAL_CONST = 4u;\n")
            errors = helper.scan_repo(root)
        self.assertTrue(any("kBadMacro" in error for error in errors), errors)
        self.assertTrue(any("kBadShared" in error for error in errors), errors)
        self.assertTrue(any("BAD_LOCAL_CONST" in error for error in errors), errors)

    def test_null_nodiscard_flags_each_null_and_nodiscard_violation(self) -> None:
        helper = load_helper("helper-null-nodiscard.py")
        cases = {
            "raw_null.c": "void f(void *p) { if (p == NULL) {} }\n",
            "legacy_nfc_null.c": "void f(void *p) { if (p == NFC_NULL) {} }\n",
            "cast_null.c": "const void *p = (const uint8_t *)0;\n",
            "source_nullptr.cpp": "void f(const char *s) { if (s == nullptr) {} }\n",
            "missing_nodiscard.h": "#pragma once\nbool probe_no_nodiscard(void);\n",
            "nodiscard_field.h": "struct S { NERO_NFC_NODISCARD bool flag{}; };\n",
            "missing_null_include.c": "void f(void *p) { if (p == NERO_NFC_NULL) {} }\n",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / "firmware/nfc_core/common/nero_nfc_null.h",
                "#define NERO_NFC_NULL nullptr\n",
            )
            for name, body in cases.items():
                write(root / "firmware/app" / name, body)
            reported = reported_basenames(helper.scan_repo(root))
        for name in cases:
            self.assertIn(name, reported, name)

    def test_null_nodiscard_flags_raw_null_missing_include_and_fields(self) -> None:
        helper = load_helper("helper-null-nodiscard.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "firmware/nfc_core/common/nero_nfc_null.h", "#define NERO_NFC_NULL nullptr\n")
            write(root / "firmware/app/raw_null.c", "void f(void *p) { if (p == NULL) {} }\n")
            write(root / "firmware/app/missing_include.c", "void f(void *p) { if (p == NERO_NFC_NULL) {} }\n")
            write(root / "firmware/app/field.h", "struct S { NERO_NFC_NODISCARD bool flag{}; };\n")
            write(root / "firmware/app/comment_ok.c", "/* NULL nullptr NERO_NFC_NULL */ void f(void) {}\n")
            reported = reported_basenames(helper.scan_repo(root))
        self.assertIn("raw_null.c", reported)
        self.assertIn("missing_include.c", reported)
        self.assertIn("field.h", reported)
        self.assertNotIn("comment_ok.c", reported)

    def test_relative_includes_rejects_parent_traversal_without_nolint_escape(self) -> None:
        helper = load_helper("helper-relative-includes.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "firmware/app/bad.c", '#include "../generated.h" // NOLINT\n')
            write(root / "firmware/app/good.c", '/* #include "../hidden.h" */\n#include "ok.h"\n')
            reported = reported_basenames(helper.scan_repo(root))
        self.assertIn("bad.c", reported)
        self.assertNotIn("good.c", reported)

    def test_resource_lifetime_flags_split_manual_pairs_and_allows_canonical_wrappers(self) -> None:
        helper = load_helper("helper-resource-lifetime.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "userspace/app/bad.c", "void f(void) { FILE *fp = fopen\n(\"x\", \"r\"); fclose(fp); } // NOLINT\n")
            write(root / "userspace/app/nero_nfc_file_raii.h", "void f(void) { FILE *fp = fopen(\"x\", \"r\"); fclose(fp); }\n")
            reported = reported_basenames(helper.scan_repo(root))
        self.assertIn("bad.c", reported)
        self.assertNotIn("nero_nfc_file_raii.h", reported)

    def test_safe_indexing_flags_unchecked_external_buffer_access(self) -> None:
        helper = load_helper("helper-safe-indexing.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "firmware/app/bad.c", "uint8_t f(const uint8_t *apdu) { return apdu[5]; } // NOLINT\n")
            write(
                root / "firmware/app/good.c",
                "uint8_t f(const uint8_t *apdu, size_t apdu_len) {\n"
                "  if (apdu_len <= 5) { return 0; }\n"
                "  return apdu[5];\n"
                "}\n",
            )
            reported = reported_basenames(helper.scan_repo(root))
        self.assertIn("bad.c", reported)
        self.assertNotIn("good.c", reported)

    def test_spec_traceability_check_detects_missing_mismatch_and_impl_policy_drift(self) -> None:
        helper = load_helper("helper-spec-traceability-check.py")
        sample = (
            "#define NFC_OK 0xA4u\n"
            "#define NFC_MISMATCH 5u\n"
            "#define NFC_RETRY_ATTEMPTS 3u\n"
        )
        defs = helper._load_defines_from_text(sample)
        self.assertEqual(defs["NFC_OK"], "0xA4u")
        self.assertEqual(helper.normalize_value("0xA4u")[0], 0xA4)
        errors: list[str] = []
        helper.validate_policy_comment("T2T", "NFC_RETRY_ATTEMPTS", "", sample, errors)
        self.assertTrue(errors)
        self.assertNotEqual(helper.normalize_value("6u")[0], helper.normalize_value(defs["NFC_MISMATCH"])[0])

    def test_spec_traceability_main_flags_missing_symbol_and_value_pair(self) -> None:
        helper = LINT_DIR / "helper-spec-traceability-check.py"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "firmware/nfc_core/common/limits.h", "/* [ISO14443-3] section 1 */\n#define NFC_PRESENT 4u\n")
            manifest = write(
                root / "docs/spec-traceability.yaml",
                "constants:\n"
                "  - spec_prefix: ISO14443-3\n"
                "    symbol: NFC_PRESENT\n"
                "    spec_value: \"5\"\n"
                "    ref: \"section 1\"\n"
                "    source: firmware/nfc_core/common/limits.h\n"
                "  - spec_prefix: ISO14443-3\n"
                "    symbol: NFC_MISSING\n"
                "    spec_value: \"4\"\n"
                "    ref: \"section 1\"\n"
                "    source: firmware/nfc_core/common/limits.h\n",
            )
            result = subprocess.run(
                [sys.executable, str(helper), "--repo-root", str(root), "--traceability", str(manifest)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("NFC_PRESENT: spec=5 code=4", result.stderr)
        self.assertIn("NFC_MISSING: source literal not found", result.stderr)

    def test_spec_traceability_main_flags_missing_source_prefix_and_ref(self) -> None:
        helper = LINT_DIR / "helper-spec-traceability-check.py"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "firmware/nfc_core/common/limits.h", "#define NFC_PRESENT 4u\n")
            manifest = write(
                root / "docs/spec-traceability.yaml",
                "constants:\n"
                "  - spec_prefix: ISO14443-3\n"
                "    symbol: NFC_PRESENT\n"
                "    spec_value: \"4\"\n"
                "    source: firmware/nfc_core/common/limits.h\n",
            )
            result = subprocess.run(
                [sys.executable, str(helper), "--repo-root", str(root), "--traceability", str(manifest)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("NFC_PRESENT: ref must be non-empty", result.stderr)
        self.assertIn("NFC_PRESENT: spec_prefix is not cited", result.stderr)

    def test_tag_metadata_policy_rejects_local_fingerprints(self) -> None:
        helper = load_helper("helper-tag-metadata-policy.py")
        errors = helper.validate_text(
            "userspace/app/bad.cpp",
            "bool x(const uint8_t *version) {\n"
            "  return version[NFC_TAG_NTAG_VER_PRODUCT_BYTE_INDEX] == NFC_TAG_NTAG_VER_PRODUCT_NTAG;\n"
            "}\n",
        )
        self.assertTrue(any("nfc_tag_type2_apply_version" in error for error in errors))

        errors = helper.validate_text(
            "firmware/reader/src/bad.cpp",
            "bool x(const uint8_t *cc) {\n"
            "  return cc[NFC_TAG_T5T_CC_MLEN_BYTE_INDEX] == 0u;\n"
            "}\n",
        )
        self.assertTrue(
            any("nfc_storage_type5_declared_cc_len_from_first_block" in error for error in errors)
        )

    def test_yamllint_requires_schema_and_canonical_sort(self) -> None:
        helper = load_helper("helper-yamllint.py")
        bad = {"constants": [{"spec_prefix": "P", "symbol": "NFC_X", "source": "a.h"}]}
        self.assertTrue(any("spec_value" in error for error in helper.validate_manifest(bad)))
        data = {
            "constants": [
                {"spec_prefix": "Z", "symbol": "B", "spec_value": "1", "ref": "section 1", "source": "b.h"},
                {"spec_prefix": "A", "symbol": "A", "spec_value": "2", "ref": "section 2", "source": "a.h"},
            ]
        }
        rendered = helper.canonical_text("", data)
        self.assertLess(rendered.index("symbol: A"), rendered.index("symbol: B"))

    def test_unsafe_api_flags_each_banned_c_api(self) -> None:
        helper = load_helper("helper-unsafe-api.py")
        from nero_lint_policy import BANNED_C_API_NAMES

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for api in BANNED_C_API_NAMES:
                write(root / "firmware/app" / f"bad_{api}.c", f"void f(void) {{ {api}(a, b); }}\n")
            reported = reported_basenames(helper.scan_repo(root))
        for api in BANNED_C_API_NAMES:
            self.assertIn(f"bad_{api}.c", reported, api)

    def test_unsafe_api_fallback_catches_split_banned_calls_in_ino_and_port(self) -> None:
        helper = load_helper("helper-unsafe-api.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "firmware/writer/bad.ino", "void f(char *d, const char *s) { strcpy\n(d, s); }\n")
            write(root / "firmware/port/board/bad.c", "void f(void) { system\n(\"true\"); }\n")
            reported = reported_basenames(helper.scan_repo(root))
        self.assertIn("bad.ino", reported)
        self.assertIn("bad.c", reported)

    def test_unsafe_memory_flags_each_raw_memory_api_outside_canonical(self) -> None:
        helper = load_helper("helper-unsafe-memory.py")
        cases = {
            "memcpy": "void f(uint8_t *d, const uint8_t *s) { memcpy(d, s, 4); }\n",
            "memmove": "void f(uint8_t *d, const uint8_t *s) { memmove(d, s, 4); }\n",
            "memset": "void f(uint8_t *p) { memset(p, 0, 8); }\n",
            "malloc": "void f(void) { void *p = malloc(16); free(p); }\n",
            "calloc": "void f(void) { void *p = calloc(4, 4); free(p); }\n",
            "realloc": "void f(void) { void *p = realloc(0, 16); free(p); }\n",
            "new": "struct S {}; void f(void) { auto *p = new S; delete p; }\n",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / "firmware/nfc_core/common/nero_nfc_mem_util.h",
                "static inline void ok(void *d, const void *s) { memcpy(d, s, 4); }\n",
            )
            for name, body in cases.items():
                suffix = "cpp" if name == "new" else "c"
                write(root / "firmware/app" / f"bad_{name}.{suffix}", body)
            reported = reported_basenames(helper.scan_repo(root))
        for name in cases:
            self.assertIn(f"bad_{name}.{'cpp' if name == 'new' else 'c'}", reported, name)
        self.assertNotIn("nero_nfc_mem_util.h", reported)

    def test_unsafe_memory_flags_split_calls_heap_and_keeps_canonical_impl_free(self) -> None:
        helper = load_helper("helper-unsafe-memory.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "firmware/app/bad.c", "void f(uint8_t *d, const uint8_t *s) { memcpy\n(d, s, 4); } // NOLINT\n")
            write(root / "firmware/app/heap.cpp", "struct S {}; void f(void) { auto *p = new S; delete p; }\n")
            write(root / "firmware/nfc_core/common/nero_nfc_mem_util.h", "void f(void *d, const void *s) { memcpy(d, s, 4); }\n")
            reported = reported_basenames(helper.scan_repo(root))
        self.assertIn("bad.c", reported)
        self.assertIn("heap.cpp", reported)
        self.assertNotIn("nero_nfc_mem_util.h", reported)


if __name__ == "__main__":
    unittest.main(testRunner=NumberedTextTestRunner, verbosity=2)
