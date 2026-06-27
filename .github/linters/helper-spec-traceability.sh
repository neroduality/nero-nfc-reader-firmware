#!/usr/bin/env bash
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

# Verify docs/spec-traceability.yaml against firmware source (symbol present + spec_value match).
# YAML schema/sort is enforced earlier in ci-lint.sh by helper-yamllint.py (--fail-on-change).
#
# Usage:
#   bash .github/linters/helper-spec-traceability.sh
#   bash .github/linters/helper-spec-traceability.sh --self-test

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

if ! python3 -c "import yaml" >/dev/null 2>&1; then
  printf 'error: PyYAML not found (install python3-yaml or: pip install pyyaml)\n' >&2
  exit 2
fi

python3 "${SCRIPT_DIR}/helper-spec-traceability-check.py" --self-test
if [[ ${1:-} == "--self-test" ]]; then
  exit 0
fi
exec python3 "${SCRIPT_DIR}/helper-spec-traceability-check.py" --repo-root "${REPO_ROOT}" "$@"
