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

# Shared firmware-root resolution for make/ helper scripts. Source; don't execute.

if [[ ${BASH_SOURCE[0]} == "${0}" ]]; then
  printf '%s\n' "error: source lib-firmware-root.sh instead of executing it" >&2
  exit 1
fi

# Echo the absolute firmware root: the optional $1 if given, else the parent of
# this helper's directory (this file lives in make/, so ".." is the repo root).
nero_resolve_firmware_root() {
  if [[ -n "${1:-}" ]]; then
    (cd "${1}" && pwd)
  else
    (cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
  fi
}
