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

# Resolve markdownlint-cli >= 0.48.0 for lint parity across distros.
# Ubuntu apt does not ship markdownlint-cli; npm global install when missing or too old.
# Debian often ships /usr/bin/nodejs but not /usr/bin/node; npm wrappers need node.
#
# Sourceable helpers (install-linux-deps.sh, ci-lint.sh):
#   nero_nfc_ensure_markdownlint
#   nero_nfc_markdownlint_collect_targets
#   nero_nfc_markdownlint_fail_on_change
#   nero_nfc_run_markdownlint
set -euo pipefail

NERO_NFC_MARKDOWNLINT_MIN_VERSION=0.48.0
NERO_NFC_MARKDOWNLINT_INSTALL_VERSION=0.48.0
NERO_NFC_NODE_MIN_MAJOR=20

nero_nfc_markdownlint_hint() {
  printf '%s\n' \
    'hint: INSTALL_DEPS=1 bash make/install-linux-deps.sh' \
    "      or: npm install -g markdownlint-cli@${NERO_NFC_MARKDOWNLINT_INSTALL_VERSION}" >&2
}

nero_nfc_node_hint() {
  printf '%s\n' \
    'hint: INSTALL_DEPS=1 bash make/install-linux-deps.sh' \
    "      or: install Node.js >= ${NERO_NFC_NODE_MIN_MAJOR} (markdownlint-cli runtime)" >&2
}

nero_nfc_node_version_major() {
  nero_nfc_ensure_node_symlink || true
  nero_nfc_have_node || return 1
  node -p 'process.versions.node.split(".")[0]' 2>/dev/null
}

nero_nfc_node_ok() {
  local major=""
  major="$(nero_nfc_node_version_major)" || return 1
  [[ ${major} -ge ${NERO_NFC_NODE_MIN_MAJOR} ]]
}

nero_nfc_have_node() {
  command -v node >/dev/null 2>&1 || command -v nodejs >/dev/null 2>&1
}

nero_nfc_ensure_node_symlink() {
  if nero_nfc_have_node; then
    return 0
  fi
  if command -v nodejs >/dev/null 2>&1; then
    if [[ ${EUID} -eq 0 ]]; then
      ln -sf /usr/bin/nodejs /usr/local/bin/node 2>/dev/null || true
    else
      mkdir -p "${HOME}/.local/bin"
      ln -sf "$(command -v nodejs)" "${HOME}/.local/bin/node" 2>/dev/null || true
      export PATH="${HOME}/.local/bin:${PATH}"
    fi
  fi
  nero_nfc_have_node
}

nero_nfc_npm_global_bin() {
  local prefix
  prefix="$(npm prefix -g 2>/dev/null || true)"
  [[ -n ${prefix} ]] || return 1
  printf '%s/bin' "${prefix}"
}

nero_nfc_prepend_npm_global_bin() {
  local npm_bin
  npm_bin="$(nero_nfc_npm_global_bin)" || return 0
  case ":${PATH}:" in
    *":${npm_bin}:"*) ;;
    *) export PATH="${npm_bin}:${PATH}" ;;
  esac
}

nero_nfc_markdownlint_version_raw() {
  local out ver
  command -v markdownlint >/dev/null 2>&1 || return 1
  out="$(markdownlint --version 2>/dev/null | head -n1)" || return 1
  [[ -n ${out} ]] || return 1
  ver="$(printf '%s\n' "${out}" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"
  [[ -n ${ver} ]] || return 1
  printf '%s\n' "${ver}"
}

nero_nfc_markdownlint_version_ge() {
  local want="$1"
  local have
  have="$(nero_nfc_markdownlint_version_raw)" || return 1
  [[ -n ${have} ]] || return 1
  [[ "$(printf '%s\n%s\n' "$want" "$have" | sort -V | head -n1)" == "$want" ]]
}

nero_nfc_ensure_markdownlint() {
  nero_nfc_ensure_node_symlink || true
  nero_nfc_prepend_npm_global_bin

  if nero_nfc_markdownlint_version_ge "$NERO_NFC_MARKDOWNLINT_MIN_VERSION"; then
    return 0
  fi
  if ! command -v npm >/dev/null 2>&1; then
    return 1
  fi

  if ! npm install -g "markdownlint-cli@${NERO_NFC_MARKDOWNLINT_INSTALL_VERSION}" >/dev/null 2>&1; then
    return 1
  fi

  nero_nfc_prepend_npm_global_bin
  nero_nfc_markdownlint_version_ge "$NERO_NFC_MARKDOWNLINT_MIN_VERSION"
}

nero_nfc_run_markdownlint() {
  nero_nfc_prepend_npm_global_bin
  command markdownlint "$@"
}

nero_nfc_markdownlint_collect_targets() {
  local repo_root="${1%/}"
  local file rel

  [[ -d $repo_root ]] || return 0

  while IFS= read -r -d '' file; do
    rel="${file#"$repo_root"/}"
    printf '%s\n' "$rel"
  done < <(
    find "$repo_root" -name '*.md' -type f \
      ! -path '*/third-party/*' \
      ! -path '*/build/*' \
      ! -path '*/build-*/*' \
      ! -path '*/dist/*' \
      ! -path '*/tests/build/*' \
      ! -path '*/tests/build-*/*' \
      ! -path '*/scan-build-report/*' \
      ! -path '*/.git/*' \
      ! -path '*/_deps/*' \
      ! -path '*/node_modules/*' \
      -print0
  ) | LC_ALL=C sort
}

nero_nfc_markdownlint_fail_on_change() {
  local config="$1"
  shift
  local -a files=("$@")
  local before="" after="" f

  if ((${#files[@]} == 0)); then
    printf 'markdownlint: OK\n'
    return 0
  fi

  before="$(mktemp)"
  after="$(mktemp)"

  for f in "${files[@]}"; do
    [[ -f ${f} ]] || continue
    sha256sum "${f}"
  done | LC_ALL=C sort >"${before}"

  nero_nfc_run_markdownlint --config "${config}" --fix "${files[@]}" || true

  for f in "${files[@]}"; do
    [[ -f ${f} ]] || continue
    sha256sum "${f}"
  done | LC_ALL=C sort >"${after}"

  if ! cmp -s "${before}" "${after}"; then
    rm -f "${before}" "${after}"
    printf 'error: markdownlint reformatted Markdown; commit the updates and re-run\n' >&2
    return 1
  fi

  rm -f "${before}" "${after}"

  if ! nero_nfc_run_markdownlint --config "${config}" "${files[@]}"; then
    return 1
  fi

  printf 'markdownlint: OK\n'
}
