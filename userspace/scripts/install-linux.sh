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

# install-linux.sh — build the ISO C++23 userspace and install binaries + udev rules.
#
# Usage:
#   bash userspace/scripts/install-linux.sh [--prefix DIR]
#
# Defaults:
#   prefix = ~/.local
#
# Installs:
#   <prefix>/bin/nero_nfc_uart
#   <prefix>/bin/reader
#   <prefix>/bin/writer
#   /etc/udev/rules.d/70-nero-nfc-arduino.rules  (via sudo; optional)
#
# Tip: Prefer `make && make install-userspace` from the firmware repo root for the normal
# build-then-copy path (`make install-userspace` skips udev unless you run this script).
#
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"
userspace_dir="$repo_root/userspace"
build_dir="$repo_root/build/userspace"
bin_dir="$build_dir/bin"
prefix="$HOME/.local"

while (($# > 0)); do
  case "$1" in
    --prefix)
      shift
      prefix="${1:?--prefix requires an argument}"
      ;;
    --prefix=*)
      prefix="${1#--prefix=}"
      ;;
    -h | --help)
      printf 'Usage: %s [--prefix DIR]\n' "$(basename "$0")"
      exit 0
      ;;
    *)
      printf 'error: unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
  shift
done

install_bin="$prefix/bin"

FIRMWARE_ROOT="$repo_root" INSTALL_DEPS=1 AUTO_INSTALL_LINUX_DEPS=1 \
  bash "$repo_root/make/install-linux-deps.sh"
jobs="$(bash "${repo_root}/make/cpu-jobs.sh")"

printf '== Building C++ userspace ==\n'
rm -rf "$build_dir"
cmake -S "$userspace_dir" -B "$build_dir" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_RUNTIME_OUTPUT_DIRECTORY="$bin_dir"
cmake --build "$build_dir" -- -j"${jobs}"

printf '\n== Installing binaries to %s ==\n' "$install_bin"
mkdir -p "$install_bin"
# Copy binaries — no symlinks.
cp "$bin_dir/nero_nfc_uart" "$install_bin/nero_nfc_uart"
cp "$bin_dir/reader" "$install_bin/reader"
cp "$bin_dir/writer" "$install_bin/writer"
chmod 755 "$install_bin/nero_nfc_uart" "$install_bin/reader" "$install_bin/writer"

printf 'Installed: nero_nfc_uart reader writer → %s\n' "$install_bin"

printf '\n== udev rules ==\n'
if command -v sudo >/dev/null 2>&1; then
  sudo bash "${repo_root}/scripts/install-udev.sh"
else
  printf 'skip: sudo not available — install udev rules manually:\n'
  printf '  sudo bash %q\n' "${repo_root}/scripts/install-udev.sh"
fi

printf '\nDone. Make sure %s is in your PATH.\n' "$install_bin"
