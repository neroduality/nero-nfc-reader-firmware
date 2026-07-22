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

# Installs packaging/70-nero-nfc-arduino.rules and 71-nero-nfc-stlink.rules into /etc/udev/rules.d/.
#
# Run from anywhere:
#   sudo bash scripts/install-udev.sh
#   sudo make -C /path/to/nero-nfc-reader-firmware install-udev
#
# The rules file lives only in this firmware repo under packaging/.
set -euo pipefail

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  cat <<'EOF'
Usage: sudo bash scripts/install-udev.sh

Installs packaging/70-nero-nfc-arduino.rules and 71-nero-nfc-stlink.rules from this firmware repository
into /etc/udev/rules.d/ and reloads udev.

From another directory:
  sudo bash /path/to/nero-nfc-reader-firmware/scripts/install-udev.sh
  sudo make -C /path/to/nero-nfc-reader-firmware install-udev
EOF
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: run as root (e.g. sudo bash $0)" >&2
  exit 1
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
udev_src_arduino="${repo_root}/packaging/70-nero-nfc-arduino.rules"
udev_src_stlink="${repo_root}/packaging/71-nero-nfc-stlink.rules"
udev_dest_arduino="/etc/udev/rules.d/70-nero-nfc-arduino.rules"
udev_dest_stlink="/etc/udev/rules.d/71-nero-nfc-stlink.rules"

if [[ ! -f ${udev_src_arduino} ]]; then
  cat >&2 <<-EOF
ERROR: udev rules file not found:
  ${udev_src_arduino}

This file ships only in the nero-nfc-reader-firmware repository (packaging/).
If you are in a sibling checkout (e.g. pcsc-fido), use an absolute path or:
  sudo make -C /path/to/nero-nfc-reader-firmware install-udev
EOF
  exit 1
fi

if [[ ! -f ${udev_src_stlink} ]]; then
  echo "ERROR: udev rules file not found: ${udev_src_stlink}" >&2
  exit 1
fi

install -Dm0644 "${udev_src_arduino}" "${udev_dest_arduino}"
install -Dm0644 "${udev_src_stlink}" "${udev_dest_stlink}"
udevadm control --reload-rules
udevadm trigger
echo "Installed udev rules:"
echo "  ${udev_dest_arduino}"
echo "  ${udev_dest_stlink}"
echo "  (source: ${repo_root}/packaging/)"
echo "Re-plug the Nucleo board if OpenOCD still reports LIBUSB_ERROR_ACCESS."
