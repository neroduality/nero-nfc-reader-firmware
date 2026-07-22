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
#
# install-pcsc-driver.sh — Register MCU board CCID VID:PID pairs with pcscd
# so pcsc_scan and SCard* APIs see the board as a reader.
#
# For commercial PC/SC readers (ACS, OMNIKEY, etc.) use upstream libccid instead —
# this script is only needed for MCU board VID:PID pairs not in libccid.
#
# Only the system ifd-ccid.bundle Info.plist is patched.  A standalone bundle
# is intentionally NOT used: if the standalone bundle symlinks to the system
# libccid.so, dlopen() resolves both paths to the same library handle and the
# shared ReaderIndex[] array causes Lun=0 collisions with other readers.
#
# Usage:
#   sudo bash scripts/install-pcsc-driver.sh          # install
#   sudo bash scripts/install-pcsc-driver.sh --remove # uninstall
#
# Restart pcscd yourself after install or remove (e.g. systemctl try-restart pcscd.socket).
set -euo pipefail

BUNDLE_NAME="nero-nfc-arduino.bundle"
CCID_ENTRIES=(
  "0x2341|0x006D|Nero NFC Arduino UNO R4 WiFi CCID"
  "0x2341|0x006E|Nero NFC NUCLEO-WBA65RI CCID"
)
# Marker written into the system plist so --remove can identify our entries
MARKER="<!-- nero-nfc-arduino -->"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
find_drivers_dir() {
  for d in \
    /usr/lib64/pcsc/drivers \
    /usr/lib/x86_64-linux-gnu/pcsc/drivers \
    /usr/lib/pcsc/drivers \
    /usr/local/lib/pcsc/drivers; do
    if [[ -d $d ]]; then
      printf '%s' "$d"
      return
    fi
  done
  printf ''
}

# Inject our VID:PID into the system ifd-ccid.bundle Info.plist.
# Appends matching <string> entries to ifdVendorID, ifdProductID, and
# ifdFriendlyName. Idempotent per friendly-name entry.
patch_system_bundle() {
  local plist="$1"
  local entries_arg
  local rc
  if [[ ! -f $plist ]]; then
    echo "  WARNING: system bundle plist not found at ${plist} — skipping." >&2
    return
  fi
  # Back up before the first repo-managed modification.
  if [[ ! -f "${plist}.nero-nfc-arduino.bak" ]] && ! grep -qF "$MARKER" "$plist"; then
    cp "$plist" "${plist}.nero-nfc-arduino.bak"
  fi
  entries_arg="$(printf '%s\n' "${CCID_ENTRIES[@]}")"
  set +e
  python3 - "$plist" "$MARKER" "$entries_arg" <<'PYEOF'
import sys, re

plist_path, marker, entries_arg = sys.argv[1], sys.argv[2], sys.argv[3]
entries = []
for line in entries_arg.splitlines():
    if not line.strip():
        continue
    vid, pid, name = line.split('|', 2)
    entries.append((vid, pid, name))

with open(plist_path) as f:
    content = f.read()

def insert_before_end_array(text, key, new_entry):
    # Find the <array> block following the given <key> and insert before </array>
    pattern = re.compile(
        r'(<key>' + re.escape(key) + r'</key>\s*<array>)(.*?)(</array>)',
        re.DOTALL
    )
    def repl(m):
        return m.group(1) + m.group(2) + new_entry + m.group(3)
    result, n = pattern.subn(repl, text, count=1)
    if n == 0:
        raise RuntimeError(f"key '{key}' with array not found in {plist_path}")
    return result

added = []
for vid, pid, name in entries:
    if f'<string>{name}</string>' in content:
        continue
    content = insert_before_end_array(content, 'ifdVendorID',
                                      f'\t\t<string>{vid}</string> {marker}\n')
    content = insert_before_end_array(content, 'ifdProductID',
                                      f'\t\t<string>{pid}</string> {marker}\n')
    content = insert_before_end_array(content, 'ifdFriendlyName',
                                      f'\t\t<string>{name}</string> {marker}\n')
    added.append(f"{vid}:{pid} ({name})")

if added:
    with open(plist_path, 'w') as f:
        f.write(content)
    print(f"  Patched {plist_path} — added " + ", ".join(added))
    sys.exit(0)

print("  System bundle already has MCU board CCID entries — skipping.")
sys.exit(10)
PYEOF
  rc=$?
  set -e
  if [[ $rc -eq 10 ]]; then
    return 0
  elif [[ $rc -ne 0 ]]; then
    return "$rc"
  fi
}

# Remove our injected lines (marked with $MARKER) from the system plist and
# restore the backup if the patch was not applied (backup present but no marker).
unpatch_system_bundle() {
  local plist="$1"
  local backup="${plist}.nero-nfc-arduino.bak"
  if [[ -f $backup ]]; then
    cp "$backup" "$plist"
    rm -f "$backup"
    echo "  System bundle restored from backup."
  elif [[ -f $plist ]] && grep -qF "$MARKER" "$plist"; then
    sed -i "/${MARKER}/d" "$plist"
    echo "  System bundle entries removed."
  else
    echo "  System bundle was not patched — nothing to undo."
  fi
}

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------
REMOVE=0
for arg in "$@"; do
  case "$arg" in
    --remove | -r) REMOVE=1 ;;
    *)
      echo "Usage: $0 [--remove]" >&2
      exit 1
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  echo "ERROR: This script must be run as root." >&2
  echo "  sudo bash $0${REMOVE:+ --remove}" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Locate pcscd drivers directory
# ---------------------------------------------------------------------------
DRIVERS_DIR="$(find_drivers_dir)"
if [[ -z $DRIVERS_DIR ]]; then
  echo "ERROR: Cannot find pcscd drivers directory." >&2
  echo "  Install pcsc-lite: dnf install pcsc-lite  OR  apt install pcscd" >&2
  exit 1
fi

BUNDLE_DIR="${DRIVERS_DIR}/${BUNDLE_NAME}"

# ---------------------------------------------------------------------------
# --remove path
# ---------------------------------------------------------------------------
if [[ $REMOVE -eq 1 ]]; then
  # Remove any legacy standalone bundle (may have been created by an older
  # version of this script).
  if [[ -d $BUNDLE_DIR ]]; then
    rm -rf "$BUNDLE_DIR"
    echo "Removed legacy bundle ${BUNDLE_DIR}"
  fi
  SYSTEM_PLIST="${DRIVERS_DIR}/ifd-ccid.bundle/Contents/Info.plist"
  unpatch_system_bundle "$SYSTEM_PLIST"
  echo ""
  echo "Done.  Restart pcscd.socket if pcscd is already running, then verify with:"
  echo "  pcsc_scan"
  exit 0
fi

# ---------------------------------------------------------------------------
# Install path: patch system bundle only.
# A standalone bundle is NOT created.  Symlinking to system libccid.so causes
# dlopen() to return the same library handle for both bundles; the resulting
# shared ReaderIndex[] produces Lun=0 conflicts with any other CCID reader
# already registered (e.g., OMNIKEY).
# ---------------------------------------------------------------------------

# Remove any legacy standalone bundle left by a previous install.
if [[ -d $BUNDLE_DIR ]]; then
  rm -rf "$BUNDLE_DIR"
  echo "Removed legacy bundle ${BUNDLE_DIR}"
fi

echo "Installing MCU board CCID entries (system plist patch):"
echo "  Drivers dir : ${DRIVERS_DIR}"

SYSTEM_PLIST="${DRIVERS_DIR}/ifd-ccid.bundle/Contents/Info.plist"
patch_system_bundle "$SYSTEM_PLIST"

echo ""
echo "Done.  Restart pcscd.socket if pcscd is already running, then plug in the board and run:"
echo "  pcsc_scan"
