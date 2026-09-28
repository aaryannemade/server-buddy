#!/usr/bin/env bash
# Update the C6 co-processor over SDIO via a one-shot P4 updater, then print
# its log. Reflash the main image afterwards (scripts/flash-p4.sh).
# Usage: scripts/update-c6.sh [--legacy] [port]
#   --legacy: C6 still on factory (pre-1.0) ESP-Hosted firmware.
set -euo pipefail
pkg=p4-c6-updater
if [[ ${1:-} == --legacy ]]; then pkg=p4-c6-updater-legacy; shift; fi
port=${1:-/dev/ttyACM0}
cd "$(dirname "$0")/.."
scripts/flash-p4.sh "$pkg" "$port" 1 >/dev/null
tok=$(mktemp); printf 'SB-C6-UPDATE-CONFIRMED' >"$tok"
# slave_fw partition offset from firmware/p4_c6_updater/partitions.csv
nix develop -c esptool.py --chip esp32p4 -p "$port" --after no_reset write_flash 0x820000 "$tok" >/dev/null
rm -f "$tok"
nix develop -c python scripts/monitor.py "$port" 60
