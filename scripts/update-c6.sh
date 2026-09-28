#!/usr/bin/env bash
# Update the C6 co-processor over SDIO via the one-shot P4 updater, then
# restore the main P4 firmware. Usage: scripts/update-c6.sh [port]
set -euo pipefail
port=${1:-/dev/ttyACM0}
here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here"
scripts/flash-p4.sh p4-c6-updater "$port" 1 >/dev/null
tok=$(mktemp); printf 'SB-C6-UPDATE-CONFIRMED' >"$tok"
# slave_fw partition offset from firmware/p4_c6_updater/partitions.csv
nix develop -c esptool.py --chip esp32p4 -p "$port" --after no_reset write_flash 0x820000 "$tok" >/dev/null
rm -f "$tok"
nix develop -c python scripts/monitor.py "$port" 180
