#!/usr/bin/env bash
# Build (via Nix) and flash the P4 image, then capture the boot log.
# Usage: scripts/flash-p4.sh [package] [port] [seconds-of-log]  (default: p4-firmware)
set -euo pipefail
pkg=${1:-p4-firmware}
port=${2:-/dev/ttyACM0}
secs=${3:-15}
out=$(nix build --no-link --print-out-paths ".#$pkg")
cd "$out"
nix develop "$OLDPWD" -c esptool.py --chip esp32p4 -p "$port" -b 460800 \
  --before default_reset --after no_reset write_flash @flash_args
nix develop "$OLDPWD" -c python - "$port" "$secs" <<'PY'
import serial, sys, time
s = serial.Serial(sys.argv[1], 115200, timeout=0.2)
s.dtr = False; s.rts = True; time.sleep(0.1); s.rts = False  # EN pulse: normal boot
end = time.time() + float(sys.argv[2])
while time.time() < end:
    sys.stdout.write(s.read(4096).decode(errors="replace")); sys.stdout.flush()
PY
