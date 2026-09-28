#!/usr/bin/env bash
# Unattended soak: logs the P4 console (no reset) and 1 Hz pings to backups/.
# Usage: scripts/soak.sh [hours=24] [ip=192.168.64.156] [port=/dev/ttyACM0]
# Stop early with: kill $(cat backups/soak.pid)
# Summary afterwards: scripts/soak.sh --report <dir>
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ${1:-} == --report ]]; then
  d=$2
  echo "pings: $(grep -c 'bytes from' "$d/ping.log") ok, $(grep -c -E 'no answer|Unreachable' "$d/ping.log") lost"
  echo "P4 boots: $(grep -c 'app_init: Project name' "$d/serial.log")"
  echo "C6 resets by host: $(grep -c 'Reset co-processor' "$d/serial.log")"
  echo "transport failures: $(grep -c 'TRANSPORT_FAILURE' "$d/serial.log")"
  echo "link down events: $(grep -c 'sb_eth: link down' "$d/serial.log")"
  grep 'C6 status' "$d/serial.log" | tail -1
  exit 0
fi
hours=${1:-24}; ip=${2:-192.168.64.156}; port=${3:-/dev/ttyACM0}
d="backups/soak-$(date +%Y%m%dT%H%M%S)"; mkdir -p "$d"
secs=$((hours * 3600))
nohup nix develop -c timeout "$secs" python scripts/monitor.py "$port" 0 --no-reset >"$d/serial.log" 2>&1 &
mon=$!
nohup timeout "$secs" ping -O -D -i 1 "$ip" >"$d/ping.log" 2>&1 &
echo "$mon $!" >backups/soak.pid
echo "soak running for ${hours}h -> $d (report: scripts/soak.sh --report $d)"
