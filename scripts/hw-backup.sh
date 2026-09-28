#!/usr/bin/env bash
# Phase 1: READ-ONLY inventory and full-flash backup of the P4 or C6.
# Never writes flash or eFuses. Output goes to ./backups/ (git-ignored).
#
# Usage: scripts/hw-backup.sh p4 /dev/ttyACM0
#        scripts/hw-backup.sh c6 /dev/ttyUSB0   # C6 held in download mode, see docs/HARDWARE_RECOVERY.md
set -euo pipefail

chip_arg=${1:-}
port=${2:-}
case "$chip_arg" in
  p4) chip=esp32p4; before=default_reset; after=hard_reset ;;
  # C6 is put in download mode by hand (IO9->GND + BOOT held); don't toggle lines.
  c6) chip=esp32c6; before=no_reset; after=no_reset ;;
  *) echo "usage: $0 <p4|c6> <serial-port>" >&2; exit 2 ;;
esac
[[ -e "$port" ]] || { echo "no such port: $port" >&2; exit 2; }

out="backups/$(date +%Y%m%dT%H%M%S)-$chip_arg"
mkdir -p "$out"
et=(esptool.py --chip "$chip" -p "$port" --before "$before" --after no_reset)
ef=(espefuse.py --chip "$chip" -p "$port" --before "$before" --do-not-confirm)

run() { local name=$1; shift; echo "== $name"; "$@" 2>&1 | tee "$out/$name.txt"; }

run chip_id        "${et[@]}" chip_id
run flash_id       "${et[@]}" flash_id
run security_info  "${et[@]}" get_security_info
run efuse_summary  "${ef[@]}" summary
"${ef[@]}" summary --format json --file "$out/efuse_summary.json"
"${ef[@]}" dump --file_name "$out/efuse_raw.bin" >/dev/null

size=$(grep -oP 'Detected flash size: \K[0-9]+MB' "$out/flash_id.txt" || true)
[[ -n "$size" ]] || { echo "could not detect flash size; aborting before read" >&2; exit 1; }
bytes=$(( ${size%MB} * 1024 * 1024 ))
echo "== read_flash 0x0 $bytes ($size)"
esptool.py --chip "$chip" -p "$port" --before "$before" --after "$after" \
  read_flash 0 "$bytes" "$out/flash_full.bin"

# Partition table lives at 0x8000 by default; decode what is there (may be encrypted).
dd if="$out/flash_full.bin" of="$out/partition_table.bin" bs=4096 skip=8 count=1 status=none
gen_esp32part.py "$out/partition_table.bin" >"$out/partition_table.csv" 2>&1 || \
  echo "partition table not decodable (encrypted or non-default offset)" | tee -a "$out/partition_table.csv"

( cd "$out" && sha256sum ./*.bin >SHA256SUMS )
echo "Backup complete: $out"
grep -iE 'secure boot|flash encryption|SPI_BOOT_CRYPT|DIS_DOWNLOAD|SECURE_VERSION' "$out/efuse_summary.txt" || true
