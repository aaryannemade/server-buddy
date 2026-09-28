# Hardware Inventory and Recovery (Phase 1)

Nothing in this phase writes flash or eFuses. Complete it before any flashing.

## Record

| Item | Value |
| --- | --- |
| Board / PCB rev | ESP32-P4-WIFI6-POE-ETH rev 2.0 |
| P4 silicon rev | **v1.3** (ROM eco2, eFuse block v0.3): build with `ESP32P4_SELECTS_REV_LESS_V3` |
| P4 flash / MAC | 32 MB GigaDevice (`c8/4019`) / `e8:f6:0a:e4:1e:7b` |
| P4 USB-UART | CH343 `1a86:55d3` → `/dev/ttyACM0`, console on GPIO 37/38 |
| P4 secure boot / flash encryption | Disabled / disabled; key blocks empty; download mode enabled; `SECURE_VERSION=0` |
| C6 firmware | Factory ESP-Hosted < 1.0 (reported "0.0.0"); **updated to ESP-Hosted 3.0.9 over SDIO on 2026-09-28** (`scripts/update-c6.sh`) |
| P4↔C6 link | SDIO slot 1, 4-bit, 40 MHz: CLK 18, CMD 19, D0–D3 14–17; C6 `CHIP_PU` on GPIO 54 (verified working) |
| Ethernet | IP101, PHY addr 1, MDC 31, MDIO 52, PHY reset 51, RMII TX_EN 49, TXD0/1 34/35, CRS_DV 28, RXD0/1 29/30, 50 MHz ref clock in on GPIO 50 (verified: 100 Mbps full duplex) |
| C6 radio MAC (ESP-NOW source) | `14:c1:9f:01:dd:18` |
| C6 flash / MAC / security | _not read (needs TTL pads; not required so far)_ |
| Previous firmware | Unknown third-party "ESP32-P4 Home Assistant Hub"; owner waived backup; P4 erased 2026-09-28 |

P4 recovery is simple while these eFuses are unburned: `nix build .#p4-firmware`
then `esptool.py --chip esp32p4 -p /dev/ttyACM0 write_flash @result/flash_args`
(run inside `result/`).

## 1. P4

1. Connect the P4 USB-UART port. Capture a boot log without BOOT held:
   `picocom -b 115200 --logfile backups/p4-boot.log /dev/ttyACM0`
   Record the silicon revision (`chip revision: vX.Y`), app version, IP.
2. `scripts/hw-backup.sh p4 /dev/ttyACM0`

## 2. C6 (separate 3.3 V TTL adapter)

1. Power the board off. Wire adapter TX->C6 RX, RX->C6 TX, GND->GND.
   **Do not connect the adapter's 3.3 V/5 V pin.**
2. Tie C6 IO9 to GND. Hold the board BOOT button (keeps P4 from resetting
   the C6), then power the board.
3. `scripts/hw-backup.sh c6 /dev/ttyUSB0`
4. Power off, remove the IO9 strap.

## 3. Restorability gate

A backup is only usable if the recorded security state allows it:

- If flash encryption is enabled, the dump is ciphertext. It can only be
  restored raw (`write_flash --force` of the full image) on the same chip,
  and only if download-mode writes are still allowed.
- If secure boot is enabled, any replacement bootloader/app must be signed
  with the device key. Stop and reassess before writing anything.
- If `DIS_DOWNLOAD_MODE` or similar is burned, serial recovery is impossible.

Restore commands (only after the gate is satisfied):

```sh
esptool.py --chip esp32p4 -p /dev/ttyACM0 write_flash 0x0 backups/<p4>/flash_full.bin
esptool.py --chip esp32c6 -p /dev/ttyUSB0 --before no_reset --after no_reset \
  write_flash 0x0 backups/<c6>/flash_full.bin
```

Rehearse non-destructively: verify the dump against the chip without writing:
`esptool.py ... verify_flash 0x0 backups/<dir>/flash_full.bin`.
Do not erase the only board to test recovery.

## C6 updates without wiring

The C6 is normally updated from the P4 over SDIO (ESP-Hosted co-processor OTA):
`scripts/update-c6.sh` flashes the one-shot `p4-c6-updater` (C6 image embedded),
writes a one-time confirmation token, runs the update, and prints the log.
Reflash the main image afterwards: `scripts/flash-p4.sh`.
If the write or the C6's image check fails, the C6 keeps its old firmware.
The TTL pads (#14, underside: TXD, RXD, GND, IO9) are only needed if a C6
image is accepted but then fails to boot.
