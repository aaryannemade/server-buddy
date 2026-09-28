# Hardware Inventory and Recovery (Phase 1)

Nothing in this phase writes flash or eFuses. Complete it before any flashing.

## Record

| Item | Value |
| --- | --- |
| Board / PCB rev | ESP32-P4-WIFI6-POE-ETH rev 2.0 |
| P4 silicon rev | _from boot log_ |
| P4 flash size / MAC | _from backup_ |
| C6 flash size / MAC | _from backup_ |
| P4 secure boot / flash encryption | _from eFuse summary_ |
| C6 secure boot / flash encryption | _from eFuse summary_ |
| Factory image source + SHA-256 | _Waveshare link_ |

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
