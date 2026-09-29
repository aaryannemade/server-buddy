# Development

## Environment

```sh
cp .envrc.example .envrc && direnv allow   # or: nix develop
nix flake check                            # all checks, offline builds
nix build .#p4-firmware                    # P4 image in ./result
```

For the board's HTTPS/WebSocket smoke test, first update the C6 and P4 as a
matched pair (the `sb_link` wire version changed), then run:

```sh
ha-python scripts/hw-api-smoke.py HUB_IP --claim \
  --token-file /tmp/server-buddy-token \
  --fingerprint-file /tmp/server-buddy-fingerprint --eviction
```

The test prints no credentials. Keep both files outside Git; subsequent runs
omit `--claim` and verify the pinned certificate and existing credential.
`--retain-node` leaves a key-only test slot for a restart check. After reboot,
use `--expect-slot SLOT --expect-epoch-change OLD_EPOCH` to verify persistence
and remove that slot. The test requires `ha-python` from the Nix shell.

The shell provides ESP-IDF v5.5.4 (`idf.py`, `esptool.py`), ESPHome, Ruff,
and Home Assistant test tools under namespaced wrappers (`ha-python`,
`ha-pytest`, `ha-mypy`) so they never shadow the IDF Python.

Nix builds disable the IDF component manager. Any managed component must be
vendored or packaged in the flake before a firmware check can use it.

## Host setup Nix cannot do

- Serial access: your user must be in `dialout` (or equivalent udev rule).
- P4 USB-UART enumerates as `/dev/ttyACM*` or `/dev/ttyUSB*`.
- C6 recovery needs a separate 3.3 V USB-TTL adapter on the C6 UART header.
  Connect TX, RX and GND only. Never connect the adapter's power pin while
  the board is powered by PoE or USB.

## P4 silicon revision

This board is P4 silicon v1.3; `firmware/p4/sdkconfig.defaults` targets
revisions < v3. A v3.x board needs those lines removed.

## XIAO Logger HAT sensor bring-up (Phase 7)

`esphome/examples/xiao-logger-hat-wifi-smoke.yaml` is a USB-powered Wi-Fi
smoke test for the Seeed XIAO ESP32-C3 and XIAO Logger HAT (SHT40 temperature/
humidity at I²C 0x44, BH1750 illuminance at 0x23). GPIO10 switches sensor
power, and GPIO6/7 are SDA/SCL. Each sensor updates every 30 seconds. There
is no battery voltage entity in this USB test.

Copy the YAML into ESPHome Builder and supply `wifi_ssid` and `wifi_password`
in its `secrets.yaml` (see `esphome/examples/secrets.example.yaml`). Use
**Install → Plug into this computer** to flash the XIAO by USB. The build uses
the ESP-IDF framework; the first PlatformIO download may take a while.

This smoke test uses ESPHome's normal Wi-Fi/API transport. It verifies sensors
in HA **directly**, not through the Server Buddy ESP-NOW hub. The encrypted
Server Buddy node transport is a separate Phase 7 external component; do not
create a Server Buddy pairing key for this smoke test. The Nix `esphome-yaml`
check validates syntax without downloading a toolchain.

### XIAO node over the Server Buddy ESP-NOW hub

`esphome/examples/xiao-logger-hat-espnow.yaml` uses the Phase 7
`esphome/components/server_buddy` external component. It uses ESPHome's
disconnected ESP-NOW radio on **channel 1** to talk to C6 radio MAC
`14:c1:9f:01:dd:18` (not the P4 Ethernet MAC). It does not connect to Wi-Fi,
provide an ESPHome API/OTA, or publish a battery voltage (USB-powered test).

1. Push the commit containing the external component so ESPHome Builder's
   `external_components` git source can fetch it.
2. In HA's **Server Buddy** integration, choose **Configure → Add a new node**.
   Add the one-time 22-character key to Builder's `secrets.yaml` as
   `server_buddy_node_key`; see
   `esphome/examples/server-buddy-node-secrets.example.yaml`. Never commit it.
3. Paste `xiao-logger-hat-espnow.yaml` into the Builder as a **new device**.
   Build, then flash the XIAO via USB/WebSerial. **Pick the port named
   "USB JTAG/serial debug unit" (Espressif).** "USB Single Serial" is the P4
   hub; Linux `ttyACM` numbers swap when boards are replugged, and the web
   flasher's erase option wipes the hub's `hub_nvs` (TLS identity, HA
   credential, node registry). Unplugging the P4's USB while flashing nodes
   avoids the mix-up. On this ESP32-C3, if WebSerial
   cannot enter download mode, hold BOOT, tap RESET and release BOOT before
   reconnecting. USB flashing is required; Wi-Fi OTA is unavailable afterward.
4. The hub's pairing window is 120 s. If it expires while building/flashing,
   use **Configure → Pair or re-pair a node**, choose that slot, and reset the
   XIAO. It retries pairing every 500 ms while unpaired. After the first
   authenticated HELLO, it publishes schema, one boot event and three sensor
   values at 30-second intervals. If sensor measurements fail after a warm
   reset, unplug/replug USB: the Logger HAT rail must power-cycle fully.

The ESPHome build uses PlatformIO downloads and is not part of offline
`nix flake check`; `esphome-yaml` validates the config locally and checks that
the component's symlinks use the exact P4 protocol C source. A full ESP32-C3
build with a dummy key was completed using ESPHome 2026.5.1. Real pairing and
report delivery require flashing with a newly generated secret.
