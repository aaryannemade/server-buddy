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
