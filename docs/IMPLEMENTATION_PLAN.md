# Server Buddy Implementation Plan

## 1. Goal

Build the Waveshare ESP32-P4-WIFI6-POE-ETH rev 2.0 board into an
Ethernet/PoE ESP-NOW hub for Home Assistant (HA).

The first usable version must:

- keep battery-powered sensor nodes off normal Wi-Fi;
- receive their ESP-NOW messages on one fixed 2.4 GHz channel;
- expose discovered devices, values, availability, and events to HA;
- acknowledge important messages and tolerate duplicates and restarts;
- be recoverable if either the P4 or C6 firmware is damaged;
- leave room for the cabinet sensor hat, LED matrix, and USB TTY features.

The hub is MQTT-like in behavior, but it does not require an MQTT broker. The
P4 retains the latest state and publishes updates to a custom HA integration.
An optional MQTT bridge can be added later without changing the radio protocol.

## 2. Important Hardware Facts

- The ESP32-P4 has no Wi-Fi radio. The onboard ESP32-C6-MINI-1U-H8 is the
  radio coprocessor.
- On this board, the P4 and C6 use SDIO for normal hosted communication. The
  board also exposes a separate C6 UART flashing header.
- The RJ45 interface uses the P4 EMAC and an IP101 PHY. The Waveshare examples
  currently document MDC GPIO 31, MDIO GPIO 52, and PHY reset GPIO 51; these
  values must be verified against the rev 2.0 schematic and actual board.
- "Board rev 2.0" is not the P4 silicon revision. Read the P4 boot log before
  building. Waveshare has different defaults for pre-v3, v3.0, and v3.1+
  silicon, and explicitly warns against forcing an incompatible image.
- Flashing the C6 with an ordinary standalone ESP-NOW application would remove
  the factory hosted firmware and break P4-to-C6 communication. The C6 image
  must remain an ESP-Hosted coprocessor with added ESP-NOW commands/events.
- ESP-NOW peers must share a channel. The hub should not join Wi-Fi because
  Ethernet supplies its IP connection. This prevents an access point or mesh
  controller from changing the radio channel underneath sleeping nodes.

## 3. Proposed Architecture

```text
ESPHome battery nodes
  sensors/events
       |
       | Server Buddy ESP-NOW protocol, fixed channel, unicast
       v
ESP32-C6 radio coprocessor
  ESP-Hosted + ESP-NOW extension
       |
       | ESP-Hosted custom RPC/events over onboard SDIO
       v
ESP32-P4 hub firmware
  registry + retained state + event stream + Ethernet API
       |
       | authenticated WebSocket/HTTP over Ethernet
       v
Home Assistant custom integration
  config flow + entities + events + diagnostics
```

### P4 responsibilities

- initialize the IP101 Ethernet PHY and obtain a DHCP or static address;
- supervise and version-check the C6 over ESP-Hosted/SDIO;
- own pairing, the device/entity registry, retained values, and availability;
- validate, deduplicate, acknowledge, and route ESP-NOW messages;
- serve an authenticated WebSocket API and small HTTP diagnostics API;
- persist configuration in NVS, but rate-limit state writes to protect flash;
- provide metrics, logs, watchdogs, and OTA coordination.

### C6 responsibilities

- remain on a configured 2.4 GHz channel without associating to an AP;
- receive and transmit ESP-NOW frames;
- maintain the ESP-NOW peer table and LMKs;
- immediately copy receive-callback data into a queue;
- forward frames and RX metadata such as source MAC, RSSI, and channel to P4;
- report send completion and radio faults to P4;
- do no HA, entity, retained-state, or application business logic.

### Home Assistant responsibilities

- discover the hub with mDNS or accept a manually entered host;
- authenticate using a per-hub token generated during pairing;
- create one HA device per remote node and one device for the hub;
- create/update entities from registry snapshots and incremental messages;
- fire HA bus events for momentary events instead of pretending they are state;
- reconnect with backoff and request a snapshot after a sequence gap;
- expose hub and node diagnostics without leaking keys or tokens.

### ESPHome node responsibilities

Create an external component, initially named `server_buddy`, that lets a node
remain a normal ESPHome project while replacing Wi-Fi/API transport with
ESP-NOW for selected data. It should support:

- sensors, binary sensors, text sensors, and explicit events first;
- stable device and entity identifiers;
- fixed channel and hub MAC configuration;
- deep-sleep-safe send, application ACK, bounded retry, and sequence numbers;
- periodic full-state reports in addition to change-only updates;
- battery voltage/percentage and boot reason metadata;
- compile-time secrets via ESPHome `secrets.yaml`, never checked into Git.

ESPHome's stock `espnow` and `packet_transport` components are useful as a
reference and provide a simpler fallback for sensor/binary-sensor-only nodes.
They do not currently provide the dynamic registry and full event/entity model
needed by this design. Do not fork ESPHome unless an external component proves
insufficient.

## 4. Repository Layout

```text
server-buddy/
  flake.nix
  flake.lock
  .envrc.example
  firmware/
    p4/
    c6/
    components/protocol/
  esphome/
    components/server_buddy/
    examples/
  custom_components/
    server_buddy/
  protocol/
    schema/
    test-vectors/
  hardware/
    rev-2.0-notes.md
  scripts/
  tests/
  docs/
```

Keep generated ESP-IDF build directories, HA test configuration, secrets,
flash dumps, and signing keys out of Git.

## 5. Phased Delivery Plan

Every phase has an exit gate. Do not start destructive hardware work before
the backup/recovery gate is complete.

### Phase 0: Flake-first development environment

The first implementation change must be `flake.nix`, followed by the generated
`flake.lock`. No firmware or integration code should land before it.

1. Pin `nixpkgs` and use one supported system helper such as `flake-parts`.
2. Provide `devShells.default` containing the pinned ESP-IDF toolchain, CMake,
   Ninja, ccache, Git, serial tools, `esptool`, Python, and test tooling.
3. Initially pin Waveshare's recommended ESP-IDF 5.5.4. Update that pin only if
   board testing proves a different release is required, and verify it against
   the exact ESP-Hosted and ESPHome versions selected for the project.
4. Include the HA Python development dependencies, `pytest`, `pytest-asyncio`,
   Ruff, mypy, and ESPHome in the shell. Use a locked Python environment rather
   than installing packages imperatively after entering the shell.
5. Export `IDF_PATH`, toolchain paths, and ccache settings from the shell hook.
   Do not encode a developer's serial port or credentials in the flake.
6. Add flake checks for formatting, Python lint/type checks, protocol unit
   tests, HA tests, and firmware builds as each target appears.
7. Add `.envrc.example` with `use flake`; developers may create an untracked
   `.envrc` locally.
8. Document the host-level setup that Nix cannot safely hide: USB permissions,
   `dialout` membership/udev rules, and access to the C6 TTL adapter.
9. Pin non-Nix dependency systems too: commit ESP-IDF component lock files, pin
   ESPHome and its platform packages, and represent Python dependencies with
   hashes. CI must prove builds work with network access disabled after inputs
   have been fetched into the Nix store.

Exit gate:

- `nix flake check` passes on a clean checkout;
- `nix develop` provides `idf.py`, `esptool.py`, `esphome`, and `pytest`;
- a trivial P4 project configures and compiles without downloads outside the
  declared/pinned dependency process.

### Phase 1: Inventory, backups, and recovery

The board already has firmware, so preserve it before flashing anything.

1. Record board SKU, PCB revision, module markings, MAC addresses, detected
   flash sizes, and P4 silicon revision from photographs and serial boot logs.
2. Connect the P4 USB-UART port and capture a complete boot log without holding
   BOOT. Record current behavior, Ethernet address, partition table, and app
   version if reported.
3. Capture the P4 eFuse/security summary, including secure boot, flash
   encryption, anti-rollback, and ROM download restrictions. Read the complete
   detected P4 flash to an ignored local backup and record its SHA-256.
4. Connect a 3.3 V TTL adapter to the dedicated C6 UART header. Follow the
   Waveshare sequence: IO9 to GND before power-on, hold the board BOOT button to
   stop the P4 controlling C6 reset, then power the board. Connect TX, RX, and
   GND only; never connect the TTL adapter's power output to a board already
   powered by PoE or USB.
5. Capture the C6 eFuse/security summary. Read the complete detected C6 flash
   to a separate ignored backup and record its SHA-256, chip ID, MAC, flash ID,
   and partition table.
6. Download and archive references to the matching Waveshare factory image and
   flashing instructions. Never commit proprietary or device-specific dumps.
7. Verify that backups/factory images, offsets, and bootloaders are compatible
   with the recorded eFuse state. A readable dump may be encrypted and is not
   automatically a usable restore image.
8. Rehearse the exact recovery process non-destructively, or prove restoration
   on sacrificial identical hardware. Do not erase the only board merely to
   test recovery.

Exit gate:

- both flash backups and serial logs exist outside Git;
- the P4 silicon revision, eFuse state, and both flash layouts are known;
- exact commands, offsets, images, and wiring for restoring P4 and C6 are
  documented and compatible with their security state.

### Phase 2: Independent board bring-up

1. Build and run Waveshare `00_board_check` using the correct silicon revision
   defaults. Verify serial, flash, PSRAM, heap, and watchdog stability.
2. Build an Ethernet-only P4 image based on `11_ethernetbasic`. Verify IP101
   link up/down events, DHCP, static-IP option, ping, and sustained traffic.
3. Bring up unmodified ESP-Hosted between P4 and C6 over SDIO. Record transport
   pins from the rev 2.0 schematic rather than relying on generic defaults.
4. Run the ESP-Hosted peer-data transfer example in both directions. Stress it
   while Ethernet traffic is active to separate SDIO problems from radio or
   application problems.
5. Run a throwaway feasibility spike on the exact pinned version matrix. Add a
   minimal C6 peer-data handler that initializes ESP-NOW, fixes the disconnected
   radio channel, forwards one received frame plus metadata, sends one frame,
   reports its completion callback, and recovers after either chip resets.
   This proves the custom boundary; generic peer-data alone does not.
6. Configure the Wi-Fi country/regulatory domain before selecting a legal
   channel. Verify and report the actual channel after startup and reapply it
   after C6 or Wi-Fi-driver recovery.
7. Add watchdog recovery for a missing or version-incompatible C6.

Exit gate:

- Ethernet remains stable for 24 hours;
- ESP-Hosted handshake and custom peer-data round trips survive resets and a
  sustained stress test;
- the ESP-NOW feasibility spike receives and transmits over the hosted link on
  the pinned P4/C6/IDF/ESP-Hosted combination;
- P4 can report P4 app, C6 app, board, and protocol versions.

### Phase 3: Freeze protocol v1 before feature code

Use a compact, explicitly versioned binary protocol. Keep an ESP-NOW v1-sized
frame at or below 250 bytes even if both current endpoints support larger v2
frames. This preserves compatibility and reduces airtime.

Before defining bytes, close every decision in section 9 and write a threat
model. The protocol freeze includes secure bootstrap, node ownership proof,
per-node LMK provisioning or derivation, key rotation/revocation, factory reset,
nonce/session persistence, replay windows, and recovery after lost credentials.
ESP-NOW PMKs do not distribute LMKs, and pairing broadcasts cannot use ESP-NOW
link encryption. An explicitly marked insecure development mode is acceptable
for early testing, but cannot satisfy a production exit gate.

Common header fields:

- magic and protocol version;
- message type and flags;
- source device ID, boot/session ID, and key epoch;
- monotonically increasing message sequence;
- acknowledged sequence for replies;
- payload length;
- integrity/authentication field as required by the selected security mode.

Initial message types:

- `HELLO`: firmware, capabilities, entity schema hash, battery, and boot reason;
- `DESCRIBE`: chunked device/entity definitions;
- `STATE`: one or more typed retained values;
- `EVENT`: event type plus typed event data;
- `ACK`: application receipt/status and optional time/channel data;
- `COMMAND`: reserved for later downlink controls;
- `PAIR_REQUEST` and `PAIR_RESPONSE`;
- `HEARTBEAT` and `ERROR`.

Define integer, float, boolean, enum, and bounded UTF-8 value encodings. Units,
device classes, and state classes belong in entity descriptions, not every
state frame. Chunked messages require a transfer ID, index/count, total bounded
length, schema/content hash, timeout, and duplicate handling. Include golden
byte vectors and malformed-frame vectors that run against C/C++ and Python
implementations.

Reliability rules:

- use unicast for enrolled nodes;
- treat ESP-NOW send success as MAC delivery only, not application processing;
- ACK `HELLO`, `DESCRIBE`, `EVENT`, and explicitly reliable state messages;
- retry with jitter and a strict maximum so a missing hub does not drain a
  battery;
- deduplicate by device, boot/session ID, and sequence;
- periodically resend complete state to repair missed updates;
- use a per-node expiry/expected-report interval for availability;
- queue only bounded downlink data for sleeping nodes;
- migrate channels with a staged command acknowledged by every enrolled node
  before the hub moves, plus a documented physical recovery procedure. A hub
  cannot simply move and then notify sleeping nodes on the old channel.

Exit gate:

- protocol document and test vectors are reviewed;
- every initially supported ESP32 node target compiles and completes a basic
  radio/deep-sleep test; ESP8266 is out of scope unless explicitly proven;
- C/C++ and Python codecs round-trip every type;
- fuzz/malformed tests cannot overrun buffers or create unbounded allocations.

### Phase 4: C6 ESP-NOW coprocessor extension

1. Pin a compatible ESP-Hosted release and build its C6 coprocessor image.
2. Add custom RPCs for radio configuration, peer add/remove, PMK/LMK setup,
   send, statistics, and controlled pairing mode.
3. Add asynchronous events for received frames, send results, peer/radio
   errors, and queue overflow.
4. Use the IDF ESP-NOW callbacks only to copy bounded data into queues; all SDIO
   forwarding happens in normal tasks.
5. Set station mode, start Wi-Fi, set the fixed channel, then initialize
   ESP-NOW. Do not connect the station to an access point. Reject channels that
   are illegal in the configured country and verify the resulting channel.
6. Expose queue high-water marks, drops, RSSI distribution, send failures,
   channel, reset count, uptime, and heap minimum.
7. Implement C6 image update through P4 only after the basic link is reliable;
   retain the TTL recovery path permanently.

Exit gate:

- a known test transmitter is received for 24 hours with no C6 crash;
- P4 can add a peer, transmit, receive an application ACK, and remove the peer;
- overload causes measured drops/backpressure, not memory growth or watchdogs.

### Phase 5: P4 hub core and Ethernet API

1. Create isolated components for Ethernet, C6 transport, protocol decoding,
   registry, router, storage, API, diagnostics, and update management.
2. Persist configuration and registry metadata in versioned NVS records.
   Retain live values in RAM and checkpoint only when necessary.
3. Implement the frozen pairing design with a timed window initiated by a
   physical action or an authenticated HA command. Unknown devices are ignored
   outside that window.
4. Implement an authenticated WebSocket endpoint for HA:
   - protocol/server hello and authentication;
   - full registry/state snapshot;
   - ordered incremental state/event/device updates;
   - subscribe and resume using a server boot/stream epoch plus sequence;
   - ping/pong and explicit error responses.
5. Add read-only HTTP endpoints for health, version, and redacted diagnostics.
   Mutating operations should use the authenticated channel.
6. Advertise `_server-buddy._tcp.local` over mDNS with model, API version, and
   stable hub ID, but no secrets.
7. Define bounded queues and backpressure between every subsystem. Event bursts
   must not block the C6 receive path or Ethernet task.
8. Define first commissioning: a physical-presence action creates a short-lived
   one-time code; the HA config flow exchanges it for a rotatable hub credential.
   Document token rotation, revocation, and recovery when HA loses credentials.
   Use TLS by default, or use a reviewed challenge-response exchange that never
   sends a reusable bearer secret in plaintext.

Exit gate:

- a host simulator can create nodes/entities and stream states/events;
- restart restores registry and sends a coherent snapshot;
- disconnect/reconnect and sequence-gap recovery are deterministic;
- malformed and unauthenticated network clients cannot affect the radio.

### Phase 6: Home Assistant custom integration

Place the integration at `custom_components/server_buddy` and make it suitable
for installation through HACS later.

1. Add `manifest.json`, translations, config flow, zeroconf discovery, and a
   reauthentication flow.
2. Put network I/O in one async client/coordinator, not in entity objects.
3. Initially implement `sensor`, `binary_sensor`, and `event` platforms. Add
   text sensors and controls only when the radio protocol supports them.
4. Use stable unique IDs composed from hub ID, node ID, and entity ID. Group
   entities under the remote node's HA device entry and link it through the hub.
   Define schema-change and stale entity/device removal behavior.
5. Mark entities unavailable using node expiry, while separately reporting hub
   connection status.
6. Convert transient packets to HA event entities or HA bus events; do not use a
   binary sensor pulse where repeated identical events could disappear. Carry a
   stable event ID through WebSocket resume so reconnect cannot fire it twice.
7. Add diagnostics, repairs for incompatible firmware/protocol versions, and a
   pairing/options flow. Redact MACs only if needed, and always redact keys,
   tokens, raw credentials, and packet payloads that may contain secrets.
8. Test config, discovery, auth failure, reconnect, registry changes, state
   restore, duplicate events, unavailable nodes, unload/reload, and migration.
9. Pin supported HA versions and run `hassfest`, HACS validation, Ruff, mypy,
   and pytest. Include custom-integration `version` metadata and release
   packaging rather than relying on an unspecified HA quality tier.

Exit gate:

- setup is entirely possible from the HA UI;
- simulated nodes create stable entities and events;
- HA restart and hub restart do not duplicate devices/entities or lose the
  current snapshot;
- the named HA/HACS validation and test suite pass.

### Phase 7: ESPHome external component and first sensor

1. Implement the node-side protocol codec and radio transport as an external
   ESPHome component using supported public component APIs.
2. Provide a minimal battery temperature example with no `wifi:` block, a fixed
   channel, unicast hub MAC, deep sleep, and secrets kept out of YAML examples.
3. Publish temperature, humidity, battery level, and a boot event.
4. Measure awake duration, retries, sleep current, delivery ratio, and expected
   battery life. Tune retries and report intervals from measurements.
5. Test hub-down behavior to ensure the node gives up and sleeps promptly.
6. Add an optional compatibility example using stock ESPHome ESP-NOW packet
   transport, but do not make it part of protocol v1 acceptance unless the P4
   explicitly implements that wire format.
7. Implement the security design selected in Phase 3. The external component
   must configure native PMK/LMK peers itself if ESPHome's public YAML surface
   does not expose the required controls.
8. Document node firmware recovery and update policy. With no `wifi:` block,
   normal ESPHome network OTA and API safe mode are unavailable; v1 may
   intentionally require wired serial updates rather than inventing radio OTA.

Exit gate:

- at least 10,000 wake/send/ACK/sleep cycles complete without a lockup;
- the same path passes with production encryption and replay protection enabled;
- lost hub and lost ACK paths respect the battery budget;
- HA shows correct state, availability, battery, diagnostics, and boot events.

### Phase 8: Security hardening and production updates

The protocol-level security design is already frozen in Phase 3 and implemented
before Phase 7 exits. This phase audits and productionizes it rather than
retrofitting security.

1. Audit ESP-NOW PMK/LMK handling for enrolled unicast peers. Never rely on the
   default PMK, and note that ESP-NOW broadcast encryption is not supported.
2. Enforce the chosen node limit. ESP-IDF supports 20 total peers; the encrypted
   peer limit is configurable, defaults can be lower, and the documented
   maximum is 17. If the product must exceed it, use the reviewed
   application-layer design rather than silently falling back to plaintext.
3. Audit replay protection, session/key epochs, receive windows, and revocation.
4. Audit HA TLS or challenge-response authentication, credential rotation, and
   certificate provisioning where applicable.
5. Enable signed firmware and secure boot/flash encryption only after the
   development and physical recovery processes are mature. These settings can
   be irreversible when eFuses are burned.
6. Implement signed P4 OTA with rollback. Treat P4, C6, and protocol versions as
   a compatibility matrix; never update the C6 blindly.
7. Add a release manifest, hashes/signatures, migration tests, and power-loss
   tests at every update boundary.

Exit gate:

- unauthorized nodes and HA clients are rejected;
- replayed packets do not reproduce events;
- interrupted updates recover to a bootable compatible pair;
- secrets are absent from logs, diagnostics, release artifacts, and Git.

### Phase 9: Additional Server Buddy functions

Add these only after the router is stable so failures remain diagnosable.

1. Cabinet sensor hat: identify the exact XIA/Xiao logger hat, voltage, bus, and
   pin assignments; add temperature, humidity, and brightness as local hub
   entities using the same registry model.
2. LED matrix: choose the matrix/controller and reserve pins/DMA early. Consume
   HA-fed statistics through explicit hub entities or a display API; isolate
   rendering from radio/network tasks.
3. USB TTY: define whether the P4 acts as USB host connected to Raspberry Pi
   UART adapters or as a USB device exposed to a Pi. Then implement access
   control, baud/configuration, buffering, and an explicit escape/recovery path.
4. Add per-feature watchdogs and feature flags so a display or USB fault cannot
   take down the ESP-NOW router.

## 6. Testing Strategy

### Automated

- shared protocol golden vectors in C/C++ and Python;
- C/C++ unit tests on host where hardware is not required;
- parser fuzzing for ESP-NOW and WebSocket input;
- HA tests using a fake hub server and time control;
- ESPHome configuration/compile tests for supported node targets;
- reproducible P4 and C6 release builds under `nix flake check` or CI;
- secret scanning, dependency/license checks, and artifact hash generation.

### Hardware-in-the-loop

- controllable power cycling for hub and at least two node variants;
- Ethernet disconnect, DHCP loss, HA restart, C6 reset, P4 reset, and PoE cycle;
- fixed-channel interference and range tests, including mesh AP channel changes;
- packet loss, duplication, reordering, bursts, and queue saturation;
- deep-sleep wake-cycle and battery-current measurements;
- 24-hour bring-up tests, then a seven-day soak before a tagged release;
- update interruption at bootloader, app, NVS migration, and C6 update stages.

### Key metrics

- frames received/dropped/invalid/duplicate per node;
- ACK latency and retry distribution;
- RSSI and last-seen time;
- C6/P4 resets, watchdogs, minimum heap, and queue high-water marks;
- HA reconnect count and snapshot/resync count;
- node awake time and energy per report.

## 7. Main Risks and Mitigations

| Risk | Mitigation |
| --- | --- |
| Existing C6 firmware is overwritten and P4 loses radio access | Back up both flashes first; extend ESP-Hosted rather than replacing it; retain TTL recovery |
| A flash dump cannot boot under the device's eFuse state | Capture security/eFuse state and prove image compatibility before any write |
| Board rev and silicon rev are confused | Record both; derive build defaults from the P4 boot log |
| Mesh/AP channel changes break sleeping nodes | Run C6 disconnected on a fixed channel and use Ethernet for IP |
| A channel becomes illegal or unusable | Set country first and use an acknowledged staged migration plus physical recovery |
| ESP-NOW send success is mistaken for end-to-end delivery | Use application ACK, sequence, retries, and deduplication |
| Dynamic HA entities churn or duplicate | Stable IDs, schema hashes, snapshots, and migration tests |
| Flash wears out from retained values | Keep live state in RAM and batch/rate-limit NVS checkpoints |
| A burst blocks the Wi-Fi callback or SDIO | Callback-to-queue handoff, bounded buffers, counters, and backpressure |
| ESPHome upstream changes break nodes | Pin versions in the flake, compile examples in CI, avoid private APIs |
| Encrypted peer limit is exceeded | Set a product node limit now or design reviewed application encryption |
| P4/C6 OTA versions become incompatible | Compatibility manifest, ordered update, health check, and rollback |

## 8. Initial Milestones

1. Reproducible Nix development shell and checks.
2. Non-destructive hardware inventory and complete P4/C6 backups.
3. P4 Ethernet, stock ESP-Hosted/SDIO, and minimal ESP-NOW feasibility spike.
4. Threat model, commissioning design, and frozen protocol v1 with
   cross-language test vectors.
5. Production C6 extension receives one ESP-NOW frame and forwards it to P4.
6. Fake hub drives the HA integration with dynamic sensor and event entities.
7. Physical node to C6 to P4 to HA vertical slice.
8. Pairing, encryption, reliability, diagnostics, and OTA hardening.

The first end-to-end demonstration should be deliberately narrow: one
battery-powered ESP32 temperature sensor, one temperature state, one battery
state, and one boot event. Expand entity types only after that path survives
restarts, packet loss, and a soak test.

## Progress

| Phase | Status |
| --- | --- |
| 0 Flake | Done. `nix flake check` builds P4 offline and runs all tests. |
| 1 Backups | P4 inventoried (v1.3 silicon, no security eFuses). Backups waived by owner; old firmware erased. C6 not yet read. |
| 2 Bring-up | Mostly done. Ethernet works (100 Mbps full duplex, DHCP, 0% loss at 1400 B pings). The ESP-NOW spike works: the P4 configures the C6 radio over `sb_link`; broadcast is delivered; unicast to an absent peer correctly fails; LMK peers work; 1000 frames at 377 frames/s with 0 drops using credit pacing; the radio is reconfigured after a C6 restart. Cable pull verified (link down detected, re-up 100 Mbps, same DHCP IP 1 s later, no reboot). Open items: 24 h soak (`scripts/soak.sh`), RX test with a second ESP32. |
| 3 Protocol | Frozen: `docs/PROTOCOL.md` and `docs/SECURITY.md`. C and Python codecs, golden vectors, differential tests and fuzzing are all in CI. |

Deviations from the original plan:

- An application-layer MIC was added, because ESP-IDF does not guarantee that
  plaintext frames from an encrypted peer are rejected.
- Staged channel migration is deferred; changing the channel requires
  re-pairing every node.
- The Phase 3 gate item "node targets compile and complete a deep-sleep test"
  moves to Phase 7. ESPHome builds fetch PlatformIO toolchains, which the
  offline flake checks cannot do.
- The C6 owns its radio: ESP-Hosted's host-driven Wi-Fi feature is disabled on
  the C6, so the P4 has no Wi-Fi station (it uses Ethernet).
- The C6 uses SDIO STREAM mode, not SW aggregation, because IDF 5.5.4 lacks the
  SDIO send-cap fix.
- When the C6 restarts on its own, ESP-Hosted's default policy also restarts
  the P4, which recovers in about 3 s. Re-initialising the link in place
  without a P4 reboot is a Phase 4 follow-up.
- C6 firmware is updated from the P4 over SDIO (`scripts/update-c6.sh`), not
  over TTL.

## 9. Protocol Freeze Decisions (resolved 2026-09-28)

- Node limit: 17 per hub, all using native ESP-NOW LMK encryption.
- Node chips: ESP32-C3, ESP32-S3, ESP32-C6. No ESP8266.
- v1 is receive-only; `COMMAND` is reserved, not implemented.
- Entity types: sensor, binary sensor, text sensor, event.
- Pairing: hub button or authenticated HA action opens a timed window.
- HA and hub share one L2 network; mDNS discovery, manual host as fallback.
- No MQTT in v1; native HA integration only.

See [SECURITY.md](SECURITY.md) and [PROTOCOL.md](PROTOCOL.md).

## 10. References

- [Waveshare board documentation](https://docs.waveshare.com/ESP32-P4-WIFI6-POE-ETH)
- [Waveshare ESP-IDF examples](https://github.com/waveshareteam/ESP32-P4-Platform)
- [Waveshare schematic](https://files.waveshare.com/wiki/ESP32-P4-WIFI6-POE-ETH/ESP32-P4-WIFI6-POE-ETH-Schematic.pdf)
- [ESP-Hosted MCU](https://github.com/espressif/esp-hosted-mcu)
- [ESP-Hosted peer-data transfer](https://github.com/espressif/esp-hosted-mcu/tree/main/examples/peer_data_transfer)
- [ESP-IDF ESP-NOW API](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/network/esp_now.html)
- [ESPHome ESP-NOW](https://esphome.io/components/espnow/)
- [ESPHome packet transport](https://esphome.io/components/packet_transport/espnow/)
- [ESPHome ESP32 Hosted](https://esphome.io/components/esp32_hosted/)
- [Home Assistant integration development](https://developers.home-assistant.io/docs/creating_component_index/)
