# Server Buddy

## Info

An ESP32-P4 Ethernet/PoE board that serves multiple functions.

The main functions are:

- An ESP-NOW router to Home Assistant that works like an MQTT hub.
- Connection to an XIA logger hat for server cabinet temperature, humidity, and
  brightness.
- Connection to an LED matrix display to show server statistics.
- A serial TTY port over USB for direct Raspberry Pi troubleshooting.

See the [implementation plan](docs/IMPLEMENTATION_PLAN.md) for the proposed
architecture, development phases, test gates, and recovery process.

## Home Assistant integration

`custom_components/server_buddy` connects Home Assistant (2026.5 or newer) to
the hub over its local TLS API ([docs/API.md](docs/API.md)).

Install it with HACS as a custom repository
(`https://github.com/aaryannemade/server-buddy`, type Integration), or copy
`custom_components/server_buddy` into your Home Assistant `config` directory,
then restart Home Assistant.

Setup:

1. The hub is discovered automatically via mDNS. Otherwise add
   **Server Buddy** under Settings → Devices & services and enter its IP.
2. An unclaimed hub is claimed by Home Assistant, which stores a credential and
   pins the hub's certificate. The fingerprint shown during setup matches the
   `TLS certificate SHA-256` line in the hub's serial log. Anyone on the local
   network can claim an unclaimed hub, so do this on a trusted network.
3. Manage nodes from the integration's **Configure** menu: *Add a new node*
   shows the node key once (for the node's ESPHome `secrets.yaml`) and opens a
   120 s pairing window; *Pair or re-pair* reopens it; *Remove* deletes the
   node from the hub. Deleting a node device in Home Assistant also removes it.

Each node becomes a device (via the hub) with sensor, binary sensor, text
sensor, and event entities from its schema. Events fire once per hub event ID,
including across reconnects. Pairing progress and node errors are also fired
as `server_buddy_pairing` and `server_buddy_node_error` bus events.

If the hub's certificate changes (for example after its API storage is
erased), Home Assistant asks for re-authentication and shows the old and new
fingerprints; only confirm if the new one matches the hub's serial log.
