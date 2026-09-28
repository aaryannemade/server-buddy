# Local API v1

The P4 exposes a TLS-only API on port 443 while Ethernet owns an IP address.
The certificate is a persistent, self-signed ECDSA P-256 identity stored in
the dedicated `hub_nvs` partition.

## HTTP Endpoints

- `GET /api/v1/health`: unauthenticated liveness, hub ID, boot, and claim state.
- `GET /api/v1/version`: unauthenticated firmware, IDF, and API versions.
- `GET /api/v1/diagnostics`: redacted hub and Ethernet counters. Requires
  `Authorization: Bearer <token>`.
- `GET /api/v1/ws`: WebSocket control, snapshots, and ordered updates.

HTTP mutations are not supported. Node keys and credentials are returned only
by their authenticated WebSocket operation.

## Commissioning

An unclaimed hub accepts one local WebSocket `claim` operation:

```json
{"op":"claim"}
```

The response contains a 43-character base64url token. The hub stores only its
SHA-256 hash. HA must retain the token and the certificate fingerprint. This
local-mode flow intentionally accepts a first-claim race on the LAN; owner
proof and protected recovery are deferred to Phase 8.

Existing credentials authenticate with:

```json
{"op":"auth","token":"..."}
```

Only one authenticated WebSocket client is supported. `credential.rotate`
durably replaces the credential and returns the replacement token. If the
claim or rotation response is lost after persistence, development recovery
requires explicitly erasing the API credential from `hub_nvs`.

## Operations

Authenticated operations are:

- `node.add`
- `node.get` with `slot`
- `node.remove` with `slot`
- `pair.open` with `slot` and `duration_ms`
- `pair.close`
- `subscribe`
- `resume` with `stream_epoch` and decimal-string `after_seq`
- `credential.rotate`
- `ping`

Pairing is targeted. An untargeted network pairing window is not exposed.
Inbound messages are JSON text frames no larger than 2048 bytes; fragmented,
binary, malformed, and trailing-data messages are rejected.

## Snapshots And Resume

`subscribe` sends `snapshot.begin`, one `snapshot.node` per slot, separate
`snapshot.entity` messages, and `snapshot.end`. It then replays updates after
the snapshot watermark and enables live delivery.

Each boot has a persisted `stream_epoch` and a RAM-only monotonic sequence.
The hub retains 64 deep-copied events. `resume` replays retained events after
`after_seq`; an old epoch, future sequence, or overwritten range returns
`resync_required`, after which HA must request a new snapshot.

`SB_EVT_NODE` events carry `refresh: true`; HA should issue `node.get` for the
reported slot to retrieve the latest schema. Removal events contain tombstone
node identity so HA can remove the correct device.
