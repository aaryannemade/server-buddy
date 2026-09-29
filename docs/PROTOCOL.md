# Server Buddy Radio Protocol v1

Frozen wire format between ESPHome nodes and the hub. Security semantics are
in [SECURITY.md](SECURITY.md). Reference implementations:
`firmware/components/sb_protocol` (C) and `protocol/python` (Python).
Golden vectors: `protocol/test-vectors/`.

## Conventions

- Little-endian integers. Frames are at most **250 bytes** (ESP-NOW v1).
- `STR`: `u8 len` + UTF-8 bytes, `len <= 64`, no NUL, strictly valid UTF-8.
- Frame = header (16) + payload (`len`) + MIC (8, all types except
  `PAIR_REQUEST`/`PAIR_RESPONSE`). Max payload is 226 with a MIC.
- Codecs never compute or check MICs/tags. Receivers verify the MIC
  (`sb_mic_verify`) **before** decoding; senders seal after encoding.
- Decoders check, in order: size <= 250 (`TOO_LARGE`), size >= 16
  (`TRUNCATED`), magic, version, type (`BAD_TYPE`, `UNSUPPORTED` for
  `COMMAND`), exact size `16 + len + mic` (`BAD_LENGTH`), flags (`BAD_FLAGS`),
  then payload (`BAD_LENGTH` for short/trailing data, `BAD_VALUE`,
  `BAD_STRING`).

## Header (16 bytes)

| Off | Size | Field | Notes |
| --- | --- | --- | --- |
| 0 | 2 | magic | bytes `53 42` ("SB") |
| 2 | 1 | version | `1` |
| 3 | 1 | type | see below |
| 4 | 1 | flags | bit0 `ACK_REQ`, bit1 `FULL_STATE`; others must be 0 |
| 5 | 1 | epoch | pairing epoch (1..255); 0 in pairing frames |
| 6 | 4 | boot | sender boot counter |
| 10 | 4 | seq | sender sequence within boot |
| 14 | 2 | len | payload length (excluding MIC) |

`ACK_REQ` is allowed only on HELLO, DESCRIBE, STATE, EVENT, HEARTBEAT and
ERROR. `FULL_STATE` is allowed only on STATE. Node identity is the ESP-NOW
source MAC, authenticated by the MIC key.

## Message types

| Type | Name | Dir | Payload |
| --- | --- | --- | --- |
| 0x01 | HELLO | N→H | `schema_hash u32, report_interval_s u16, boot_reason u8, hello_flags u8` (8) |
| 0x02 | DESCRIBE | N→H | `transfer u8, index u8, count u8, total u16, schema_hash u32, data[1..217]` |
| 0x03 | STATE | N→H | `n u8 (1..32)`, then `n` × `entity u8, VALUE` (unique entities) |
| 0x04 | EVENT | N→H | `entity u8, event_type u8, origin_boot u32, event_no u16, VALUE` |
| 0x05 | ACK | H→N | `acked_boot u32, acked_seq u32, status u8, channel u8, unix_time u32` (14) |
| 0x06 | COMMAND | H→N | reserved, rejected in v1 |
| 0x07 | PAIR_REQUEST | N→H | `key_id[4], node_mac[6], node_nonce[16], tag[16]` (42, no MIC) |
| 0x08 | PAIR_RESPONSE | H→N | `status u8, hub_mac[6], hub_nonce[16], channel u8, epoch u8, tag[16]` (41, no MIC) |
| 0x09 | HEARTBEAT | N→H | empty |
| 0x0A | ERROR | both | `code u8, detail STR` |

- `report_interval_s`: 0 means event-only; there is no availability timeout.
- `boot_reason`: 0 unknown, 1 power-on, 2 deep-sleep wake, 3 watchdog,
  4 brownout, 5 software. `hello_flags` bit0 = first boot after pairing.
- ACK `status`: 0 OK, 1 DUPLICATE, 2 NEED_DESCRIBE, 3 NEW_BOOT, 4 MALFORMED,
  5 BUSY. `unix_time` 0 means unknown.
- PAIR_RESPONSE `status`: 0 ACCEPTED (epoch must be non-zero), 1 HUB_FULL.
- ERROR `code`: 0 unspecified, 1 protocol, 2 schema, 3 resource, 4 sensor.
  Receivers treat unknown codes as 0. ERROR requires an enrolled peer (valid
  MIC) and never triggers a reply.
- Pairing tags: `trunc16(HMAC-SHA256(K_node, label || m))`. For requests,
  `label = "sb-v1 req"` and `m` is the frame before the tag. For responses,
  `label = "sb-v1 resp"` and `m = node_nonce || frame before the tag`.
- MIC: `trunc8(HMAC-SHA256(K_mic, "sb-v1 mic" || dir || frame before MIC))`,
  where `dir` is 0 for node→hub and 1 for hub→node.

## VALUE

`u8 type` followed by:

| Type | Name | Data |
| --- | --- | --- |
| 0 | NONE | none (unavailable/unknown) |
| 1 | BOOL | `u8` 0 or 1 |
| 2 | I32 | `i32` |
| 3 | U32 | `u32` |
| 4 | F32 | IEEE-754 `f32`, must be finite (nodes send NONE for NaN) |
| 5 | ENUM | `u8` |
| 6 | STR | `STR` |

## DESCRIBE transfers

All chunks of a transfer share `transfer`, `count` (1..10), `total`
(1..2048) and `schema_hash`. `index` runs 0..count-1. Chunk data concatenates
in index order to exactly `total` bytes. The hub:

- discards a transfer after 5 s without progress;
- ignores duplicate chunks;
- verifies `schema_hash == u32_le(SHA-256(blob)[0:4])`.

Schema blob:

```text
node_name STR, model STR, fw_version STR, entity_count u8 (1..32)
entity_count × {
  entity u8 (unique), platform u8, value_type u8 (1..6), state_class u8,
  accuracy i8, entity_flags u8,
  object_id STR (1..32, [a-z0-9_]), name STR, unit STR,
  device_class STR, extra STR
}
```

- `platform`: 1 sensor, 2 binary_sensor, 3 text_sensor, 4 event.
- `state_class`: 0 none, 1 measurement, 2 total, 3 total_increasing.
- `entity_flags` bit0: diagnostic.
- `extra`: comma-separated event types for events (the EVENT `event_type`
  field indexes this list); empty otherwise.
- A changed `schema_hash` replaces the node's entity set. Entities that
  disappear are marked unavailable, and HA removes them (see Phase 6).
- Home Assistant identifies an entity by `(entity, object_id)`. Keep both stable
  across firmware updates: changing either creates a new HA entity (and loses
  the old one's history and customisations). Never reuse an `entity` number for
  a different meaning.

## Reliability

- Nodes set `ACK_REQ` on HELLO, DESCRIBE, EVENT, and on STATE frames that
  must be delivered. Retries reuse the same `(boot, seq)`.
- Retry: up to 3 attempts with a randomized 30–60 ms gap, then sleep. EVENTs
  that are still unACKed stay queued in RTC memory (max 8) with their
  original `(origin_boot, event_no)` and are resent on the next wake.
- `FULL_STATE` marks a STATE frame that contains every retained entity. Nodes
  send one at least every 10th report.
- The hub marks a node unavailable after `3 × report_interval_s` without a
  valid frame (never if the interval is 0).
- Nodes send HELLO on cold boot. Deep-sleep wakes go straight to STATE/EVENT.
  Any ACK with NEED_DESCRIBE makes the node send HELLO and all DESCRIBE chunks
  before further reports.
- The channel is fixed per hub and configured on each node. Changing it
  requires re-pairing every node (documented recovery); staged migration is
  deferred.
- Codec buffers are stack-heavy (`sb_frame_t` ~0.5 KB, `sb_schema_t` ~1.6 KB).
  Never encode or decode inside the ESP-NOW/Wi-Fi callback; copy frames into a
  queue instead.
