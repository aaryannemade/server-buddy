"""Generate golden test vectors: python -m sb_protocol.vectors <outdir>.

Line format (frames/schema): name|OK or error name|hex|canonical description
Line format (crypto): kind|hex fields...|expected hex
"""

from __future__ import annotations

import random
import struct
import sys
from pathlib import Path

from . import crypto
from .codec import (
    FLAG_ACK_REQ,
    FLAG_FULL_STATE,
    Entity,
    Frame,
    MsgType,
    ProtocolError,
    Schema,
    Value,
    VType,
    decode,
    decode_schema,
    describe,
    describe_schema,
    encode,
    encode_schema,
    split_schema,
)

K_NODE = bytes(range(16))
NODE_MAC = bytes.fromhex("aabbccddee01")
HUB_MAC = bytes.fromhex("112233445566")
NODE_NONCE = bytes(range(0x20, 0x30))
HUB_NONCE = bytes(range(0x40, 0x50))
EPOCH = 3
LMK, K_MIC = crypto.session_keys(K_NODE, NODE_NONCE, HUB_NONCE, NODE_MAC, HUB_MAC, EPOCH)
NO_MIC_TYPES = (MsgType.PAIR_REQUEST, MsgType.PAIR_RESPONSE)


def direction(t: MsgType) -> int:
    return crypto.DIR_HUB_TO_NODE if t is MsgType.ACK else crypto.DIR_NODE_TO_HUB


def wire(f: Frame) -> bytes:
    """Encode and, for enrolled types, seal with the demo MIC key."""
    b = encode(f)
    return b if f.type in NO_MIC_TYPES else crypto.seal(K_MIC, direction(f.type), b)


def raw(t, payload=b"", flags=0, epoch=0, boot=1, seq=1, plen=None, magic=b"SB", ver=1, mic=None):
    n = len(payload) if plen is None else plen
    if mic is None:
        mic = b"" if t in (0x07, 0x08) else bytes(8)
    return magic + struct.pack("<BBBBIIH", ver, t, flags, epoch, boot, seq, n) + payload + mic


def demo_schema() -> Schema:
    def s(x: str) -> bytes:
        return x.encode()

    return Schema(
        s("Garage Sensor"),
        s("esp32-c3"),
        s("1.0.0"),
        [
            Entity(1, 1, VType.F32, 1, 1, 0, s("temperature"), s("Temperature"), s("°C"), s("temperature"), b""),
            Entity(2, 1, VType.F32, 1, 0, 0, s("humidity"), s("Humidity"), s("%"), s("humidity"), b""),
            Entity(3, 1, VType.U32, 1, 0, 1, s("battery"), s("Battery"), s("%"), s("battery"), b""),
            Entity(4, 2, VType.BOOL, 0, 0, 0, s("door"), s("Door"), b"", s("door"), b""),
            Entity(5, 3, VType.STR, 0, 0, 1, s("reset_reason"), s("Reset reason"), b"", b"", b""),
            Entity(6, 4, VType.ENUM, 0, 0, 0, s("button"), s("Button"), b"", s("button"), s("press,double_press,long_press")),
            Entity(7, 1, VType.I32, 1, 0, 1, s("rssi"), s("Signal"), s("dBm"), s("signal_strength"), b""),
        ],
    )


def valid_frames() -> list[tuple[str, Frame]]:
    blob = encode_schema(demo_schema())
    chunks = split_schema(blob, xfer=7)
    for i, c in enumerate(chunks):
        c.epoch, c.boot, c.seq = 3, 12, 2 + i
    full = Frame(
        MsgType.DESCRIBE, 0, 3, 12, 99,
        dict(xfer=1, index=0, count=1, total=217, hash=0xDEADBEEF, data=bytes(217)),
    )
    req = Frame(
        MsgType.PAIR_REQUEST, 0, 0, 1, 0,
        dict(key_id=crypto.key_id(K_NODE), mac=NODE_MAC, nonce=NODE_NONCE, tag=bytes(16)),
    )
    req.body["tag"] = crypto.request_tag(K_NODE, encode(req)[:-16])
    resp = Frame(
        MsgType.PAIR_RESPONSE, 0, 0, 5, 9,
        dict(status=0, mac=HUB_MAC, nonce=HUB_NONCE, channel=6, pepoch=3, tag=bytes(16)),
    )
    resp.body["tag"] = crypto.response_tag(K_NODE, NODE_NONCE, encode(resp)[:-16])
    return [
        ("hello", Frame(MsgType.HELLO, FLAG_ACK_REQ, 3, 12, 1,
                        dict(schema_hash=0x01020304, interval=300, reason=1, hflags=1))),
        *[(f"describe_{i}", c) for i, c in enumerate(chunks)],
        ("describe_max_frame", full),
        ("state_all_types", Frame(MsgType.STATE, FLAG_ACK_REQ | FLAG_FULL_STATE, 3, 12, 10, dict(entries=[
            (1, Value.f32(21.5)), (2, Value.f32(-0.1)), (3, Value(VType.U32, 0xFFFFFFFF)),
            (4, Value(VType.BOOL, True)), (5, Value.str_("deep sleep ✓ 😀")),
            (6, Value(VType.ENUM, 2)), (7, Value(VType.I32, -71)), (8, Value.none()),
        ]))),
        ("state_empty_string", Frame(MsgType.STATE, 0, 3, 12, 11, dict(entries=[(5, Value.str_(""))]))),
        ("event_enum", Frame(MsgType.EVENT, FLAG_ACK_REQ, 3, 12, 12,
                             dict(entity=6, etype=1, oboot=11, evno=65535, value=Value.none()))),
        ("event_str", Frame(MsgType.EVENT, FLAG_ACK_REQ, 3, 12, 13,
                            dict(entity=6, etype=0, oboot=12, evno=0, value=Value.str_("x" * 64)))),
        ("ack", Frame(MsgType.ACK, 0, 3, 5, 100, dict(aboot=12, aseq=13, status=2, channel=6, time=1790000000))),
        ("pair_request", req),
        ("pair_response", resp),
        ("pair_response_hub_full", Frame(MsgType.PAIR_RESPONSE, 0, 0, 5, 10, dict(
            status=1, mac=HUB_MAC, nonce=HUB_NONCE, channel=6, pepoch=0, tag=bytes(16)))),
        ("heartbeat", Frame(MsgType.HEARTBEAT, 0, 3, 0xFFFFFFFF, 0xFFFFFFFF)),
        ("error", Frame(MsgType.ERROR, 0, 3, 12, 14, dict(code=4, detail=b"bad schema"))),
        ("error_unknown_code", Frame(MsgType.ERROR, FLAG_ACK_REQ, 3, 12, 15, dict(code=200, detail=b""))),
    ]


def invalid_frames() -> list[tuple[str, bytes]]:
    H, S, E = MsgType.HELLO, MsgType.STATE, MsgType.EVENT
    hello = struct.pack("<IHBB", 1, 60, 1, 0)
    return [
        ("too_large", raw(S, bytes(235))),
        ("truncated_header", raw(H, hello)[:15]),
        ("empty", b""),
        ("bad_magic", raw(H, hello, magic=b"SC")),
        ("bad_version", raw(H, hello, ver=2)),
        ("len_mismatch_short", raw(H, hello, plen=7)),
        ("len_mismatch_long", raw(H, hello, plen=9)),
        ("bad_flags", raw(H, hello, flags=0x04)),
        ("full_state_on_hello", raw(H, hello, flags=0x02)),
        ("ack_req_on_ack", raw(MsgType.ACK, struct.pack("<IIBBI", 1, 1, 0, 6, 0), flags=0x01)),
        ("ack_req_on_pair", raw(MsgType.PAIR_REQUEST, bytes(42), flags=0x01)),
        ("missing_mic", raw(H, hello, mic=b"")),
        ("short_mic", raw(H, hello, mic=bytes(7))),
        ("pair_with_mic", raw(MsgType.PAIR_REQUEST, bytes(42), mic=bytes(8))),
        ("bad_type_zero", raw(0, b"")),
        ("bad_type_high", raw(0x0B, b"")),
        ("command_reserved", raw(MsgType.COMMAND, b"")),
        ("hello_short", raw(H, hello[:7])),
        ("hello_long", raw(H, hello + b"\x00")),
        ("hello_bad_reason", raw(H, struct.pack("<IHBB", 1, 60, 6, 0))),
        ("hello_bad_hflags", raw(H, struct.pack("<IHBB", 1, 60, 1, 2))),
        ("heartbeat_trailing", raw(MsgType.HEARTBEAT, b"\x00")),
        ("state_zero", raw(S, b"\x00")),
        ("state_33", raw(S, bytes([33]) + b"".join(bytes([i, 0]) for i in range(33)))),
        ("state_dup", raw(S, b"\x02\x01\x00\x01\x00")),
        ("state_truncated_value", raw(S, b"\x01\x01\x04\x00\x00")),
        ("state_missing_entry", raw(S, b"\x02\x01\x00")),
        ("value_bad_type", raw(S, b"\x01\x01\x07")),
        ("value_bad_bool", raw(S, b"\x01\x01\x01\x02")),
        ("value_nan", raw(S, b"\x01\x01\x04" + struct.pack("<f", float("nan")))),
        ("value_inf", raw(S, b"\x01\x01\x04" + struct.pack("<f", float("inf")))),
        ("str_too_long", raw(S, b"\x01\x01\x06\x41" + b"a" * 65)),
        ("str_truncated", raw(S, b"\x01\x01\x06\x05abc")),
        ("str_overlong", raw(S, b"\x01\x01\x06\x02\xc0\x80")),
        ("str_surrogate", raw(S, b"\x01\x01\x06\x03\xed\xa0\x80")),
        ("str_above_max", raw(S, b"\x01\x01\x06\x04\xf4\x90\x80\x80")),
        ("str_nul", raw(S, b"\x01\x01\x06\x01\x00")),
        ("str_lone_cont", raw(S, b"\x01\x01\x06\x01\x80")),
        ("str_cut_seq", raw(S, b"\x01\x01\x06\x02\xe2\x9c")),
        ("str_lead_f5", raw(S, b"\x01\x01\x06\x04\xf5\x80\x80\x80")),
        ("str_lead_f8", raw(S, b"\x01\x01\x06\x05\xf8\x88\x80\x80\x80")),
        ("str_overlong_3byte", raw(S, b"\x01\x01\x06\x03\xe0\x80\xaf")),
        ("event_short", raw(E, b"\x06\x01")),
        ("event_no_value", raw(E, b"\x06\x01" + bytes(6))),
        ("ack_bad_status", raw(MsgType.ACK, struct.pack("<IIBBI", 1, 1, 6, 6, 0))),
        ("ack_short", raw(MsgType.ACK, bytes(13))),
        ("pair_req_epoch", raw(MsgType.PAIR_REQUEST, bytes(42), epoch=1)),
        ("pair_req_short", raw(MsgType.PAIR_REQUEST, bytes(41))),
        ("pair_resp_epoch_zero", raw(MsgType.PAIR_RESPONSE, bytes(41))),
        ("pair_resp_bad_status", raw(MsgType.PAIR_RESPONSE, b"\x02" + bytes(40))),
        ("pair_resp_header_epoch", raw(MsgType.PAIR_RESPONSE, b"\x00" + bytes(22) + b"\x06\x03" + bytes(16), epoch=1)),
        ("describe_short_hdr", raw(MsgType.DESCRIBE, bytes(8))),
        ("describe_no_data", raw(MsgType.DESCRIBE, struct.pack("<BBBHI", 1, 0, 1, 1, 0))),
        ("describe_count_zero", raw(MsgType.DESCRIBE, struct.pack("<BBBHI", 1, 0, 0, 1, 0) + b"x")),
        ("describe_count_11", raw(MsgType.DESCRIBE, struct.pack("<BBBHI", 1, 0, 11, 1, 0) + b"x")),
        ("describe_index_oob", raw(MsgType.DESCRIBE, struct.pack("<BBBHI", 1, 2, 2, 1, 0) + b"x")),
        ("describe_total_zero", raw(MsgType.DESCRIBE, struct.pack("<BBBHI", 1, 0, 1, 0, 0) + b"x")),
        ("describe_total_2049", raw(MsgType.DESCRIBE, struct.pack("<BBBHI", 1, 0, 1, 2049, 0) + b"x")),
        ("error_no_detail", raw(MsgType.ERROR, b"\x01")),
    ]


def invalid_schemas() -> list[tuple[str, bytes]]:
    good = encode_schema(demo_schema())
    head = b"\x01n\x01m\x011"
    ent = b"\x01\x01\x04\x01\x00\x00" + b"\x01t" + b"\x00" * 4

    def one(e: bytes) -> bytes:
        return head + b"\x01" + e

    return [
        ("schema_trailing", good + b"\x00"),
        ("schema_truncated", good[:-1]),
        ("schema_too_large", bytes(2049)),
        ("schema_no_entities", head + b"\x00"),
        ("schema_33_entities", head + b"\x21" + b"".join(bytes([i]) + ent[1:] for i in range(33))),
        ("schema_bad_platform", one(b"\x01\x05" + ent[2:])),
        ("schema_bad_vtype_none", one(b"\x01\x01\x00" + ent[3:])),
        ("schema_bad_state_class", one(b"\x01\x01\x04\x04" + ent[4:])),
        ("schema_bad_flags", one(ent[:5] + b"\x02" + ent[6:])),
        ("schema_object_id_upper", one(ent[:6] + b"\x01T" + ent[8:])),
        ("schema_object_id_empty", one(ent[:6] + b"\x00" + ent[8:])),
        ("schema_dup_entity", head + b"\x02" + ent + ent),
        ("schema_bad_utf8_name", b"\x01\xff\x01m\x011\x01" + ent),
        ("schema_name_too_long", b"\x41" + b"a" * 65 + b"\x01m\x011\x01" + ent),
    ]


def _err(fn, data: bytes) -> str:
    try:
        fn(data)
    except ProtocolError as e:
        return e.err.name
    raise AssertionError("expected failure")


def frame_lines() -> list[str]:
    out = []
    for name, f in valid_frames():
        b = wire(f)
        out.append(f"{name}|OK|{b.hex()}|{describe(decode(b))}")
    for name, b in invalid_frames():
        out.append(f"{name}|{_err(decode, b)}|{b.hex()}|")
    return out


def schema_lines() -> list[str]:
    blob = encode_schema(demo_schema())
    out = [f"demo|OK|{blob.hex()}|{describe_schema(decode_schema(blob))}"]
    for name, b in invalid_schemas():
        out.append(f"{name}|{_err(decode_schema, b)}|{b.hex()}|")
    return out


def crypto_lines() -> list[str]:
    frames = dict(valid_frames())
    req = encode(frames["pair_request"])[:-16]
    resp = encode(frames["pair_response"])[:-16]
    hello = encode(frames["hello"])[:-8]
    ack = encode(frames["ack"])[:-8]
    rfc_ikm, rfc_salt, rfc_info = bytes([0x0B] * 22), bytes(range(13)), bytes(range(0xF0, 0xFA))
    k, nn, hn, nm, hm = K_NODE.hex(), NODE_NONCE.hex(), HUB_NONCE.hex(), NODE_MAC.hex(), HUB_MAC.hex()
    return [
        f"hkdf|{rfc_ikm.hex()}|{rfc_salt.hex()}|{rfc_info.hex()}|42|"
        + crypto.hkdf_sha256(rfc_ikm, rfc_salt, rfc_info, 42).hex(),
        f"keyid|{k}|{crypto.key_id(K_NODE).hex()}",
        f"keys|{k}|{nn}|{hn}|{nm}|{hm}|{EPOCH}|{LMK.hex()}|{K_MIC.hex()}",
        f"mic|{K_MIC.hex()}|0|{hello.hex()}|{crypto.mic(K_MIC, 0, hello).hex()}",
        f"mic|{K_MIC.hex()}|1|{ack.hex()}|{crypto.mic(K_MIC, 1, ack).hex()}",
        f"reqtag|{k}|{req.hex()}|{crypto.request_tag(K_NODE, req).hex()}",
        f"resptag|{k}|{nn}|{resp.hex()}|{crypto.response_tag(K_NODE, NODE_NONCE, resp).hex()}",
    ]


def mutation_lines(n: int, seed: int = 1) -> list[str]:
    """Randomly mutated frames labelled by the Python decoder (differential test)."""
    rng = random.Random(seed)
    seeds = [wire(f) for _, f in valid_frames()] + [b for _, b in invalid_frames()]
    out = []
    for i in range(n):
        b = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 4)):
            op = rng.randrange(3)
            if op == 0 and b:
                b[rng.randrange(len(b))] = rng.randrange(256)
            elif op == 1 and b:
                del b[rng.randrange(len(b))]
            else:
                b.insert(rng.randrange(len(b) + 1), rng.randrange(256))
        try:
            desc, res = describe(decode(bytes(b))), "OK"
        except ProtocolError as e:
            desc, res = "", e.err.name
        out.append(f"m{i}|{res}|{bytes(b).hex()}|{desc}")
    return out


FILES = {"frames.txt": frame_lines, "schema.txt": schema_lines, "crypto.txt": crypto_lines}


def render() -> dict[str, str]:
    return {name: "\n".join(fn()) + "\n" for name, fn in FILES.items()}


if __name__ == "__main__":
    if sys.argv[1] == "--mutations":
        Path(sys.argv[3]).write_text("\n".join(mutation_lines(int(sys.argv[2]))) + "\n")
        sys.exit(0)
    outdir = Path(sys.argv[1])
    for name, text in render().items():
        (outdir / name).write_text(text)
