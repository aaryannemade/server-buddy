"""Server Buddy radio protocol v1 codec (reference implementation).

Mirrors firmware/components/sb_protocol. See docs/PROTOCOL.md.
"""

from __future__ import annotations

import hashlib
import math
import struct
from dataclasses import dataclass, field
from enum import IntEnum

MAGIC = b"SB"
VERSION = 1
HEADER_LEN = 16
MAX_FRAME = 250
MIC_LEN = 8
MAX_PAYLOAD = MAX_FRAME - HEADER_LEN - MIC_LEN
MAX_STR = 64
MAX_STATE_ENTRIES = 32
MAX_DESCRIBE_CHUNKS = 10
MAX_SCHEMA = 2048
DESCRIBE_HDR = 9
MAX_ENTITIES = 32
MAX_OBJECT_ID = 32

FLAG_ACK_REQ = 0x01
FLAG_FULL_STATE = 0x02
FLAGS_MASK = FLAG_ACK_REQ | FLAG_FULL_STATE


class Err(IntEnum):
    OK = 0
    TOO_LARGE = 1
    TRUNCATED = 2
    BAD_MAGIC = 3
    BAD_VERSION = 4
    BAD_LENGTH = 5
    BAD_FLAGS = 6
    BAD_TYPE = 7
    UNSUPPORTED = 8
    BAD_VALUE = 9
    BAD_STRING = 10


class ProtocolError(ValueError):
    def __init__(self, err: Err, msg: str = "") -> None:
        super().__init__(f"{err.name}: {msg}" if msg else err.name)
        self.err = err


class MsgType(IntEnum):
    HELLO = 0x01
    DESCRIBE = 0x02
    STATE = 0x03
    EVENT = 0x04
    ACK = 0x05
    COMMAND = 0x06
    PAIR_REQUEST = 0x07
    PAIR_RESPONSE = 0x08
    HEARTBEAT = 0x09
    ERROR = 0x0A


class VType(IntEnum):
    NONE = 0
    BOOL = 1
    I32 = 2
    U32 = 3
    F32 = 4
    ENUM = 5
    STR = 6


NO_MIC = {MsgType.PAIR_REQUEST, MsgType.PAIR_RESPONSE}
ACK_REQ_ALLOWED = {
    MsgType.HELLO, MsgType.DESCRIBE, MsgType.STATE, MsgType.EVENT, MsgType.HEARTBEAT, MsgType.ERROR,
}


def mic_len(t: MsgType) -> int:
    return 0 if t in NO_MIC else MIC_LEN


ACK_STATUS_MAX = 5  # OK, DUPLICATE, NEED_DESCRIBE, NEW_BOOT, MALFORMED, BUSY
PAIR_STATUS_MAX = 1  # ACCEPTED, HUB_FULL
BOOT_REASON_MAX = 5
PLATFORM_MIN, PLATFORM_MAX = 1, 4
STATE_CLASS_MAX = 3


@dataclass(frozen=True)
class Value:
    type: VType
    v: bool | int | float | bytes | None = None

    @staticmethod
    def none() -> Value:
        return Value(VType.NONE)

    @staticmethod
    def f32(x: float) -> Value:
        # Round-trip through f32 so Python and C hold identical values.
        return Value(VType.F32, struct.unpack("<f", struct.pack("<f", x))[0])

    @staticmethod
    def str_(s: str | bytes) -> Value:
        return Value(VType.STR, s.encode() if isinstance(s, str) else s)


@dataclass
class Frame:
    type: MsgType
    flags: int = 0
    epoch: int = 0
    boot: int = 0
    seq: int = 0
    body: dict = field(default_factory=dict)
    mic: bytes = bytes(MIC_LEN)  # ignored for pairing frames


# ---------------------------------------------------------------- reader


class _R:
    def __init__(self, buf: bytes) -> None:
        self.buf, self.pos = buf, 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.buf):
            raise ProtocolError(Err.BAD_LENGTH, "short payload")
        out = self.buf[self.pos : self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def i8(self) -> int:
        return struct.unpack("<b", self.take(1))[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def str_(self) -> bytes:
        n = self.u8()
        if n > MAX_STR:
            raise ProtocolError(Err.BAD_STRING, "string too long")
        raw = self.take(n)
        _check_utf8(raw)
        return raw

    def end(self) -> None:
        if self.pos != len(self.buf):
            raise ProtocolError(Err.BAD_LENGTH, "trailing bytes")


def _check_utf8(raw: bytes) -> None:
    if b"\x00" in raw:
        raise ProtocolError(Err.BAD_STRING, "NUL in string")
    try:
        raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as e:
        raise ProtocolError(Err.BAD_STRING, "invalid UTF-8") from e


def _read_value(r: _R) -> Value:
    t = r.u8()
    if t > VType.STR:
        raise ProtocolError(Err.BAD_VALUE, "value type")
    vt = VType(t)
    if vt is VType.NONE:
        return Value(vt)
    if vt is VType.BOOL:
        b = r.u8()
        if b > 1:
            raise ProtocolError(Err.BAD_VALUE, "bool")
        return Value(vt, bool(b))
    if vt is VType.I32:
        return Value(vt, struct.unpack("<i", r.take(4))[0])
    if vt is VType.U32:
        return Value(vt, r.u32())
    if vt is VType.F32:
        f = struct.unpack("<f", r.take(4))[0]
        if not math.isfinite(f):
            raise ProtocolError(Err.BAD_VALUE, "non-finite float")
        return Value(vt, f)
    if vt is VType.ENUM:
        return Value(vt, r.u8())
    return Value(vt, r.str_())


# ---------------------------------------------------------------- writer


def _w_str(s: bytes) -> bytes:
    if len(s) > MAX_STR:
        raise ProtocolError(Err.BAD_STRING, "string too long")
    _check_utf8(s)
    return bytes([len(s)]) + s


def _w_value(v: Value) -> bytes:
    t = bytes([v.type])
    if v.type is VType.NONE:
        return t
    if v.type is VType.BOOL:
        return t + bytes([1 if v.v else 0])
    if v.type is VType.I32:
        return t + struct.pack("<i", v.v)
    if v.type is VType.U32:
        return t + struct.pack("<I", v.v)
    if v.type is VType.F32:
        assert isinstance(v.v, float)
        if not math.isfinite(v.v):
            raise ProtocolError(Err.BAD_VALUE, "non-finite float")
        return t + struct.pack("<f", v.v)
    if v.type is VType.ENUM:
        return t + bytes([v.v])
    assert isinstance(v.v, bytes)
    return t + _w_str(v.v)


def _encode_body(f: Frame) -> bytes:
    b = f.body
    t = f.type
    if t is MsgType.HELLO:
        return struct.pack(
            "<IHBB", b["schema_hash"], b["interval"], b["reason"], b["hflags"]
        )
    if t is MsgType.DESCRIBE:
        return (
            struct.pack(
                "<BBBHI", b["xfer"], b["index"], b["count"], b["total"], b["hash"]
            )
            + b["data"]
        )
    if t is MsgType.STATE:
        out = bytes([len(b["entries"])])
        for eid, val in b["entries"]:
            out += bytes([eid]) + _w_value(val)
        return out
    if t is MsgType.EVENT:
        return (
            struct.pack("<BBIH", b["entity"], b["etype"], b["oboot"], b["evno"])
            + _w_value(b["value"])
        )
    if t is MsgType.ACK:
        return struct.pack(
            "<IIBBI", b["aboot"], b["aseq"], b["status"], b["channel"], b["time"]
        )
    if t is MsgType.PAIR_REQUEST:
        return b["key_id"] + b["mac"] + b["nonce"] + b["tag"]
    if t is MsgType.PAIR_RESPONSE:
        return (
            bytes([b["status"]])
            + b["mac"]
            + b["nonce"]
            + bytes([b["channel"], b["pepoch"]])
            + b["tag"]
        )
    if t is MsgType.HEARTBEAT:
        return b""
    if t is MsgType.ERROR:
        return bytes([b["code"]]) + _w_str(b["detail"])
    raise ProtocolError(Err.UNSUPPORTED, t.name)


def encode(f: Frame) -> bytes:
    """Encode and validate by decoding the result (encoder never emits junk)."""
    payload = _encode_body(f)
    out = (
        MAGIC
        + struct.pack(
            "<BBBBIIH", VERSION, f.type, f.flags, f.epoch, f.boot, f.seq, len(payload)
        )
        + payload
        + (f.mic if mic_len(f.type) else b"")
    )
    decode(out)
    return out


# ---------------------------------------------------------------- decoder


def decode(buf: bytes) -> Frame:
    if len(buf) > MAX_FRAME:
        raise ProtocolError(Err.TOO_LARGE)
    if len(buf) < HEADER_LEN:
        raise ProtocolError(Err.TRUNCATED)
    if buf[0:2] != MAGIC:
        raise ProtocolError(Err.BAD_MAGIC)
    ver, t, flags, epoch, boot, seq, plen = struct.unpack_from("<BBBBIIH", buf, 2)
    if ver != VERSION:
        raise ProtocolError(Err.BAD_VERSION)
    if t not in MsgType._value2member_map_:
        raise ProtocolError(Err.BAD_TYPE)
    mt = MsgType(t)
    if mt is MsgType.COMMAND:
        raise ProtocolError(Err.UNSUPPORTED, "COMMAND reserved in v1")
    ml = mic_len(mt)
    if HEADER_LEN + plen + ml != len(buf):
        raise ProtocolError(Err.BAD_LENGTH, "header len")
    if (
        flags & ~FLAGS_MASK
        or (flags & FLAG_ACK_REQ and mt not in ACK_REQ_ALLOWED)
        or (flags & FLAG_FULL_STATE and mt is not MsgType.STATE)
    ):
        raise ProtocolError(Err.BAD_FLAGS)
    r = _R(buf[HEADER_LEN : HEADER_LEN + plen])
    mic = bytes(buf[HEADER_LEN + plen :]) if ml else bytes(MIC_LEN)
    body: dict = {}

    if mt is MsgType.HELLO:
        body = dict(schema_hash=r.u32(), interval=r.u16(), reason=r.u8(), hflags=r.u8())
        if body["reason"] > BOOT_REASON_MAX or body["hflags"] & ~0x01:
            raise ProtocolError(Err.BAD_VALUE, "hello")
    elif mt is MsgType.DESCRIBE:
        body = dict(xfer=r.u8(), index=r.u8(), count=r.u8(), total=r.u16(), hash=r.u32())
        body["data"] = r.take(len(r.buf) - r.pos)
        if (
            not 1 <= body["count"] <= MAX_DESCRIBE_CHUNKS
            or body["index"] >= body["count"]
            or not 1 <= body["total"] <= MAX_SCHEMA
            or not body["data"]
        ):
            raise ProtocolError(Err.BAD_VALUE, "describe")
    elif mt is MsgType.STATE:
        n = r.u8()
        if not 1 <= n <= MAX_STATE_ENTRIES:
            raise ProtocolError(Err.BAD_VALUE, "state count")
        entries = []
        for _ in range(n):
            entries.append((r.u8(), _read_value(r)))
        if len({e for e, _ in entries}) != n:
            raise ProtocolError(Err.BAD_VALUE, "duplicate entity")
        body = dict(entries=entries)
    elif mt is MsgType.EVENT:
        body = dict(entity=r.u8(), etype=r.u8(), oboot=r.u32(), evno=r.u16(), value=_read_value(r))
    elif mt is MsgType.ACK:
        body = dict(aboot=r.u32(), aseq=r.u32(), status=r.u8(), channel=r.u8(), time=r.u32())
        if body["status"] > ACK_STATUS_MAX:
            raise ProtocolError(Err.BAD_VALUE, "ack status")
    elif mt is MsgType.PAIR_REQUEST:
        body = dict(key_id=r.take(4), mac=r.take(6), nonce=r.take(16), tag=r.take(16))
        if epoch != 0:
            raise ProtocolError(Err.BAD_VALUE, "pair epoch")
    elif mt is MsgType.PAIR_RESPONSE:
        body = dict(
            status=r.u8(), mac=r.take(6), nonce=r.take(16), channel=r.u8(), pepoch=r.u8(), tag=r.take(16)
        )
        if epoch != 0 or body["status"] > PAIR_STATUS_MAX or (
            body["status"] == 0 and body["pepoch"] == 0
        ):
            raise ProtocolError(Err.BAD_VALUE, "pair response")
    elif mt is MsgType.HEARTBEAT:
        pass
    elif mt is MsgType.ERROR:
        body = dict(code=r.u8(), detail=r.str_())
    r.end()
    return Frame(mt, flags, epoch, boot, seq, body, mic)


# ---------------------------------------------------------------- schema


@dataclass
class Entity:
    entity: int
    platform: int
    value_type: int
    state_class: int = 0
    accuracy: int = 0
    flags: int = 0
    object_id: bytes = b""
    name: bytes = b""
    unit: bytes = b""
    device_class: bytes = b""
    extra: bytes = b""


@dataclass
class Schema:
    node_name: bytes
    model: bytes
    fw_version: bytes
    entities: list[Entity]


def _valid_object_id(s: bytes) -> bool:
    return 1 <= len(s) <= MAX_OBJECT_ID and all(
        c == 0x5F or 0x30 <= c <= 0x39 or 0x61 <= c <= 0x7A for c in s
    )


def decode_schema(blob: bytes) -> Schema:
    if len(blob) > MAX_SCHEMA:
        raise ProtocolError(Err.TOO_LARGE)
    r = _R(blob)
    s = Schema(r.str_(), r.str_(), r.str_(), [])
    n = r.u8()
    if not 1 <= n <= MAX_ENTITIES:
        raise ProtocolError(Err.BAD_VALUE, "entity count")
    for _ in range(n):
        e = Entity(r.u8(), r.u8(), r.u8(), r.u8(), r.i8(), r.u8())
        e.object_id, e.name, e.unit, e.device_class, e.extra = (
            r.str_(), r.str_(), r.str_(), r.str_(), r.str_()
        )
        if (
            not PLATFORM_MIN <= e.platform <= PLATFORM_MAX
            or not VType.BOOL <= e.value_type <= VType.STR
            or e.state_class > STATE_CLASS_MAX
            or e.flags & ~0x01
        ):
            raise ProtocolError(Err.BAD_VALUE, "entity fields")
        if not _valid_object_id(e.object_id):
            raise ProtocolError(Err.BAD_STRING, "object_id")
        s.entities.append(e)
    if len({e.entity for e in s.entities}) != n:
        raise ProtocolError(Err.BAD_VALUE, "duplicate entity")
    r.end()
    return s


def encode_schema(s: Schema) -> bytes:
    out = _w_str(s.node_name) + _w_str(s.model) + _w_str(s.fw_version)
    out += bytes([len(s.entities)])
    for e in s.entities:
        out += struct.pack(
            "<BBBBbB", e.entity, e.platform, e.value_type, e.state_class, e.accuracy, e.flags
        )
        for f in (e.object_id, e.name, e.unit, e.device_class, e.extra):
            out += _w_str(f)
    decode_schema(out)
    return out


def schema_hash(blob: bytes) -> int:
    return struct.unpack("<I", hashlib.sha256(blob).digest()[:4])[0]


def split_schema(blob: bytes, xfer: int) -> list[Frame]:
    """Split a schema blob into DESCRIBE frames (header fields left at 0)."""
    chunk = MAX_PAYLOAD - DESCRIBE_HDR
    parts = [blob[i : i + chunk] for i in range(0, len(blob), chunk)]
    h = schema_hash(blob)
    return [
        Frame(
            MsgType.DESCRIBE,
            FLAG_ACK_REQ,
            body=dict(xfer=xfer, index=i, count=len(parts), total=len(blob), hash=h, data=p),
        )
        for i, p in enumerate(parts)
    ]


# ------------------------------------------------ canonical descriptions
# Byte-exact text shared with the C implementation for cross-checking.


def describe_value(v: Value) -> str:
    t = v.type
    if t is VType.NONE:
        return "N"
    if t is VType.BOOL:
        return f"B:{int(bool(v.v))}"
    if t is VType.I32:
        return f"I:{v.v}"
    if t is VType.U32:
        return f"U:{v.v}"
    if t is VType.F32:
        return "F:" + struct.pack(">f", v.v).hex()
    if t is VType.ENUM:
        return f"E:{v.v}"
    assert isinstance(v.v, bytes)
    return "S:" + v.v.hex()


def describe(f: Frame) -> str:
    b = f.body
    head = f"{f.type.name} f={f.flags:02x} e={f.epoch} b={f.boot} s={f.seq} "
    t = f.type
    if t is MsgType.HELLO:
        tail = f"hash={b['schema_hash']:08x} int={b['interval']} reason={b['reason']} hf={b['hflags']}"
    elif t is MsgType.DESCRIBE:
        tail = (
            f"xfer={b['xfer']} idx={b['index']} cnt={b['count']} total={b['total']} "
            f"hash={b['hash']:08x} data={b['data'].hex()}"
        )
    elif t is MsgType.STATE:
        tail = "[" + ",".join(f"{e}:{describe_value(v)}" for e, v in b["entries"]) + "]"
    elif t is MsgType.EVENT:
        tail = (
            f"ent={b['entity']} type={b['etype']} oboot={b['oboot']} evno={b['evno']} "
            f"val={describe_value(b['value'])}"
        )
    elif t is MsgType.ACK:
        tail = f"aboot={b['aboot']} aseq={b['aseq']} st={b['status']} ch={b['channel']} t={b['time']}"
    elif t is MsgType.PAIR_REQUEST:
        tail = f"kid={b['key_id'].hex()} mac={b['mac'].hex()} nn={b['nonce'].hex()} tag={b['tag'].hex()}"
    elif t is MsgType.PAIR_RESPONSE:
        tail = (
            f"st={b['status']} mac={b['mac'].hex()} hn={b['nonce'].hex()} "
            f"ch={b['channel']} ep={b['pepoch']} tag={b['tag'].hex()}"
        )
    elif t is MsgType.HEARTBEAT:
        tail = "-"
    else:
        tail = f"code={b['code']} detail={b['detail'].hex()}"
    if mic_len(t):
        tail += f" mic={f.mic.hex()}"
    return head + tail


def describe_schema(s: Schema) -> str:
    out = f"name={s.node_name.hex()} model={s.model.hex()} fw={s.fw_version.hex()} n={len(s.entities)}"
    for e in s.entities:
        out += (
            f" {{{e.entity},{e.platform},{e.value_type},{e.state_class},{e.accuracy},{e.flags},"
            f"{e.object_id.hex()},{e.name.hex()},{e.unit.hex()},{e.device_class.hex()},{e.extra.hex()}}}"
        )
    return out
