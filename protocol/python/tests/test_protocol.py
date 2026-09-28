import random
from pathlib import Path

import pytest

from sb_protocol import crypto
from sb_protocol.codec import (
    MAX_FRAME,
    ProtocolError,
    decode,
    decode_schema,
    describe,
    encode,
    encode_schema,
    schema_hash,
)
from sb_protocol.vectors import (
    HUB_NONCE,
    K_MIC,
    K_NODE,
    NODE_NONCE,
    NO_MIC_TYPES,
    demo_schema,
    direction,
    render,
    valid_frames,
)

VECTORS = Path(__file__).resolve().parents[2] / "test-vectors"


def lines(name):
    return [ln.split("|") for ln in (VECTORS / name).read_text().splitlines()]


@pytest.mark.parametrize("name", ["frames.txt", "schema.txt", "crypto.txt"])
def test_vectors_up_to_date(name):
    assert (VECTORS / name).read_text() == render()[name], "regenerate vectors"


def test_frame_vectors_roundtrip():
    for name, expect, hexs, desc in lines("frames.txt"):
        buf = bytes.fromhex(hexs)
        if expect == "OK":
            f = decode(buf)
            assert describe(f) == desc, name
            assert encode(f) == buf, name
        else:
            with pytest.raises(ProtocolError) as e:
                decode(buf)
            assert e.value.err.name == expect, name


def test_schema_roundtrip_and_chunks():
    blob = encode_schema(demo_schema())
    assert encode_schema(decode_schema(blob)) == blob
    chunks = [f for n, f in valid_frames() if n.startswith("describe_") and n[-1].isdigit()]
    assert len(chunks) >= 2
    assert b"".join(c.body["data"] for c in chunks) == blob
    assert all(c.body["hash"] == schema_hash(blob) for c in chunks)
    assert all(len(encode(c)) <= MAX_FRAME for c in chunks)


def test_pairing_tags_verify_and_reject_tamper():
    frames = dict(valid_frames())
    req = encode(frames["pair_request"])
    assert crypto.verify(crypto.request_tag(K_NODE, req[:-16]), req[-16:])
    bad = bytearray(req)
    bad[20] ^= 1
    assert not crypto.verify(crypto.request_tag(K_NODE, bytes(bad[:-16])), req[-16:])
    resp = encode(frames["pair_response"])
    assert crypto.verify(crypto.response_tag(K_NODE, NODE_NONCE, resp[:-16]), resp[-16:])
    # Response is bound to the node's nonce.
    assert not crypto.verify(crypto.response_tag(K_NODE, HUB_NONCE, resp[:-16]), resp[-16:])


def test_session_keys_depend_on_every_input():
    base = (K_NODE, NODE_NONCE, HUB_NONCE, b"\x01" * 6, b"\x02" * 6, 3)
    lmk, kmic = crypto.session_keys(*base)
    assert lmk != kmic
    for i in range(len(base)):
        args = list(base)
        args[i] = 4 if i == 5 else bytes([args[i][0] ^ 1]) + args[i][1:]
        l2, m2 = crypto.session_keys(*args)
        assert l2 != lmk and m2 != kmic


def test_golden_frames_carry_valid_mics():
    for name, expect, hexs, _ in lines("frames.txt"):
        if expect != "OK":
            continue
        buf = bytes.fromhex(hexs)
        f = decode(buf)
        if f.type in NO_MIC_TYPES:
            continue
        d = direction(f.type)
        assert crypto.mic_ok(K_MIC, d, buf), name
        assert not crypto.mic_ok(K_MIC, 1 - d, buf), name  # direction-bound
        bad = bytearray(buf)
        bad[6] ^= 1  # boot counter
        assert not crypto.mic_ok(K_MIC, d, bytes(bad)), name


def test_mutation_fuzz_only_raises_protocol_error():
    rng = random.Random(1234)
    seeds = [bytes.fromhex(h) for _, e, h, _ in lines("frames.txt")]
    for _ in range(20000):
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
            f = decode(bytes(b))
        except ProtocolError:
            continue
        assert encode(f) == bytes(b)
