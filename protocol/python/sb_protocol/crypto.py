"""Pairing crypto for protocol v1. See docs/SECURITY.md."""

from __future__ import annotations

import hashlib
import hmac

KEY_LEN = 16
NONCE_LEN = 16
TAG_LEN = 16
KEY_ID_LEN = 4
LMK_LEN = 16
MIC_LEN = 8
PMK = b"ServerBuddyPMKv1"  # non-secret by design (see SECURITY.md)

LABEL_ID = b"sb-v1 id"
LABEL_REQ = b"sb-v1 req"
LABEL_RESP = b"sb-v1 resp"
LABEL_KEYS = b"sb-v1 keys"
LABEL_MIC = b"sb-v1 mic"
DIR_NODE_TO_HUB = 0
DIR_HUB_TO_NODE = 1


def _hmac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-SHA256."""
    prk = _hmac(salt or bytes(32), ikm)
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = _hmac(prk, t + info + bytes([i]))
        out += t
        i += 1
    return out[:length]


def key_id(k_node: bytes) -> bytes:
    return _hmac(k_node, LABEL_ID)[:KEY_ID_LEN]


def session_keys(
    k_node: bytes,
    node_nonce: bytes,
    hub_nonce: bytes,
    node_mac: bytes,
    hub_mac: bytes,
    epoch: int,
) -> tuple[bytes, bytes]:
    """Returns (lmk, k_mic)."""
    okm = hkdf_sha256(
        k_node,
        node_nonce + hub_nonce,
        LABEL_KEYS + node_mac + hub_mac + bytes([epoch]),
        32,
    )
    return okm[:16], okm[16:]


def mic(k_mic: bytes, direction: int, frame_before_mic: bytes) -> bytes:
    return _hmac(k_mic, LABEL_MIC + bytes([direction]) + frame_before_mic)[:MIC_LEN]


def seal(k_mic: bytes, direction: int, frame: bytes) -> bytes:
    """Fill the trailing MIC of an encoded (non-pairing) frame."""
    body = frame[:-MIC_LEN]
    return body + mic(k_mic, direction, body)


def mic_ok(k_mic: bytes, direction: int, frame: bytes) -> bool:
    if len(frame) < MIC_LEN:
        return False
    return verify(mic(k_mic, direction, frame[:-MIC_LEN]), frame[-MIC_LEN:])


def request_tag(k_node: bytes, frame_before_tag: bytes) -> bytes:
    return _hmac(k_node, LABEL_REQ + frame_before_tag)[:TAG_LEN]


def response_tag(k_node: bytes, node_nonce: bytes, frame_before_tag: bytes) -> bytes:
    return _hmac(k_node, LABEL_RESP + node_nonce + frame_before_tag)[:TAG_LEN]


def verify(expected: bytes, got: bytes) -> bool:
    return hmac.compare_digest(expected, got)
