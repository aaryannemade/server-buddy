"""Protocol-level tests of the API client."""

from __future__ import annotations

import aiohttp
import pytest

from custom_components.server_buddy.client import (
    AlreadyClaimed,
    AuthFailed,
    CannotConnect,
    CertificateMismatch,
    HubConnection,
    ResyncRequired,
    fetch_json,
    parse_node,
    parse_snapshot,
)
from fake_hub import FakeHub


async def test_claim_pin_and_resume(fake_hub: FakeHub, tls: tuple[str, str, str]) -> None:
    """Claim pins the served certificate; resume and resync follow the stream."""
    async with aiohttp.ClientSession() as session:
        conn = HubConnection(session, "127.0.0.1", fake_hub.port, fingerprint=None)
        hello = await conn.connect()
        assert hello["hub_id"] == fake_hub.hub_id
        token = await conn.claim()
        assert conn.fingerprint == tls[2] and token == fake_hub.token
        snapshot = parse_snapshot(await conn.request("subscribe", collect_events=True))
        assert set(snapshot.nodes) == {"42"}
        assert snapshot.nodes["42"].entity(4).event_types == ["press", "hold"]
        await conn.close()

        second = HubConnection(session, "127.0.0.1", fake_hub.port, fingerprint=None)
        await second.connect()
        with pytest.raises(AlreadyClaimed):
            await second.claim()
        await second.close()

        events: list[dict] = []
        pinned = HubConnection(
            session, "127.0.0.1", fake_hub.port, fingerprint=tls[2], on_event=events.append
        )
        await pinned.connect()
        await pinned.auth(token)
        await fake_hub.emit(1, 0, 42, entity=1, value=1.5)
        replay = await pinned.request(
            "resume", stream_epoch=fake_hub.boot, after_seq="0", collect_events=True
        )
        assert [m["type"] for m in replay] == ["event", "result"]
        with pytest.raises(ResyncRequired):
            await pinned.request("resume", stream_epoch=fake_hub.boot + 1, after_seq="0")
        await fake_hub.emit(3, 0, 42, available=True)
        for _ in range(100):
            if events:
                break
            await __import__("asyncio").sleep(0.01)
        assert events and events[0]["kind"] == 3
        await pinned.close()
        assert pinned.closed


async def test_auth_and_pin_failures(fake_hub: FakeHub, other_tls: tuple[str, str, str]) -> None:
    """Wrong tokens and wrong certificates are distinct, fatal errors."""
    fake_hub.token = "T" * 43
    async with aiohttp.ClientSession() as session:
        conn = HubConnection(session, "127.0.0.1", fake_hub.port, fingerprint=None)
        await conn.connect()
        with pytest.raises(AuthFailed):
            await conn.auth("U" * 43)
        await conn.close()

        with pytest.raises(CertificateMismatch):
            await HubConnection(
                session, "127.0.0.1", fake_hub.port, fingerprint=other_tls[2]
            ).connect()
        with pytest.raises(CertificateMismatch):
            await fetch_json(
                session, "127.0.0.1", fake_hub.port, "/version", fingerprint=other_tls[2]
            )
        with pytest.raises(AuthFailed):
            await fetch_json(session, "127.0.0.1", fake_hub.port, "/diagnostics", token="bad")
        with pytest.raises(CannotConnect):
            await fetch_json(session, "127.0.0.1", 1, "/health")


def test_parsers_reject_malformed_input() -> None:
    """Incomplete snapshots and entity lists are protocol errors."""
    with pytest.raises(CannotConnect):
        parse_snapshot([{"type": "snapshot.begin", "stream_epoch": 1, "stream_seq": "0"}])
    node = {
        "slot": 0,
        "state": 2,
        "node_id": "1",
        "has_schema": True,
        "schema_hash": 1,
        "entity_count": 2,
    }
    with pytest.raises(CannotConnect):
        parse_node(node, [{"entity": 1, "platform": 1, "value_type": 4, "object_id": "t"}])
    with pytest.raises(CannotConnect):
        parse_node({**node, "entity_count": 1}, [{"entity": 1, "platform": 1, "value_type": 4}])
