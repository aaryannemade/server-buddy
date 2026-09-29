"""TLS fake of the P4 local API (firmware/p4/main/sb_api.c message shapes)."""

from __future__ import annotations

import asyncio
import contextlib
import secrets
import ssl
from dataclasses import dataclass, field
from typing import Any

from aiohttp import WSMsgType, web

RING = 64


@dataclass
class FakeNode:
    slot: int
    node_id: int
    state: int = 2
    name: str = ""
    model: str = ""
    fw_version: str = ""
    available: bool = True
    report_interval_s: int = 60
    generation: int = 1
    entities: list[dict[str, Any]] = field(default_factory=list)

    def json(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "slot": self.slot,
            "state": self.state,
            "mac": f"02:00:00:00:00:{self.slot:02x}",
            "node_id": str(self.node_id),
            "generation": self.generation,
            "available": self.available,
            "last_seen_ms": "0",
            "rssi": -50,
            "epoch": 1,
            "report_interval_s": self.report_interval_s,
            "boot_reason": 1,
            "has_schema": bool(self.entities),
        }
        if self.entities:
            data |= {
                "schema_hash": 1234,
                "name": self.name,
                "model": self.model,
                "fw_version": self.fw_version,
                "entity_count": len(self.entities),
            }
        return data


def entity(
    number: int,
    object_id: str,
    platform: int,
    value_type: int,
    value: Any = None,
    **extra: Any,
) -> dict[str, Any]:
    """Build a schema entity as the hub serialises it."""
    data = {
        "entity": number,
        "platform": platform,
        "value_type": value_type,
        "state_class": 0,
        "accuracy": -1,
        "flags": 0,
        "object_id": object_id,
        "name": object_id.replace("_", " ").title(),
        "value": value,
    }
    data |= extra
    return data


class FakeHub:
    """Enough of the hub API to exercise the integration end to end."""

    def __init__(self) -> None:
        self.hub_id = "sb-0123456789ab"
        self.boot = 1
        self.api = "v1"
        self.token: str | None = None
        self.nodes: dict[int, FakeNode] = {}
        self.ring: list[dict[str, Any]] = []
        self.seq = 0
        self.requests: list[str] = []
        self.sockets: set[web.WebSocketResponse] = set()
        self.auth_ws: web.WebSocketResponse | None = None
        self.subscribed: dict[web.WebSocketResponse, int] = {}
        self.next_node_id = 1000
        self.drop_next_node_get = False
        self.auth_tokens: list[str] = []
        self.port = 0
        self._runner: web.AppRunner | None = None

    @property
    def claimed(self) -> bool:
        return self.token is not None

    # ------------------------------------------------------------ server

    async def start(self, cert: str, key: str) -> None:
        app = web.Application()
        app.router.add_get("/api/v1/health", self._health)
        app.router.add_get("/api/v1/version", self._version)
        app.router.add_get("/api/v1/diagnostics", self._diagnostics)
        app.router.add_get("/api/v1/ws", self._ws)
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(cert, key)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", 0, ssl_context=context)
        await site.start()
        self.port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]

    async def stop(self) -> None:
        await self.drop()
        if self._runner is not None:
            await self._runner.cleanup()

    async def drop(self) -> None:
        """Abruptly end all WebSocket sessions."""
        for ws in list(self.sockets):
            with contextlib.suppress(Exception):
                await ws.close()
        self.sockets.clear()
        self.subscribed.clear()
        self.auth_ws = None

    def revoke_session(self) -> None:
        """Firmware behaviour after a failed send: auth dropped, socket left open."""
        self.subscribed.clear()
        self.auth_ws = None

    async def reboot(self) -> None:
        """New stream epoch; values and availability are lost (docs/API.md)."""
        await self.drop()
        self.boot += 1
        self.ring.clear()
        self.seq = 0
        for node in self.nodes.values():
            node.available = False
            for item in node.entities:
                item["value"] = None

    async def _health(self, request: web.Request) -> web.Response:
        return web.json_response(
            {"status": "ok", "hub_id": self.hub_id, "boot": self.boot, "claimed": self.claimed}
        )

    async def _version(self, request: web.Request) -> web.Response:
        return web.json_response(
            {"project": "server_buddy_p4", "version": "1", "idf": "v5.5.4", "api": self.api}
        )

    async def _diagnostics(self, request: web.Request) -> web.Response:
        if request.headers.get("Authorization") != f"Bearer {self.token}":
            return web.Response(status=401)
        return web.json_response({"credential_generation": 1, "hub": {"rx": 3}})

    # ------------------------------------------------------------ stream

    async def emit(self, kind: int, slot: int, node_id: int, **fields: Any) -> dict[str, Any]:
        self.seq += 1
        event = {
            "type": "event",
            "seq": str(self.seq),
            "kind": kind,
            "slot": slot,
            "entity": 0,
            "event_type": 0,
            "pair": 0,
            "available": False,
            "tombstone": False,
            "node_id": str(node_id),
            "generation": 1,
        }
        if kind == 0:
            event |= {"refresh": True, "refresh_op": "node.get"}
        event |= fields
        self.ring = [*self.ring, event][-RING:]
        for ws in list(self.subscribed):
            await self._flush(ws)
        return event

    async def _flush(self, ws: web.WebSocketResponse) -> None:
        sent = self.subscribed.get(ws)
        if sent is None or ws.closed:
            return
        for event in self.ring:
            if int(event["seq"]) > sent:
                await ws.send_json(event)
                sent = int(event["seq"])
        self.subscribed[ws] = sent

    async def set_value(self, slot: int, number: int, value: Any) -> None:
        node = self.nodes[slot]
        for item in node.entities:
            if item["entity"] == number:
                item["value"] = value
        await self.emit(1, slot, node.node_id, entity=number, value=value)

    # --------------------------------------------------------- websocket

    async def _ws(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        self.sockets.add(ws)
        await ws.send_json(
            {
                "type": "hello",
                "hub_id": self.hub_id,
                "boot": self.boot,
                "claimed": self.claimed,
                "credential_generation": 1,
                "max_inbound": 2048,
                "stream_epoch": self.boot,
                "stream_seq": str(self.seq),
            }
        )
        try:
            async for msg in ws:
                if msg.type != WSMsgType.TEXT:
                    break
                await self._handle(ws, msg.json())
        finally:
            self.sockets.discard(ws)
            self.subscribed.pop(ws, None)
            if self.auth_ws is ws:
                self.auth_ws = None
        return ws

    async def _result(
        self, ws: web.WebSocketResponse, op: str, ok: bool = True, **extra: Any
    ) -> None:
        await ws.send_json(
            {"type": "result", "op": op, "ok": ok, "result": 0 if ok else -2} | extra
        )

    async def _error(self, ws: web.WebSocketResponse, op: str, code: str, **extra: Any) -> None:
        await ws.send_json({"type": "error", "op": op, "code": code} | extra)

    async def _send_node(self, ws: web.WebSocketResponse, kind: str, node: FakeNode) -> None:
        for index, item in enumerate(node.entities):
            await ws.send_json({"type": kind, "slot": node.slot, "index": index, "entity": item})

    async def _handle(self, ws: web.WebSocketResponse, msg: dict[str, Any]) -> None:
        op = msg.get("op", "")
        self.requests.append(op)
        if op == "claim":
            if self.claimed:
                await self._error(ws, op, "already_claimed")
                return
            self.token = secrets.token_urlsafe(32)
            self.auth_ws = ws
            await self._result(ws, op, generation=1, token=self.token)
            return
        if op == "auth":
            self.auth_tokens.append(str(msg.get("token")))
            if self.auth_ws is not None and self.auth_ws is not ws and not self.auth_ws.closed:
                await self._error(ws, op, "client_busy")
            elif self.claimed and msg.get("token") == self.token:
                self.auth_ws = ws
                await self._result(ws, op, generation=1)
            else:
                await self._error(ws, op, "unauthorized")
            return
        if ws is not self.auth_ws:
            await self._error(ws, op, "unauthorized")
            return

        if op == "subscribe":
            seq = self.seq
            await ws.send_json(
                {
                    "type": "snapshot.begin",
                    "stream_epoch": self.boot,
                    "stream_seq": str(seq),
                    "slots": 17,
                }
            )
            for slot in range(17):
                node = self.nodes.get(slot)
                message: dict[str, Any] = {
                    "type": "snapshot.node",
                    "slot": slot,
                    "found": node is not None,
                }
                if node is not None:
                    message["node"] = node.json()
                await ws.send_json(message)
                if node is not None:
                    await self._send_node(ws, "snapshot.entity", node)
            await ws.send_json(
                {"type": "snapshot.end", "stream_epoch": self.boot, "stream_seq": str(seq)}
            )
            await self._resume(ws, self.boot, seq)
        elif op == "resume":
            await self._resume(ws, int(msg["stream_epoch"]), int(msg["after_seq"]))
        elif op == "node.get":
            if self.drop_next_node_get:
                self.drop_next_node_get = False
                await self.drop()
                return
            node = self.nodes.get(int(msg["slot"]))
            await self._result(
                ws, op, found=node is not None, **({"node": node.json()} if node else {})
            )
            if node is not None:
                await self._send_node(ws, "node.entity", node)
                await ws.send_json(
                    {"type": "node.end", "slot": node.slot, "entity_count": len(node.entities)}
                )
        elif op == "node.add":
            slot = next(s for s in range(17) if s not in self.nodes)
            self.next_node_id += 1
            node = FakeNode(slot=slot, node_id=self.next_node_id, state=1, available=False)
            self.nodes[slot] = node
            await self._result(ws, op, key="A" * 22, node=node.json())
            await self.emit(0, slot, node.node_id)
        elif op == "node.remove":
            node = self.nodes.pop(int(msg["slot"]), None)
            if node is None:
                await self._result(ws, op, ok=False)
                return
            await self._result(ws, op)
            await self.emit(0, node.slot, node.node_id, tombstone=True)
        elif op in ("pair.open", "pair.close"):
            await self._result(ws, op)
        elif op == "ping":
            await ws.send_json({"type": "pong"})
        else:
            await self._error(ws, op, "unknown_op")

    async def _resume(self, ws: web.WebSocketResponse, epoch: int, after: int) -> None:
        oldest = int(self.ring[0]["seq"]) if self.ring else self.seq + 1
        if epoch != self.boot or after > self.seq or (after < oldest - 1):
            await self._error(
                ws, "resume", "resync_required", stream_epoch=self.boot, latest_seq=str(self.seq)
            )
            return
        for event in self.ring:
            if int(event["seq"]) > after:
                await ws.send_json(event)
        await self._result(ws, "resume", stream_epoch=self.boot, latest_seq=str(self.seq))
        self.subscribed[ws] = self.seq
        await asyncio.sleep(0)
