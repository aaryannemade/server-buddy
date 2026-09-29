"""Async client for the Server Buddy local API v1 (see docs/API.md).

Independent of Home Assistant so it can be tested against a fake hub. The hub
accepts one request at a time per connection; responses are matched by order,
while stream events can be interleaved and are delivered through callbacks.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import aiohttp

_LOGGER = logging.getLogger(__name__)

API_VERSION = "v1"
DEFAULT_PORT = 443
TIMEOUT = 15.0
SNAPSHOT_TIMEOUT = 60.0
HEARTBEAT = 30.0
TOKEN_LEN = 43

type Message = dict[str, Any]


class ServerBuddyError(Exception):
    """Base error for hub communication."""


class CannotConnect(ServerBuddyError):
    """The hub is unreachable or sent an unexpected response."""


class AuthFailed(ServerBuddyError):
    """The hub rejected the credential."""


class CertificateMismatch(ServerBuddyError):
    """The hub certificate does not match the pinned fingerprint."""


class AlreadyClaimed(ServerBuddyError):
    """The hub has already been claimed by another client."""


class ResyncRequired(ServerBuddyError):
    """The requested stream position is no longer available."""


class RequestError(ServerBuddyError):
    """The hub rejected a request."""

    def __init__(self, op: str, code: str) -> None:
        super().__init__(f"{op}: {code}")
        self.op = op
        self.code = code


def _ssl(fingerprint: str | None) -> aiohttp.Fingerprint | bool:
    # Unpinned connections are only used before commissioning (docs/SECURITY.md).
    return aiohttp.Fingerprint(bytes.fromhex(fingerprint)) if fingerprint else False


def base_url(host: str, port: int) -> str:
    """Return the API base URL."""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"https://{host}:{port}/api/{API_VERSION}"


async def fetch_json(
    session: aiohttp.ClientSession,
    host: str,
    port: int,
    path: str,
    *,
    fingerprint: str | None = None,
    token: str | None = None,
) -> Message:
    """GET a JSON document from the hub."""
    headers = {"Authorization": f"Bearer {token}"} if token else None
    try:
        async with session.get(
            base_url(host, port) + path,
            ssl=_ssl(fingerprint),
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=TIMEOUT),
        ) as resp:
            if resp.status == 401:
                raise AuthFailed("unauthorized")
            resp.raise_for_status()
            data = await resp.json(content_type=None)
    except aiohttp.ServerFingerprintMismatch as err:
        raise CertificateMismatch("certificate fingerprint changed") from err
    except (aiohttp.ClientError, TimeoutError, ValueError) as err:
        raise CannotConnect(str(err) or type(err).__name__) from err
    if not isinstance(data, dict):
        raise CannotConnect("unexpected response")
    return data


# ------------------------------------------------------------------- models


@dataclass
class HubEntity:
    """An entity described by a node schema."""

    number: int
    platform: int
    value_type: int
    state_class: int
    accuracy: int
    flags: int
    object_id: str
    name: str
    unit: str
    device_class: str
    extra: str
    value: Any = None

    @property
    def event_types(self) -> list[str]:
        """Event type names, indexed by the EVENT event_type field."""
        return [part.strip() for part in self.extra.split(",") if part.strip()]


@dataclass
class HubNode:
    """A registry slot on the hub."""

    slot: int
    state: int
    node_id: str
    generation: int
    available: bool
    rssi: int
    report_interval_s: int
    boot_reason: int
    mac: str
    has_schema: bool
    schema_hash: int | None
    name: str
    model: str
    fw_version: str
    entities: dict[int, HubEntity] = field(default_factory=dict)

    def entity(self, number: int) -> HubEntity | None:
        """Look up an entity by its wire ID (object IDs need not be unique)."""
        return self.entities.get(number)


@dataclass
class Snapshot:
    """A registry snapshot plus stream events replayed after its watermark."""

    epoch: int
    seq: int
    nodes: dict[str, HubNode]
    events: list[Message]


def _int(msg: Message, key: str, default: int | None = None) -> int:
    value = msg.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise CannotConnect(f"malformed field {key}")
    try:
        return int(value)
    except ValueError as err:
        raise CannotConnect(f"malformed field {key}") from err


def _str(msg: Message, key: str) -> str:
    value = msg.get(key, "")
    if not isinstance(value, str):
        raise CannotConnect(f"malformed field {key}")
    return value


def parse_entity(msg: Any) -> HubEntity:
    """Parse one entity description."""
    if not isinstance(msg, dict):
        raise CannotConnect("malformed entity")
    object_id = _str(msg, "object_id")
    if not object_id:
        raise CannotConnect("entity without object_id")
    return HubEntity(
        number=_int(msg, "entity"),
        platform=_int(msg, "platform"),
        value_type=_int(msg, "value_type"),
        state_class=_int(msg, "state_class", 0),
        accuracy=_int(msg, "accuracy", -1),
        flags=_int(msg, "flags", 0),
        object_id=object_id,
        name=_str(msg, "name"),
        unit=_str(msg, "unit"),
        device_class=_str(msg, "device_class"),
        extra=_str(msg, "extra"),
        value=msg.get("value"),
    )


def parse_node(msg: Any, entities: list[Any]) -> HubNode:
    """Parse node metadata and its separately delivered entities."""
    if not isinstance(msg, dict):
        raise CannotConnect("malformed node")
    has_schema = bool(msg.get("has_schema"))
    node = HubNode(
        slot=_int(msg, "slot"),
        state=_int(msg, "state"),
        node_id=str(_int(msg, "node_id")),
        generation=_int(msg, "generation", 0),
        available=bool(msg.get("available")),
        rssi=_int(msg, "rssi", 0),
        report_interval_s=_int(msg, "report_interval_s", 0),
        boot_reason=_int(msg, "boot_reason", 0),
        mac=_str(msg, "mac"),
        has_schema=has_schema,
        schema_hash=_int(msg, "schema_hash") if has_schema else None,
        name=_str(msg, "name"),
        model=_str(msg, "model"),
        fw_version=_str(msg, "fw_version"),
    )
    parsed = [parse_entity(item) for item in entities]
    if has_schema and len(parsed) != _int(msg, "entity_count", len(parsed)):
        raise CannotConnect("incomplete entity list")
    node.entities = {entity.number: entity for entity in parsed}
    return node


def parse_snapshot(messages: list[Message]) -> Snapshot:
    """Parse the response to a subscribe request."""
    if not messages or messages[0].get("type") != "snapshot.begin":
        raise CannotConnect("snapshot missing begin")
    begin = messages[0]
    epoch, seq = _int(begin, "stream_epoch"), _int(begin, "stream_seq")
    nodes: dict[str, HubNode] = {}
    events: list[Message] = []
    current: Message | None = None
    entities: list[Any] = []
    ended = False

    def flush() -> None:
        if current is not None:
            node = parse_node(current, entities)
            nodes[node.node_id] = node

    for msg in messages[1:]:
        kind = msg.get("type")
        if kind == "snapshot.node":
            flush()
            current, entities = (msg.get("node") if msg.get("found") else None), []
        elif kind == "snapshot.entity":
            if current is None or msg.get("slot") != current.get("slot"):
                raise CannotConnect("entity outside its node")
            entities.append(msg.get("entity"))
        elif kind == "snapshot.end":
            flush()
            current, ended = None, True
        elif kind == "event":
            events.append(msg)
    if not ended:
        raise CannotConnect("snapshot missing end")
    return Snapshot(epoch, seq, nodes, events)


def parse_node_get(messages: list[Message]) -> HubNode | None:
    """Parse the response to node.get; None if the slot is empty."""
    result = next(
        (m for m in messages if m.get("type") == "result" and m.get("op") == "node.get"), None
    )
    if result is None:
        raise CannotConnect("node.get without result")
    if not result.get("found"):
        return None
    entities = [m.get("entity") for m in messages if m.get("type") == "node.entity"]
    return parse_node(result.get("node"), entities)


# --------------------------------------------------------------- connection


@dataclass
class _Pending:
    op: str
    future: asyncio.Future[list[Message]]
    on_complete: Callable[[list[Message]], None] | None
    collect_events: bool
    messages: list[Message] = field(default_factory=list)

    def is_terminal(self, msg: Message) -> bool:
        kind = msg.get("type")
        if kind == "error":
            # op is absent when the hub could not parse the request at all.
            return msg.get("op") in (None, self.op, "resume" if self.op == "subscribe" else None)
        if self.op == "ping":
            return kind == "pong"
        if self.op in ("subscribe", "resume"):
            return kind == "result" and msg.get("op") == "resume"
        if self.op == "node.get":
            if kind == "node.end" and any(
                m.get("type") == "result" and m.get("op") == "node.get" for m in self.messages
            ):
                return True
            return (
                kind == "result"
                and msg.get("op") == "node.get"
                and not (msg.get("ok") and msg.get("found"))
            )
        return kind == "result" and msg.get("op") == self.op


def _error_for(pending: _Pending, msg: Message) -> ServerBuddyError | None:
    if msg.get("type") == "error":
        code = str(msg.get("code", "unknown"))
        if code == "unauthorized":
            return AuthFailed(code)
        if code == "resync_required":
            return ResyncRequired(code)
        if code == "already_claimed":
            return AlreadyClaimed(code)
        return RequestError(str(msg.get("op") or pending.op), code)
    if msg.get("type") == "result" and not msg.get("ok"):
        return RequestError(pending.op, str(msg.get("result", "failed")))
    return None


class HubConnection:
    """One authenticated-or-not WebSocket session with the hub."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        host: str,
        port: int,
        *,
        fingerprint: str | None,
        on_event: Callable[[Message], None] | None = None,
        on_stream_error: Callable[[Message], None] | None = None,
    ) -> None:
        self._session = session
        self._host = host
        self._port = port
        self._pin = fingerprint
        self._on_event = on_event
        self._on_stream_error = on_stream_error
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._reader: asyncio.Task[None] | None = None
        self._pending: _Pending | None = None
        self._lock = asyncio.Lock()
        self._closed = asyncio.Event()
        self.fingerprint: str | None = None
        self.hello: Message = {}

    async def connect(self) -> Message:
        """Open the WebSocket and return the hub's hello."""
        try:
            self._ws = await self._session.ws_connect(
                base_url(self._host, self._port) + "/ws",
                ssl=_ssl(self._pin),
                heartbeat=HEARTBEAT,
                timeout=aiohttp.ClientWSTimeout(ws_close=TIMEOUT),
            )
            msg = await self._ws.receive(timeout=TIMEOUT)
        except asyncio.CancelledError:
            await self.close()
            raise
        except aiohttp.ServerFingerprintMismatch as err:
            await self.close()
            raise CertificateMismatch("certificate fingerprint changed") from err
        except (aiohttp.ClientError, TimeoutError, OSError) as err:
            await self.close()
            raise CannotConnect(str(err) or type(err).__name__) from err
        hello = self._decode(msg)
        if hello is None or hello.get("type") != "hello" or not hello.get("hub_id"):
            await self.close()
            raise CannotConnect("hub did not send hello")
        ssl_object = self._ws.get_extra_info("ssl_object")
        cert = ssl_object.getpeercert(binary_form=True) if ssl_object else None
        if not cert:
            await self.close()
            raise CannotConnect("no TLS certificate")
        self.fingerprint = hashlib.sha256(cert).hexdigest()
        self.hello = hello
        self._reader = asyncio.get_running_loop().create_task(self._read())
        return hello

    @property
    def closed(self) -> bool:
        """Return True once the connection has ended."""
        return self._closed.is_set()

    async def wait_closed(self) -> None:
        """Wait until the connection ends."""
        await self._closed.wait()

    async def close(self) -> None:
        """Close the connection."""
        reader, self._reader = self._reader, None
        if reader is not None and reader is not asyncio.current_task():
            reader.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await reader
        if self._ws is not None and not self._ws.closed:
            with contextlib.suppress(aiohttp.ClientError, OSError, TimeoutError):
                await self._ws.close()
        self._finish()

    def _finish(self) -> None:
        pending, self._pending = self._pending, None
        if pending is not None and not pending.future.done():
            pending.future.set_exception(CannotConnect("connection closed"))
        self._closed.set()

    @staticmethod
    def _decode(msg: aiohttp.WSMessage) -> Message | None:
        if msg.type != aiohttp.WSMsgType.TEXT:
            return None
        try:
            data = json.loads(msg.data)
        except ValueError:
            return None
        return data if isinstance(data, dict) else None

    async def _read(self) -> None:
        assert self._ws is not None
        try:
            async for raw in self._ws:
                if raw.type in (aiohttp.WSMsgType.ERROR, aiohttp.WSMsgType.CLOSE):
                    break
                msg = self._decode(raw)
                if msg is None:
                    _LOGGER.debug("Ignoring non-JSON message from hub")
                    continue
                self._dispatch(msg)
        except (aiohttp.ClientError, OSError) as err:
            _LOGGER.debug("Hub connection lost: %s", err)
        except Exception:
            _LOGGER.exception("Unexpected Server Buddy stream error")
        finally:
            self._finish()
            # Release the hub's single client slot promptly.
            if self._ws is not None and not self._ws.closed:
                with contextlib.suppress(Exception):
                    await self._ws.close()

    def _dispatch(self, msg: Message) -> None:
        kind = msg.get("type")
        pending = self._pending
        if kind == "error" and msg.get("op") == "stream":
            if self._on_stream_error:
                self._on_stream_error(msg)
            return
        if kind == "event" and not (pending and pending.collect_events):
            if self._on_event:
                self._on_event(msg)
            return
        if kind == "error" and pending and not pending.is_terminal(msg):
            _LOGGER.debug("Ignoring stale hub error for %s", msg.get("op"))
            return
        if (
            kind == "result"
            and pending
            and msg.get("op")
            not in (
                pending.op,
                "resume" if pending.op == "subscribe" else pending.op,
            )
        ):
            _LOGGER.debug("Ignoring stale hub result for %s", msg.get("op"))
            return
        if pending is None:
            _LOGGER.debug("Unexpected hub message: %s", kind)
            return
        pending.messages.append(msg)
        if not pending.is_terminal(msg):
            return
        self._pending = None
        error = _error_for(pending, msg)
        if error is None and pending.on_complete is not None:
            try:
                # Applied in stream order, before any later event is handled.
                pending.on_complete(pending.messages)
            except ServerBuddyError as err:
                error = err
            except Exception as err:  # malformed hub data must not wedge the request
                _LOGGER.debug("Failed to apply hub response: %r", err)
                error = CannotConnect("bad hub response")
        if pending.future.done():
            return
        if error is not None:
            pending.future.set_exception(error)
        else:
            pending.future.set_result(pending.messages)

    async def request(
        self,
        op: str,
        *,
        timeout: float = TIMEOUT,
        on_complete: Callable[[list[Message]], None] | None = None,
        collect_events: bool = False,
        **fields: Any,
    ) -> list[Message]:
        """Send one request and wait for its complete response."""
        async with self._lock:
            if self._ws is None or self.closed:
                raise CannotConnect("not connected")
            future: asyncio.Future[list[Message]] = asyncio.get_running_loop().create_future()
            self._pending = _Pending(op, future, on_complete, collect_events)
            try:
                await self._ws.send_json({"op": op, **fields})
                return await asyncio.wait_for(future, timeout)
            except asyncio.CancelledError:
                await self.close()
                raise
            except (aiohttp.ClientError, OSError, ConnectionError) as err:
                await self.close()
                raise CannotConnect(str(err) or "send failed") from err
            except TimeoutError as err:
                await self.close()
                raise CannotConnect(f"{op} timed out") from err
            finally:
                if self._pending is not None and self._pending.future is future:
                    self._pending = None

    async def claim(self) -> str:
        """Claim an unclaimed hub; returns the new credential."""
        result = (await self.request("claim"))[-1]
        token = result.get("token")
        if not isinstance(token, str) or len(token) != TOKEN_LEN:
            raise CannotConnect("malformed claim response")
        return token

    async def auth(self, token: str) -> None:
        """Authenticate this session."""
        await self.request("auth", token=token)
