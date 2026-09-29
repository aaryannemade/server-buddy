"""Runtime state for one Server Buddy hub config entry."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from typing import TYPE_CHECKING, Any

from homeassistant.const import CONF_HOST, CONF_PORT, CONF_TOKEN, Platform
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryError
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.dispatcher import async_dispatcher_send

from .client import (
    API_VERSION,
    SNAPSHOT_TIMEOUT,
    AuthFailed,
    CannotConnect,
    CertificateMismatch,
    HubConnection,
    HubEntity,
    HubNode,
    Message,
    ResyncRequired,
    ServerBuddyError,
    fetch_json,
    parse_node_get,
    parse_snapshot,
)
from .const import (
    CONF_FINGERPRINT,
    CONF_HUB_ID,
    DOMAIN,
    EVENT_NODE_ERROR,
    EVENT_PAIRING,
    EVT_AVAIL,
    EVT_EVENT,
    EVT_NODE,
    EVT_NODE_ERROR,
    EVT_PAIR,
    EVT_STATE,
    HUB_MODEL,
    MANUFACTURER,
    PAIR_STATUS,
    PAIR_WINDOW_S,
    PLATFORM_BINARY_SENSOR,
    PLATFORM_EVENT,
    PLATFORM_SENSOR,
    PLATFORM_TEXT_SENSOR,
)

if TYPE_CHECKING:
    from . import ServerBuddyConfigEntry

_LOGGER = logging.getLogger(__name__)

EVENT_ID_MEMORY = 512
PENDING_EVENT_MEMORY = 64
PENDING_EVENT_MAX_AGE_S = 30.0
RECONNECT_MAX_S = 60.0
PING_INTERVAL = 30.0
REFRESH_RETRY_S = 5.0

# Schema platform -> HA entity domain.
ENTITY_DOMAINS: dict[int, Platform] = {
    PLATFORM_SENSOR: Platform.SENSOR,
    PLATFORM_TEXT_SENSOR: Platform.SENSOR,
    PLATFORM_BINARY_SENSOR: Platform.BINARY_SENSOR,
    PLATFORM_EVENT: Platform.EVENT,
}


def entity_unique_id(hub_id: str, node_id: str, entity: HubEntity) -> str:
    """Stable unique ID of a node entity.

    The wire number keeps IDs unique if two entities share an object ID; the object ID
    keeps a renumbered entity from inheriting another entity's history and statistics.
    """
    return f"{hub_id}_{node_id}_{entity.number}_{entity.object_id}"


def node_identifier(hub_id: str, node_id: str) -> str:
    """Device registry identifier of a node."""
    return f"{hub_id}_{node_id}"


def node_display_name(node: HubNode) -> str:
    """Human-readable node name before and after its schema is known."""
    return node.name or f"Server Buddy node {node.slot}"


class ServerBuddyHub:
    """Owns the hub connection, retained registry state, and HA registries."""

    def __init__(self, hass: HomeAssistant, entry: ServerBuddyConfigEntry) -> None:
        self.hass = hass
        self.entry = entry
        self.hub_id: str = entry.data[CONF_HUB_ID]
        self.host: str = entry.data[CONF_HOST]
        self.port: int = entry.data[CONF_PORT]
        self._token: str = entry.data[CONF_TOKEN]
        self._fingerprint: str = entry.data[CONF_FINGERPRINT]
        self._session = async_get_clientsession(hass)
        self.nodes: dict[str, HubNode] = {}
        self.version: Message = {}
        self.connected = False
        self.epoch: int | None = None
        self.seq: int | None = None
        self.added: set[tuple[str, str]] = set()
        self._conn: HubConnection | None = None
        self._event_ids: OrderedDict[str, None] = OrderedDict()
        self._refreshing: set[int] = set()
        self._refresh_again: set[int] = set()
        self._refresh_slots: set[int] = set()
        self._pending_events: list[tuple[float, Message]] = []
        self._event_ready: set[tuple[str, int]] = set()
        self._replaying = False
        prefix = f"{DOMAIN}_{entry.entry_id}"
        self.signal_new = f"{prefix}_new"
        self.signal_connection = f"{prefix}_connection"
        self._signal_prefix = prefix

    # ------------------------------------------------------------ signals

    def signal_node(self, node_id: str) -> str:
        """Dispatcher signal for a node's state or availability."""
        return f"{self._signal_prefix}_node_{node_id}"

    def signal_event(self, node_id: str) -> str:
        """Dispatcher signal for a node's transient events."""
        return f"{self._signal_prefix}_event_{node_id}"

    # ---------------------------------------------------------- lifecycle

    async def async_setup(self) -> None:
        """Verify the API version, connect, and load the initial snapshot."""
        self.version = await fetch_json(
            self._session, self.host, self.port, "/version", fingerprint=self._fingerprint
        )
        issue_id = f"unsupported_api_{self.hub_id}"
        if self.version.get("api") != API_VERSION:
            ir.async_create_issue(
                self.hass,
                DOMAIN,
                issue_id,
                is_fixable=False,
                severity=ir.IssueSeverity.ERROR,
                translation_key="unsupported_api",
                translation_placeholders={
                    "hub_id": self.hub_id,
                    "api": str(self.version.get("api")),
                    "supported": API_VERSION,
                },
            )
            raise ConfigEntryError(f"Unsupported hub API {self.version.get('api')}")
        ir.async_delete_issue(self.hass, DOMAIN, issue_id)
        await self._async_connect()
        self.entry.async_create_background_task(
            self.hass, self._async_supervise(), f"{DOMAIN} {self.hub_id} connection"
        )

    async def async_stop(self) -> None:
        """Close the connection on unload."""
        conn, self._conn = self._conn, None
        if conn is not None:
            await conn.close()
        self.connected = False

    async def _async_connect(self) -> None:
        conn = HubConnection(
            self._session,
            self.host,
            self.port,
            fingerprint=self._fingerprint,
            on_event=self._handle_event,
            on_stream_error=self._handle_stream_error,
        )
        hello = await conn.connect()
        self._conn = conn
        try:
            if hello.get("hub_id") != self.hub_id:
                raise CannotConnect(f"expected hub {self.hub_id}, found {hello.get('hub_id')}")
            await conn.auth(self._token)
            try:
                await self._async_sync_stream(conn, hello)
            except AuthFailed as err:
                # The credential was just accepted: a later "unauthorized" means the hub
                # dropped the session (e.g. after a send failure), so reconnect instead.
                raise CannotConnect(f"session reset by hub: {err}") from err
        except BaseException:
            self._conn = None
            await conn.close()
            raise
        self._set_connected(True)
        for slot in list(self._refresh_slots):
            self._schedule_refresh(slot)

    async def _async_sync_stream(self, conn: HubConnection, hello: Message) -> None:
        """Resume from the last applied sequence, or take a fresh snapshot."""
        epoch = int(hello.get("stream_epoch", -1))
        if epoch == self.epoch and self.seq is not None:
            try:
                await conn.request(
                    "resume",
                    stream_epoch=epoch,
                    after_seq=str(self.seq),
                    collect_events=True,
                    on_complete=self._apply_resume,
                    timeout=SNAPSHOT_TIMEOUT,
                )
                return
            except ResyncRequired:
                pass
        await self._async_subscribe(conn)

    async def _async_subscribe(self, conn: HubConnection) -> None:
        await conn.request(
            "subscribe",
            collect_events=True,
            on_complete=self._apply_snapshot,
            timeout=SNAPSHOT_TIMEOUT,
        )

    async def _async_supervise(self) -> None:
        delay = 1.0
        while True:
            conn = self._conn
            if conn is not None:
                while not conn.closed:
                    try:
                        await asyncio.wait_for(conn.wait_closed(), PING_INTERVAL)
                    except TimeoutError:
                        try:
                            await conn.request("ping")
                        except ServerBuddyError as err:
                            _LOGGER.debug("Hub %s stopped responding: %s", self.hub_id, err)
                            await conn.close()
                if self._conn is conn:
                    self._conn = None
            self._set_connected(False)
            while True:
                await asyncio.sleep(delay)
                try:
                    await self._async_connect()
                except (AuthFailed, CertificateMismatch) as err:
                    _LOGGER.warning("Hub %s rejected credentials: %s", self.hub_id, err)
                    self.entry.async_start_reauth(self.hass)
                    return
                except ServerBuddyError as err:
                    _LOGGER.debug("Reconnect to %s failed: %s", self.hub_id, err)
                    delay = min(delay * 2, RECONNECT_MAX_S)
                else:
                    _LOGGER.info("Reconnected to Server Buddy hub %s", self.hub_id)
                    delay = 1.0
                    break

    @callback
    def _set_connected(self, connected: bool) -> None:
        if self.connected != connected:
            self.connected = connected
            async_dispatcher_send(self.hass, self.signal_connection)

    @callback
    def _reconnect(self) -> None:
        conn = self._conn
        if conn is not None and not conn.closed:
            self.entry.async_create_background_task(
                self.hass, conn.close(), f"{DOMAIN} {self.hub_id} reconnect"
            )

    # ------------------------------------------------------ stream state

    @callback
    def _apply_snapshot(self, messages: list[Message]) -> None:
        snapshot = parse_snapshot(messages)
        self.nodes = snapshot.nodes
        self.epoch, self.seq = snapshot.epoch, snapshot.seq
        self._replaying = True
        try:
            for event in snapshot.events:
                self._handle_event(event)
        finally:
            self._replaying = False
        self._sync_registry()
        self._notify_all()

    @callback
    def _apply_resume(self, messages: list[Message]) -> None:
        result = messages[-1]
        self._replaying = True
        try:
            for event in messages[:-1]:
                if event.get("type") == "event":
                    self._handle_event(event)
        finally:
            self._replaying = False
        if self.seq is None or str(self.seq) != str(result.get("latest_seq")):
            self.seq = None
            raise ResyncRequired("stream gap during resume")
        self._notify_all()

    @callback
    def _notify_all(self) -> None:
        async_dispatcher_send(self.hass, self.signal_new)
        for node_id in list(self.nodes):
            async_dispatcher_send(self.hass, self.signal_node(node_id))

    @callback
    def _handle_stream_error(self, msg: Message) -> None:
        _LOGGER.info("Hub %s stream error %s; resynchronising", self.hub_id, msg.get("code"))
        self.seq = None
        self._reconnect()

    @callback
    def _handle_event(self, msg: Message) -> None:
        try:
            seq, kind = int(msg["seq"]), int(msg["kind"])
            slot = int(msg.get("slot", -1))
        except (KeyError, TypeError, ValueError):
            _LOGGER.debug("Ignoring malformed hub event")
            return
        if self.seq is not None:
            if seq <= self.seq:
                return  # already applied
            if seq != self.seq + 1:
                _LOGGER.info("Hub %s stream gap after %s; resuming", self.hub_id, self.seq)
                if self._replaying:
                    self.seq = None
                    raise ResyncRequired("stream gap during replay")
                self._reconnect()
                return
        self.seq = seq
        node_id = str(msg.get("node_id", ""))
        node = self.nodes.get(node_id)

        if kind == EVT_NODE:
            if msg.get("tombstone"):
                self._remove_node(node_id)
            else:
                self._schedule_refresh(slot)
        elif kind == EVT_STATE:
            entity = node.entities.get(int(msg.get("entity", -1))) if node else None
            if node is None or entity is None:
                self._schedule_refresh(slot)
                return
            entity.value = msg.get("value")
            async_dispatcher_send(self.hass, self.signal_node(node_id))
        elif kind == EVT_EVENT:
            self._handle_node_event(node, msg, slot)
        elif kind == EVT_AVAIL:
            if node is None:
                self._schedule_refresh(slot)
                return
            node.available = bool(msg.get("available"))
            async_dispatcher_send(self.hass, self.signal_node(node_id))
        elif kind == EVT_PAIR:
            self.hass.bus.async_fire(
                EVENT_PAIRING,
                {
                    "hub_id": self.hub_id,
                    "slot": slot if slot != 0xFF else None,
                    "status": PAIR_STATUS.get(int(msg.get("pair", -1)), "unknown"),
                },
            )
        elif kind == EVT_NODE_ERROR:
            _LOGGER.warning(
                "Node %s reported error code %s",
                node.name if node else node_id,
                msg.get("event_type"),
            )
            self.hass.bus.async_fire(
                EVENT_NODE_ERROR,
                {"hub_id": self.hub_id, "node_id": node_id, "code": msg.get("event_type")},
            )

    @callback
    def _handle_node_event(self, node: HubNode | None, msg: Message, slot: int) -> None:
        entity = node.entities.get(int(msg.get("entity", -1))) if node else None
        if node is None or entity is None:
            # Schema not known yet (e.g. first boot after pairing): hold until it is.
            self._buffer_event(msg)
            self._schedule_refresh(slot)
            return
        if (node.node_id, entity.number) not in self._event_ready:
            reg_id = er.async_get(self.hass).async_get_entity_id(
                Platform.EVENT, DOMAIN, entity_unique_id(self.hub_id, node.node_id, entity)
            )
            reg_entry = er.async_get(self.hass).async_get(reg_id) if reg_id else None
            if reg_entry is None or reg_entry.disabled_by is None:
                self._buffer_event(msg)  # entity is being added; deliver when it listens
            return  # disabled entities never receive events
        event_id = str(msg.get("event_id", ""))
        if not self.remember_event_id(event_id):
            return
        types = entity.event_types
        index = int(msg.get("event_type", 0))
        event_type = types[index] if 0 <= index < len(types) else str(index)
        attributes: dict[str, Any] = {"event_id": event_id}
        if msg.get("value") is not None:
            attributes["value"] = msg["value"]
        async_dispatcher_send(
            self.hass, self.signal_event(node.node_id), entity.number, event_type, attributes
        )

    @callback
    def remember_event_id(self, event_id: str) -> bool:
        """Record an event ID; False if it was already seen."""
        if not event_id:
            return True
        if event_id in self._event_ids:
            return False
        self._event_ids[event_id] = None
        while len(self._event_ids) > EVENT_ID_MEMORY:
            self._event_ids.popitem(last=False)
        return True

    @callback
    def mark_event_ready(self, node_id: str, number: int) -> None:
        """The HA event entity is listening; flush queued early events."""
        self._event_ready.add((node_id, number))
        self._flush_pending_events()

    @callback
    def mark_event_gone(self, node_id: str, number: int) -> None:
        """An event entity has been removed."""
        self._event_ready.discard((node_id, number))

    @callback
    def _buffer_event(self, msg: Message) -> None:
        event_id = msg.get("event_id")
        if event_id and any(old.get("event_id") == event_id for _, old in self._pending_events):
            return
        self._pending_events.append((time.monotonic(), msg))
        if len(self._pending_events) > PENDING_EVENT_MEMORY:
            self._pending_events.pop(0)
            _LOGGER.warning("Hub %s dropped a node event waiting for its entity", self.hub_id)

    @callback
    def _flush_pending_events(self) -> None:
        # Stale transient events (e.g. a button press held across a long outage) must
        # not fire automations late.
        cutoff = time.monotonic() - PENDING_EVENT_MAX_AGE_S
        pending, self._pending_events = self._pending_events, []
        for received, msg in pending:
            if received < cutoff:
                continue
            node = self.nodes.get(str(msg.get("node_id", "")))
            number = int(msg.get("entity", -1))
            if node and (node.node_id, number) in self._event_ready:
                self._handle_node_event(node, msg, node.slot)
            else:
                self._pending_events.append((received, msg))

    @callback
    def _schedule_refresh(self, slot: int) -> None:
        if slot < 0 or slot == 0xFF:
            return
        self._refresh_slots.add(slot)
        if self._conn is None or self._conn.closed:
            return
        if slot in self._refreshing:
            self._refresh_again.add(slot)
            return
        self._refreshing.add(slot)
        self.entry.async_create_background_task(
            self.hass, self._async_refresh(slot), f"{DOMAIN} {self.hub_id} refresh {slot}"
        )

    async def _async_refresh(self, slot: int) -> None:
        try:
            while True:
                self._refresh_again.discard(slot)
                conn = self._conn
                if conn is None:
                    return
                try:
                    await conn.request(
                        "node.get", slot=slot, on_complete=lambda m: self._apply_node(slot, m)
                    )
                except AuthFailed:
                    # Session dropped by the hub; the reconnect retries pending slots.
                    self._reconnect()
                    return
                except CannotConnect as err:
                    _LOGGER.debug("Refresh of slot %s interrupted: %s", slot, err)
                    return  # retried after reconnect (slot stays in _refresh_slots)
                except ServerBuddyError as err:
                    _LOGGER.debug("Refresh of slot %s failed: %s; retrying", slot, err)
                    await asyncio.sleep(REFRESH_RETRY_S)
                    continue
                self._refresh_slots.discard(slot)
                if slot not in self._refresh_again:
                    return
        finally:
            self._refreshing.discard(slot)

    @callback
    def _apply_node(self, slot: int, messages: list[Message]) -> None:
        node = parse_node_get(messages)
        for other in [n for n in self.nodes.values() if n.slot == slot]:
            if node is None or other.node_id != node.node_id:
                del self.nodes[other.node_id]
                async_dispatcher_send(self.hass, self.signal_node(other.node_id))
        if node is not None:
            self.nodes[node.node_id] = node
        self._sync_registry()
        async_dispatcher_send(self.hass, self.signal_new)
        if node is not None:
            async_dispatcher_send(self.hass, self.signal_node(node.node_id))
        self._flush_pending_events()

    @callback
    def _remove_node(self, node_id: str) -> None:
        removed = self.nodes.pop(node_id, None)
        if removed is not None:
            self._pending_events = [
                item for item in self._pending_events if str(item[1].get("node_id")) != node_id
            ]
            self._refresh_slots.discard(removed.slot)
            async_dispatcher_send(self.hass, self.signal_node(node_id))
        self._sync_registry()

    # --------------------------------------------------------- registries

    @callback
    def expected_entities(self) -> set[tuple[str, str]]:
        """(domain, unique_id) of every entity that should exist."""
        wanted = {(Platform.BINARY_SENSOR.value, f"{self.hub_id}_connection")}
        for node in self.nodes.values():
            for entity in node.entities.values():
                domain = ENTITY_DOMAINS.get(entity.platform)
                if domain is not None:
                    wanted.add(
                        (
                            domain.value,
                            entity_unique_id(self.hub_id, node.node_id, entity),
                        )
                    )
        return wanted

    @callback
    def _sync_registry(self) -> None:
        dev_reg = dr.async_get(self.hass)
        ent_reg = er.async_get(self.hass)
        entry_id = self.entry.entry_id
        hub_device = dev_reg.async_get_or_create(
            config_entry_id=entry_id,
            identifiers={(DOMAIN, self.hub_id)},
            manufacturer=MANUFACTURER,
            model=HUB_MODEL,
            name=f"Server Buddy {self.hub_id}",
            sw_version=str(self.version.get("version", "")) or None,
        )
        devices = {hub_device.id}
        for node in self.nodes.values():
            device = dev_reg.async_get_or_create(
                config_entry_id=entry_id,
                identifiers={(DOMAIN, node_identifier(self.hub_id, node.node_id))},
                via_device=(DOMAIN, self.hub_id),
                manufacturer=MANUFACTURER,
                model=node.model or None,
                sw_version=node.fw_version or None,
                name=node_display_name(node),
            )
            devices.add(device.id)

        wanted = self.expected_entities()
        # A node that exists but has no schema yet (re-pair, failed DESCRIBE) keeps its
        # entities so user names, areas and disabled flags survive the gap.
        keep_prefixes = tuple(
            f"{node_identifier(self.hub_id, node.node_id)}_"
            for node in self.nodes.values()
            if not node.has_schema
        )
        kept: set[tuple[str, str]] = set()
        for reg_entry in er.async_entries_for_config_entry(ent_reg, entry_id):
            key = (reg_entry.domain, reg_entry.unique_id)
            if key in wanted:
                continue
            if keep_prefixes and reg_entry.unique_id.startswith(keep_prefixes):
                kept.add(key)  # its live object stays; never add a second one
                continue
            ent_reg.async_remove(reg_entry.entity_id)
        self.added &= wanted | kept
        for device_entry in dr.async_entries_for_config_entry(dev_reg, entry_id):
            if device_entry.id not in devices:
                dev_reg.async_update_device(device_entry.id, remove_config_entry_id=entry_id)

    def node_for_device(self, device: dr.DeviceEntry) -> HubNode | None:
        """Return the node represented by a device registry entry."""
        for domain, identifier in device.identifiers:
            if domain != DOMAIN:
                continue
            for node in self.nodes.values():
                if identifier == node_identifier(self.hub_id, node.node_id):
                    return node
        return None

    # ------------------------------------------------------ admin requests

    def _connection(self) -> HubConnection:
        if self._conn is None or not self.connected:
            raise CannotConnect("hub not connected")
        return self._conn

    async def async_add_node(self) -> tuple[int, str]:
        """Create a key-only slot; returns (slot, one-time node key)."""
        result = (await self._connection().request("node.add"))[-1]
        node, key = result.get("node"), result.get("key")
        if not isinstance(node, dict) or not isinstance(key, str):
            raise CannotConnect("malformed node.add response")
        return int(node["slot"]), key

    async def async_remove_node(self, node: HubNode) -> None:
        """Remove a node from the hub registry."""
        await self._connection().request("node.remove", slot=node.slot)

    async def async_pair(self, node: HubNode) -> None:
        """Open a targeted pairing window for a node."""
        await self._connection().request(
            "pair.open", slot=node.slot, duration_ms=PAIR_WINDOW_S * 1000
        )

    async def async_diagnostics(self) -> Message:
        """Fetch the hub's redacted diagnostics."""
        return await fetch_json(
            self._session,
            self.host,
            self.port,
            "/diagnostics",
            fingerprint=self._fingerprint,
            token=self._token,
        )
