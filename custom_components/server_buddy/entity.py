"""Base entities for Server Buddy nodes."""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum

from homeassistant.const import EntityCategory, Platform
from homeassistant.core import callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .client import HubEntity, HubNode
from .const import DOMAIN, ENTITY_FLAG_DIAGNOSTIC
from .hub import ENTITY_DOMAINS, ServerBuddyHub, entity_unique_id, node_identifier


def enum_or_none[E: StrEnum](enum: type[E], value: str) -> E | None:
    """Map a schema string to an HA enum, ignoring unknown values."""
    try:
        return enum(value) if value else None
    except ValueError:
        return None


class ServerBuddyNodeEntity(Entity):
    """An entity described by a node's schema, identified by its object ID."""

    _attr_should_poll = False
    _attr_has_entity_name = True

    def __init__(self, hub: ServerBuddyHub, node: HubNode, entity: HubEntity) -> None:
        self.hub = hub
        self.node_id = node.node_id
        self.number = entity.number
        self._attr_unique_id = entity_unique_id(hub.hub_id, node.node_id, entity)
        self._attr_name = entity.name or entity.object_id
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, node_identifier(hub.hub_id, node.node_id))}
        )
        if entity.flags & ENTITY_FLAG_DIAGNOSTIC:
            self._attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def name(self) -> str | None:
        """Follow schema renames without a reload."""
        entity = self.schema_entity
        if entity is not None:
            self._attr_name = entity.name or entity.object_id
        return self._attr_name

    @property
    def node(self) -> HubNode | None:
        """The node, if it still exists."""
        return self.hub.nodes.get(self.node_id)

    @property
    def schema_entity(self) -> HubEntity | None:
        """The entity's current schema description."""
        node = self.node
        return node.entity(self.number) if node else None

    @property
    def available(self) -> bool:
        """Available while the hub is connected and the node is reporting."""
        node = self.node
        return (
            self.hub.connected
            and node is not None
            and node.entity(self.number) is not None
            and (node.available or node.report_interval_s == 0)
        )

    async def async_added_to_hass(self) -> None:
        """Follow node updates and hub connectivity."""
        for signal in (self.hub.signal_node(self.node_id), self.hub.signal_connection):
            self.async_on_remove(
                async_dispatcher_connect(self.hass, signal, self.async_write_ha_state)
            )


def setup_node_platform(
    hub: ServerBuddyHub,
    domain: Platform,
    factory: Callable[[ServerBuddyHub, HubNode, HubEntity], Entity | None],
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> Callable[[], None]:
    """Add entities for this domain now and whenever the registry changes."""

    @callback
    def add_new() -> None:
        new: list[Entity] = []
        for node in list(hub.nodes.values()):
            for entity in node.entities.values():
                if ENTITY_DOMAINS.get(entity.platform) != domain:
                    continue
                key = (domain.value, entity_unique_id(hub.hub_id, node.node_id, entity))
                if key in hub.added:
                    continue
                created = factory(hub, node, entity)
                if created is not None:
                    hub.added.add(key)
                    new.append(created)
        if new:
            async_add_entities(new)

    add_new()
    return async_dispatcher_connect(hub.hass, hub.signal_new, add_new)
