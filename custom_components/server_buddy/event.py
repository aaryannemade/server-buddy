"""Event entities for transient node events (buttons, boots, alarms)."""

from __future__ import annotations

from typing import Any

from homeassistant.components.event import EventDeviceClass, EventEntity
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import ServerBuddyConfigEntry
from .client import HubEntity, HubNode
from .entity import ServerBuddyNodeEntity, enum_or_none, setup_node_platform
from .hub import ServerBuddyHub

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ServerBuddyConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up event entities from the hub registry."""
    entry.async_on_unload(
        setup_node_platform(
            entry.runtime_data, Platform.EVENT, ServerBuddyEvent, async_add_entities
        )
    )


class ServerBuddyEvent(ServerBuddyNodeEntity, EventEntity):
    """Fires once per hub event ID; reconnects never replay it."""

    def __init__(self, hub: ServerBuddyHub, node: HubNode, entity: HubEntity) -> None:
        super().__init__(hub, node, entity)
        self._attr_event_types = entity.event_types or ["event"]
        self._attr_device_class = enum_or_none(EventDeviceClass, entity.device_class)

    async def async_added_to_hass(self) -> None:
        """Follow node events."""
        await super().async_added_to_hass()
        # After an HA restart, a node re-sending its last queued event must not fire twice.
        last = await self.async_get_last_state()
        if last is not None and isinstance(last.attributes.get("event_id"), str):
            self.hub.remember_event_id(last.attributes["event_id"])
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass, self.hub.signal_event(self.node_id), self._handle_event
            )
        )
        self.hub.mark_event_ready(self.node_id, self.number)
        self.async_on_remove(lambda: self.hub.mark_event_gone(self.node_id, self.number))

    @callback
    def _handle_event(
        self, entity_number: int, event_type: str, attributes: dict[str, Any]
    ) -> None:
        if entity_number != self.number:
            return
        if event_type not in self._attr_event_types:
            entity = self.schema_entity
            self._attr_event_types = (entity.event_types if entity else []) or [event_type]
            if event_type not in self._attr_event_types:
                return
        self._trigger_event(event_type, attributes)
        self.async_write_ha_state()
