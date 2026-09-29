"""Binary sensors: node binary sensors and hub connectivity."""

from __future__ import annotations

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.const import EntityCategory, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import ServerBuddyConfigEntry
from .const import DOMAIN
from .entity import ServerBuddyNodeEntity, enum_or_none, setup_node_platform
from .hub import ServerBuddyHub

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ServerBuddyConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up binary sensors from the hub registry."""
    hub = entry.runtime_data
    connection_key = (Platform.BINARY_SENSOR.value, f"{hub.hub_id}_connection")
    if connection_key not in hub.added:
        hub.added.add(connection_key)
        async_add_entities([ServerBuddyConnectionSensor(hub)])
    entry.async_on_unload(
        setup_node_platform(
            hub, Platform.BINARY_SENSOR, ServerBuddyBinarySensor, async_add_entities
        )
    )


class ServerBuddyBinarySensor(ServerBuddyNodeEntity, BinarySensorEntity):
    """A node binary sensor."""

    @property
    def is_on(self) -> bool | None:
        """Current state; None while unknown."""
        entity = self.schema_entity
        return entity.value if entity and isinstance(entity.value, bool) else None

    @property
    def device_class(self) -> BinarySensorDeviceClass | None:
        """Device class from the schema, if HA knows it."""
        entity = self.schema_entity
        return enum_or_none(BinarySensorDeviceClass, entity.device_class) if entity else None


class ServerBuddyConnectionSensor(BinarySensorEntity):
    """Whether Home Assistant is connected to the hub."""

    _attr_should_poll = False
    _attr_has_entity_name = True
    _attr_translation_key = "connection"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, hub: ServerBuddyHub) -> None:
        self.hub = hub
        self._attr_unique_id = f"{hub.hub_id}_connection"
        self._attr_device_info = DeviceInfo(identifiers={(DOMAIN, hub.hub_id)})

    @property
    def is_on(self) -> bool:
        """True while the WebSocket session is established."""
        return self.hub.connected

    async def async_added_to_hass(self) -> None:
        """Follow connection changes."""
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass, self.hub.signal_connection, self.async_write_ha_state
            )
        )
