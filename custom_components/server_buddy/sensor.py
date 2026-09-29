"""Sensor and text-sensor entities for Server Buddy nodes."""

from __future__ import annotations

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorStateClass
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import ServerBuddyConfigEntry
from .client import HubEntity, HubNode
from .const import PLATFORM_SENSOR, VALUE_BOOL, VALUE_STR
from .entity import ServerBuddyNodeEntity, enum_or_none, setup_node_platform
from .hub import ServerBuddyHub

PARALLEL_UPDATES = 0

NON_NUMERIC_CLASSES = {
    SensorDeviceClass.DATE,
    SensorDeviceClass.ENUM,
    SensorDeviceClass.TIMESTAMP,
}

STATE_CLASSES = {
    1: SensorStateClass.MEASUREMENT,
    2: SensorStateClass.TOTAL,
    3: SensorStateClass.TOTAL_INCREASING,
}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ServerBuddyConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up sensors from the hub registry."""
    entry.async_on_unload(
        setup_node_platform(
            entry.runtime_data, Platform.SENSOR, ServerBuddySensor, async_add_entities
        )
    )


class ServerBuddySensor(ServerBuddyNodeEntity, SensorEntity):
    """A numeric sensor (platform 1) or text sensor (platform 3)."""

    def __init__(self, hub: ServerBuddyHub, node: HubNode, entity: HubEntity) -> None:
        super().__init__(hub, node, entity)
        if entity.platform == PLATFORM_SENSOR and entity.accuracy >= 0:
            self._attr_suggested_display_precision = entity.accuracy

    def _numeric(self) -> HubEntity | None:
        entity = self.schema_entity
        if entity is None or entity.platform != PLATFORM_SENSOR:
            return None
        if entity.value_type in (VALUE_BOOL, VALUE_STR):
            return None
        return entity

    @property
    def native_value(self) -> str | int | float | None:
        """Current value; None while unknown."""
        entity = self.schema_entity
        if entity is None or entity.value is None:
            return None
        value = entity.value
        if self._numeric() is None:
            return str(value)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        number: int | float = value
        return number

    @property
    def native_unit_of_measurement(self) -> str | None:
        """Unit from the schema (numeric sensors only)."""
        entity = self._numeric()
        return entity.unit or None if entity else None

    @property
    def device_class(self) -> SensorDeviceClass | None:
        """Device class from the schema, if HA knows it."""
        entity = self._numeric()
        device_class = enum_or_none(SensorDeviceClass, entity.device_class) if entity else None
        # These classes need datetime values or declared options; nodes send plain numbers.
        return None if device_class in NON_NUMERIC_CLASSES else device_class

    @property
    def state_class(self) -> SensorStateClass | None:
        """State class from the schema."""
        entity = self._numeric()
        return STATE_CLASSES.get(entity.state_class) if entity else None
