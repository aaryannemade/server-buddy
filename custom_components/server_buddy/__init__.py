"""The Server Buddy ESP-NOW hub integration."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady, HomeAssistantError
from homeassistant.helpers import device_registry as dr

from .client import AuthFailed, CertificateMismatch, ServerBuddyError
from .const import DOMAIN
from .hub import ServerBuddyHub

PLATFORMS = [Platform.BINARY_SENSOR, Platform.EVENT, Platform.SENSOR]

type ServerBuddyConfigEntry = ConfigEntry[ServerBuddyHub]


async def async_setup_entry(hass: HomeAssistant, entry: ServerBuddyConfigEntry) -> bool:
    """Connect to the hub and set up its entities."""
    hub = ServerBuddyHub(hass, entry)
    try:
        await hub.async_setup()
    except (AuthFailed, CertificateMismatch) as err:
        raise ConfigEntryAuthFailed(str(err)) from err
    except ServerBuddyError as err:
        # Includes client_busy while a previous session is still closing.
        raise ConfigEntryNotReady(f"Cannot connect to {hub.host}: {err}") from err
    entry.runtime_data = hub
    entry.async_on_unload(hub.async_stop)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ServerBuddyConfigEntry) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def async_remove_config_entry_device(
    hass: HomeAssistant, entry: ServerBuddyConfigEntry, device: dr.DeviceEntry
) -> bool:
    """Deleting a node device in HA removes the node from the hub."""
    hub = getattr(entry, "runtime_data", None)
    if hub is None:
        raise HomeAssistantError("Connect to the hub before removing its nodes")
    if (DOMAIN, hub.hub_id) in device.identifiers:
        return False
    node = hub.node_for_device(device)
    if node is None:
        return True
    try:
        await hub.async_remove_node(node)
    except ServerBuddyError as err:
        raise HomeAssistantError(f"Could not remove node from hub: {err}") from err
    return True
