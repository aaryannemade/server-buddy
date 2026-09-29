"""Diagnostics for Server Buddy (credentials and MACs redacted)."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.const import CONF_TOKEN
from homeassistant.core import HomeAssistant

from . import ServerBuddyConfigEntry
from .client import ServerBuddyError

TO_REDACT = {CONF_TOKEN, "mac", "key"}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ServerBuddyConfigEntry
) -> dict[str, Any]:
    """Return redacted hub and node diagnostics."""
    hub = getattr(entry, "runtime_data", None)
    if hub is None:
        return async_redact_data({"entry": dict(entry.data), "state": entry.state.value}, TO_REDACT)
    try:
        hub_diagnostics: dict[str, Any] = await hub.async_diagnostics()
    except ServerBuddyError as err:
        hub_diagnostics = {"error": str(err)}
    nodes = []
    for node in sorted(hub.nodes.values(), key=lambda n: n.slot):
        data = asdict(node)
        data["entities"] = [asdict(entity) for entity in node.entities.values()]
        nodes.append(data)
    return async_redact_data(
        {
            "entry": dict(entry.data),
            "connection": {"connected": hub.connected, "epoch": hub.epoch, "seq": hub.seq},
            "version": hub.version,
            "hub": hub_diagnostics,
            "nodes": nodes,
        },
        TO_REDACT,
    )
