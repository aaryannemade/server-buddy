"""Opt-in: run the integration inside HA against a real, already claimed hub.

SB_HUB_HOST=192.168.64.156 SB_HUB_TOKEN_FILE=/tmp/sb-token \
SB_HUB_FINGERPRINT_FILE=/tmp/sb-fingerprint ha-pytest tests/ha/test_hardware.py

Creates and removes one key-only node; never prints credentials.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import pytest_socket
from homeassistant.const import CONF_HOST, CONF_PORT, CONF_TOKEN
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from pytest_homeassistant_custom_component.common import MockConfigEntry

from conftest import Waiter
from custom_components.server_buddy.const import CONF_FINGERPRINT, CONF_HUB_ID, DOMAIN

HOST = os.environ.get("SB_HUB_HOST")
pytestmark = pytest.mark.skipif(not HOST, reason="set SB_HUB_HOST to test real hardware")


async def test_real_hub(hass: HomeAssistant, socket_enabled: None, wait_for: Waiter) -> None:
    """Setup, hub device, node add/remove round trip, reconnect, unload."""
    assert HOST is not None
    pytest_socket.socket_allow_hosts([HOST, "127.0.0.1"])
    token = Path(os.environ["SB_HUB_TOKEN_FILE"]).read_text().strip()
    fingerprint = Path(os.environ["SB_HUB_FINGERPRINT_FILE"]).read_text().strip()
    hub_id = os.environ.get("SB_HUB_ID", "sb-e8f60ae41e7b")
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=hub_id,
        data={
            CONF_HOST: HOST,
            CONF_PORT: 443,
            CONF_HUB_ID: hub_id,
            CONF_TOKEN: token,
            CONF_FINGERPRINT: fingerprint,
        },
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    hub = entry.runtime_data
    assert hub.connected
    assert (
        hass.states.get(f"binary_sensor.server_buddy_{hub_id.replace('-', '_')}_connection").state
        == "on"
    )

    dev_reg = dr.async_get(hass)
    slot, key = await hub.async_add_node()
    assert len(key) == 22
    await wait_for(lambda: any(n.slot == slot for n in hub.nodes.values()))
    node = next(n for n in hub.nodes.values() if n.slot == slot)
    node_id = node.node_id
    await wait_for(
        lambda: dev_reg.async_get_device(identifiers={(DOMAIN, f"{hub_id}_{node_id}")}) is not None
    )
    await hub.async_pair(node)

    # Drop the session; the integration must resume and keep the registry.
    seq = hub.seq
    await hub._conn.close()  # type: ignore[union-attr]
    await wait_for(lambda: hub.connected and hub._conn is not None and not hub._conn.closed)
    assert hub.seq is not None and seq is not None and hub.seq >= seq
    assert any(n.node_id == node_id for n in hub.nodes.values())

    await hub.async_remove_node(node)
    await wait_for(
        lambda: dev_reg.async_get_device(identifiers={(DOMAIN, f"{hub_id}_{node_id}")}) is None
    )
    assert await hass.config_entries.async_unload(entry.entry_id)
