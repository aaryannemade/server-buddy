"""Diagnostics redaction."""

from __future__ import annotations

import json

from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.server_buddy.diagnostics import async_get_config_entry_diagnostics
from fake_hub import FakeHub


async def test_diagnostics_redacts_secrets(
    hass: HomeAssistant, fake_hub: FakeHub, setup_integration: MockConfigEntry
) -> None:
    """Credentials and node MACs never appear in diagnostics."""
    data = await async_get_config_entry_diagnostics(hass, setup_integration)
    text = json.dumps(data)
    assert fake_hub.token not in text
    assert "02:00:00:00:00:00" not in text
    assert data["entry"]["token"] == "**REDACTED**"
    assert data["hub"]["hub"]["rx"] == 3
    assert data["connection"]["connected"] is True
    assert data["nodes"][0]["entities"][0]["object_id"] == "temperature"
