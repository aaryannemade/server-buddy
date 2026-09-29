"""Config, reauth, and options flow tests."""

from __future__ import annotations

from ipaddress import ip_address

from homeassistant.config_entries import SOURCE_USER, SOURCE_ZEROCONF
from homeassistant.const import CONF_HOST, CONF_PORT, CONF_TOKEN
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.service_info.zeroconf import ZeroconfServiceInfo
from pytest_homeassistant_custom_component.common import MockConfigEntry

from conftest import Waiter
from custom_components.server_buddy.const import CONF_FINGERPRINT, CONF_HUB_ID, DOMAIN
from fake_hub import FakeHub


def zeroconf_info(hub: FakeHub, api: str = "1") -> ZeroconfServiceInfo:
    return ZeroconfServiceInfo(
        ip_address=ip_address("127.0.0.1"),
        ip_addresses=[ip_address("127.0.0.1")],
        port=hub.port,
        hostname=f"{hub.hub_id}.local.",
        type="_server-buddy._tcp.local.",
        name="Server Buddy._server-buddy._tcp.local.",
        properties={"id": hub.hub_id, "model": "esp32-p4-wifi6-poe-eth", "api": api},
    )


async def test_user_flow_claims_and_pins(
    hass: HomeAssistant, fake_hub: FakeHub, tls: tuple[str, str, str]
) -> None:
    """Manual setup claims an unclaimed hub and pins its certificate."""
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    assert result["type"] is FlowResultType.FORM and result["step_id"] == "user"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOST: "127.0.0.1", CONF_PORT: fake_hub.port}
    )
    assert result["type"] is FlowResultType.FORM and result["step_id"] == "claim"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["result"].unique_id == fake_hub.hub_id
    assert result["data"] == {
        CONF_HOST: "127.0.0.1",
        CONF_PORT: fake_hub.port,
        CONF_HUB_ID: fake_hub.hub_id,
        CONF_TOKEN: fake_hub.token,
        CONF_FINGERPRINT: tls[2],
    }
    await hass.async_block_till_done()
    assert result["result"].state.value == "loaded"
    await hass.config_entries.async_unload(result["result"].entry_id)


async def test_user_flow_errors(hass: HomeAssistant, fake_hub: FakeHub) -> None:
    """Unreachable hosts and unsupported APIs are reported on the form."""
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    port = fake_hub.port
    fake_hub.api = "v2"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOST: "127.0.0.1", CONF_PORT: port}
    )
    assert result["errors"] == {"base": "unsupported_api"}
    await fake_hub.stop()
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOST: "127.0.0.1", CONF_PORT: port}
    )
    assert result["errors"] == {"base": "cannot_connect"}


async def test_claimed_hub_requires_token(hass: HomeAssistant, fake_hub: FakeHub) -> None:
    """An already claimed hub asks for its credential."""
    fake_hub.token = "S" * 43
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOST: "127.0.0.1", CONF_PORT: fake_hub.port}
    )
    assert result["step_id"] == "token"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_TOKEN: "W" * 43}
    )
    assert result["errors"] == {"base": "invalid_auth"}
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_TOKEN: "S" * 43}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done()
    await hass.config_entries.async_unload(result["result"].entry_id)


async def test_zeroconf_discovery(hass: HomeAssistant, fake_hub: FakeHub) -> None:
    """Discovery confirms, then claims."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_ZEROCONF}, data=zeroconf_info(fake_hub)
    )
    assert result["step_id"] == "discovery_confirm"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["step_id"] == "claim"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done()
    await hass.config_entries.async_unload(result["result"].entry_id)


async def test_zeroconf_rejects_other_api(hass: HomeAssistant, fake_hub: FakeHub) -> None:
    """Unsupported API versions are not offered."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_ZEROCONF}, data=zeroconf_info(fake_hub, api="2")
    )
    assert result["type"] is FlowResultType.ABORT and result["reason"] == "not_supported"


async def test_zeroconf_ignores_impostor_address(hass: HomeAssistant, fake_hub: FakeHub) -> None:
    """An announcement whose certificate does not match the pin never moves the entry."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=fake_hub.hub_id,
        data={
            CONF_HOST: "10.0.0.9",
            CONF_PORT: 443,
            CONF_HUB_ID: fake_hub.hub_id,
            CONF_TOKEN: "T" * 43,
            CONF_FINGERPRINT: "00" * 32,
        },
    )
    entry.add_to_hass(hass)
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_ZEROCONF}, data=zeroconf_info(fake_hub)
    )
    assert result["type"] is FlowResultType.ABORT and result["reason"] == "already_configured"
    assert entry.data[CONF_HOST] == "10.0.0.9"


async def test_zeroconf_updates_moved_hub(
    hass: HomeAssistant, fake_hub: FakeHub, tls: tuple[str, str, str]
) -> None:
    """A configured hub that changed address is updated, not duplicated."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=fake_hub.hub_id,
        data={
            CONF_HOST: "10.0.0.9",
            CONF_PORT: 443,
            CONF_HUB_ID: fake_hub.hub_id,
            CONF_TOKEN: "T" * 43,
            CONF_FINGERPRINT: tls[2],
        },
    )
    entry.add_to_hass(hass)
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_ZEROCONF}, data=zeroconf_info(fake_hub)
    )
    assert result["type"] is FlowResultType.ABORT and result["reason"] == "already_configured"
    assert entry.data[CONF_HOST] == "127.0.0.1" and entry.data[CONF_PORT] == fake_hub.port


async def test_reauth_reclaims_reset_hub(
    hass: HomeAssistant,
    fake_hub: FakeHub,
    config_entry: MockConfigEntry,
    tls: tuple[str, str, str],
) -> None:
    """After the hub's API storage is erased, reauth requires confirming the new certificate."""
    config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        config_entry, data={**config_entry.data, CONF_FINGERPRINT: "11" * 32}
    )
    old_token = config_entry.data[CONF_TOKEN]
    fake_hub.token = None
    result = await config_entry.start_reauth_flow(hass)
    assert result["step_id"] == "reauth_confirm"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["step_id"] == "certificate_changed"
    assert result["description_placeholders"]["new"].replace(":", "").lower() == tls[2]
    assert fake_hub.auth_tokens == []  # nothing sent before the user confirmed
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["step_id"] == "claim"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] is FlowResultType.ABORT and result["reason"] == "reauth_successful"
    assert config_entry.data[CONF_TOKEN] == fake_hub.token != old_token
    assert config_entry.data[CONF_FINGERPRINT] == tls[2]
    await hass.async_block_till_done()
    await hass.config_entries.async_unload(config_entry.entry_id)


async def test_reauth_certificate_change_never_sends_stored_token(
    hass: HomeAssistant, fake_hub: FakeHub, config_entry: MockConfigEntry
) -> None:
    """A changed certificate on a claimed hub leads to the token form, not the old token."""
    config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        config_entry, data={**config_entry.data, CONF_FINGERPRINT: "22" * 32}
    )
    result = await config_entry.start_reauth_flow(hass)
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["step_id"] == "certificate_changed"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["step_id"] == "token"
    assert fake_hub.auth_tokens == []


async def test_reauth_same_certificate_reuses_valid_token(
    hass: HomeAssistant, fake_hub: FakeHub, config_entry: MockConfigEntry
) -> None:
    """Transient auth trouble with an unchanged pin recovers without user input."""
    config_entry.add_to_hass(hass)
    result = await config_entry.start_reauth_flow(hass)
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] is FlowResultType.ABORT and result["reason"] == "reauth_successful"
    await hass.async_block_till_done()
    await hass.config_entries.async_unload(config_entry.entry_id)


async def test_reauth_rotated_token_keeps_pin(
    hass: HomeAssistant, fake_hub: FakeHub, config_entry: MockConfigEntry, tls: tuple[str, str, str]
) -> None:
    """A rejected token with the same certificate asks for a new token and keeps the pin."""
    config_entry.add_to_hass(hass)
    fake_hub.token = "R" * 43
    result = await config_entry.start_reauth_flow(hass)
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["step_id"] == "token"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_TOKEN: "R" * 43}
    )
    assert result["reason"] == "reauth_successful"
    assert config_entry.data[CONF_FINGERPRINT] == tls[2]
    await hass.async_block_till_done()
    await hass.config_entries.async_unload(config_entry.entry_id)


async def test_options_add_pair_remove(
    hass: HomeAssistant, fake_hub: FakeHub, setup_integration: MockConfigEntry, wait_for: Waiter
) -> None:
    """Node administration from the options flow."""
    entry = setup_integration
    result = await hass.config_entries.options.async_init(entry.entry_id)
    assert result["type"] is FlowResultType.MENU
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"next_step_id": "add_node"}
    )
    result = await hass.config_entries.options.async_configure(result["flow_id"], {})
    assert result["step_id"] == "node_key"
    assert result["description_placeholders"]["key"] == "A" * 22
    result = await hass.config_entries.options.async_configure(result["flow_id"], {})
    assert result["type"] is FlowResultType.CREATE_ENTRY

    dev_reg = dr.async_get(hass)
    new_id = f"{fake_hub.hub_id}_{fake_hub.next_node_id}"
    await wait_for(lambda: dev_reg.async_get_device(identifiers={(DOMAIN, new_id)}) is not None)
    assert dev_reg.async_get_device(identifiers={(DOMAIN, new_id)}).name == "Server Buddy node 1"

    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"next_step_id": "pair_node"}
    )
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"node": str(fake_hub.next_node_id)}
    )
    assert result["type"] is FlowResultType.ABORT and result["reason"] == "pairing_started"
    assert "pair.open" in fake_hub.requests

    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"next_step_id": "remove_node"}
    )
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"node": str(fake_hub.next_node_id)}
    )
    assert result["type"] is FlowResultType.ABORT and result["reason"] == "node_removed"
    await wait_for(lambda: dev_reg.async_get_device(identifiers={(DOMAIN, new_id)}) is None)
