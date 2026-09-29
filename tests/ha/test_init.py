"""End-to-end tests against the TLS fake hub."""

from __future__ import annotations

import logging

import pytest
from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import STATE_UNAVAILABLE, STATE_UNKNOWN
from homeassistant.core import Event, HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.setup import async_setup_component
from pytest_homeassistant_custom_component.common import MockConfigEntry

from conftest import Waiter
from custom_components.server_buddy.const import DOMAIN
from fake_hub import FakeHub, FakeNode, entity

TEMP = "sensor.garage_temperature"
DOOR = "binary_sensor.garage_door"
STATUS = "sensor.garage_status"
BUTTON = "event.garage_button"
BATTERY = "sensor.garage_battery"
CONNECTION = "binary_sensor.server_buddy_sb_0123456789ab_connection"


def event_triggers(hass: HomeAssistant) -> set[str]:
    """Distinct trigger timestamps of the button event entity."""
    seen: set[str] = set()

    def listener(event: Event) -> None:
        new = event.data["new_state"]
        if (
            event.data["entity_id"] == BUTTON
            and new
            and new.state
            not in (
                STATE_UNAVAILABLE,
                STATE_UNKNOWN,
            )
        ):
            seen.add(new.state)

    hass.bus.async_listen("state_changed", listener)
    return seen


async def test_snapshot_creates_devices_and_entities(
    hass: HomeAssistant, fake_hub: FakeHub, setup_integration: MockConfigEntry
) -> None:
    """Schema entities map onto HA platforms under a node device via the hub."""
    temp = hass.states.get(TEMP)
    assert temp is not None and temp.state == "21.5"
    assert temp.attributes["unit_of_measurement"] == "°C"
    assert temp.attributes["device_class"] == "temperature"
    assert temp.attributes["state_class"] == "measurement"
    assert hass.states.get(DOOR).state == "off"
    assert hass.states.get(DOOR).attributes["device_class"] == "door"
    assert hass.states.get(STATUS).state == "ok"
    assert hass.states.get(BUTTON).state == STATE_UNKNOWN
    assert hass.states.get(BUTTON).attributes["event_types"] == ["press", "hold"]
    assert hass.states.get(CONNECTION).state == "on"

    ent_reg = er.async_get(hass)
    assert ent_reg.async_get(BATTERY).entity_category == "diagnostic"
    assert ent_reg.async_get(TEMP).unique_id == f"{fake_hub.hub_id}_42_1_temperature"

    dev_reg = dr.async_get(hass)
    hub_dev = dev_reg.async_get_device(identifiers={(DOMAIN, fake_hub.hub_id)})
    node_dev = dev_reg.async_get_device(identifiers={(DOMAIN, f"{fake_hub.hub_id}_42")})
    assert hub_dev is not None and node_dev is not None
    assert node_dev.via_device_id == hub_dev.id
    assert node_dev.name == "Garage" and node_dev.model == "esp32-c3"


async def test_state_availability_and_events(
    hass: HomeAssistant, fake_hub: FakeHub, setup_integration: MockConfigEntry, wait_for: Waiter
) -> None:
    """Stream events update state, availability, and fire event entities once."""
    await fake_hub.set_value(0, 1, 23.25)
    await wait_for(lambda: hass.states.get(TEMP).state == "23.25")
    await fake_hub.set_value(0, 2, True)
    await wait_for(lambda: hass.states.get(DOOR).state == "on")
    await fake_hub.set_value(0, 1, None)
    await wait_for(lambda: hass.states.get(TEMP).state == STATE_UNKNOWN)

    await fake_hub.emit(3, 0, 42, available=False)
    await wait_for(lambda: hass.states.get(TEMP).state == STATE_UNAVAILABLE)
    await fake_hub.emit(3, 0, 42, available=True)
    await wait_for(lambda: hass.states.get(TEMP).state != STATE_UNAVAILABLE)

    fired = event_triggers(hass)
    await fake_hub.emit(2, 0, 42, entity=4, event_type=1, event_id="sb-x-42-1-7-1")
    await wait_for(lambda: hass.states.get(BUTTON).attributes.get("event_type") == "hold")
    assert hass.states.get(BUTTON).attributes["event_id"] == "sb-x-42-1-7-1"
    # The hub never re-emits an event ID; a duplicate with a new seq is ignored.
    await fake_hub.emit(2, 0, 42, entity=4, event_type=0, event_id="sb-x-42-1-7-1")
    await fake_hub.set_value(0, 1, 1.0)
    await wait_for(lambda: hass.states.get(TEMP).state == "1.0")
    assert len(fired) == 1


async def test_reconnect_resumes_without_duplicates(
    hass: HomeAssistant, fake_hub: FakeHub, setup_integration: MockConfigEntry, wait_for: Waiter
) -> None:
    """A dropped session resumes from the last sequence; missed events replay once."""
    hub = setup_integration.runtime_data
    fired = event_triggers(hass)
    await fake_hub.emit(2, 0, 42, entity=4, event_id="sb-e1")
    await wait_for(lambda: len(fired) == 1)

    await fake_hub.drop()
    await wait_for(lambda: hass.states.get(CONNECTION).state == "off")
    assert hass.states.get(TEMP).state == STATE_UNAVAILABLE
    # Happens while HA is disconnected: must be replayed by resume.
    fake_hub.nodes[0].entities[0]["value"] = 30.0
    await fake_hub.emit(1, 0, 42, entity=1, value=30.0)
    await fake_hub.emit(2, 0, 42, entity=4, event_id="sb-e2")
    await wait_for(lambda: hass.states.get(CONNECTION).state == "on")
    await wait_for(lambda: hass.states.get(TEMP).state == "30.0")
    await wait_for(lambda: len(fired) >= 2)
    assert fake_hub.requests.count("subscribe") == 1
    assert "resume" in fake_hub.requests
    assert hub.seq == fake_hub.seq
    await hass.async_block_till_done()
    assert len(fired) == 2


async def test_hub_restart_resyncs_snapshot(
    hass: HomeAssistant, fake_hub: FakeHub, setup_integration: MockConfigEntry, wait_for: Waiter
) -> None:
    """A new stream epoch forces a coherent snapshot; values restart unknown."""
    await fake_hub.reboot()
    await wait_for(lambda: fake_hub.requests.count("subscribe") == 2)
    await wait_for(lambda: hass.states.get(CONNECTION).state == "on")
    assert hass.states.get(TEMP).state == STATE_UNAVAILABLE  # node not yet reporting
    await fake_hub.emit(3, 0, 42, available=True)
    await wait_for(lambda: hass.states.get(TEMP).state == STATE_UNKNOWN)
    await fake_hub.set_value(0, 1, 19.0)
    await wait_for(lambda: hass.states.get(TEMP).state == "19.0")
    assert (
        len(er.async_entries_for_config_entry(er.async_get(hass), setup_integration.entry_id)) == 6
    )


async def test_schema_change_and_node_lifecycle(
    hass: HomeAssistant, fake_hub: FakeHub, setup_integration: MockConfigEntry, wait_for: Waiter
) -> None:
    """New nodes appear, changed schemas drop stale entities, removal deletes the device."""
    ent_reg = er.async_get(hass)
    dev_reg = dr.async_get(hass)

    fake_hub.nodes[3] = FakeNode(
        slot=3, node_id=77, name="Attic", entities=[entity(1, "humidity", 1, 4, 55.0, unit="%")]
    )
    await fake_hub.emit(0, 3, 77)
    await wait_for(lambda: hass.states.get("sensor.attic_humidity") is not None)
    assert hass.states.get("sensor.attic_humidity").state == "55.0"

    fake_hub.nodes[0].entities = [
        e for e in fake_hub.nodes[0].entities if e["object_id"] != "status"
    ]
    await fake_hub.emit(0, 0, 42)
    await wait_for(lambda: ent_reg.async_get(STATUS) is None)
    await wait_for(lambda: hass.states.get(STATUS) is None)
    assert hass.states.get(TEMP).state == "21.5"

    del fake_hub.nodes[3]
    await fake_hub.emit(0, 3, 77, tombstone=True)
    await wait_for(
        lambda: dev_reg.async_get_device(identifiers={(DOMAIN, f"{fake_hub.hub_id}_77")}) is None
    )
    assert ent_reg.async_get("sensor.attic_humidity") is None


async def test_stale_registry_removed_at_startup(
    hass: HomeAssistant, fake_hub: FakeHub, config_entry: MockConfigEntry
) -> None:
    """Devices/entities for nodes removed while HA was down are cleaned up."""
    config_entry.add_to_hass(hass)
    dev_reg = dr.async_get(hass)
    ent_reg = er.async_get(hass)
    stale = dev_reg.async_get_or_create(
        config_entry_id=config_entry.entry_id, identifiers={(DOMAIN, f"{fake_hub.hub_id}_9")}
    )
    ent_reg.async_get_or_create(
        "sensor", DOMAIN, f"{fake_hub.hub_id}_9_gone", config_entry=config_entry, device_id=stale.id
    )
    assert await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()
    assert dev_reg.async_get(stale.id) is None
    assert ent_reg.async_get_entity_id("sensor", DOMAIN, f"{fake_hub.hub_id}_9_gone") is None
    await hass.config_entries.async_unload(config_entry.entry_id)


async def test_remove_device_removes_node(
    hass: HomeAssistant,
    hass_ws_client,
    fake_hub: FakeHub,
    setup_integration: MockConfigEntry,
    wait_for: Waiter,
) -> None:
    """Deleting the node device in HA removes the node from the hub; the hub device stays."""
    assert await async_setup_component(hass, "config", {})
    dev_reg = dr.async_get(hass)
    node_dev = dev_reg.async_get_device(identifiers={(DOMAIN, f"{fake_hub.hub_id}_42")})
    hub_dev = dev_reg.async_get_device(identifiers={(DOMAIN, fake_hub.hub_id)})
    client = await hass_ws_client(hass)

    await client.send_json_auto_id(
        {
            "type": "config/device_registry/remove_config_entry",
            "config_entry_id": setup_integration.entry_id,
            "device_id": hub_dev.id,
        }
    )
    assert not (await client.receive_json())["success"]

    await client.send_json_auto_id(
        {
            "type": "config/device_registry/remove_config_entry",
            "config_entry_id": setup_integration.entry_id,
            "device_id": node_dev.id,
        }
    )
    assert (await client.receive_json())["success"]
    assert 0 not in fake_hub.nodes
    await wait_for(lambda: dev_reg.async_get(node_dev.id) is None)


async def test_setup_retries_when_hub_offline(
    hass: HomeAssistant, fake_hub: FakeHub, config_entry: MockConfigEntry
) -> None:
    """An unreachable hub leaves the entry in setup-retry."""
    await fake_hub.stop()
    config_entry.add_to_hass(hass)
    await hass.config_entries.async_setup(config_entry.entry_id)
    assert config_entry.state is ConfigEntryState.SETUP_RETRY


async def test_bad_credential_starts_reauth(
    hass: HomeAssistant, fake_hub: FakeHub, config_entry: MockConfigEntry
) -> None:
    """A rejected token starts the reauth flow."""
    config_entry.add_to_hass(hass)
    fake_hub.token = "X" * 43
    await hass.config_entries.async_setup(config_entry.entry_id)
    assert config_entry.state is ConfigEntryState.SETUP_ERROR
    flows = hass.config_entries.flow.async_progress()
    assert any(f["context"]["source"] == "reauth" for f in flows)


async def test_certificate_change_starts_reauth(
    hass: HomeAssistant, fake_hub: FakeHub, config_entry: MockConfigEntry
) -> None:
    """A changed hub certificate is never trusted silently."""
    config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        config_entry, data={**config_entry.data, "fingerprint": "00" * 32}
    )
    await hass.config_entries.async_setup(config_entry.entry_id)
    assert config_entry.state is ConfigEntryState.SETUP_ERROR
    assert any(
        f["context"]["source"] == "reauth" for f in hass.config_entries.flow.async_progress()
    )


async def test_unsupported_api_raises_issue(
    hass: HomeAssistant, fake_hub: FakeHub, config_entry: MockConfigEntry
) -> None:
    """A different hub API version fails setup with a repair issue."""
    from homeassistant.helpers import issue_registry as ir

    fake_hub.api = "v2"
    config_entry.add_to_hass(hass)
    await hass.config_entries.async_setup(config_entry.entry_id)
    assert config_entry.state is ConfigEntryState.SETUP_ERROR
    assert ir.async_get(hass).async_get_issue(DOMAIN, f"unsupported_api_{fake_hub.hub_id}")


async def test_event_before_schema_is_delivered(
    hass: HomeAssistant, fake_hub: FakeHub, setup_integration: MockConfigEntry, wait_for: Waiter
) -> None:
    """A new node's first boot event arrives with its schema update and still fires."""
    fake_hub.nodes[5] = FakeNode(
        slot=5, node_id=55, name="Porch", entities=[entity(1, "boot", 4, 0, extra="boot")]
    )
    await fake_hub.emit(0, 5, 55)
    await fake_hub.emit(2, 5, 55, entity=1, event_type=0, event_id="sb-porch-boot-1")
    await wait_for(
        lambda: (
            (state := hass.states.get("event.porch_boot")) is not None
            and state.attributes.get("event_id") == "sb-porch-boot-1"
        )
    )


async def test_refresh_survives_disconnect(
    hass: HomeAssistant, fake_hub: FakeHub, setup_integration: MockConfigEntry, wait_for: Waiter
) -> None:
    """A schema refresh cut off by a disconnect is retried after resume."""
    fake_hub.nodes[6] = FakeNode(
        slot=6, node_id=66, name="Shed", entities=[entity(1, "lux", 1, 4, 10.0)]
    )
    fake_hub.drop_next_node_get = True
    await fake_hub.emit(0, 6, 66)
    await wait_for(lambda: hass.states.get("sensor.shed_lux") is not None)
    assert fake_hub.requests.count("subscribe") == 1  # resumed, not re-snapshotted


async def test_session_reset_reconnects_without_reauth(
    hass: HomeAssistant, fake_hub: FakeHub, setup_integration: MockConfigEntry, wait_for: Waiter
) -> None:
    """The hub dropping auth on an open socket triggers reconnect, never reauth."""
    fake_hub.revoke_session()
    fake_hub.nodes[7] = FakeNode(
        slot=7, node_id=77, name="Loft", entities=[entity(1, "temp", 1, 4, 5.0)]
    )
    await fake_hub.emit(0, 7, 77)  # not delivered: session revoked
    hub = setup_integration.runtime_data
    hub._schedule_refresh(7)  # a later refresh meets "unauthorized"
    await wait_for(lambda: hass.states.get("sensor.loft_temp") is not None)
    assert len(fake_hub.auth_tokens) == 2
    assert not hass.config_entries.flow.async_progress()


async def test_schema_less_node_keeps_customisations(
    hass: HomeAssistant,
    fake_hub: FakeHub,
    setup_integration: MockConfigEntry,
    wait_for: Waiter,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A node temporarily without schema (re-pair) keeps its registry entries."""
    caplog.set_level(logging.ERROR)
    ent_reg = er.async_get(hass)
    ent_reg.async_update_entity(TEMP, name="Workshop temperature")
    saved = fake_hub.nodes[0].entities
    fake_hub.nodes[0].entities = []
    await fake_hub.emit(0, 0, 42)
    await wait_for(lambda: hass.states.get(TEMP).state == STATE_UNAVAILABLE)
    assert ent_reg.async_get(TEMP).name == "Workshop temperature"
    fake_hub.nodes[0].entities = saved
    await fake_hub.emit(0, 0, 42)
    await wait_for(lambda: hass.states.get(TEMP).state == "21.5")
    assert hass.states.get(TEMP).name == "Workshop temperature"
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


async def test_renumbered_entity_does_not_inherit_history(
    hass: HomeAssistant, fake_hub: FakeHub, setup_integration: MockConfigEntry, wait_for: Waiter
) -> None:
    """A wire number reused for a different entity gets a new HA entity."""
    ent_reg = er.async_get(hass)
    old_uid = ent_reg.async_get(TEMP).unique_id
    fake_hub.nodes[0].entities[0] = entity(1, "humidity", 1, 4, 40.0, unit="%")
    await fake_hub.emit(0, 0, 42)
    await wait_for(lambda: hass.states.get("sensor.garage_humidity") is not None)
    assert ent_reg.async_get_entity_id("sensor", DOMAIN, old_uid) is None
    assert hass.states.get("sensor.garage_humidity").state == "40.0"


async def test_disabled_event_entity_is_ignored(
    hass: HomeAssistant, fake_hub: FakeHub, setup_integration: MockConfigEntry, wait_for: Waiter
) -> None:
    """Events for a disabled entity neither buffer nor trigger schema refreshes."""
    ent_reg = er.async_get(hass)
    ent_reg.async_update_entity(BUTTON, disabled_by=er.RegistryEntryDisabler.USER)
    await hass.config_entries.async_reload(setup_integration.entry_id)
    await hass.async_block_till_done()
    hub = setup_integration.runtime_data
    requests = len(fake_hub.requests)
    for n in range(80):
        await fake_hub.emit(2, 0, 42, entity=4, event_id=f"sb-disabled-{n}")
    await wait_for(lambda: hub.seq == fake_hub.seq)
    assert not hub._pending_events
    assert "node.get" not in fake_hub.requests[requests:]


async def test_stale_buffered_event_is_dropped(
    hass: HomeAssistant,
    fake_hub: FakeHub,
    setup_integration: MockConfigEntry,
    wait_for: Waiter,
) -> None:
    """An early event older than the buffer limit never fires late."""
    hub = setup_integration.runtime_data
    fake_hub.nodes[8] = FakeNode(
        slot=8, node_id=88, name="Gate", entities=[entity(1, "ring", 4, 0, extra="ring")]
    )
    msg = {
        "type": "event",
        "seq": "0",
        "kind": 2,
        "slot": 8,
        "entity": 1,
        "event_type": 0,
        "node_id": "88",
        "event_id": "sb-gate-old",
    }
    hub._buffer_event(msg)
    hub._pending_events[0] = (hub._pending_events[0][0] - 60, msg)
    await fake_hub.emit(0, 8, 88)
    await wait_for(lambda: hass.states.get("event.gate_ring") is not None)
    await hass.async_block_till_done()
    assert hass.states.get("event.gate_ring").state == STATE_UNKNOWN


async def test_unload_closes_socket(
    hass: HomeAssistant, fake_hub: FakeHub, setup_integration: MockConfigEntry, wait_for: Waiter
) -> None:
    """Unloading releases the hub's single client slot."""
    assert fake_hub.sockets
    await hass.config_entries.async_unload(setup_integration.entry_id)
    await wait_for(lambda: not fake_hub.sockets)
