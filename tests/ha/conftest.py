"""Fixtures for Server Buddy integration tests."""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
from collections.abc import AsyncGenerator, Awaitable, Callable
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from homeassistant.const import CONF_HOST, CONF_PORT, CONF_TOKEN
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.server_buddy.const import CONF_FINGERPRINT, CONF_HUB_ID, DOMAIN
from fake_hub import FakeHub, FakeNode, entity


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations: None) -> None:
    """Load custom_components/server_buddy."""


def _certificate(directory: Path, name: str) -> tuple[str, str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / f"{name}.crt", directory / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return str(cert_path), str(key_path), fingerprint


@pytest.fixture(scope="session")
def tls(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, str, str]:
    """Hub certificate, key, and SHA-256 fingerprint."""
    return _certificate(tmp_path_factory.mktemp("tls"), "hub")


@pytest.fixture(scope="session")
def other_tls(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, str, str]:
    """A different identity (e.g. after a hub factory reset)."""
    return _certificate(tmp_path_factory.mktemp("tls2"), "other")


@pytest.fixture
async def fake_hub(tls: tuple[str, str, str], socket_enabled: None) -> AsyncGenerator[FakeHub]:
    """A running TLS fake hub with one enrolled sensor node."""
    hub = FakeHub()
    hub.nodes[0] = FakeNode(
        slot=0,
        node_id=42,
        name="Garage",
        model="esp32-c3",
        fw_version="1.0.0",
        entities=[
            entity(
                1,
                "temperature",
                1,
                4,
                21.5,
                unit="°C",
                device_class="temperature",
                state_class=1,
                accuracy=1,
            ),
            entity(2, "door", 2, 1, False, device_class="door"),
            entity(3, "status", 3, 6, "ok"),
            entity(4, "button", 4, 5, extra="press,hold"),
            entity(5, "battery", 1, 4, 3.9, unit="V", device_class="voltage", flags=1),
        ],
    )
    await hub.start(tls[0], tls[1])
    yield hub
    await hub.stop()


@pytest.fixture
def config_entry(fake_hub: FakeHub, tls: tuple[str, str, str]) -> MockConfigEntry:
    """A config entry for the claimed fake hub."""
    fake_hub.token = "T" * 43
    return MockConfigEntry(
        domain=DOMAIN,
        unique_id=fake_hub.hub_id,
        title=f"Server Buddy {fake_hub.hub_id}",
        data={
            CONF_HOST: "127.0.0.1",
            CONF_PORT: fake_hub.port,
            CONF_HUB_ID: fake_hub.hub_id,
            CONF_TOKEN: fake_hub.token,
            CONF_FINGERPRINT: tls[2],
        },
    )


@pytest.fixture
async def setup_integration(
    hass: HomeAssistant, config_entry: MockConfigEntry
) -> AsyncGenerator[MockConfigEntry]:
    """Set up the integration and unload it after the test."""
    config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()
    yield config_entry
    if config_entry.state.recoverable:
        await hass.config_entries.async_unload(config_entry.entry_id)
    await hass.async_block_till_done()


type Waiter = Callable[[Callable[[], bool]], Awaitable[None]]


@pytest.fixture
def wait_for(hass: HomeAssistant) -> Waiter:
    """Wait for a condition driven by untracked socket tasks."""

    async def _wait(condition: Callable[[], bool]) -> None:
        for _ in range(500):
            await hass.async_block_till_done()
            if condition():
                return
            await asyncio.sleep(0.01)
        raise AssertionError("condition not reached")

    return _wait
