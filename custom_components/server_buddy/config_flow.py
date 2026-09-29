"""Config and options flows for Server Buddy."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import (
    SOURCE_REAUTH,
    ConfigEntryState,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.const import CONF_HOST, CONF_PORT, CONF_TOKEN
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import TextSelector, TextSelectorConfig, TextSelectorType
from homeassistant.helpers.service_info.zeroconf import ZeroconfServiceInfo

from .client import (
    API_VERSION,
    DEFAULT_PORT,
    AlreadyClaimed,
    AuthFailed,
    CannotConnect,
    CertificateMismatch,
    HubConnection,
    Message,
    RequestError,
    ServerBuddyError,
    fetch_json,
)
from .const import CONF_FINGERPRINT, CONF_HUB_ID, DOMAIN, PAIR_WINDOW_S
from .hub import node_display_name

_LOGGER = logging.getLogger(__name__)

USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Optional(CONF_PORT, default=DEFAULT_PORT): vol.All(int, vol.Range(1, 65535)),
    }
)
TOKEN_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_TOKEN): TextSelector(
            TextSelectorConfig(type=TextSelectorType.PASSWORD, autocomplete="off")
        )
    }
)


def _format_fingerprint(fingerprint: str) -> str:
    """SHA-256 fingerprint in the usual colon-separated form."""
    return ":".join(fingerprint[i : i + 2] for i in range(0, len(fingerprint), 2)).upper()


class UnsupportedApi(ServerBuddyError):
    """The hub speaks a different API version."""


class WrongHub(ServerBuddyError):
    """A different hub answered at this address."""


class ServerBuddyConfigFlow(ConfigFlow, domain=DOMAIN):
    """Discover, claim, and authenticate a Server Buddy hub."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialise flow state."""
        self._host = ""
        self._port = DEFAULT_PORT
        self._hub_id: str | None = None
        self._fingerprint: str | None = None
        self._old_fingerprint: str | None = None
        self._old_token: str | None = None
        self._claimed = False

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: Any) -> ServerBuddyOptionsFlow:
        """Node administration flow."""
        return ServerBuddyOptionsFlow()

    async def _async_probe(self) -> Message:
        session = async_get_clientsession(self.hass)
        version = await fetch_json(session, self._host, self._port, "/version")
        if version.get("api") != API_VERSION:
            raise UnsupportedApi(str(version.get("api")))
        health = await fetch_json(session, self._host, self._port, "/health")
        hub_id = health.get("hub_id")
        if not isinstance(hub_id, str) or not hub_id:
            raise CannotConnect("health without hub_id")
        if self._hub_id is not None and hub_id != self._hub_id:
            raise WrongHub(hub_id)
        return health

    async def _async_identify(self) -> str:
        """First contact: learn the certificate the hub presents (trust on first use)."""
        conn = HubConnection(
            async_get_clientsession(self.hass), self._host, self._port, fingerprint=None
        )
        try:
            hello = await conn.connect()
            if hello.get("hub_id") != self._hub_id:
                raise WrongHub(str(hello.get("hub_id")))
            assert conn.fingerprint is not None
            return conn.fingerprint
        finally:
            await conn.close()

    async def _async_credential(self, token: str | None) -> str:
        """Claim (token None) or authenticate over a connection pinned to the flow's pin."""
        assert self._fingerprint is not None
        conn = HubConnection(
            async_get_clientsession(self.hass),
            self._host,
            self._port,
            fingerprint=self._fingerprint,
        )
        try:
            hello = await conn.connect()
            if hello.get("hub_id") != self._hub_id:
                raise WrongHub(str(hello.get("hub_id")))
            if token is None:
                return await conn.claim()
            await conn.auth(token)
            return token
        finally:
            await conn.close()

    async def _async_next(self, health: Message) -> ConfigFlowResult:
        """Pin the certificate, then claim or authenticate."""
        fingerprint = await self._async_identify()
        if self._old_fingerprint is not None and fingerprint != self._old_fingerprint:
            # Never re-pin silently: a changed certificate may be an impostor.
            self._fingerprint = fingerprint
            self._claimed = bool(health.get("claimed"))
            return await self.async_step_certificate_changed()
        self._fingerprint = fingerprint
        return await self._async_route(bool(health.get("claimed")))

    async def _async_route(self, claimed: bool) -> ConfigFlowResult:
        if not claimed:
            return await self.async_step_claim()
        if self._old_token is not None and self._fingerprint == self._old_fingerprint:
            try:
                token = await self._async_credential(self._old_token)
            except ServerBuddyError:
                pass
            else:
                return self._async_finish(token)
        return await self.async_step_token()

    async def async_step_certificate_changed(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show old and new fingerprints; continue only on explicit confirmation."""
        if user_input is not None:
            return await self._async_route(self._claimed)
        return self.async_show_form(
            step_id="certificate_changed",
            description_placeholders={
                "hub_id": str(self._hub_id),
                "old": _format_fingerprint(self._old_fingerprint or ""),
                "new": _format_fingerprint(self._fingerprint or ""),
            },
        )

    def _probe_error(self, err: ServerBuddyError) -> str:
        if isinstance(err, UnsupportedApi):
            return "unsupported_api"
        if isinstance(err, WrongHub):
            return "wrong_hub"
        if isinstance(err, CertificateMismatch):
            return "certificate_changed"
        return "cannot_connect"

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Manual setup by host."""
        errors: dict[str, str] = {}
        if user_input is not None:
            self._host = user_input[CONF_HOST].strip()
            self._port = user_input[CONF_PORT]
            self._hub_id = None
            try:
                health = await self._async_probe()
            except ServerBuddyError as err:
                errors["base"] = self._probe_error(err)
            else:
                self._hub_id = health["hub_id"]
                await self.async_set_unique_id(self._hub_id)
                self._abort_if_unique_id_configured(
                    updates={CONF_HOST: self._host, CONF_PORT: self._port}
                )
                try:
                    return await self._async_next(health)
                except ServerBuddyError as err:
                    errors["base"] = self._probe_error(err)
        return self.async_show_form(
            step_id="user",
            data_schema=self.add_suggested_values_to_schema(USER_SCHEMA, user_input),
            errors=errors,
        )

    async def async_step_zeroconf(self, discovery_info: ZeroconfServiceInfo) -> ConfigFlowResult:
        """Discovery via _server-buddy._tcp."""
        hub_id = discovery_info.properties.get("id")
        if not hub_id or discovery_info.properties.get("api") != "1":
            return self.async_abort(reason="not_supported")
        addresses = [discovery_info.ip_address, *discovery_info.ip_addresses]
        ipv4 = next((a for a in addresses if a.version == 4), None)
        if ipv4 is None:
            return self.async_abort(reason="not_supported")
        self._host = str(ipv4)
        self._port = discovery_info.port or DEFAULT_PORT
        self._hub_id = hub_id
        await self.async_set_unique_id(hub_id)
        entry = self.hass.config_entries.async_entry_for_domain_unique_id(DOMAIN, hub_id)
        if entry is not None and (entry.data[CONF_HOST], entry.data[CONF_PORT]) != (
            self._host,
            self._port,
        ):
            # Anyone can announce this hub ID: follow a move only if the new address
            # presents the certificate this entry already trusts.
            try:
                await fetch_json(
                    async_get_clientsession(self.hass),
                    self._host,
                    self._port,
                    "/version",
                    fingerprint=entry.data[CONF_FINGERPRINT],
                )
            except ServerBuddyError:
                return self.async_abort(reason="already_configured")
        self._abort_if_unique_id_configured(updates={CONF_HOST: self._host, CONF_PORT: self._port})
        self.context["title_placeholders"] = {"name": hub_id}
        return await self.async_step_discovery_confirm()

    async def async_step_discovery_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Confirm a discovered hub."""
        if user_input is not None:
            try:
                health = await self._async_probe()
                return await self._async_next(health)
            except ServerBuddyError as err:
                return self.async_abort(reason=self._probe_error(err))
        return self.async_show_form(
            step_id="discovery_confirm",
            description_placeholders={"hub_id": str(self._hub_id), "host": self._host},
        )

    async def async_step_claim(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Claim an unclaimed hub (accepted first-claim risk, docs/SECURITY.md)."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                token = await self._async_credential(None)
            except AlreadyClaimed:
                return await self.async_step_token()
            except ServerBuddyError as err:
                errors["base"] = self._probe_error(err)
            else:
                return self._async_finish(token)
        return self.async_show_form(
            step_id="claim",
            description_placeholders=self._placeholders(),
            errors=errors,
        )

    async def async_step_token(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Authenticate with an existing credential."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                token = await self._async_credential(user_input[CONF_TOKEN].strip())
            except AuthFailed:
                errors["base"] = "invalid_auth"
            except RequestError as err:
                errors["base"] = "hub_busy" if err.code == "client_busy" else "cannot_connect"
            except ServerBuddyError as err:
                errors["base"] = self._probe_error(err)
            else:
                return self._async_finish(token)
        return self.async_show_form(
            step_id="token",
            data_schema=TOKEN_SCHEMA,
            description_placeholders=self._placeholders(),
            errors=errors,
        )

    def _placeholders(self) -> dict[str, str]:
        return {
            "hub_id": str(self._hub_id),
            "host": self._host,
            "fingerprint": _format_fingerprint(self._fingerprint or ""),
        }

    def _async_finish(self, token: str) -> ConfigFlowResult:
        assert self._hub_id is not None and self._fingerprint is not None
        data = {
            CONF_HOST: self._host,
            CONF_PORT: self._port,
            CONF_HUB_ID: self._hub_id,
            CONF_TOKEN: token,
            CONF_FINGERPRINT: self._fingerprint,
        }
        if self.source == SOURCE_REAUTH:
            return self.async_update_reload_and_abort(self._get_reauth_entry(), data=data)
        return self.async_create_entry(title=f"Server Buddy {self._hub_id}", data=data)

    async def async_step_reauth(self, entry_data: dict[str, Any]) -> ConfigFlowResult:
        """Re-establish a rejected credential or changed certificate."""
        self._host = entry_data[CONF_HOST]
        self._port = entry_data[CONF_PORT]
        self._hub_id = entry_data[CONF_HUB_ID]
        self._old_fingerprint = entry_data[CONF_FINGERPRINT]
        self._old_token = entry_data[CONF_TOKEN]
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Probe the hub, then reuse, claim, or ask for a credential."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                health = await self._async_probe()
                return await self._async_next(health)
            except ServerBuddyError as err:
                errors["base"] = self._probe_error(err)
        return self.async_show_form(
            step_id="reauth_confirm",
            description_placeholders={"hub_id": str(self._hub_id)},
            errors=errors,
        )


class ServerBuddyOptionsFlow(OptionsFlow):
    """Add, pair, and remove nodes on a running hub."""

    def __init__(self) -> None:
        """Initialise."""
        self._key = ""
        self._slot = 0

    def _nodes(self) -> dict[str, str]:
        hub = self.config_entry.runtime_data
        return {
            node.node_id: f"{node_display_name(node)} (slot {node.slot})"
            for node in sorted(hub.nodes.values(), key=lambda n: n.slot)
        }

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Choose an action."""
        if self.config_entry.state is not ConfigEntryState.LOADED:
            return self.async_abort(reason="not_loaded")
        return self.async_show_menu(
            step_id="init", menu_options=["add_node", "pair_node", "remove_node"]
        )

    async def async_step_add_node(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Create a node slot and its one-time key."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                self._slot, self._key = await self.config_entry.runtime_data.async_add_node()
            except RequestError as err:
                errors["base"] = "hub_full" if err.code == "-1" else "request_failed"
            except ServerBuddyError:
                errors["base"] = "cannot_connect"
            else:
                return await self.async_step_node_key()
        return self.async_show_form(step_id="add_node", errors=errors)

    async def async_step_node_key(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show the node key once; it is not stored in Home Assistant."""
        if user_input is not None:
            self._key = ""
            return self.async_create_entry(data=dict(self.config_entry.options))
        return self.async_show_form(
            step_id="node_key",
            description_placeholders={
                "key": self._key,
                "slot": str(self._slot),
                "seconds": str(PAIR_WINDOW_S),
            },
        )

    async def _async_node_action(
        self, step_id: str, user_input: dict[str, Any] | None, done: str
    ) -> ConfigFlowResult:
        nodes = self._nodes()
        if not nodes:
            return self.async_abort(reason="no_nodes")
        errors: dict[str, str] = {}
        if user_input is not None:
            hub = self.config_entry.runtime_data
            node = hub.nodes.get(user_input["node"])
            try:
                if node is None:
                    raise CannotConnect("node vanished")
                if step_id == "pair_node":
                    await hub.async_pair(node)
                else:
                    await hub.async_remove_node(node)
            except RequestError:
                errors["base"] = "request_failed"
            except ServerBuddyError:
                errors["base"] = "cannot_connect"
            else:
                return self.async_abort(reason=done)
        return self.async_show_form(
            step_id=step_id,
            data_schema=vol.Schema({vol.Required("node"): vol.In(nodes)}),
            errors=errors,
        )

    async def async_step_pair_node(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Open a targeted pairing window (new node or re-pair)."""
        return await self._async_node_action("pair_node", user_input, "pairing_started")

    async def async_step_remove_node(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Remove a node and its key from the hub."""
        return await self._async_node_action("remove_node", user_input, "node_removed")
