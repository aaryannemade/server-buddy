"""Server Buddy protocol v1 node transport over ESP-NOW.

Unlike ESPHome packet_transport, this component uses the P4 hub's frozen
pairing, schema, MIC, and ACK wire format. The shared C protocol codec and
crypto sources are symlinked to firmware/components/sb_protocol (one source of
truth; ESPHome copies them into its build directory).
"""

from __future__ import annotations

import base64
import binascii

import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.const import CONF_ID

from esphome.components import espnow, sensor

CODEOWNERS = ["@aaryannemade"]
DEPENDENCIES = ["espnow", "sensor"]

CONF_ESPNOW_ID = "espnow_id"
CONF_HUB_MAC = "hub_mac"
CONF_NODE_KEY = "node_key"
CONF_TEMPERATURE_ID = "temperature_id"
CONF_HUMIDITY_ID = "humidity_id"
CONF_ILLUMINANCE_ID = "illuminance_id"


def validate_node_key(value: str) -> str:
    """Decode HA's one-time 22-char base64url node key (16 bytes)."""
    value = cv.string_strict(value)
    if len(value) != 22:
        raise cv.Invalid("node_key must be the 22-character key shown by Server Buddy in HA")
    try:
        key = base64.b64decode(value + "==", altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as err:
        raise cv.Invalid("node_key is not valid base64url") from err
    if len(key) != 16 or base64.urlsafe_b64encode(key).decode().rstrip("=") != value:
        raise cv.Invalid("node_key must decode to exactly 16 bytes")
    return value


server_buddy_ns = cg.esphome_ns.namespace("server_buddy")
ServerBuddyNode = server_buddy_ns.class_("ServerBuddyNode", cg.Component)

CONFIG_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(ServerBuddyNode),
            cv.Required(CONF_ESPNOW_ID): cv.use_id(espnow.ESPNowComponent),
            cv.Required(CONF_HUB_MAC): cv.mac_address,
            cv.Required(CONF_NODE_KEY): validate_node_key,
            cv.Required(CONF_TEMPERATURE_ID): cv.use_id(sensor.Sensor),
            cv.Required(CONF_HUMIDITY_ID): cv.use_id(sensor.Sensor),
            cv.Required(CONF_ILLUMINANCE_ID): cv.use_id(sensor.Sensor),
        }
    ).extend(cv.COMPONENT_SCHEMA),
    cv.only_on_esp32,
)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    radio = await cg.get_variable(config[CONF_ESPNOW_ID])
    cg.add(var.set_espnow(radio))
    cg.add(var.set_hub_mac(config[CONF_HUB_MAC].parts))
    key = base64.urlsafe_b64decode(config[CONF_NODE_KEY] + "==")
    cg.add(var.set_node_key(list(key)))
    for key, setter in (
        (CONF_TEMPERATURE_ID, "set_temperature_sensor"),
        (CONF_HUMIDITY_ID, "set_humidity_sensor"),
        (CONF_ILLUMINANCE_ID, "set_illuminance_sensor"),
    ):
        cg.add(getattr(var, setter)(await cg.get_variable(config[key])))
