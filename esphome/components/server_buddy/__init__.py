"""Server Buddy protocol v1 node transport over ESP-NOW.

Unlike ESPHome packet_transport, this component uses the P4 hub's frozen
pairing, schema, MIC, and ACK wire format. The shared C protocol codec and
crypto sources are symlinked to firmware/components/sb_protocol (one source of
truth; ESPHome copies them into its build directory).

Exported entities are ordinary ESPHome sensors, binary sensors and text
sensors listed by ID. Their HA metadata (name, unit, device class, state
class, precision, diagnostic category) is read from their validated YAML at
code-generation time, which is stable across ESPHome releases.
"""

from __future__ import annotations

import base64
import binascii
import re
import zlib
from typing import Any

import esphome.codegen as cg
import esphome.config_validation as cv
import esphome.final_validate as fv
from esphome.const import (
    CONF_ACCURACY_DECIMALS,
    CONF_DEVICE_CLASS,
    CONF_ENTITY_CATEGORY,
    CONF_ID,
    CONF_NAME,
    CONF_STATE_CLASS,
    CONF_UNIT_OF_MEASUREMENT,
)
from esphome.core import CORE, ID

from esphome.components import binary_sensor, espnow, sensor, text_sensor

CODEOWNERS = ["@aaryannemade"]
DEPENDENCIES = ["espnow"]
AUTO_LOAD = ["sensor", "binary_sensor", "text_sensor"]

CONF_ESPNOW_ID = "espnow_id"
CONF_HUB_MAC = "hub_mac"
CONF_NODE_KEY = "node_key"
CONF_REPORT_INTERVAL = "report_interval"
CONF_SENSORS = "sensors"
CONF_BINARY_SENSORS = "binary_sensors"
CONF_TEXT_SENSORS = "text_sensors"
CONF_NUMBER = "number"
CONF_BOOT_EVENT_NUMBER = "boot_event_number"

# Protocol v1 limits (docs/PROTOCOL.md).
MAX_STR = 64
MAX_OBJECT_ID = 32
MAX_ENTITIES = 32
MAX_SCHEMA = 2048
DEFAULT_BOOT_EVENT_NUMBER = 255  # wire number of the built-in boot event

PLATFORM_SENSOR = 1
PLATFORM_BINARY_SENSOR = 2
PLATFORM_TEXT_SENSOR = 3
# ESPHome StateClass -> protocol state_class (0 none, 1 measurement, 2 total,
# 3 total_increasing). ESPHome has no angle class in the protocol: map to
# measurement.
STATE_CLASSES = {
    "measurement": 1,
    "measurement_angle": 1,
    "total": 2,
    "total_increasing": 3,
}


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


def _entity_list(id_type: Any) -> Any:
    """Accept `- my_id` or `- {id: my_id, number: 7}`."""
    item = cv.Schema(
        {
            cv.Required(CONF_ID): cv.use_id(id_type),
            cv.Optional(CONF_NUMBER): cv.int_range(min=1, max=254),
        }
    )

    def validate(value: Any) -> Any:
        if not isinstance(value, dict):
            value = {CONF_ID: value}
        return item(value)

    return cv.ensure_list(validate)


server_buddy_ns = cg.esphome_ns.namespace("server_buddy")
ServerBuddyNode = server_buddy_ns.class_("ServerBuddyNode", cg.Component)

CONFIG_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(ServerBuddyNode),
            cv.Required(CONF_ESPNOW_ID): cv.use_id(espnow.ESPNowComponent),
            cv.Required(CONF_HUB_MAC): cv.mac_address,
            cv.Required(CONF_NODE_KEY): validate_node_key,
            cv.Optional(CONF_REPORT_INTERVAL, default="60s"): cv.All(
                cv.positive_time_period_seconds,
                cv.Range(min=cv.TimePeriod(seconds=5), max=cv.TimePeriod(seconds=65535)),
            ),
            cv.Optional(CONF_SENSORS, default=[]): _entity_list(sensor.Sensor),
            cv.Optional(CONF_BINARY_SENSORS, default=[]): _entity_list(binary_sensor.BinarySensor),
            cv.Optional(CONF_TEXT_SENSORS, default=[]): _entity_list(text_sensor.TextSensor),
            # Keep a node's boot event on the number it was first paired with.
            cv.Optional(CONF_BOOT_EVENT_NUMBER, default=DEFAULT_BOOT_EVENT_NUMBER): cv.int_range(
                min=1, max=255
            ),
        }
    ).extend(cv.COMPONENT_SCHEMA),
    cv.only_on_esp32,
)


# ------------------------------------------------------------ metadata


def _find_entity_config(node: Any, target: ID) -> dict | None:
    """Locate an entity's validated config (possibly nested, e.g. sht4x temperature)."""
    if isinstance(node, dict):
        found = node.get(CONF_ID)
        # Match the declaration, not references such as our own `sensors:` list.
        if isinstance(found, ID) and found.id == target.id and found.is_declaration:
            return node
        for value in node.values():
            if (result := _find_entity_config(value, target)) is not None:
                return result
    elif isinstance(node, list):
        for value in node:
            if (result := _find_entity_config(value, target)) is not None:
                return result
    return None


def _utf8_prefix(text: str, limit: int = MAX_STR) -> str:
    data = text.encode()[:limit]
    return data.decode("utf-8", errors="ignore")


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")[:MAX_OBJECT_ID].rstrip("_")


def _object_id(name: str, fallback: str) -> str:
    """Stable [a-z0-9_]{1,32} identifier derived from the entity name."""
    return _slug(name) or _slug(fallback) or "entity"


def _str_len(text: str) -> int:
    return 1 + len(text.encode())


def _describe(full_config: Any, platform: int, conf: dict, device_name: str) -> dict[str, Any]:
    entity_id: ID = conf[CONF_ID]
    full = _find_entity_config(full_config, entity_id)
    if full is None:
        raise cv.Invalid(f"could not find the configuration of '{entity_id.id}'")
    # ESPHome shows unnamed entities under the device's friendly name.
    name = full.get(CONF_NAME) or device_name
    accuracy = full.get(CONF_ACCURACY_DECIMALS)
    if platform == PLATFORM_SENSOR and accuracy is not None and not -128 <= int(accuracy) <= 127:
        raise cv.Invalid(f"accuracy_decimals for '{entity_id.id}' must fit in an int8")
    return {
        "platform": platform,
        "number": conf.get(CONF_NUMBER),
        "object_id": _object_id(name, entity_id.id),
        "name": _utf8_prefix(name),
        "unit": _utf8_prefix(full.get(CONF_UNIT_OF_MEASUREMENT) or ""),
        "device_class": _utf8_prefix(full.get(CONF_DEVICE_CLASS) or ""),
        "state_class": (
            STATE_CLASSES.get(str(full.get(CONF_STATE_CLASS) or ""), 0)
            if platform == PLATFORM_SENSOR
            else 0
        ),
        "accuracy": int(accuracy) if platform == PLATFORM_SENSOR and accuracy is not None else -1,
        "flags": 1 if str(full.get(CONF_ENTITY_CATEGORY) or "") == "diagnostic" else 0,
    }


def _assign_numbers(entities: list[dict[str, Any]], boot_number: int) -> None:
    """Explicit numbers win; others hash their object_id so reordering is harmless."""
    used: dict[int, str] = {boot_number: "the boot event"}
    for entity in entities:
        if (number := entity["number"]) is not None:
            if number in used:
                raise cv.Invalid(
                    f"number {number} is used by both {used[number]} and '{entity['object_id']}'"
                )
            used[number] = f"'{entity['object_id']}'"
    for entity in entities:
        if entity["number"] is not None:
            continue
        number = zlib.crc32(entity["object_id"].encode()) % 254 + 1
        if number in used:
            raise cv.Invalid(
                f"'{entity['object_id']}' hashes to number {number}, already used by "
                f"{used[number]}; give one of them an explicit `number:`"
            )
        used[number] = f"'{entity['object_id']}'"
        entity["number"] = number


def _schema_size(node: tuple[str, str, str], entities: list[dict[str, Any]]) -> int:
    """Exact encoded size (sb_encode_schema), including the boot event."""
    size = sum(_str_len(s) for s in node) + 1
    for entity in entities:
        size += 6 + sum(
            _str_len(entity[key]) for key in ("object_id", "name", "unit", "device_class")
        )
        size += _str_len("")  # extra
    boot = ("boot", "Boot", "", "", "boot")  # object_id, name, unit, device_class, extra
    return size + 6 + sum(_str_len(s) for s in boot)


def _plan(config: dict, full_config: Any) -> dict[str, Any]:
    core = full_config.get("esphome", {})
    friendly = core.get("friendly_name") or core.get("name") or "ESPHome node"
    board = (full_config.get("esp32") or {}).get("board") or "ESPHome node"
    from esphome.const import __version__ as esphome_version

    node = (_utf8_prefix(friendly), _utf8_prefix(board), _utf8_prefix(f"ESPHome {esphome_version}"))
    entities = []
    for platform, key in (
        (PLATFORM_SENSOR, CONF_SENSORS),
        (PLATFORM_BINARY_SENSOR, CONF_BINARY_SENSORS),
        (PLATFORM_TEXT_SENSOR, CONF_TEXT_SENSORS),
    ):
        for index, item in enumerate(config[key]):
            with cv.prepend_path([key, index]):
                entities.append((_describe(full_config, platform, item, friendly), item[CONF_ID]))
    descriptions = [d for d, _ in entities]
    if not descriptions:
        raise cv.Invalid("export at least one sensor, binary sensor or text sensor")
    if len(descriptions) > MAX_ENTITIES - 1:
        raise cv.Invalid(f"at most {MAX_ENTITIES - 1} entities can be exported")
    object_ids = [d["object_id"] for d in descriptions]
    if len(set(object_ids)) != len(object_ids):
        raise cv.Invalid(f"exported entity names must be unique: {object_ids}")
    _assign_numbers(descriptions, config[CONF_BOOT_EVENT_NUMBER])
    if (size := _schema_size(node, descriptions)) > MAX_SCHEMA:
        raise cv.Invalid(f"schema is {size} bytes; the protocol limit is {MAX_SCHEMA}")
    return {"node": node, "entities": entities}


def _final_validate(config: dict) -> dict:
    # Runs at `esphome config` time, so problems show as normal config errors.
    CORE.data.setdefault("server_buddy", {})[config[CONF_ID].id] = _plan(
        config, fv.full_config.get()
    )
    return config


FINAL_VALIDATE_SCHEMA = _final_validate


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    radio = await cg.get_variable(config[CONF_ESPNOW_ID])
    cg.add(var.set_espnow(radio))
    cg.add(var.set_hub_mac(config[CONF_HUB_MAC].parts))
    key = base64.urlsafe_b64decode(config[CONF_NODE_KEY] + "==")
    cg.add(var.set_node_key(list(key)))
    cg.add(var.set_report_interval(config[CONF_REPORT_INTERVAL].total_seconds))
    cg.add(var.set_boot_event_number(config[CONF_BOOT_EVENT_NUMBER]))

    plan = CORE.data["server_buddy"][config[CONF_ID].id]
    cg.add(var.set_node_info(*plan["node"]))
    for description, entity_id in plan["entities"]:
        entity = await cg.get_variable(entity_id)
        setter = {
            PLATFORM_SENSOR: "add_sensor",
            PLATFORM_BINARY_SENSOR: "add_binary_sensor",
            PLATFORM_TEXT_SENSOR: "add_text_sensor",
        }[description["platform"]]
        cg.add(
            getattr(var, setter)(
                entity,
                description["number"],
                description["object_id"],
                description["name"],
                description["unit"],
                description["device_class"],
                description["state_class"],
                description["accuracy"],
                description["flags"],
            )
        )
