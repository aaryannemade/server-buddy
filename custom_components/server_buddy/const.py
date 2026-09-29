"""Constants for the Server Buddy integration."""

from __future__ import annotations

from typing import Final

DOMAIN: Final = "server_buddy"

CONF_HUB_ID: Final = "hub_id"
CONF_FINGERPRINT: Final = "fingerprint"

MANUFACTURER: Final = "Server Buddy"
HUB_MODEL: Final = "ESP32-P4-WIFI6-POE-ETH"

PAIR_WINDOW_S: Final = 120

# Hub stream event kinds (sb_hub_evt_kind_t).
EVT_NODE: Final = 0
EVT_STATE: Final = 1
EVT_EVENT: Final = 2
EVT_AVAIL: Final = 3
EVT_PAIR: Final = 4
EVT_NODE_ERROR: Final = 5

PAIR_STATUS: Final = {0: "opened", 1: "responded", 2: "done", 3: "failed", 4: "closed"}

# Schema entity platforms (docs/PROTOCOL.md).
PLATFORM_SENSOR: Final = 1
PLATFORM_BINARY_SENSOR: Final = 2
PLATFORM_TEXT_SENSOR: Final = 3
PLATFORM_EVENT: Final = 4

# Value types.
VALUE_BOOL: Final = 1
VALUE_STR: Final = 6

# Registry node states.
NODE_KEY_ONLY: Final = 1
NODE_ENROLLED: Final = 2

ENTITY_FLAG_DIAGNOSTIC: Final = 0x01

EVENT_PAIRING: Final = f"{DOMAIN}_pairing"
EVENT_NODE_ERROR: Final = f"{DOMAIN}_node_error"
