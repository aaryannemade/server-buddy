"""Offline stand-in for the hassfest/HACS checks this integration relies on."""

from __future__ import annotations

import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPONENT = ROOT / "custom_components" / "server_buddy"


def test_manifest_and_hacs_metadata() -> None:
    """Required custom-integration fields are present and consistent."""
    manifest = json.loads((COMPONENT / "manifest.json").read_text())
    assert manifest["domain"] == "server_buddy"
    assert manifest["config_flow"] is True
    assert manifest["iot_class"] == "local_push"
    assert manifest["integration_type"] == "hub"
    assert manifest["requirements"] == []
    assert manifest["zeroconf"] == ["_server-buddy._tcp.local."]
    assert all(part.isdigit() for part in manifest["version"].split("."))
    hacs = json.loads((ROOT / "hacs.json").read_text())
    assert hacs["name"] == manifest["name"]


def _step_ids(tree: ast.AST) -> set[str]:
    steps = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name.startswith("async_step_"):
            steps.add(node.name.removeprefix("async_step_"))
    return steps


def test_every_flow_step_and_error_is_translated() -> None:
    """Every form, menu option, error, and abort reason has English text."""
    strings = json.loads((COMPONENT / "translations" / "en.json").read_text())
    source = (COMPONENT / "config_flow.py").read_text()
    tree = ast.parse(source)
    shown = {
        kw.value.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        for kw in node.keywords
        if kw.arg == "step_id" and isinstance(kw.value, ast.Constant)
    }
    config_steps = set(strings["config"]["step"])
    option_steps = set(strings["options"]["step"])
    assert shown <= config_steps | option_steps
    assert set(strings["options"]["step"]["init"]["menu_options"]) <= _step_ids(tree)

    literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    for section in ("config", "options"):
        for key in ("error", "abort"):
            for code in strings[section][key]:
                assert code in literals or code in {"already_configured", "reauth_successful"}
    for code in (
        "cannot_connect",
        "invalid_auth",
        "hub_busy",
        "unsupported_api",
        "wrong_hub",
        "not_supported",
        "pairing_started",
        "node_removed",
        "no_nodes",
        "not_loaded",
        "hub_full",
        "request_failed",
    ):
        assert any(
            code in strings[section][key]
            for section in ("config", "options")
            for key in ("error", "abort")
        ), code
