#!/usr/bin/env python3
"""HTTPS/WebSocket/mDNS-independent on-device API smoke test.

Usage: ha-python scripts/hw-api-smoke.py HOST --token-file /tmp/sb-token \
       --fingerprint-file /tmp/sb-fingerprint [--claim] [--eviction]

The token and pinned fingerprint stay outside the repository. Claiming is
explicit; never print the token or a newly generated node key.
"""

import argparse
import asyncio
import hashlib
import json
import os
import socket
import ssl
from pathlib import Path

import aiohttp


def pinned_certificate(host: str, path: Path) -> None:
    context = ssl._create_unverified_context()
    with socket.create_connection((host, 443), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            digest = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
    if path.exists():
        if path.read_text().strip() != digest:
            raise RuntimeError("hub certificate fingerprint changed")
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as output:
            output.write(digest + "\n")
    print("TLS certificate fingerprint matches pin")


async def receive(ws):
    message = await ws.receive(timeout=15)
    if message.type != aiohttp.WSMsgType.TEXT:
        raise RuntimeError(f"unexpected WebSocket frame: {message.type}")
    return json.loads(message.data)


async def request(ws, **fields):
    await ws.send_json(fields)
    for _ in range(70):
        message = await receive(ws)
        if fields["op"] == "subscribe" and message.get("type") == "snapshot.begin":
            return message
        if message.get("op") == fields["op"] and message.get("type") in ("result", "error"):
            return message
    raise RuntimeError(f"no response to {fields['op']}")


async def exercise(args):
    pinned_certificate(args.host, args.fingerprint_file)
    endpoint = f"https://{args.host}/api/v1"
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as client:
        async with client.get(endpoint + "/health", ssl=False) as response:
            health = await response.json()
            assert response.status == 200 and health["status"] == "ok", health
        async with client.get(endpoint + "/version", ssl=False) as response:
            version = await response.json()
            assert response.status == 200 and version["api"] == "v1", version
        async with client.get(endpoint + "/diagnostics", ssl=False) as response:
            assert response.status == 401, response.status

        async with client.ws_connect(endpoint.replace("https:", "wss:") + "/ws", ssl=False) as ws:
            hello = await receive(ws)
            assert hello["type"] == "hello" and hello["hub_id"] == health["hub_id"]
            if args.expect_epoch_change is not None:
                assert hello["stream_epoch"] != args.expect_epoch_change
            if not health["claimed"]:
                if not args.claim or args.token_file.exists():
                    raise RuntimeError("unclaimed hub: pass --claim and a new token-file")
                claimed = await request(ws, op="claim")
                assert claimed["ok"] and len(claimed["token"]) == 43
                fd = os.open(args.token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as output:
                    output.write(claimed["token"] + "\n")
                print("first claim succeeded; token stored outside repository")
            else:
                token = args.token_file.read_text().strip()
                authenticated = await request(ws, op="auth", token=token)
                assert authenticated["ok"], authenticated
                print("existing credential authenticated")

            token = args.token_file.read_text().strip()
            if args.expect_slot is not None:
                assert (await request(ws, op="subscribe"))["type"] == "snapshot.begin"
                found = False
                while True:
                    item = await receive(ws)
                    if item.get("type") == "snapshot.node" and item.get("slot") == args.expect_slot:
                        found = item["found"] and item["node"]["state"] == 1
                    if item.get("type") == "result" and item.get("op") == "resume":
                        break
                assert found, "restart snapshot omitted persisted key-only node"
                assert (await request(ws, op="node.remove", slot=args.expect_slot))["ok"]
                print("restart snapshot restored registry node, then removed test node")
            async with client.get(endpoint + "/diagnostics", ssl=False,
                                  headers={"Authorization": f"Bearer {token}"}) as response:
                diagnostics = await response.json()
                assert response.status == 200 and "hub" in diagnostics
            async with client.ws_connect(endpoint.replace("https:", "wss:") + "/ws", ssl=False) as guest:
                await receive(guest)
                denied = await request(guest, op="pair.close")
                assert denied["code"] == "unauthorized", denied
                await guest.send_str('{"op":"pair.close"}garbage')
                malformed = await receive(guest)
                assert malformed["code"] == "invalid_json", malformed
            print("diagnostics auth and malformed/unauthorized requests passed")

            created = await request(ws, op="node.add")
            assert created["ok"] and len(created["key"]) == 22
            slot = created["node"]["slot"]
            try:
                begin = await request(ws, op="subscribe")
                assert begin["type"] == "snapshot.begin", begin
                records = []
                while True:
                    item = await receive(ws)
                    records.append(item)
                    if item["type"] == "result" and item["op"] == "resume":
                        break
                assert any(item["type"] == "snapshot.node" and item["slot"] == slot
                           and item["found"] for item in records), records
                assert records[-1]["ok"]
                print("snapshot and watermark replay passed")

                removed = await request(ws, op="node.remove", slot=slot)
                assert removed["ok"], removed
                for _ in range(10):
                    item = await receive(ws)
                    if item.get("tombstone") and item.get("slot") == slot:
                        break
                else:
                    raise RuntimeError("missing live removal tombstone")
                print("live removal event passed")
            finally:
                # If an assertion fails, do not leave a permanently enrolled slot.
                await ws.close()

        async with client.ws_connect(endpoint.replace("https:", "wss:") + "/ws", ssl=False) as ws:
            await receive(ws)
            assert (await request(ws, op="auth", token=token))["ok"]
            await ws.send_json({"op": "resume", "stream_epoch": hello["stream_epoch"],
                                "after_seq": hello["stream_seq"]})
            replay = []
            while True:
                item = await receive(ws)
                replay.append(item)
                if item["type"] == "result":
                    break
            assert replay[-1]["ok"] and any(item.get("type") == "event" for item in replay)
            wrong_epoch = await request(ws, op="resume", stream_epoch=hello["stream_epoch"] + 1,
                                        after_seq="0")
            assert wrong_epoch["code"] == "resync_required", wrong_epoch
            print("disconnect/reconnect replay and wrong-epoch resync passed")

            if args.eviction:
                # Pairing events exercise a ring overrun without flash/NVS wear.
                pending = await request(ws, op="node.add")
                assert pending["ok"], pending
                slot = pending["node"]["slot"]
                try:
                    for _ in range(36):
                        assert (await request(ws, op="pair.open", slot=slot,
                                              duration_ms=1000))["ok"]
                        assert (await request(ws, op="pair.close"))["ok"]
                    gap = await request(ws, op="resume", stream_epoch=hello["stream_epoch"],
                                        after_seq="0")
                    assert gap["code"] == "resync_required", gap
                    print("64-event replay-ring eviction detected")
                finally:
                    await request(ws, op="node.remove", slot=slot)
            if args.retain_node:
                retained = await request(ws, op="node.add")
                assert retained["ok"]
                print(f"retained key-only slot {retained['node']['slot']} for restart check")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--fingerprint-file", required=True, type=Path)
    parser.add_argument("--claim", action="store_true")
    parser.add_argument("--eviction", action="store_true")
    parser.add_argument("--retain-node", action="store_true")
    parser.add_argument("--expect-slot", type=int)
    parser.add_argument("--expect-epoch-change", type=int)
    asyncio.run(exercise(parser.parse_args()))


if __name__ == "__main__":
    main()
