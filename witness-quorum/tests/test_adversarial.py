"""Disposable fault tests; never open the enrolled publisher or running nodes.

Certified-decision fixtures sign with test members' keys. These tests exercise
local validation and persistence, not a live Byzantine consensus campaign.
"""
import asyncio
import copy
import json
import os
import sqlite3
import struct

import pytest

from test_core import deployment, decision
from witness.crypto import b64, canonical, digest, sign, unb64
from witness.node import Node
from witness.store import Store
from witness.transport import Channel, HEADER, MAX_FRAME, Transport, read_frame, write_frame


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [
    ("ledger", "00" * 32), ("to", "2"), ("version", 0),
    ("suite", "AES-only"), ("challenge", b64(bytes(31))),
    ("kem", b64(bytes(17))), ("extra", True),
])
async def test_signed_malformed_hello_never_reaches_application(deployment, field, value):
    root, client = deployment
    secret = unb64(json.loads((root / "secrets/node-1.json").read_text())["secret"])
    transport = Transport("1", secret, client.config)
    calls = []

    async def handler(sender, request):
        calls.append(request)
        return {}

    server = await asyncio.start_server(lambda r, w: transport.serve(r, w, handler), "127.0.0.1", 0)
    reader, writer = await asyncio.open_connection("127.0.0.1", server.sockets[0].getsockname()[1])
    try:
        from witness.crypto import ml_kem_768
        public, _ = ml_kem_768.keygen()
        hello = {"version": 1, "suite": "ML-KEM-768/ML-DSA-65/AES-256-GCM",
                 "ledger": client.config["ledger_id"], "from": client.transport.identity,
                 "to": "1", "challenge": b64(os.urandom(32)), "kem": b64(public)}
        hello[field] = value
        # A known member signs the malformed transcript: signature validity alone
        # must not bypass protocol binding or KEM input validation.
        packet = {"hello": hello, "signature": b64(sign(client.transport.secret, canonical(hello), b"WITNESS-HELLO-v1"))}
        await write_frame(writer, canonical(packet))
        assert await asyncio.wait_for(reader.read(), 3) == b""
        assert not calls
        assert transport.rejected == 1
    finally:
        writer.close()
        await writer.wait_closed()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["session", "sequence", "flags", "length", "direction", "truncated"])
async def test_invalid_record_does_not_advance_receive_counter(mutation):
    material, sid, packets = os.urandom(72), os.urandom(16), []

    class Writer:
        def write(self, data): packets.append(data)
        async def drain(self): pass

    await Channel(None, Writer(), material, True, sid).send({"private": "token"})
    packet = bytearray(packets[0])
    fields = list(HEADER.unpack(packet[4:4 + HEADER.size]))
    if mutation == "session": fields[4] = os.urandom(16)
    elif mutation == "sequence": fields[5] = 1
    elif mutation == "flags": fields[3] = 1
    elif mutation == "length": fields[6] += 1
    if mutation == "truncated":
        packet = packet[:-1]
    else:
        packet[4:4 + HEADER.size] = HEADER.pack(*fields)
    reader = asyncio.StreamReader()
    reader.feed_data(packet)
    reader.feed_eof()
    receiver = Channel(reader, None, material, mutation == "direction", sid)
    with pytest.raises(Exception):
        await receiver.receive()
    assert receiver.received == 0


@pytest.mark.asyncio
async def test_oversized_frame_rejected_before_body_read():
    reader = asyncio.StreamReader()
    reader.feed_data(struct.pack(">I", MAX_FRAME + 1))
    with pytest.raises(ValueError, match="frame too large"):
        await asyncio.wait_for(read_frame(reader), 1)


def test_disk_full_rolls_back_all_application_tables(deployment, tmp_path):
    root, client = deployment
    store = Store(tmp_path / "full.sqlite", client.config)
    try:
        before = store.snapshot()
        # Bound only this disposable SQLite database, never fill the host disk.
        store.db.execute("CREATE TABLE padding(value BLOB)")
        pages = store.db.execute("PRAGMA page_count").fetchone()[0]
        store.db.execute(f"PRAGMA max_page_count={pages}")
        try:
            while True:
                with store.db:
                    store.db.execute("INSERT INTO padding VALUES(?)", (bytes(3500),))
        except sqlite3.OperationalError as error:
            assert "full" in str(error).lower()
        event = client.command(0, digest(b"disk-full"))
        with pytest.raises(sqlite3.OperationalError, match="full"):
            store.apply(event, decision(root, client, event, 1), 1)
        assert store.snapshot() == before
        assert store.db.execute("SELECT COUNT(*) FROM decisions").fetchone()[0] == 0
        assert store.audit()["height"] == 0
        # Space restored: the same request can commit once, with certified replay.
        store.db.execute("PRAGMA max_page_count=10000")
        assert store.apply(event, decision(root, client, event, 1), 1)["ok"]
        assert store.audit()["height"] == 1
    finally:
        store.db.close()


@pytest.mark.parametrize("mutation", ["record", "event", "proof", "decision-gap"])
def test_persisted_corruption_quarantines_reopened_store(deployment, tmp_path, mutation):
    root, client = deployment
    path = tmp_path / "corrupt.sqlite"
    store = Store(path, client.config)
    event = client.command(0, digest(b"persisted"))
    store.apply(event, decision(root, client, event, 1), 1)
    if mutation == "record": store.db.execute("UPDATE records SET hash=?", ("00" * 32,))
    elif mutation == "event": store.db.execute("UPDATE events SET result='{}'")
    elif mutation == "proof":
        proof = copy.deepcopy(store.latest())
        proof["Signatures"][1] = proof["Signatures"][0]
        store.db.execute("UPDATE decisions SET proof=?", (json.dumps(proof),))
    else: store.db.execute("UPDATE decisions SET slot=2")
    store.db.commit()
    store.db.close()
    with pytest.raises(ValueError): Store(path, client.config)


def test_missing_volume_marker_refuses_node_start(deployment):
    root, _ = deployment
    marker = root / "data/node-1/provisioned"
    marker.unlink()
    with pytest.raises(ValueError, match="refusing to vote"):
        Node(root, 1)
    assert not (marker.parent / "ledger.sqlite").exists()


def test_modified_genesis_refuses_node_start(deployment):
    root, _ = deployment
    path = root / "genesis.json"
    config = json.loads(path.read_text())
    config["quorum"] = 1
    path.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(ValueError, match="genesis hash mismatch"):
        Node(root, 1)
