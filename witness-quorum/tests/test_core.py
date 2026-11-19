import asyncio
import copy
import json
import os
import struct
from pathlib import Path

import pytest
from witness.setup import provision
from witness.client import Client
from witness.crypto import canonical, digest, b64, unb64, token, sign, verify, ml_dsa_65
from witness.codec import COMMAND, RECORD, ACK, encode_command, validate
from witness.store import Store
from witness.proof import proposal_digest, verify_decision, verify_certificate
from witness.transport import Channel, Transport


@pytest.fixture
def deployment(tmp_path):
    root = tmp_path / "cluster"
    provision(root)
    return root, Client(root)


def decision(root, client, event, slot):
    p = {"Payload":b64(canonical(event)),"Header":b64(client.config["ledger_id"].encode()),"Metadata":b64(b"\x10" + bytes([slot])),"VerificationSequence":1}
    msg = canonical({"Digest":proposal_digest(p),"Aux":None})
    sigs = []
    for i in range(1,6):
        sk = unb64(json.loads((root / "secrets" / f"node-{i}.json").read_text())["secret"])
        sigs.append({"ID":i,"Msg":b64(msg),"Value":b64(sign(sk,bytes.fromhex(client.config["ledger_id"])+msg,b"WITNESS-ENGINE-v1"))})
    return {"Proposal":p,"Signatures":sigs}


def test_canonical_layout_and_context(deployment):
    root,c = deployment
    assert (COMMAND.size,RECORD.size,ACK.size)==(236,264,136)
    e=c.command(1,digest(b"package"));assert len(encode_command(e["command"],c.config))==240
    validate(e,c.config)
    changed=copy.deepcopy(e);changed["command"]["digest"]=digest(b"other")
    with pytest.raises(ValueError):validate(changed,c.config)
    for field,value in (("sequence",True),("sequence",-1),("token","00"),("payload",b64(b"bad"))):
        changed=copy.deepcopy(e);changed["command"][field]=value
        with pytest.raises((ValueError,struct.error)):validate(changed,c.config)
    pk,sk=ml_dsa_65.keygen();s=sign(sk,b"x",b"a")
    with pytest.raises(ValueError):verify(pk,b"x",s,b"b")


def test_stable_private_token(deployment):
    _,c=deployment
    a=c.command(2,digest(b"a"));b=c.command(2,digest(b"b"));d=c.command(3,digest(b"a"))
    assert a["command"]["token"]==b["command"]["token"]!=d["command"]["token"]
    assert "index" not in a["command"]
    with pytest.raises(ValueError):c.command(1024,digest(b"x"))


def test_reservation_completion_retry_and_reopen(deployment,tmp_path):
    root,c=deployment;path=tmp_path/"db.sqlite";s=Store(path,c.config)
    e=c.command(1,digest(b"p"));r=s.apply(e,decision(root,c,e,1),1);assert r["ok"]
    assert s.apply(e,decision(root,c,e,2),2)==r
    conflict=c.command(1,digest(b"wrong"));assert not s.apply(conflict,decision(root,c,conflict,3),3)["ok"]
    complete=c.command(1,e["command"]["digest"],"COMPLETE",r["hash"],b64(bytes(32)))
    assert s.apply(complete,decision(root,c,complete,4),4)["state"]=="COMPLETED"
    abandon=c.command(1,e["command"]["digest"],"ABANDON",r["hash"],reason=1)
    assert not s.apply(abandon,decision(root,c,abandon,5),5)["ok"]
    assert s.audit()["height"]==2;s.db.close()
    reopened=Store(path,c.config);assert reopened.tip()[0]==2;reopened.db.close()


def test_abandon_is_permanent_and_bad_reference(deployment,tmp_path):
    root,c=deployment;s=Store(tmp_path/"db",c.config)
    e=c.command(4,digest(b"p"));r=s.apply(e,decision(root,c,e,1),1)
    wrong=c.command(4,e["command"]["digest"],"COMPLETE","11"*32,b64(bytes(32)))
    assert not s.apply(wrong,decision(root,c,wrong,2),2)["ok"]
    abandon=c.command(4,e["command"]["digest"],"ABANDON",r["hash"],reason=2)
    assert s.apply(abandon,decision(root,c,abandon,3),3)["state"]=="ABANDONED"
    new=c.command(4,digest(b"new"));assert not s.apply(new,decision(root,c,new,4),4)["ok"]


def test_forged_duplicate_and_wrong_proposal_proofs(deployment):
    root,c=deployment;e=c.command(1,digest(b"p"));d=decision(root,c,e,1)
    assert verify_decision(d,c.config)[2]==1
    for mutation in ("duplicate","short","payload","signature","ledger"):
        bad=copy.deepcopy(d)
        if mutation=="duplicate":bad["Signatures"][1]=bad["Signatures"][0]
        elif mutation=="short":bad["Signatures"]=bad["Signatures"][:4]
        elif mutation=="payload":bad["Proposal"]["Payload"]=b64(b"{}")
        elif mutation=="ledger":bad["Proposal"]["Header"]=b64(b"wrong")
        else:bad["Signatures"][0]["Value"]=b64(bytes(3309))
        with pytest.raises((ValueError,KeyError)):verify_decision(bad,c.config)


def test_detect_derived_table_and_chain_corruption(deployment,tmp_path):
    root,c=deployment;path=tmp_path/"db";s=Store(path,c.config)
    e=c.command(0,digest(b"p"));s.apply(e,decision(root,c,e,1),1)
    s.db.execute("UPDATE reservations SET state='FREE'");s.db.commit()
    with pytest.raises(ValueError,match="certified replay"):s.audit()
    s.db.close()
    with pytest.raises(ValueError):Store(path,c.config)


@pytest.mark.asyncio
async def test_authenticated_encrypted_channel_and_wrong_identity(deployment):
    root,c=deployment
    sk=unb64(json.loads((root/"secrets"/"node-1.json").read_text())["secret"])
    transport=Transport("1",sk,c.config)
    async def handler(sender,req):return {"sender":sender,"echo":req}
    server=await asyncio.start_server(lambda r,w:transport.serve(r,w,handler),"127.0.0.1",0)
    port=server.sockets[0].getsockname()[1]
    c.config["nodes"]["1"]["port"]=port
    try:
        got=await c.transport.request("1",{"private":"test-body"})
        assert got["echo"]["private"]=="test-body"
        intruder=Transport("not-provisioned",sk,c.config)
        with pytest.raises(Exception):await intruder.request("1",{"bad":True},timeout=2)
    finally:server.close();await server.wait_closed()


@pytest.mark.asyncio
async def test_record_ciphertext_tamper_and_replay():
    material=os.urandom(72);sid=os.urandom(16);captured=[]
    class Writer:
        def write(self,raw):captured.append(raw)
        async def drain(self):pass
    tx=Channel(None,Writer(),material,True,sid)
    await tx.send({"secret":"hidden-index-token"})
    packet=captured[0]
    assert b"hidden-index-token" not in packet
    reader=asyncio.StreamReader();reader.feed_data(packet+packet)
    rx=Channel(reader,None,material,False,sid)
    assert await rx.receive()=={"secret":"hidden-index-token"}
    with pytest.raises(ValueError,match="replay"):await rx.receive()
    bad=bytearray(packet);bad[-1]^=1
    reader=asyncio.StreamReader();reader.feed_data(bad)
    with pytest.raises(Exception):await Channel(reader,None,material,False,sid).receive()
