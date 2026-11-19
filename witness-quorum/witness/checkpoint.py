"""Export a five-witness certified prefix. Historical proof, not freshness oracle."""
import argparse
import asyncio
import json
from pathlib import Path
from .client import Client
from .crypto import canonical,digest,unb64,verify


def verify_checkpoint(proof, config):
    payload = proof["payload"]
    if payload["ledger"] != config["ledger_id"] or payload["epoch"] != config["epoch"] or digest(unb64(proof["snapshot"])) != payload["state_hash"]:
        raise ValueError("checkpoint state/genesis mismatch")
    seen = set()
    for approval in proof["approvals"]:
        node = str(approval["witness"])
        if node not in config["nodes"] or node in seen or approval["payload"] != payload:
            raise ValueError("checkpoint voter or payload mismatch")
        seen.add(node)
        verify(unb64(config["nodes"][node]["public"]), canonical(payload), unb64(approval["signature"]), b"WITNESS-CHECKPOINT-v2")
    if len(seen) < 5:
        raise ValueError("checkpoint has no quorum")
    return payload


async def export(root, destination):
    client=Client(root)
    async def one(i):
        try:
            return await client.transport.request(i,{"op":"checkpoint"})
        except Exception:
            return None
    responses=await asyncio.gather(*(one(i) for i in client.config["nodes"]))
    groups={}
    for r in responses:
        if r is None:continue
        node=str(r["witness"])
        if node not in client.config["nodes"]:raise ValueError("unknown checkpoint voter")
        payload=r["payload"]
        if payload["ledger"]!=client.config["ledger_id"] or digest(unb64(r["snapshot"]))!=payload["state_hash"]:raise ValueError("snapshot binding failure")
        verify(unb64(client.config["nodes"][node]["public"]),canonical(payload),unb64(r["signature"]),b"WITNESS-CHECKPOINT-v2")
        groups.setdefault(digest(canonical(payload)),{})[node]=r
    for group in groups.values():
        if len(group)>=5:
            selected=list(group.values())[:5]
            proof={"payload":selected[0]["payload"],"snapshot":selected[0]["snapshot"],"approvals":[{k:v for k,v in r.items() if k!="snapshot"} for r in selected]}
            verify_checkpoint(proof, client.config)
            Path(destination).write_bytes(canonical(proof))
            return proof["payload"]
    raise ValueError("no five identical checkpoint attestations; retry after convergence")


if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--root");p.add_argument("--output",default="reports/checkpoint.json");a=p.parse_args()
    print(json.dumps(asyncio.run(export(a.root,a.output)),indent=2))
