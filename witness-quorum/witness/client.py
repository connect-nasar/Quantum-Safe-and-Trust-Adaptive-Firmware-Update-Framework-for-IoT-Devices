import argparse
import asyncio
import json
import os
import time
from pathlib import Path
from .crypto import canonical, unb64, token, digest
from .codec import envelope
from .transport import Transport
from .proof import verify_result


class Client:
    def __init__(self, root=None):
        from .deployment import active_root
        root = active_root(root)
        self.config = json.loads((root / "genesis.json").read_text())
        from .node import Node
        # Same pinned administrator verification as every witness.
        checker = object.__new__(Node); checker.root = root; checker.config = self.config; checker.check_genesis()
        self.key = json.loads((root / "secrets" / "client.json").read_text())
        expected_commitment = digest(b"WITNESS-KEY-v1" + bytes.fromhex(self.key["key_id"]) + unb64(self.key["index_key"]))
        if self.config["publishers"][self.key["key_id"]]["token_commitment"] != expected_commitment:
            raise ValueError("token derivation key does not match pinned registration")
        self.transport = Transport(self.key["id"], unb64(self.key["secret"]), self.config)

    def command(self, index, package_digest, kind="RESERVE", reference="00"*32, payload="", sequence=0, reason=0):
        if not 0 <= index < self.config["publishers"][self.key["key_id"]]["capacity"]:
            raise ValueError("index outside registered capacity")
        c = {"client": self.key["id"], "key_id": self.key["key_id"], "token": token(unb64(self.key["index_key"]), self.key["key_id"], index), "digest": package_digest, "type": kind, "reference": reference, "payload": payload, "event_id": os.urandom(16).hex(), "sequence": sequence, "reason": reason}
        return envelope(c, self.config, unb64(self.key["secret"]))

    async def status(self):
        async def one(i):
            try:
                return await self.transport.request(i, {"op": "status"}, timeout=3)
            except Exception:
                return {"node": int(i), "offline": True}
        return await asyncio.gather(*(one(i) for i in self.config["nodes"]))

    async def submit(self, event, timeout=45):
        # Persist event at the calling signing service before using this API.
        started = time.monotonic()
        groups = {}
        last_submit = 0
        while time.monotonic() - started < timeout:
            op = "submit" if time.monotonic() - last_submit > 4 else "result"
            if op == "submit":
                last_submit = time.monotonic()
            async def one(i):
                try:
                    response = await self.transport.request(i, {"op": op, "event": event}, timeout=4)
                    if response.get("pending"):
                        return
                    result = verify_result(response, event["command"], self.config)
                    # Proof signature subsets may differ; group deterministic result.
                    stable = {k:v for k,v in result.items() if k != "decision"}
                    key = digest(canonical(stable))
                    groups.setdefault(key, {})[response["witness"]] = response
                except (Exception, asyncio.CancelledError):
                    return
            await asyncio.gather(*(one(i) for i in self.config["nodes"]))
            for group in groups.values():
                if len(group) >= 5:
                    responses = sorted(group.values(), key=lambda r:r["witness"])[:5]
                    result = verify_result(responses[0], event["command"], self.config)
                    return {"result": result, "approvals": responses, "latency_ms": round((time.monotonic()-started)*1000,2)}
            await asyncio.sleep(.25)
        raise TimeoutError("no five-member finalized result; do not sign")


async def run(args):
    client = Client(args.root)
    if args.action == "status":
        print(json.dumps(await client.status(), indent=2)); return
    if args.action == "demo":
        if not client.config["publishers"][client.key["key_id"]].get("synthetic", False):
            raise ValueError("synthetic demo disabled for OTA publisher; use the gated OTA signer")
        event = client.command(args.index, digest(b"standalone-demo-package"))
        from .deployment import active_root
        target = active_root(args.root) / "client-events"
        target.mkdir(exist_ok=True)
        path = target / (event["command"]["event_id"] + ".json")
        with path.open("xb") as f:
            f.write(canonical(event));f.flush();os.fsync(f.fileno())
    else:
        event = json.loads(Path(args.event).read_text())
        path = Path(args.event)
    certificate = await client.submit(event, args.timeout)
    proof_path = path.with_suffix(".certificate.json")
    proof_path.write_bytes(canonical(certificate))
    print(json.dumps({"ok": certificate["result"]["ok"], "result": {k:v for k,v in certificate["result"].items() if k not in {"body","event","decision"}}, "approvals": [x["witness"] for x in certificate["approvals"]], "latency_ms": certificate["latency_ms"], "certificate": str(proof_path.resolve())},indent=2))


if __name__ == "__main__":
    p = argparse.ArgumentParser();p.add_argument("action", choices=["status","demo","submit"]);p.add_argument("--root");p.add_argument("--index",type=int,default=0);p.add_argument("--event");p.add_argument("--timeout",type=float,default=45)
    asyncio.run(run(p.parse_args()))
