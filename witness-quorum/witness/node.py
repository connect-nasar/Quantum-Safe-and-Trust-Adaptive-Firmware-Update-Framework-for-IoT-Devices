import argparse
import asyncio
import json
import os
import secrets
import signal
from pathlib import Path

from aiohttp import web, ClientSession, ClientTimeout
from .crypto import canonical, unb64, b64, sign, verify, digest
from .codec import validate, ACK
from .store import Store
from .transport import Transport
from .proof import verify_decision


class Node:
    def __init__(self, root, identity):
        self.root, self.identity = Path(root), str(identity)
        self.config = json.loads((self.root / "genesis.json").read_text())
        # Pin genesis and check its administrator signature before opening data.
        self.check_genesis()
        self.secret = unb64(json.loads((self.root / "secrets" / f"node-{identity}.json").read_text())["secret"])
        self.transport = Transport(self.identity, self.secret, self.config)
        self.directory = self.root / "data" / f"node-{identity}"
        if not (self.directory / "provisioned").exists():
            raise ValueError("empty/unprovisioned witness volume: refusing to vote")
        self.store = Store(self.directory / "ledger.sqlite", self.config)
        self.bridge_token = secrets.token_hex(32)
        self.bridge_port = 11100 + int(identity)
        self.engine_port = 10100 + int(identity)
        self.engine_url = f"http://127.0.0.1:{self.engine_port}"
        self.tasks = set()
        self.last_errors = []
        self.sync_lock = asyncio.Lock()

    def check_genesis(self):
        cfg = dict(self.config)
        admin = unb64((self.root / "admin.pub").read_text().strip())
        signature = unb64(cfg.pop("signature"))
        ledger_id = cfg.pop("ledger_id")
        if digest(b"WITNESS-GENESIS-v2" + canonical(cfg)) != ledger_id:
            raise ValueError("genesis hash mismatch")
        verify(admin, canonical(cfg), signature, b"WITNESS-GENESIS-v2")

    async def engine(self, path, value=None):
        async with self.http.post(self.engine_url + path, data=canonical(value or {}), headers={"Authorization": "Bearer " + self.bridge_token}) as r:
            if r.status != 200:
                raise ValueError("engine: " + (await r.text())[:500])
            return await r.json()

    def launch(self, coro):
        task = asyncio.create_task(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def send(self, target, payload):
        try:
            await self.transport.request(str(target), payload, timeout=6)
        except (Exception, asyncio.CancelledError):
            # SmartBFT owns retry, timeout and view-change policy.
            pass

    def signed_result(self, c):
        result = self.store.result(c["client"], c["event_id"])
        if result is None:
            return {"pending": True}
        result = dict(result)
        proof = None
        if result.get("ok"):
            proof = self.store.db.execute("SELECT proof FROM decisions WHERE slot=?", (result["slot"],)).fetchone()
            result["decision"] = json.loads(proof[0])
        payload = {"ledger": self.config["ledger_id"], "event_hash": digest(canonical(c)), "result": result}
        return {"payload": payload, "witness": int(self.identity), "signature": b64(sign(self.secret, canonical(payload), b"WITNESS-RESULT-v2"))}

    async def peer(self, sender, req):
        op = req.get("op")
        if op in {"consensus", "transaction"}:
            if sender not in self.config["nodes"]:
                raise ValueError("only witness peers may send engine messages")
            await self.engine("/message", {"From": int(sender), "Kind": op, "Data": req["data"]})
            return {"ok": True}
        if op == "history":
            if sender not in self.config["nodes"]:
                raise ValueError("history restricted to peers")
            return {"decisions": self.store.decisions(int(req["after"]))}
        if sender not in self.config["clients"]:
            raise ValueError("client operation unauthorized")
        if op == "status":
            try:
                engine = await self.engine("/status")
            except (ValueError, OSError):
                engine = {"leader": 0}
            height, tip = self.store.tip()
            return {"node": int(self.identity), "height": height, "tip": tip, "leader": engine["leader"], "rejected_channels": self.transport.rejected}
        if op == "checkpoint":
            snapshot = self.store.snapshot()
            height, tip = self.store.tip()
            slot = self.store.db.execute("SELECT COALESCE(MAX(slot),0) FROM decisions").fetchone()[0]
            payload = {"ledger": self.config["ledger_id"], "epoch": self.config["epoch"], "height": height, "tip": tip, "slot": slot, "state_hash": digest(snapshot)}
            return {"payload": payload, "snapshot": b64(snapshot), "witness": int(self.identity), "signature": b64(sign(self.secret, canonical(payload), b"WITNESS-CHECKPOINT-v2"))}
        if op in {"submit", "result"}:
            c = validate(req["event"], self.config)
            if sender != c["client"]:
                raise ValueError("client channel/command mismatch")
            old = self.store.db.execute("SELECT command_hash FROM events WHERE client=? AND event_id=?", (c["client"], c["event_id"])).fetchone()
            if old and old[0] != digest(canonical(c)):
                raise ValueError("event ID conflict")
            if op == "submit" and not old:
                await self.engine("/submit", req["event"])
            return self.signed_result(c)
        raise ValueError("unknown operation")

    async def synchronize(self):
        async with self.sync_lock:
            applied = self.store.db.execute("SELECT COALESCE(MAX(slot),0) FROM decisions").fetchone()[0]
            fetched = []
            # Every returned block must carry independently verified five-member
            # SmartBFT commit signatures; an untrusted peer cannot inject history.
            async def query(peer):
                try:
                    return (await self.transport.request(peer, {"op": "history", "after": applied}, timeout=4))["decisions"]
                except Exception:
                    return []
            results = await asyncio.gather(*(query(p) for p in self.config["nodes"] if p != self.identity))
            # Never apply unverified history in Python. Go validates each decision
            # and Deliver checks contiguous slots and deterministic chain linkage.
            candidates = sorted(results, key=len, reverse=True)
            for chain in candidates:
                if not chain:
                    continue
                valid = True
                for decision in chain:
                    try:
                        await self.engine("/verify_decision", decision)
                    except Exception:
                        valid = False
                        break
                if valid:
                    fetched = chain
                    break
            return fetched

    async def rpc(self, request):
        if request.headers.get("Authorization") != "Bearer " + self.bridge_token:
            raise web.HTTPUnauthorized()
        method = request.match_info["method"]
        data = await request.json()
        try:
            if method == "sign":
                out = {"Signature": b64(sign(self.secret, bytes.fromhex(self.config["ledger_id"]) + unb64(data["message"]), b"WITNESS-ENGINE-v1"))}
            elif method == "verify_signature":
                public = self.config["nodes"].get(str(data["ID"]))
                if public is None:
                    raise ValueError("unknown voter")
                verify(unb64(public["public"]), bytes.fromhex(self.config["ledger_id"]) + unb64(data["Msg"]), unb64(data["Value"]), b"WITNESS-ENGINE-v1")
                out = {}
            elif method == "verify_request":
                validate(json.loads(unb64(data["raw"])), self.config)
                out = {}
            elif method == "send":
                if len(self.tasks) < 4096:
                    self.launch(self.send(data["target"], {"op": data["kind"], "data": data["data"]}))
                out = {}
            elif method == "deliver":
                decision = data["decision"]
                _, _, verified_slot = verify_decision(decision, self.config)
                if verified_slot != int(data["slot"]):
                    raise ValueError("slot binding mismatch")
                event = json.loads(unb64(decision["Proposal"]["Payload"]))
                self.store.apply(event, decision, int(data["slot"]))
                out = {}
            elif method == "latest":
                out = self.store.latest()
            elif method == "sync":
                out = await self.synchronize()
            else:
                raise ValueError("unknown RPC")
            return web.json_response(out)
        except (ValueError, KeyError, TypeError) as error:
            return web.json_response({"error": str(error)}, status=400)

    async def run(self, engine_binary):
        self.http = ClientSession(timeout=ClientTimeout(total=110))
        app = web.Application(client_max_size=4 * 1024 * 1024)
        app.router.add_post("/rpc/{method}", self.rpc)
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, "127.0.0.1", self.bridge_port).start()
        peer_cfg = self.config["nodes"][self.identity]
        server = await asyncio.start_server(lambda r, w: self.transport.serve(r, w, self.peer), os.environ.get("WITNESS_BIND", "127.0.0.1"), peer_cfg["port"], limit=4*1024*1024)
        env = dict(os.environ, WITNESS_ID=self.identity, BRIDGE_URL=f"http://127.0.0.1:{self.bridge_port}", BRIDGE_TOKEN=self.bridge_token, ENGINE_ADDR=f"127.0.0.1:{self.engine_port}", DATA_DIR=str(self.directory), LEDGER_ID=self.config["ledger_id"])
        engine = await asyncio.create_subprocess_exec(str(engine_binary), env=env)
        print(f"witness {self.identity}: encrypted listener {peer_cfg['port']}", flush=True)
        try:
            code = await engine.wait()
            raise RuntimeError(f"consensus engine exited: {code}")
        finally:
            if engine.returncode is None:
                engine.terminate()
                await engine.wait()
            server.close()
            await server.wait_closed()
            for task in list(self.tasks):
                task.cancel()
            await self.http.close()
            await runner.cleanup()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--id", required=True, type=int, choices=range(1, 8))
    parser.add_argument("--engine", required=True)
    args = parser.parse_args()
    asyncio.run(Node(args.root, args.id).run(args.engine))


if __name__ == "__main__":
    main()
