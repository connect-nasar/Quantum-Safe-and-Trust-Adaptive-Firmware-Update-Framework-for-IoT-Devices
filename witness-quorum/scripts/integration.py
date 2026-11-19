"""Native seven-process fault campaign; writes factual, machine-readable results."""
import asyncio
import copy
import json
import sys
import time
from pathlib import Path

BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE))
from witness.client import Client
from witness.crypto import digest,b64,canonical
from witness.local import start,stop
from witness.proof import verify_certificate
from witness.store import Store


async def campaign():
    root=BASE/"runtime"/"local"
    from witness.deployment import active_root
    if active_root()!=root:
        raise RuntimeError("Archived synthetic campaign disabled while OTA deployment is active; use the disposable OTA integration runner deliberately")
    c=Client(root);report={"mode":"seven native processes, not Docker", "ledger":c.config["ledger_id"],"tests":[]}
    serial=int(time.time())%1000000
    index=100
    # Repeated runs choose new indices rather than resetting durable witness data.
    import sqlite3
    with sqlite3.connect(root/"data/node-1/ledger.sqlite") as db:
        index=max(100,db.execute("SELECT COUNT(*) FROM reservations").fetchone()[0]+100)
    def record(name,**values):
        report["tests"].append({"name":name,"passed":True,**values});print(name,"PASS",flush=True)
    async def settled(nodes=7,timeout=40):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            states=await c.status();online=[s for s in states if not s.get("offline")]
            if len(online)>=nodes and all(s["leader"]>0 for s in online) and len({(s["height"],s["tip"]) for s in online})==1:
                return states
            await asyncio.sleep(.5)
        raise AssertionError("witnesses did not converge")
    async def submit(e,timeout=45):
        cert=await c.submit(e,timeout);verify_certificate(cert,e["command"],c.config);return cert
    try:
        await settled()
        e=c.command(index,digest(f"package-{serial}".encode()))
        cert=await submit(e);assert cert["result"]["ok"]
        record("five-member finalized reservation",latency_ms=cert["latency_ms"],approvals=[r["witness"] for r in cert["approvals"]])
        again=await submit(e);assert again["result"]["hash"]==cert["result"]["hash"]
        record("exact retry returns original record")
        conflict=c.command(index,digest(b"conflicting-package"));assert not (await submit(conflict))["result"]["ok"]
        record("conflicting digest rejected")
        done=c.command(index,e["command"]["digest"],"COMPLETE",cert["result"]["hash"],b64(bytes(32)))
        assert (await submit(done))["result"]["state"]=="COMPLETED"
        record("completion finalized")
        assert not (await submit(c.command(index,digest(b"reuse"))))["result"]["ok"]
        record("completed token cannot be reused")
        competing=[c.command(index+1,digest(f"concurrent-{i}".encode())) for i in range(2)]
        results=await asyncio.gather(*(submit(x) for x in competing))
        assert sum(r["result"]["ok"] for r in results)==1
        winner=next(r for r in results if r["result"]["ok"])
        win_event=winner["result"]["event"]["command"]
        abandoned=c.command(index+1,win_event["digest"],"ABANDON",winner["result"]["hash"],reason=1)
        assert (await submit(abandoned))["result"]["state"]=="ABANDONED"
        assert not (await submit(c.command(index+1,digest(b"reuse-abandoned"))))["result"]["ok"]
        record("concurrent conflict ordered; abandoned capacity permanent")
        stop(root,[6,7]);await asyncio.sleep(1)
        offline=await submit(c.command(index+2,digest(b"two-offline")))
        assert offline["result"]["ok"]
        record("two unavailable witnesses: quorum succeeds",latency_ms=offline["latency_ms"])
        stop(root,[5]);await asyncio.sleep(.5)
        blocked=c.command(index+3,digest(b"three-offline"))
        try:await submit(blocked,timeout=7)
        except TimeoutError:record("three unavailable witnesses: fails closed")
        else:raise AssertionError("four witnesses unexpectedly authorized")
        start(root,[5,6,7]);await settled(timeout=60)
        record("restarted witnesses catch up to identical tip")
        before=await c.status();leader=next(s["leader"] for s in before if not s.get("offline"))
        stop(root,[leader]);await asyncio.sleep(1)
        moved=await submit(c.command(index+4,digest(b"leader-unavailable")),timeout=65)
        assert moved["result"]["ok"]
        new_states=await c.status();new_leader=next(s["leader"] for s in new_states if not s.get("offline"))
        assert new_leader!=leader
        record("SmartBFT replaces unavailable leader",old_leader=leader,new_leader=new_leader,latency_ms=moved["latency_ms"])
        start(root,[leader]);await settled(timeout=60)
        stop(root,list(range(1,8)));await asyncio.sleep(1);start(root,list(range(1,8)))
        await settled(timeout=60)
        assert not (await submit(c.command(index,digest(b"after-restart-reuse"))))["result"]["ok"]
        record("full cluster restart preserves consumed positions")
        final=await settled()
        for i in range(1,8):
            store=Store(root/f"data/node-{i}/ledger.sqlite",c.config);store.audit();store.db.close()
        record("all seven databases pass certified replay and chain audit")
        bad=copy.deepcopy(cert);bad["approvals"][1]=bad["approvals"][0]
        try:verify_certificate(bad,e["command"],c.config)
        except ValueError:record("offline certificate rejects duplicate identity")
        else:raise AssertionError("duplicate certificate voter accepted")
        report["final_status"]=final
        report["passed"]=True
    except BaseException as error:
        report["passed"]=False;report["error"]=repr(error)
        raise
    finally:
        start(root,list(range(1,8)))
        (BASE/"reports").mkdir(exist_ok=True)
        (BASE/"reports/integration.json").write_bytes(canonical(report))


if __name__=="__main__":asyncio.run(campaign())
