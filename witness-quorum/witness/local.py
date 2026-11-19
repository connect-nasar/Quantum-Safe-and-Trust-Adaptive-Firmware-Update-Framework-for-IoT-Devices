"""Manage only this deployment's seven native test processes."""
import argparse
import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from .deployment import active_root

BASE = Path(__file__).resolve().parents[1]


def start(root, ids):
    root = active_root(root)
    manifest = root / "processes.json"
    running = json.loads(manifest.read_text()) if manifest.exists() else {}
    for i in ids:
        key = str(i)
        if key in running:
            try:
                os.kill(running[key], 0)
                continue
            except OSError:
                pass
        log = (root / f"node-{i}.log").open("ab", buffering=0)
        engine = BASE / "bin" / ("witness-engine.exe" if os.name == "nt" else "witness-engine")
        args = [sys.executable, "-m", "witness.node", "--root", str(root), "--id", str(i), "--engine", str(engine)]
        proc = subprocess.Popen(args, cwd=BASE, stdout=log, stderr=log, creationflags=subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0, start_new_session=os.name!="nt")
        log.close()
        running[key] = proc.pid
    manifest.write_text(json.dumps(running,indent=2))
    print(json.dumps({"deployment": str(root), "processes": running},indent=2))


def stop(root, ids):
    root = active_root(root)
    manifest = root / "processes.json"
    running = json.loads(manifest.read_text()) if manifest.exists() else {}
    for i in ids:
        pid = running.pop(str(i), None)
        if pid:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                try:
                    os.killpg(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
    manifest.write_text(json.dumps(running,indent=2))


if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("action",choices=["start","stop"]);parser.add_argument("--root");parser.add_argument("--ids",nargs="+",type=int,choices=range(1,8),default=list(range(1,8)))
    a=parser.parse_args();(start if a.action=="start" else stop)(a.root,a.ids)
