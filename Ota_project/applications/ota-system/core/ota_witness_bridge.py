"""Stdlib-only connection to the separately installed witness signing service."""
import hashlib
import json
import os
import subprocess
from pathlib import Path

FILES = {"manifest.json", "firmware.bin", "firmware.sig", "firmware.pub", "firmware.kem", "firmware.nonce", "firmware.tag", "firmware.witness.json"}


def connection(root):
    root=Path(root).resolve();path=root/"witness-connection.json"
    if not path.exists(): raise RuntimeError("Witness enrollment missing; refusing unguarded XMSS signing")
    config=json.loads(path.read_text())
    for key in ("ota_root", "project", "python", "deployment"):
        config[key] = str((root / config[key]).resolve())
    if config.get("schema")!=1 or config.get("required") is not True or Path(config["ota_root"]).resolve()!=root:
        raise RuntimeError("Invalid witness connection; signing is blocked")
    if not Path(config["python"]).is_file() or not (Path(config["project"])/"witness/ota_signer.py").is_file():
        raise RuntimeError("Standalone witness runtime unavailable; signing is blocked")
    return config


def invoke(root,action,extra=(),payload=None):
    config=connection(root)
    command=[config["python"],"-m","witness.ota_signer",action,"--config",str(Path(root)/"witness-connection.json"),*extra]
    result=subprocess.run(command,input=payload,cwd=config["project"],capture_output=True,timeout=150)
    if result.returncode:
        raise RuntimeError(result.stderr.decode("utf-8",errors="replace").strip() or "Witness signing failed; no fallback is permitted")
    return result.stdout


def publish(root,version):
    return invoke(root,"publish",["--version",str(version)]).decode("utf-8").strip()


def sign_package(root,package):
    import base64
    raw=json.dumps({k:base64.b64encode(v).decode() for k,v in package.items()},separators=(",",":")).encode()
    output=json.loads(invoke(root,"sign-package",payload=raw))
    return {k:base64.b64decode(v,validate=True) for k,v in output.items()}


def package_generation(root):
    root=Path(root).resolve();pointer=root/"witness-publication.json"
    if not pointer.exists(): return root
    config=connection(root);value=json.loads(pointer.read_text())
    expected=(Path(config["deployment"])/"publications").resolve()
    directory=(root / value["generation"]).resolve()
    if directory.parent!=expected or directory.name!=value["operation"] or value["ledger"]!=json.loads((Path(config["deployment"])/"genesis.json").read_text())["ledger_id"]:
        raise RuntimeError("Invalid witness publication pointer")
    return directory


def read_package_file(directory,name):
    if name not in FILES: raise ValueError("Unsupported package file")
    return (Path(directory)/name).read_bytes()
