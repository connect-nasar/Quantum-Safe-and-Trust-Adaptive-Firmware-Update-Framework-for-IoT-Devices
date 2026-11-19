import argparse
import json
import os
from pathlib import Path
from .crypto import ml_dsa_65, canonical, b64, digest, sign, token


def provision(root, docker=False, publisher_public=None, consumed=0):
    root = Path(root)
    if root.exists():
        raise ValueError("refusing to overwrite existing deployment; use a new directory")
    root.mkdir(parents=True)
    (root / "secrets").mkdir(mode=0o700)
    admin_pk, admin_sk = ml_dsa_65.keygen()
    nodes = {}
    for i in range(1, 8):
        pk, sk = ml_dsa_65.keygen()
        nodes[str(i)] = {"public": b64(pk), "host": f"witness-{i}" if docker else "127.0.0.1", "port": 9100+i}
        (root / "secrets" / f"node-{i}.json").write_text(json.dumps({"secret": b64(sk)}))
        directory = root / "data" / f"node-{i}"
        directory.mkdir(parents=True)
        (directory / "provisioned").write_text("fresh test deployment\n")
    pk, sk = ml_dsa_65.keygen()
    client_id = digest(pk)
    # Synthetic publisher registration for standalone witness experiments;
    # no real OTA signing key is copied or used.
    publisher = digest(publisher_public) if publisher_public else digest(b"WITNESS-SYNTHETIC-PUBLISHER" + os.urandom(32))
    index_key = os.urandom(32)
    if not 0 <= consumed <= 1023: raise ValueError("invalid bootstrap consumption")
    registration = {"client": client_id, "capacity": 1024, "token_commitment": digest(b"WITNESS-KEY-v1" + bytes.fromhex(publisher) + index_key), "synthetic": publisher_public is None}
    if publisher_public:
        registration["public_key"] = b64(publisher_public)
        registration["bootstrap_consumed_tokens"] = [token(index_key, publisher, i) for i in range(consumed)]
    cfg = {"format": 2, "suite": 1, "epoch": 1, "quorum": 5, "nodes": nodes, "clients": {client_id: b64(pk)}, "publishers": {publisher: registration}, "admin": b64(admin_pk)}
    raw = canonical(cfg)
    cfg["ledger_id"] = digest(b"WITNESS-GENESIS-v2" + raw)
    cfg["signature"] = b64(sign(admin_sk, raw, b"WITNESS-GENESIS-v2"))
    (root / "genesis.json").write_bytes(canonical(cfg))
    (root / "admin.pub").write_text(b64(admin_pk))
    (root / "secrets" / "admin.json").write_text(json.dumps({"secret": b64(admin_sk)}))
    (root / "secrets" / "client.json").write_text(json.dumps({"id": client_id, "secret": b64(sk), "key_id": publisher, "index_key": b64(index_key)}))
    (root / "client-events").mkdir()
    for file in (root / "secrets").iterdir():
        file.chmod(0o600)
    if docker and os.name != "nt" and os.getuid() == 0:
        for path in root.rglob("*"):
            os.chown(path, 10001, 10001)
    return cfg


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default="runtime/local")
    parser.add_argument("--docker", action="store_true")
    args = parser.parse_args()
    config = provision(args.root, args.docker)
    print(json.dumps({"root": str(Path(args.root).resolve()), "ledger_id": config["ledger_id"], "witnesses": 7, "quorum": 5}))
