"""Quorum-gated XMSS signer with durable allocation and immutable publication.

The original state is used for one C signing call only after a five-member
certificate; the next BDS state is committed BEFORE that call. Uncertain
operations burn capacity instead of attempting the old reservation again.
"""
import argparse
import asyncio
import ctypes
import json
import os
import secrets
import sqlite3
import sys
from contextlib import contextmanager
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .client import Client
from .crypto import canonical, b64, unb64, digest, ml_kem_768, token
from .native import Native
from .proof import verify_certificate

PACKAGE_NAMES = {"manifest.json", "firmware.bin", "firmware.sig", "firmware.pub", "firmware.kem", "firmware.nonce", "firmware.tag", "firmware.witness.json"}


def atomic_file(path, value, private=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    try:
        with temporary.open("xb") as f:
            if private: os.chmod(temporary, 0o600)
            f.write(value); f.flush(); os.fsync(f.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            fd = os.open(path.parent, os.O_RDONLY)
            try: os.fsync(fd)
            finally: os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def exclusive(path):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as f:
        if path.stat().st_size == 0: f.write(b"\0"); f.flush()
        f.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise RuntimeError("another witness signing operation is active") from error
        try: yield
        finally:
            f.seek(0)
            if os.name == "nt": msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            else: fcntl.flock(f, fcntl.LOCK_UN)


def package_digest(files):
    expected = {"manifest.json", "firmware.bin", "firmware.kem", "firmware.nonce", "firmware.tag"}
    if not expected <= files.keys(): raise ValueError("incomplete package")
    m = json.loads(files["manifest.json"])
    for k in ("version", "size", "encrypted_size"):
        if type(m[k]) is not int or not 0 <= m[k] < 2**32: raise ValueError("invalid package integer")
    if len(files["firmware.kem"]) != 1088 or len(files["firmware.nonce"]) != 12 or len(files["firmware.tag"]) != 16:
        raise ValueError("invalid cryptographic field length")
    if m["encrypted_size"] != len(files["firmware.bin"]): raise ValueError("ciphertext length mismatch")
    return bytes.fromhex(digest(m["version"].to_bytes(4,"big") + m["size"].to_bytes(4,"big") + m["encrypted_size"].to_bytes(4,"big") + bytes.fromhex(digest(files["firmware.bin"])) + files["firmware.kem"] + files["firmware.nonce"] + files["firmware.tag"]))


def encode_files(files): return canonical({k:b64(v) for k,v in files.items()})
def decode_files(raw): return {k:unb64(v) for k,v in json.loads(raw).items()}


class Signer:
    def __init__(self, deployment, ota_root, native=None, fault=None):
        self.deployment, self.ota = Path(deployment).resolve(), Path(ota_root).resolve()
        self.client = Client(self.deployment)
        self.native = native or Native()
        self.directory = self.deployment / "signer"
        self.directory.mkdir(mode=0o700, exist_ok=True)
        self.path = self.directory / "state.sqlite"
        if not self.path.exists(): raise ValueError("signer not enrolled; refusing implicit key import")
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL"); self.db.execute("PRAGMA synchronous=FULL")
        if self.db.execute("PRAGMA integrity_check").fetchone()[0] != "ok": raise ValueError("signer database corruption")
        state = self.state()
        if state["ledger"] != self.client.config["ledger_id"] or digest(state["public"]) != self.client.key["key_id"]:
            raise ValueError("signer ledger/publisher mismatch")
        if (self.deployment / state["ota_root"]).resolve() != self.ota: raise ValueError("signer is enrolled to another OTA directory")
        self.fault = fault or (lambda stage: None)

    @staticmethod
    def enroll(deployment, ota_root, state, public):
        deployment, ota_root = Path(deployment).resolve(), Path(ota_root).resolve()
        client = Client(deployment); Native().check(state, public)
        if digest(public) != client.key["key_id"]: raise ValueError("publisher enrollment mismatch")
        directory = deployment / "signer"; directory.mkdir(mode=0o700, exist_ok=True)
        path = directory / "state.sqlite"
        if path.exists(): raise ValueError("refusing to replace enrolled signing state")
        db = sqlite3.connect(path)
        db.execute("PRAGMA journal_mode=WAL"); db.execute("PRAGMA synchronous=FULL")
        db.executescript("""
        CREATE TABLE state(id INTEGER PRIMARY KEY CHECK(id=1),secret BLOB NOT NULL,public BLOB NOT NULL,ledger TEXT NOT NULL,ota_root TEXT NOT NULL,sequence INTEGER NOT NULL);
        CREATE TABLE operations(id TEXT PRIMARY KEY,job TEXT NOT NULL,status TEXT NOT NULL,idx INTEGER NOT NULL,event TEXT NOT NULL,certificate TEXT,files BLOB NOT NULL,signature BLOB,generation TEXT,terminal_event TEXT,terminal_certificate TEXT,error TEXT);
        CREATE INDEX jobs ON operations(job);
        """)
        with db: db.execute("INSERT INTO state VALUES(1,?,?,?,?,0)", (state,public,client.config["ledger_id"],os.path.relpath(ota_root, deployment)))
        db.close(); os.chmod(path,0o600)

    def state(self): return self.db.execute("SELECT * FROM state WHERE id=1").fetchone()

    def mirror(self):
        state=self.state()
        atomic_file(self.ota/"xmss_private.key",state["secret"],private=True)
        if (self.ota/"firmware.pub").read_bytes()!=state["public"]: raise ValueError("public-key mirror was changed")

    def check_mirror(self):
        state=self.state(); mirror=(self.ota/"xmss_private.key").read_bytes()
        if mirror == state["secret"]: return
        if len(mirror)!=len(state["secret"]) or mirror[4:132]!=state["secret"][4:132]:
            raise ValueError("legacy signing key identity changed")
        if int.from_bytes(mirror[:4],"big")>int.from_bytes(state["secret"][:4],"big"):
            raise ValueError("legacy signing state is ahead of journal; stop and reconcile")
        # A crash may leave the compatibility mirror behind authoritative state.
        self.mirror()

    def recover(self):
        self.check_mirror()
        pending=list(self.db.execute("SELECT * FROM operations WHERE status IN ('RESERVING','QUORUM','INTENT') ORDER BY rowid"))
        for op in pending:
            current=self.state()["secret"]; index=int.from_bytes(current[:4],"big")
            if index<op["idx"]: raise ValueError("signer journal index regression")
            next_state=self.native.advance(current) if index==op["idx"] else current
            with self.db:
                self.db.execute("UPDATE state SET secret=? WHERE id=1",(next_state,))
                self.db.execute("UPDATE operations SET status='ABANDONED',error='uncertain previous process; permanently consumed' WHERE id=?",(op["id"],))
            self.mirror()

    async def report(self, op_id):
        op=self.db.execute("SELECT * FROM operations WHERE id=?",(op_id,)).fetchone()
        if op["terminal_certificate"] or not op["certificate"]: return
        certificate=json.loads(op["certificate"]); original=json.loads(op["event"])
        if not certificate["result"].get("ok"): return
        if op["status"] not in {"COMPLETED","ABANDONED"}: return
        if op["terminal_event"]: event=json.loads(op["terminal_event"])
        else:
            completed=op["status"]=="COMPLETED"
            event=self.client.command(op["idx"],original["command"]["digest"],"COMPLETE" if completed else "ABANDON",certificate["result"]["hash"],b64(bytes.fromhex(digest(op["signature"]+bytes.fromhex(certificate["result"]["hash"])))) if completed else "",sequence=original["command"]["sequence"],reason=0 if completed else 1)
            with self.db: self.db.execute("UPDATE operations SET terminal_event=? WHERE id=?",(canonical(event).decode(),op_id))
        try:
            terminal=await self.client.submit(event,timeout=6)
            verify_certificate(terminal,event["command"],self.client.config)
            if terminal["result"].get("ok"):
                with self.db: self.db.execute("UPDATE operations SET terminal_certificate=? WHERE id=?",(canonical(terminal).decode(),op_id))
        except Exception:
            pass # Immutable outbox retained for an explicit retry.

    async def sign_package(self, files, job=None, timeout=35):
        files={k:v for k,v in files.items() if k in PACKAGE_NAMES-{"firmware.sig","firmware.pub","firmware.witness.json"}}
        message=package_digest(files); job=job or digest(b"PACKAGE"+encode_files(files))
        self.recover()
        old=self.db.execute("SELECT * FROM operations WHERE job=? AND status='COMPLETED' ORDER BY rowid DESC LIMIT 1",(job,)).fetchone()
        if old:
            cert=json.loads(old["certificate"]);event=json.loads(old["event"])
            verify_certificate(cert,event["command"],self.client.config)
            saved=decode_files(old["files"])
            if not self.native.verify(old["signature"],package_digest(saved),self.state()["public"]): raise ValueError("stored result corruption")
            await self.report(old["id"])
            return self.result(old["id"])
        for _ in range(1023):
            state=self.state(); secret,public=state["secret"],state["public"]
            self.native.check(secret,public)
            index=int.from_bytes(secret[:4],"big"); sequence=state["sequence"]+1
            event=self.client.command(index,message.hex(),sequence=sequence)
            op_id=event["command"]["event_id"]
            with self.db:
                self.db.execute("UPDATE state SET sequence=? WHERE id=1",(sequence,))
                self.db.execute("INSERT INTO operations(id,job,status,idx,event,files) VALUES(?,?,'RESERVING',?,?,?)",(op_id,job,index,canonical(event).decode(),encode_files(files)))
            self.fault("request_durable")
            cert=await self.client.submit(event,timeout=timeout)
            verified=verify_certificate(cert,event["command"],self.client.config)
            if not verified.get("ok"):
                next_state=self.native.advance(secret)
                with self.db:
                    self.db.execute("UPDATE state SET secret=? WHERE id=1",(next_state,))
                    self.db.execute("UPDATE operations SET status='ABANDONED',certificate=?,error='witness rejected already-consumed token' WHERE id=?",(canonical(cert).decode(),op_id))
                self.mirror()
                if verified.get("error")!="token permanently consumed": raise ValueError("witness reservation rejected")
                continue
            with self.db: self.db.execute("UPDATE operations SET status='QUORUM',certificate=? WHERE id=?",(canonical(cert).decode(),op_id))
            self.fault("quorum_durable")
            advanced=self.native.advance(secret)
            # Allocate permanently before producing a one-time signature. The
            # old state exists only in this serialized process's memory now.
            with self.db:
                self.db.execute("UPDATE state SET secret=? WHERE id=1",(advanced,))
                self.db.execute("UPDATE operations SET status='INTENT' WHERE id=?",(op_id,))
            self.mirror()
            self.fault("advance_durable")
            signature,after=self.native.sign(secret,message,public)
            if after!=advanced: raise ValueError("native BDS transition differs from durable allocation")
            self.fault("native_returned")
            output=dict(files,**{"firmware.sig":signature,"firmware.pub":public,"firmware.witness.json":canonical(cert)})
            generation=self.deployment/"publications"/op_id
            generation.mkdir(parents=True,exist_ok=False)
            for name,value in output.items(): atomic_file(generation/name,value)
            with self.db:
                self.db.execute("UPDATE operations SET status='COMPLETED',signature=?,generation=? WHERE id=?",(signature,os.path.relpath(generation, self.deployment),op_id))
            self.fault("result_durable")
            await self.report(op_id)
            return self.result(op_id)
        raise ValueError("no remaining unconsumed XMSS capacity")

    def result(self,op_id):
        op=self.db.execute("SELECT * FROM operations WHERE id=?",(op_id,)).fetchone()
        if op["status"]!="COMPLETED": raise ValueError("operation has no completed result")
        directory=(self.deployment / op["generation"]).resolve()
        files={name:(directory/name).read_bytes() for name in PACKAGE_NAMES}
        if files["firmware.sig"]!=op["signature"] or package_digest(files)!=package_digest(decode_files(op["files"])):
            raise ValueError("immutable publication was altered")
        if files["firmware.pub"]!=self.state()["public"] or json.loads(files["firmware.witness.json"])!=json.loads(op["certificate"]):
            raise ValueError("publication proof/key corruption")
        event=json.loads(op["event"]); certificate=json.loads(op["certificate"])
        verified=verify_certificate(certificate,event["command"],self.client.config)
        message=package_digest(files)
        if not verified.get("ok") or event["command"]["digest"]!=message.hex() or event["command"]["token"]!=token(unb64(self.client.key["index_key"]),self.client.key["key_id"],op["idx"]) or not self.native.verify(op["signature"],message,files["firmware.pub"]):
            raise ValueError("completed result failed authorization/signature audit")
        return {"operation":op_id,"index":op["idx"],"generation":str(directory),"files":files,"certificate":json.loads(op["certificate"])}

    def publish(self,result):
        files=result["files"];version=json.loads(files["manifest.json"])["version"]
        pointer_path=self.ota/"witness-publication.json"
        if pointer_path.exists():
            old=json.loads(pointer_path.read_text())
            old_version=json.loads((self.ota / old["generation"] / "manifest.json").read_bytes())["version"]
            if version<old_version: raise ValueError("refusing to republish older version")
            if version==old_version and old["operation"]!=result["operation"]: raise ValueError("version already bound to another package")
        pointer={"schema":1,"ledger":self.client.config["ledger_id"],"operation":result["operation"],"generation":os.path.relpath(result["generation"], self.ota),"hashes":{k:digest(v) for k,v in files.items()}}
        atomic_file(pointer_path,canonical(pointer))
        self.fault("publication_durable")
        # Compatibility files for existing host tools. The HTTP server reads the
        # atomic immutable-generation pointer, not these individual mirrors.
        for name,value in files.items(): atomic_file(self.ota/name,value)


async def publish_firmware(signer,version):
    if type(version) is not int or not 1<=version<2**32: raise ValueError("version outside uint32")
    firmware=(signer.ota/"input_firmware.bin").read_bytes()
    if not 0<len(firmware)<=0x1E0000: raise ValueError("firmware length outside OTA bounds")
    recipient=(signer.ota/"mlkem_device.pub").read_bytes()
    if len(recipient)!=1184: raise ValueError("recipient enrollment missing")
    job=digest(b"OTA-PUBLISH-v1"+version.to_bytes(4,"big")+bytes.fromhex(digest(firmware))+bytes.fromhex(digest(recipient)))
    # Existing completed job restores the exact original encrypted package.
    old=signer.db.execute("SELECT files FROM operations WHERE job=? AND status='COMPLETED' ORDER BY rowid DESC LIMIT 1",(job,)).fetchone()
    if old: files=decode_files(old["files"])
    else:
        current=signer.ota/"manifest.json"
        if current.exists() and version<=json.loads(current.read_bytes())["version"]: raise ValueError("new version must exceed published version")
        kem,shared=ml_kem_768.encaps(recipient);nonce=os.urandom(12)
        encrypted=AESGCM(shared).encrypt(nonce,firmware,None)
        # The deployed ESP32 uses an ordered sscanf manifest parser. Keep this
        # wire representation separate from sorted canonical proof encoding.
        manifest={"version":version,"size":len(firmware),"encrypted_size":len(firmware)}
        files={"manifest.json":json.dumps(manifest,separators=(",", ":")).encode(),"firmware.bin":encrypted[:-16],"firmware.kem":kem,"firmware.nonce":nonce,"firmware.tag":encrypted[-16:]}
    result=await signer.sign_package(files,job=job)
    signer.publish(result)
    return result


async def run(args):
    config_path = Path(args.config).resolve()
    config=json.loads(config_path.read_text())
    for key in ("deployment", "ota_root"):
        config[key] = str((config_path.parent / config[key]).resolve())
    if config.get("required") is not True: raise ValueError("witness authorization must be required")
    signer=Signer(config["deployment"],config["ota_root"])
    if signer.client.key["key_id"]!=config["publisher_id"]: raise ValueError("connection publisher mismatch")
    with exclusive(signer.directory/"signer.lock"):
        if args.action=="publish":
            result=await publish_firmware(signer,args.version)
            print(f"Published encrypted version {args.version}; five verified witness approvals; XMSS index {result['index']}; operation {result['operation']}")
        elif args.action=="sign-package":
            raw=sys.stdin.buffer.read(4*1024*1024+1)
            if len(raw)>4*1024*1024: raise ValueError("package input too large")
            result=await signer.sign_package(decode_files(raw))
            sys.stdout.buffer.write(encode_files(result["files"]))
        elif args.action=="retry-reports":
            for op in signer.db.execute("SELECT id FROM operations WHERE status IN ('COMPLETED','ABANDONED') AND terminal_certificate IS NULL"):
                await signer.report(op["id"])
            print("Completion/abandonment outbox retry finished")
        elif args.action=="preflight":
            signer.check_mirror()
            state=signer.state();signer.native.check(state["secret"],state["public"])
            statuses=await signer.client.status();online=[s for s in statuses if not s.get("offline") and s["leader"]>0]
            if len(online)<5:raise ValueError("fewer than five witnesses are reachable; signing would be blocked")
            print(json.dumps({"connected":True,"publisher_id":signer.client.key["key_id"],"ledger_id":signer.client.config["ledger_id"],"reachable":len(online),"required":5,"preflight_only":True,"signature_created":False}))
    signer.db.close()


if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("action",choices=["publish","sign-package","retry-reports","preflight"]);p.add_argument("--config",required=True);p.add_argument("--version",type=int);a=p.parse_args()
    try: asyncio.run(run(a))
    except Exception as error:
        print("Witness signing blocked: "+str(error),file=sys.stderr);sys.exit(1)
