import json
import sqlite3
from pathlib import Path
from .crypto import canonical, digest, b64
from .codec import validate, record


class Store:
    def __init__(self, path, config, verify_on_open=True):
        self.config = config
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY,v TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS decisions(slot INTEGER PRIMARY KEY,proof TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS records(height INTEGER PRIMARY KEY,hash TEXT UNIQUE NOT NULL,body TEXT NOT NULL,event TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS events(client TEXT,event_id TEXT,command_hash TEXT,result TEXT,PRIMARY KEY(client,event_id));
        CREATE TABLE IF NOT EXISTS reservations(key_id TEXT,token TEXT,digest TEXT,reference TEXT,state TEXT,PRIMARY KEY(key_id,token));
        """)
        with self.db:
            old = self.db.execute("SELECT v FROM meta WHERE k='genesis'").fetchone()
            if old and old[0] != config["ledger_id"]:
                raise ValueError("database belongs to another ledger")
            self.db.execute("INSERT OR IGNORE INTO meta VALUES('genesis',?)", (config["ledger_id"],))
            for key_id, registration in config["publishers"].items():
                for token in registration.get("bootstrap_consumed_tokens", []):
                    reference = digest(b"WITNESS-IMPORTED-v1" + bytes.fromhex(key_id) + bytes.fromhex(token))
                    self.db.execute("INSERT OR IGNORE INTO reservations VALUES(?,?,?,?,?)", (key_id, token, "00"*32, reference, "ABANDONED"))
        if verify_on_open:
            self.audit()

    def tip(self):
        row = self.db.execute("SELECT height,hash FROM records ORDER BY height DESC LIMIT 1").fetchone()
        return (row[0], row[1]) if row else (0, self.config["ledger_id"])

    def latest(self):
        row = self.db.execute("SELECT proof FROM decisions ORDER BY slot DESC LIMIT 1").fetchone()
        return json.loads(row[0]) if row else {"Proposal": {}, "Signatures": []}

    def decisions(self, after=0):
        return [json.loads(r[0]) for r in self.db.execute("SELECT proof FROM decisions WHERE slot>? ORDER BY slot LIMIT 32", (after,))]

    def result(self, client, event_id):
        row = self.db.execute("SELECT result FROM events WHERE client=? AND event_id=?", (client, event_id)).fetchone()
        return json.loads(row[0]) if row else None

    def snapshot(self):
        state = {}
        for table, order in (("records", "height"), ("reservations", "key_id,token"), ("events", "client,event_id")):
            state[table] = [dict(r) for r in self.db.execute(f"SELECT * FROM {table} ORDER BY {order}")]
        return canonical(state)

    def apply(self, event, decision, slot):
        c = validate(event, self.config)
        raw_hash = digest(canonical(c))
        with self.db:
            existing_slot = self.db.execute("SELECT proof FROM decisions WHERE slot=?", (slot,)).fetchone()
            if existing_slot:
                if json.loads(existing_slot[0])["Proposal"] != decision["Proposal"]:
                    raise ValueError("conflicting finalized decision")
                return self.result(c["client"], c["event_id"])
            last_slot = self.db.execute("SELECT COALESCE(MAX(slot),0) FROM decisions").fetchone()[0]
            if slot != last_slot + 1:
                raise ValueError("decision gap")
            old = self.db.execute("SELECT command_hash,result FROM events WHERE client=? AND event_id=?", (c["client"], c["event_id"])).fetchone()
            if old:
                self.db.execute("INSERT INTO decisions VALUES(?,?)", (slot, canonical(decision).decode()))
                return json.loads(old[1]) if old[0] == raw_hash else {"ok": False, "error": "event ID conflict"}
            reserved = self.db.execute("SELECT * FROM reservations WHERE key_id=? AND token=?", (c["key_id"], c["token"])).fetchone()
            error = None
            if c["type"] == "RESERVE":
                if reserved:
                    error = "token permanently consumed"
            elif not reserved or reserved["reference"] != c["reference"] or reserved["digest"] != c["digest"]:
                error = "reservation reference mismatch"
            elif reserved["state"] != "RESERVED":
                error = "terminal reservation"
            if error:
                result = {"ok": False, "error": error}
            else:
                height, previous = self.tip()
                body, h = record(c, self.config, height + 1, previous)
                result = {"ok": True, "height": height + 1, "hash": h, "body": b64(body), "event": event, "slot": slot, "state": {"RESERVE": "RESERVED", "COMPLETE": "COMPLETED", "ABANDON": "ABANDONED"}[c["type"]]}
                self.db.execute("INSERT INTO records VALUES(?,?,?,?)", (height + 1, h, b64(body), canonical(event).decode()))
                if c["type"] == "RESERVE":
                    self.db.execute("INSERT INTO reservations VALUES(?,?,?,?,?)", (c["key_id"], c["token"], c["digest"], h, "RESERVED"))
                else:
                    self.db.execute("UPDATE reservations SET state=? WHERE key_id=? AND token=?", (result["state"], c["key_id"], c["token"]))
            self.db.execute("INSERT INTO events VALUES(?,?,?,?)", (c["client"], c["event_id"], raw_hash, canonical(result).decode()))
            self.db.execute("INSERT INTO decisions VALUES(?,?)", (slot, canonical(decision).decode()))
        return result

    def audit(self):
        from .proof import verify_decision
        if self.db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("database integrity failure")
        previous = self.config["ledger_id"]
        expected = 1
        for row in self.db.execute("SELECT * FROM records ORDER BY height"):
            c = validate(json.loads(row["event"]), self.config)
            body, h = record(c, self.config, expected, previous)
            if row["height"] != expected or row["hash"] != h or row["body"] != b64(body):
                raise ValueError("ledger hash chain corruption")
            previous, expected = h, expected + 1
        replay = Store(":memory:", self.config, verify_on_open=False)
        for row in self.db.execute("SELECT slot,proof FROM decisions ORDER BY slot"):
            decision = json.loads(row["proof"])
            event, _, slot = verify_decision(decision, self.config)
            if slot != row["slot"]:
                raise ValueError("stored decision slot mismatch")
            replay.apply(event, decision, slot)
        for table, ordering in (("records", "height"), ("reservations", "key_id,token"), ("events", "client,event_id")):
            actual = [tuple(r) for r in self.db.execute(f"SELECT * FROM {table} ORDER BY {ordering}")]
            rebuilt = [tuple(r) for r in replay.db.execute(f"SELECT * FROM {table} ORDER BY {ordering}")]
            if actual != rebuilt:
                raise ValueError(f"{table} differs from certified replay")
        replay.db.close()
        return {"height": expected - 1, "tip": previous}
