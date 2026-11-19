"""Architecture-v2 canonical binary command and ledger encoding."""
import struct
from .crypto import unb64, b64, digest, sign, verify

COMMAND = struct.Struct(">4sHH32sQ32sBBH32s32s32s16sQ32s")
RECORD = struct.Struct(">4sHH32sQQ32sBBH32s32s32s16sQ32s20s")
ACK = struct.Struct(">4sHH32sQQQQ32s32s")
TYPES = {"RESERVE": 1, "COMPLETE": 2, "ABANDON": 3}


def fixed(value, length):
    raw = bytes.fromhex(value)
    if len(raw) != length or value != raw.hex():
        raise ValueError("noncanonical hex field")
    return raw


def encode_command(c, config):
    if set(c) != {"type", "client", "key_id", "token", "digest", "event_id", "sequence", "reference", "reason", "payload"}:
        raise ValueError("command fields mismatch")
    kind = TYPES[c["type"]]
    payload = unb64(c["payload"])
    if len(payload) != (32 if kind == 2 else 0):
        raise ValueError("wrong payload size")
    reason = c["reason"]
    if type(reason) is not int or not 0 <= reason <= 4 or (kind != 3 and reason != 0) or (kind == 3 and reason == 0):
        raise ValueError("invalid reason")
    if type(c["sequence"]) is not int or not 0 <= c["sequence"] < 2**63:
        raise ValueError("invalid sequence")
    ref = fixed(c["reference"], 32)
    if (kind == 1) != (ref == bytes(32)):
        raise ValueError("invalid reservation reference")
    body = COMMAND.pack(b"WCMD", 2, 1, fixed(config["ledger_id"], 32), config["epoch"], fixed(c["client"], 32), kind, 0, reason, fixed(c["key_id"], 32), fixed(c["token"], 32), fixed(c["digest"], 32), fixed(c["event_id"], 16), c["sequence"], ref)
    return body + struct.pack(">I", len(payload)) + payload


def envelope(c, config, secret):
    return {"command": c, "signature": b64(sign(secret, encode_command(c, config), b"WITNESS-CMD-v2"))}


def validate(e, config):
    if set(e) != {"command", "signature"}:
        raise ValueError("invalid envelope")
    c = e["command"]
    encoded = encode_command(c, config)
    identity = config["clients"].get(c["client"])
    publisher = config["publishers"].get(c["key_id"])
    if identity is None or publisher is None or publisher["client"] != c["client"]:
        raise ValueError("unauthorized client/publisher")
    verify(unb64(identity), encoded, unb64(e["signature"]), b"WITNESS-CMD-v2")
    return c


def record(c, config, height, previous):
    body = RECORD.pack(b"WLED", 2, 1, fixed(config["ledger_id"], 32), config["epoch"], height, fixed(previous, 32), TYPES[c["type"]], 0, c["reason"], fixed(c["key_id"], 32), fixed(c["token"], 32), fixed(c["digest"], 32), fixed(c["event_id"], 16), c["sequence"], fixed(c["reference"], 32), bytes(20))
    payload = unb64(c["payload"])
    return body, digest(b"WITNESS-LEDGER-v2" + body + struct.pack(">I", len(payload)) + payload)
