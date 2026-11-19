"""Offline verification of SmartBFT proposal commit signatures and ledger results."""
import json
from .crypto import unb64, digest, verify, canonical
from .codec import validate, record, RECORD


def der(tag, value):
    n = len(value)
    length = bytes([n]) if n < 128 else bytes([0x80 + (n.bit_length() + 7)//8]) + n.to_bytes((n.bit_length()+7)//8, "big")
    return bytes([tag]) + length + value


def proposal_digest(p):
    n = p.get("VerificationSequence", 0)
    if n < 0:
        raise ValueError("negative verification sequence")
    integer = n.to_bytes(max(1, (n.bit_length()+7)//8), "big")
    if integer[0] & 128:
        integer = b"\0" + integer
    fields = b"".join(der(4, unb64(p.get(k) or "")) for k in ("Payload", "Header", "Metadata")) + der(2, integer)
    return digest(der(0x30, fields))


def metadata(raw):
    """Read standard protobuf uint fields 1/2, skip other wire fields safely."""
    i, values = 0, {}
    def varint():
        nonlocal i
        value = 0
        for shift in range(0, 70, 7):
            if i >= len(raw):
                raise ValueError("truncated metadata")
            b = raw[i]; i += 1
            value |= (b & 127) << shift
            if b < 128:
                return value
        raise ValueError("oversize varint")
    while i < len(raw):
        tag = varint(); wire = tag & 7
        if wire == 0:
            values[tag >> 3] = varint()
        elif wire == 2:
            n = varint(); i += n
        elif wire in (1, 5):
            i += 8 if wire == 1 else 4
        else:
            raise ValueError("invalid metadata wire type")
        if i > len(raw):
            raise ValueError("truncated metadata")
    return values.get(1, 0), values.get(2, 0)


def verify_decision(decision, config):
    p = decision["Proposal"]
    if unb64(p["Header"]) != config["ledger_id"].encode() or p["VerificationSequence"] != 1:
        raise ValueError("decision belongs to another ledger/suite")
    event = json.loads(unb64(p["Payload"]))
    validate(event, config)
    d = proposal_digest(p)
    seen = set()
    for s in decision["Signatures"]:
        node = str(s["ID"])
        if node not in config["nodes"] or node in seen:
            raise ValueError("unknown or duplicate commit voter")
        seen.add(node)
        message = unb64(s["Msg"])
        if json.loads(message)["Digest"] != d:
            raise ValueError("commit signature not bound to proposal")
        verify(unb64(config["nodes"][node]["public"]), bytes.fromhex(config["ledger_id"]) + message, unb64(s["Value"]), b"WITNESS-ENGINE-v1")
    if len(seen) < 5:
        raise ValueError("fewer than five commit voters")
    view, slot = metadata(unb64(p["Metadata"]))
    if slot < 1:
        raise ValueError("invalid consensus slot")
    return event, view, slot


def verify_result(response, command, config):
    node = str(response["witness"])
    if node not in config["nodes"]:
        raise ValueError("unprovisioned result identity")
    payload = response["payload"]
    if payload["ledger"] != config["ledger_id"] or payload["event_hash"] != digest(canonical(command)):
        raise ValueError("result request binding failed")
    verify(unb64(config["nodes"][node]["public"]), canonical(payload), unb64(response["signature"]), b"WITNESS-RESULT-v2")
    result = payload["result"]
    if result.get("ok"):
        event, _, slot = verify_decision(result["decision"], config)
        if event != result["event"] or event["command"] != command or slot != result["slot"]:
            raise ValueError("result is not the committed command")
        raw = unb64(result["body"])
        fields = RECORD.unpack(raw)
        body, h = record(command, config, result["height"], fields[6].hex())
        if raw != body or h != result["hash"]:
            raise ValueError("record hash mismatch")
    return result


def verify_certificate(certificate, command, config):
    seen, stable = set(), None
    for response in certificate["approvals"]:
        if response["witness"] in seen:
            raise ValueError("duplicate result voter")
        seen.add(response["witness"])
        result = verify_result(response, command, config)
        value = {k:v for k,v in result.items() if k != "decision"}
        if stable is not None and stable != value:
            raise ValueError("mismatched result votes")
        stable = value
    if len(seen) < 5:
        raise ValueError("insufficient result quorum")
    if certificate["result"] != certificate["approvals"][0]["payload"]["result"]:
        raise ValueError("certificate result differs from signed result")
    return stable
