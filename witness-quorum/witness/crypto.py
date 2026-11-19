import base64
import hashlib
import hmac
import json
import struct

from pqcrypto.sign import ml_dsa_65
from pqcrypto.kem import ml_kem_768
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def b64(value):
    return base64.b64encode(value).decode()


def unb64(value):
    return base64.b64decode(value, validate=True)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def sign(secret, message, context):
    return ml_dsa_65.sign(secret, message, context=context)


def verify(public, message, signature, context):
    try:
        if ml_dsa_65.verify(public, message, signature, context=context) is False:
            raise ValueError("invalid ML-DSA signature")
    except Exception as error:
        raise ValueError("invalid ML-DSA signature") from error


def token(secret, key_id, index):
    if len(secret) != 32 or not 0 <= index < 2**64:
        raise ValueError("invalid private token input")
    return hmac.new(secret, b"WITNESS-IDX-v1" + bytes.fromhex(key_id) + struct.pack(">Q", index), hashlib.sha256).hexdigest()


def derive(shared, transcript):
    return HKDF(algorithm=hashes.SHA256(), length=72, salt=hashlib.sha256(transcript).digest(), info=b"WITNESS-CHANNEL-v1").derive(shared)
