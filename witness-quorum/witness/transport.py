"""Experimental mutually authenticated ephemeral ML-KEM record channel.

One bounded request/response per fresh connection: no traffic-key resumption.
This custom protocol has tests, not an independent cryptographic review.
"""
import asyncio
import json
import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .crypto import canonical, b64, unb64, sign, verify, derive, ml_kem_768

MAX_FRAME = 4 * 1024 * 1024
HEADER = struct.Struct(">4sHBB16sQI")


async def read_frame(reader):
    n = struct.unpack(">I", await reader.readexactly(4))[0]
    if n > MAX_FRAME:
        raise ValueError("frame too large")
    return await reader.readexactly(n)


async def write_frame(writer, data):
    if len(data) > MAX_FRAME:
        raise ValueError("frame too large")
    writer.write(struct.pack(">I", len(data)) + data)
    await writer.drain()


class Channel:
    def __init__(self, reader, writer, material, initiator, sid):
        self.reader, self.writer = reader, writer
        keys = (material[:32], material[32:64])
        prefixes = (material[64:68], material[68:72])
        self.tx = AESGCM(keys[0 if initiator else 1])
        self.rx = AESGCM(keys[1 if initiator else 0])
        self.tp, self.rp = prefixes[0 if initiator else 1], prefixes[1 if initiator else 0]
        self.sid = sid
        self.sent = self.received = 0

    async def send(self, value):
        raw = canonical(value)
        header = HEADER.pack(b"WREC", 1, 1, 0, self.sid, self.sent, len(raw))
        ct = self.tx.encrypt(self.tp + struct.pack(">Q", self.sent), raw, header)
        await write_frame(self.writer, header + ct)
        self.sent += 1

    async def receive(self):
        packet = await read_frame(self.reader)
        if len(packet) < HEADER.size + 16:
            raise ValueError("short record")
        magic, version, kind, flags, sid, sequence, n = HEADER.unpack(packet[:HEADER.size])
        if (magic, version, kind, flags, sid, sequence) != (b"WREC", 1, 1, 0, self.sid, self.received) or len(packet) != HEADER.size + n + 16:
            raise ValueError("record header/replay rejection")
        raw = self.rx.decrypt(self.rp + struct.pack(">Q", sequence), packet[HEADER.size:], packet[:HEADER.size])
        self.received += 1
        return json.loads(raw)


class Transport:
    def __init__(self, identity, secret, config):
        self.identity, self.secret, self.config = identity, secret, config
        self.keys = {str(k): v["public"] for k, v in config["nodes"].items()}
        self.keys.update(config["clients"])
        self.limit = asyncio.Semaphore(48)
        self.rejected = 0

    def check(self, identity, message, signature, context):
        if identity not in self.keys:
            raise ValueError("unprovisioned identity")
        verify(unb64(self.keys[identity]), message, unb64(signature), context)

    async def connect(self, host, port, target):
        reader, writer = await asyncio.open_connection(host, port, limit=MAX_FRAME)
        try:
            pk, sk = ml_kem_768.keygen()
            hello = {"version": 1, "suite": "ML-KEM-768/ML-DSA-65/AES-256-GCM", "ledger": self.config["ledger_id"], "from": self.identity, "to": str(target), "challenge": b64(os.urandom(32)), "kem": b64(pk)}
            await write_frame(writer, canonical({"hello": hello, "signature": b64(sign(self.secret, canonical(hello), b"WITNESS-HELLO-v1"))}))
            reply = json.loads(await read_frame(reader))
            response = reply["response"]
            if set(response) != {"challenge", "ciphertext"} or len(unb64(response["challenge"])) != 32:
                raise ValueError("bad responder challenge")
            transcript = canonical({"hello": hello, "response": response})
            self.check(str(target), transcript, reply["signature"], b"WITNESS-REPLY-v1")
            material = derive(ml_kem_768.decaps(sk, unb64(response["ciphertext"])), transcript)
            del sk
            channel = Channel(reader, writer, material, True, __import__('hashlib').sha256(transcript).digest()[:16])
            await channel.send({"finished": "initiator"})
            if await channel.receive() != {"finished": "responder"}:
                raise ValueError("key confirmation failed")
            return channel
        except BaseException:
            writer.close()
            await writer.wait_closed()
            raise

    async def request(self, target, payload, timeout=8):
        peer = self.config["nodes"][str(target)]
        async with self.limit:
            async with asyncio.timeout(timeout):
                channel = await self.connect(peer["host"], peer["port"], str(target))
                try:
                    await channel.send(payload)
                    result = await channel.receive()
                    if "error" in result:
                        raise ValueError(result["error"])
                    return result
                finally:
                    channel.writer.close()
                    await channel.writer.wait_closed()

    async def serve(self, reader, writer, handler):
        try:
            async with self.limit:
                async with asyncio.timeout(15):
                    packet = json.loads(await read_frame(reader))
                    hello = packet["hello"]
                    if set(hello) != {"version", "suite", "ledger", "from", "to", "challenge", "kem"} or hello["to"] != self.identity or hello["ledger"] != self.config["ledger_id"] or hello["version"] != 1 or hello["suite"] != "ML-KEM-768/ML-DSA-65/AES-256-GCM" or len(unb64(hello["challenge"])) != 32:
                        raise ValueError("wrong handshake binding")
                    self.check(hello["from"], canonical(hello), packet["signature"], b"WITNESS-HELLO-v1")
                    ct, shared = ml_kem_768.encaps(unb64(hello["kem"]))
                    response = {"challenge": b64(os.urandom(32)), "ciphertext": b64(ct)}
                    transcript = canonical({"hello": hello, "response": response})
                    await write_frame(writer, canonical({"response": response, "signature": b64(sign(self.secret, transcript, b"WITNESS-REPLY-v1"))}))
                    channel = Channel(reader, writer, derive(shared, transcript), False, __import__('hashlib').sha256(transcript).digest()[:16])
                    if await channel.receive() != {"finished": "initiator"}:
                        raise ValueError("key confirmation failed")
                    await channel.send({"finished": "responder"})
                    request = await channel.receive()
                    try:
                        result = await handler(hello["from"], request)
                    except (ValueError, KeyError, TypeError) as error:
                        result = {"error": str(error)}
                    await channel.send(result)
        except (Exception, asyncio.CancelledError):
            self.rejected += 1
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
