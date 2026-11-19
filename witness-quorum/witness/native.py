"""Deployed XMSS_MODE=1 binding, with a no-signature BDS burn transition."""
import ctypes
import os
import subprocess
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]


def build(workspace=None):
    workspace = Path(workspace) if workspace is not None else BASE.parent / "Ota_project"
    source = Path(workspace) / "crypto-libs/xmss/src"
    fips = Path(workspace) / "crypto-libs/fips202/src"
    output = BASE / "bin" / ("witness_xmss.dll" if os.name == "nt" else "libwitness_xmss.so")
    output.parent.mkdir(parents=True, exist_ok=True)
    names = ("XMSS_commons.c", "XMSS_hash.c", "XMSS_hash_address.c", "XMSS_hash_wrapper.c", "XMSS_randombytes.c", "XMSS_sha256.c", "XMSS_wots.c", "XMSS_xmss.c")
    inputs = [BASE / "native/xmss_advance.c", *(source / n for n in names), fips / "fips202.c"]
    command = ["gcc", "-O2", "-shared", "-DXMSS_MODE=1", "-I"+str(source), "-I"+str(fips), *(str(p) for p in inputs), "-o", str(output), "-lm"]
    if os.name == "nt": command += ["-lbcrypt"]
    else: command += ["-fPIC"]
    subprocess.run(command, check=True, capture_output=True, timeout=120)
    return output


class Native:
    def __init__(self, path=None):
        self.path = Path(path) if path else BASE / "bin" / ("witness_xmss.dll" if os.name == "nt" else "libwitness_xmss.so")
        self.lib = ctypes.CDLL(str(self.path))
        self.lib.xmss_xmssmt_core_sk_bytes.restype = ctypes.c_ulonglong
        self.size = self.lib.xmss_xmssmt_core_sk_bytes()
        self.lib.xmss_keypair.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self.lib.xmss_sign.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_void_p, ctypes.c_ulonglong]
        self.lib.xmss_sign_open.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p]
        self.lib.witness_xmss_advance.argtypes = [ctypes.c_void_p]

    def check(self, state, public):
        if len(state) != self.size or len(public) != 64 or state[68:132] != public:
            raise ValueError("XMSS key/state profile mismatch")
        if int.from_bytes(state[:4], "big") >= 1023:
            raise ValueError("XMSS usable capacity exhausted; final leaf reserved")

    def keypair(self):
        public = ctypes.create_string_buffer(64); state = ctypes.create_string_buffer(self.size)
        if self.lib.xmss_keypair(public, state): raise ValueError("XMSS key generation failed")
        return public.raw, state.raw

    def advance(self, state):
        if len(state) != self.size: raise ValueError("wrong XMSS state length")
        buf = ctypes.create_string_buffer(state, len(state))
        if self.lib.witness_xmss_advance(buf): raise ValueError("XMSS state cannot advance")
        return buf.raw

    def sign(self, state, message, public):
        self.check(state, public)
        if len(message) != 32: raise ValueError("package digest must be 32 bytes")
        index = int.from_bytes(state[:4], "big")
        buf = ctypes.create_string_buffer(state, len(state)); out = ctypes.create_string_buffer(2532); n = ctypes.c_ulonglong()
        if self.lib.xmss_sign(buf, out, ctypes.byref(n), ctypes.create_string_buffer(message), 32) or n.value != 2532:
            raise ValueError("XMSS signing failed")
        signature = out.raw[:2500]
        if int.from_bytes(signature[:4], "big") != index or int.from_bytes(buf.raw[:4], "big") != index + 1:
            raise ValueError("XMSS index transition mismatch")
        if not self.verify(signature, message, public): raise ValueError("new XMSS signature failed verification")
        return signature, buf.raw

    def verify(self, signature, message, public):
        if len(signature) != 2500 or len(message) != 32 or len(public) != 64: return False
        out = ctypes.create_string_buffer(2532); n = ctypes.c_ulonglong()
        return self.lib.xmss_sign_open(out, ctypes.byref(n), ctypes.create_string_buffer(signature+message), 2532, ctypes.create_string_buffer(public)) == 0 and n.value == 32 and out.raw[:32] == message


if __name__ == "__main__": print(build())
