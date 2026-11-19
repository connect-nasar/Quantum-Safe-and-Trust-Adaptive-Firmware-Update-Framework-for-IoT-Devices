"""Check publisher output against the deployed device's actual sscanf format."""
import ctypes
import os
import sqlite3
from types import SimpleNamespace
import pytest
from witness.crypto import ml_kem_768
from witness.ota_signer import publish_firmware


@pytest.mark.asyncio
@pytest.mark.parametrize("version", [301, 2**32 - 1])
async def test_publisher_manifest_parses_with_deployed_c_format(tmp_path, version):
    public, _ = ml_kem_768.keygen()
    (tmp_path / "mlkem_device.pub").write_bytes(public)
    (tmp_path / "input_firmware.bin").write_bytes(bytes(42))
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE operations(job TEXT,status TEXT,files TEXT)")
    captured = []

    async def sign_package(files, job):
        captured.append(files)
        return {"files": files}

    signer = SimpleNamespace(ota=tmp_path, db=db, sign_package=sign_package, publish=lambda result: None)
    try:
        await publish_firmware(signer, version)
        raw = captured[0]["manifest.json"]
        assert raw == ('{"version":%d,"size":42,"encrypted_size":42}' % version).encode()
        runtime = ctypes.CDLL("msvcrt" if os.name == "nt" else None)
        v, size, encrypted = ctypes.c_uint(), ctypes.c_int(), ctypes.c_int()
        count = runtime.sscanf(ctypes.c_char_p(raw), ctypes.c_char_p(b'{"version":%u,"size":%d,"encrypted_size":%d}'), ctypes.byref(v), ctypes.byref(size), ctypes.byref(encrypted))
        assert (count, v.value, size.value, encrypted.value) == (3, version, 42, 42)
    finally:
        db.close()
