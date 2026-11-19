#!/usr/bin/env python3
"""
XMSS signer using ctypes to call the compiled C library functions.
Bypasses Windows Smart App Control by running as Python instead of .exe.

Usage: python xmss_signer_python.py <version>
"""

import json
import sys
import ctypes
import hashlib
import os
import subprocess
from pathlib import Path
from ctypes import c_char_p, c_size_t, c_int, c_uint, c_ulonglong, POINTER, create_string_buffer
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Load the compiled XMSS library built from the same C sources
ROOT = Path(__file__).resolve().parent

def load_xmss_lib():
    """Load the XMSS shared library."""
    try:
        # Try Windows DLL first
        lib_path = ROOT / "xmss_lib.dll"
        source_root = ROOT.parent.parent / "crypto-libs" / "xmss" / "src"
        fips_source = ROOT.parent.parent / "crypto-libs" / "fips202" / "src" / "fips202.c"
        xmss_sources = [
            source_root / name for name in (
                "XMSS_core_fast.c", "XMSS_commons.c", "XMSS_hash.c",
                "XMSS_hash_address.c", "XMSS_hash_wrapper.c",
                "XMSS_randombytes.c", "XMSS_sha256.c", "XMSS_wots.c",
                "XMSS_xmss.c",
            )
        ]
        sources = xmss_sources + [fips_source]
        rebuild = not lib_path.exists() or any(
            source.stat().st_mtime_ns > lib_path.stat().st_mtime_ns
            for source in sources
        )
        if rebuild:
            # Try to build it on demand
            print(f"Building xmss_lib.dll...", file=sys.stderr)
            import subprocess
            command = [
                "gcc", "-shared", "-o", str(lib_path),
                *(str(source) for source in sources),
                "-DXMSS_MODE=1",
                "-I" + str(source_root),
                "-I" + str(ROOT.parent.parent / "crypto-libs" / "fips202" / "src"),
                "-lm",
            ]
            if os.name == "nt":
                command.append("-lbcrypt")
            result = subprocess.run(
                command,
                cwd=str(ROOT),
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                print(f"Build failed: {result.stderr}", file=sys.stderr)
                return None
            print(f"Built xmss_lib.dll", file=sys.stderr)
        
        lib = ctypes.CDLL(str(lib_path))
        return lib
    except Exception as e:
        print(f"Failed to load XMSS library: {e}", file=sys.stderr)
        return None

def read_file(path):
    """Read binary file."""
    with open(path, 'rb') as f:
        return f.read()

def write_file(path, data):
    """Write binary file."""
    with open(path, 'wb') as f:
        f.write(data)

def encapsulate_mlkem(device_public_key):
    helper = ROOT / "mlkem_encapsulate.exe"
    if not helper.exists():
        include_dir = ROOT.parent.parent / "crypto-libs" / "host" / "liboqs" / "build" / "include"
        library = ROOT.parent.parent / "crypto-libs" / "host" / "liboqs" / "build" / "lib" / "liboqs.a"
        result = subprocess.run([
            "gcc", "-O2", "-I", str(include_dir), str(ROOT / "mlkem_encapsulate.c"),
            str(library), "-o", str(helper)
        ], cwd=str(ROOT), capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "ML-KEM helper build failed")

    kem_path = ROOT / "firmware.kem"
    secret_path = ROOT / "session.secret"
    result = subprocess.run([
        str(helper), str(device_public_key), str(kem_path), str(secret_path)
    ], cwd=str(ROOT), capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "ML-KEM encapsulation failed")
    return read_file(secret_path), read_file(kem_path)

def xmss_sign_firmware_native(version):
    """Sign only through the required external five-of-seven witness service."""
    try:
        from core.ota_witness_bridge import publish
        print(publish(ROOT, version))
        return True
    except Exception as error:
        print(f"Error: {error}", file=sys.stderr)
        return False


def rotate_xmss_key():
    """Generate a fresh XMSS signing keypair using the platform CSPRNG."""
    if (ROOT / "witness-connection.json").exists():
        print("Error: Witness-enrolled key rotation requires new publisher provisioning; automatic rotation is disabled.", file=sys.stderr)
        return False
    lib = load_xmss_lib()
    if lib is None:
        print("Error: Could not load XMSS library", file=sys.stderr)
        return False

    try:
        xmss_keypair = lib.xmss_keypair
        xmss_keypair.argtypes = [POINTER(ctypes.c_ubyte), POINTER(ctypes.c_ubyte)]
        xmss_keypair.restype = c_int
        secret_key_length_fn = lib.xmss_xmssmt_core_sk_bytes
        secret_key_length_fn.restype = c_size_t
    except AttributeError as error:
        print(f"Error: Required XMSS function not found: {error}", file=sys.stderr)
        return False

    public_key_length = 64  # XMSS_MODE=1
    secret_key_length = secret_key_length_fn()
    public_key = (ctypes.c_ubyte * public_key_length)()
    secret_key = (ctypes.c_ubyte * secret_key_length)()
    if xmss_keypair(public_key, secret_key) != 0:
        print("Error: XMSS key generation failed", file=sys.stderr)
        return False

    write_file(ROOT / "xmss_private.key", bytes(secret_key))
    write_file(ROOT / "firmware.pub", bytes(public_key))
    trusted_header = ROOT / "esp32_ota_hybrid" / "src" / "xmss_trusted_key.h"
    key_values = ", ".join(
        f"0x{value:02X}" for value in bytes(public_key)
    )
    trusted_header.write_text(
        "#ifndef XMSS_TRUSTED_KEY_H\n"
        "#define XMSS_TRUSTED_KEY_H\n\n"
        "static const unsigned char XMSS_TRUSTED_PUBLIC_KEY[64] = {\n"
        f"    {key_values}\n"
        "};\n\n"
        "#endif\n",
        encoding="ascii",
    )
    print("Generated a new XMSS_MODE=1 signing keypair with the OS CSPRNG.")
    print(f"Updated the ESP32 trust anchor at {trusted_header}.")
    print("Rebuild and USB-flash firmware with this public key pinned before publishing updates.")
    return True

def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--rotate-key":
        sys.exit(0 if rotate_xmss_key() else 1)
    if len(sys.argv) != 2:
        print("Usage: xmss_signer_python.py <version> | --rotate-key", file=sys.stderr)
        sys.exit(2)
    
    try:
        version = int(sys.argv[1])
        if version < 1:
            raise ValueError("version must be >= 1")
    except ValueError:
        print("Error: version must be a positive integer", file=sys.stderr)
        sys.exit(2)
    
    if not xmss_sign_firmware_native(version):
        sys.exit(1)
    
    sys.exit(0)

if __name__ == "__main__":
    main()
