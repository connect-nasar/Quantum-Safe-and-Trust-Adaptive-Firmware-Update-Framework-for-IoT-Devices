#!/usr/bin/env python3
import re
import sys
from pathlib import Path

EXPECTED_BYTES = 1184

if len(sys.argv) != 3:
    raise SystemExit("Usage: python save_mlkem_public_key.py SERIAL_LOG OUTPUT_KEY")

text = Path(sys.argv[1]).read_text(errors="ignore")
hex_lines = re.findall(r"^[0-9a-fA-F]{32}$", text, re.MULTILINE)
key = bytes.fromhex("".join(hex_lines))
if len(key) != EXPECTED_BYTES:
    raise SystemExit(f"Expected {EXPECTED_BYTES} public-key bytes, found {len(key)}")
Path(sys.argv[2]).write_bytes(key)
print(f"Wrote {len(key)} bytes to {sys.argv[2]}")
