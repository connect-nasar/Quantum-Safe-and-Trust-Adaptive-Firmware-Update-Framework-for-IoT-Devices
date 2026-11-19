from pathlib import Path
import json

BASE = Path(__file__).resolve().parents[1]


def active_root(root=None):
    if root is not None:
        return Path(root).resolve()
    pointer = BASE / "runtime/active.json"
    if pointer.exists(): return (pointer.parent / json.loads(pointer.read_text())["root"]).resolve()
    return BASE / "runtime/local"
