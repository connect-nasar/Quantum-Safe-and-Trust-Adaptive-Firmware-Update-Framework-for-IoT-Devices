"""Locate moved research evidence without rewriting historical records."""
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIRS = frozenset({"benchmarks", "collection_runs", "correctness", "experiments", "journal_studies", "security_tests", "witness_device_runs"})


def relocated_path(value):
    path = Path(value)
    if path.exists():
        return path
    try:
        relative = path.resolve().relative_to(APP_ROOT)
    except ValueError:
        return path
    if relative.parts and relative.parts[0] in EVIDENCE_DIRS:
        moved = APP_ROOT / "test" / relative
        if moved.exists():
            return moved
    return path


def experiment_directory(root):
    root = Path(root)
    current = root / "test" / "experiments"
    historical = root / "experiments"
    if not current.exists() and historical.exists():
        return historical
    return current
