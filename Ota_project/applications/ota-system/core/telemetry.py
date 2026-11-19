"""Thread-safe live telemetry and bounded retries for Windows file contention."""
from collections import deque
from datetime import datetime, timezone
import errno
import json
import os
from pathlib import Path
import tempfile
import threading
import time


def retry_io(action):
    for attempt in range(5):
        try:
            return action()
        except OSError as error:
            transient = error.errno in (errno.EACCES, errno.EPERM, errno.EBUSY, errno.EINVAL)
            transient = transient or getattr(error, "winerror", None) in (32, 33)
            if not transient or attempt == 4:
                raise
            time.sleep(0.02 * (attempt + 1))


def atomic_write(path, payload):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        retry_io(lambda: os.replace(temporary, path))
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class TelemetryStore:
    def __init__(self, root):
        self.root = Path(root)
        self.lock = threading.RLock()
        self.latest = None
        self.events = deque(maxlen=100)
        self.last_seen = None
        self.persistence_error = ""
        try:
            value = json.loads((self.root / "device_status.json").read_bytes())
            if isinstance(value, dict):
                self.latest = value
        except (OSError, ValueError):
            pass

    def observe(self, status):
        status = dict(status, server_received_at=datetime.now(timezone.utc).isoformat(
            timespec="milliseconds").replace("+00:00", "Z"))
        payload = json.dumps(status, separators=(",", ":")).encode("utf-8")
        with self.lock:
            self.latest = status
            self.last_seen = time.monotonic()
            self.events.append(status)
            errors = []
            try:
                atomic_write(self.root / "device_status.json", payload)
            except OSError as error:
                errors.append(f"Latest telemetry could not be saved: {error}")
            try:
                def append_history():
                    with (self.root / "device_status_history.jsonl").open("ab") as stream:
                        stream.write(payload + b"\n")
                retry_io(append_history)
            except OSError as error:
                errors.append(f"Telemetry history could not be saved: {error}")
            self.persistence_error = "; ".join(errors)
        return status, self.persistence_error

    def snapshot(self):
        with self.lock:
            age = None if self.last_seen is None else time.monotonic() - self.last_seen
            return dict(self.latest or {}), age, self.persistence_error
