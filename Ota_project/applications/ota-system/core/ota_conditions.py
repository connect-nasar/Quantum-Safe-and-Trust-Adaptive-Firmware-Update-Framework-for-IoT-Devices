

import threading
import time


SCENARIOS = ("normal_update", "slow_server", "server_unavailable",
             "interrupted_download", "weak_wifi_manual")


class CollectionConditions:
    def __init__(self):
        self.lock = threading.Lock()
        self.clear()

    def clear(self):
        with self.lock:
            self.scenario = "normal_update"
            self.unavailable_until = 0
            self.truncated = False
            self.expires_at = 0
            self.delay_ms = 500
            self.chunk_pause_ms = 50
            self.chunk_bytes = 16384
            self.truncate_fraction = 0.25

    def configure(self, scenario, duration_seconds=None, delay_ms=500,
                  chunk_pause_ms=50, chunk_bytes=16384, truncate_fraction=0.25):
        if scenario not in SCENARIOS:
            raise ValueError("Unknown collection scenario")
        if (duration_seconds is not None and not 1 <= duration_seconds <= 300
                or not 0 <= delay_ms <= 2000 or not 0 <= chunk_pause_ms <= 200
                or not 1024 <= chunk_bytes <= 65536 or not 0.05 <= truncate_fraction <= 0.9):
            raise ValueError("Fault parameters outside supported bounds")
        with self.lock:
            self.scenario = scenario
            self.unavailable_until = time.monotonic() + (duration_seconds or 15) if scenario == "server_unavailable" else 0
            self.expires_at = time.monotonic() + duration_seconds if duration_seconds is not None else 0
            self.truncated = False
            self.delay_ms = delay_ms
            self.chunk_pause_ms = chunk_pause_ms
            self.chunk_bytes = chunk_bytes
            self.truncate_fraction = truncate_fraction

    def response(self, path):
        with self.lock:
            if self.expires_at and time.monotonic() >= self.expires_at:
                return "normal"
            if path == "/manifest.json" and time.monotonic() < self.unavailable_until:
                return "unavailable"
            if self.scenario == "slow_server":
                return "slow" if path in ("/manifest.json", "/firmware.bin") else "normal"
            if (self.scenario == "interrupted_download" and path == "/firmware.bin"
                    and not self.truncated):
                self.truncated = True
                return "truncate"
            return "normal"
