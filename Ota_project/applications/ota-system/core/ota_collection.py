

import json
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class AttemptRecorder:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.lock = threading.RLock()
        self.active = None
        self.latest = None
        self.latest_seen = 0
        self.last_result = None

    def begin(self, device_id, version, firmware_hash, timeout=600,
              scenario="normal_update", pre_seconds=0, post_seconds=0):
        with self.lock:
            if self.active is not None:
                raise RuntimeError("An attempt is already active")
            self.directory.mkdir(parents=True, exist_ok=True)
            self.active = {
                "attempt_id": uuid.uuid4().hex,
                "schema_version": 2,
                "scenario": scenario,
                "device_id": device_id,
                "target_version": version,
                "firmware_sha256": firmware_hash,
                "started_at": utc_now(),
                "outcome": "running",
                "phase": "pre_update" if pre_seconds else "publishing",
                "timeout_seconds": timeout,
                "pre_window_seconds": pre_seconds,
                "post_window_seconds": post_seconds,
                "pre_samples": 0,
                "post_samples": 0,
                "observed_failures": [],
                "injections": [],
            }
            self.deadline = time.monotonic() + timeout
            self.installed_uptime = None
            self.update_id = None
            self.post_started = None
            self._save()

    def arm(self):
        with self.lock:
            self.active["phase"] = "waiting_for_device"
            self.active["published_at"] = utc_now()
            self.deadline = time.monotonic() + self.active["timeout_seconds"]
            self._save()

    def note_injection(self, detail):
        with self.lock:
            if self.active:
                self.active["injections"].append(dict(at=utc_now(), **detail))
                self._save()

    def start_publishing(self):
        with self.lock:
            if self.active is None:
                raise RuntimeError("Collection attempt ended before publishing")
            if (self.active["pre_window_seconds"] and
                    (self.active["pre_samples"] < 10 or
                     time.monotonic() - self.latest_seen > 5)):
                raise RuntimeError("Insufficient fresh pre-update telemetry; reconnect the device")
            self.active["phase"] = "publishing"
            self.active["pre_window_finished_at"] = utc_now()
            self._save()

    def _save(self):
        path = self.directory / (self.active["attempt_id"] + ".json")
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.active, indent=2), encoding="utf-8")
        # Windows readers/scanners can briefly deny an atomic rename. Retry the
        # same complete file; never truncate the last committed record in place.
        for attempt in range(6):
            try:
                temporary.replace(path)
                break
            except PermissionError as error:
                if getattr(error, "winerror", None) not in (5, 32, 33) or attempt == 5:
                    raise
                time.sleep(0.01 * (2 ** attempt))

    def finish(self, outcome, reason):
        with self.lock:
            if self.active is None:
                return None
            self.active.update(outcome=outcome, reason=reason, finished_at=utc_now())
            self._save()
            result = self.active
            self.last_result = result
            self.active = None
            return result

    def observe(self, status):
        with self.lock:
            self.latest = dict(status)
            self.latest_seen = time.monotonic()
            attempt = self.active
            if attempt is None or status.get("device_id") != attempt["device_id"]:
                return
            event = dict(status, collection_attempt_id=attempt["attempt_id"],
                         scenario=attempt["scenario"], collection_phase=attempt["phase"])
            path = self.directory / (attempt["attempt_id"] + ".jsonl")
            with path.open("a", encoding="utf-8") as output:
                output.write(json.dumps(event, separators=(",", ":")) + "\n")
            state = status.get("state")
            if state in ("failed", "rejected"):
                attempt["observed_failures"].append(dict(
                    state=state, reason=status.get("reason"),
                    version=status.get("version"), at=status.get("server_received_at")))
                self._save()
            if attempt["phase"] == "pre_update":
                attempt["pre_samples"] += 1
                return
            if attempt["phase"] == "publishing":
                return
            if status.get("version") != attempt["target_version"]:
                return
            if attempt["phase"] == "post_update":
                if state != "idle" or status.get("reason") != "no_update":
                    self.finish("failed", "Unhealthy telemetry during post-update observation")
                    return
                if status.get("uptime_ms", 0) < self.post_last_uptime:
                    self.finish("failed", "Unexpected reboot during post-update observation")
                    return
                self.post_last_uptime = status.get("uptime_ms", 0)
                attempt["post_samples"] += 1
                if (time.monotonic() - self.post_started >= attempt["post_window_seconds"]
                        and attempt["post_samples"] >= 10):
                    outcome = "recovered" if attempt["observed_failures"] else "success"
                    self.finish(outcome, "Installed, rebooted, and observed healthy post-update telemetry")
                return
            if status.get("update_id"):
                if self.update_id and status["update_id"] != self.update_id:
                    self.finish("failed", "Unexpected second OTA attempt")
                    return
                self.update_id = status["update_id"]
            if state in ("failed", "rejected"):
                expected = (attempt["scenario"] == "interrupted_download"
                            and state == "failed" and status.get("reason") == "download"
                            and len(attempt["observed_failures"]) == 1
                            and any(item.get("kind") == "truncate_download" for item in attempt["injections"]))
                if expected:
                    attempt["phase"] = "waiting_for_recovery"
                    self.update_id = None
                    self._save()
                else:
                    self.finish("failed", status.get("reason", state))
            elif state == "installed":
                self.installed_uptime = status.get("uptime_ms")
                attempt["phase"] = "waiting_for_reboot"
                attempt["update_id"] = self.update_id
                self._save()
            elif (state == "idle" and status.get("reason") == "no_update"
                  and self.installed_uptime is not None
                  and isinstance(status.get("uptime_ms"), (int, float))
                  and status["uptime_ms"] < self.installed_uptime):
                if attempt["post_window_seconds"]:
                    self.post_started = time.monotonic()
                    self.post_last_uptime = status["uptime_ms"]
                    attempt.update(phase="post_update", reboot_confirmed_at=utc_now())
                    self._save()
                else:
                    outcome = "recovered" if attempt["observed_failures"] else "success"
                    self.finish(outcome, "Installed and confirmed after reboot")

    def poll(self):
        with self.lock:
            if self.active and time.monotonic() >= self.deadline:
                return self.finish("timeout", "No confirmed completion within timeout")
            return None
