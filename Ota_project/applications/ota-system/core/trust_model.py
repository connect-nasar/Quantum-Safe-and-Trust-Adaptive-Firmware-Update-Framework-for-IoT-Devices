import json
import math
import statistics
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path


FEATURES = (
    "rssi_median", "rssi_min", "heap_min", "heap_drop",
    "http_latency_median_ms", "http_latency_p95_ms", "failure_fraction",
    "http_failure_rate", "reconnects_per_minute", "offline_fraction",
    "unexpected_reset_fraction",
)
LABELS = ("nominal", "slow_service", "service_unavailable")


def timestamp(row):
    return datetime.fromisoformat(row["server_received_at"].replace("Z", "+00:00")).timestamp()


def extract_features(rows):
    if len(rows) < 10:
        raise ValueError("At least ten telemetry readings are required")
    ordered = sorted(rows, key=timestamp)
    required = ("rssi", "heap", "last_http_latency_ms", "uptime_ms",
                "http_request_count", "http_failure_count",
                "wifi_reconnect_attempts", "wifi_offline_ms")
    for row in ordered:
        if any(not isinstance(row.get(field), (int, float)) or
               isinstance(row[field], bool) or not math.isfinite(row[field]) for field in required):
            raise ValueError("Missing or non-finite runtime telemetry")
        if any(row[field] < 0 for field in required if field != "rssi"):
            raise ValueError("Negative runtime telemetry counter")
    duration = timestamp(ordered[-1]) - timestamp(ordered[0])
    if duration < 20 or duration > 65:
        raise ValueError("Telemetry window must span 20–65 seconds")
    deltas = {field: 0 for field in ("http_request_count", "http_failure_count",
                                   "wifi_reconnect_attempts", "wifi_offline_ms")}
    rebooted = False
    for previous, current in zip(ordered, ordered[1:]):
        if current["uptime_ms"] < previous["uptime_ms"]:
            rebooted = True
            continue
        for field in deltas:
            delta = current[field] - previous[field]
            if delta < 0:
                raise ValueError("Telemetry counters decreased without a reboot")
            deltas[field] += delta
    latency = sorted(row["last_http_latency_ms"] for row in ordered)
    unexpected = {"panic", "interrupt_watchdog", "task_watchdog", "watchdog", "brownout"}
    values = {
        "rssi_median": statistics.median(row["rssi"] for row in ordered),
        "rssi_min": min(row["rssi"] for row in ordered),
        "heap_min": min(row["heap"] for row in ordered),
        "heap_drop": max(0, ordered[0]["heap"] - ordered[-1]["heap"]),
        "http_latency_median_ms": statistics.median(latency),
        "http_latency_p95_ms": latency[math.ceil(len(latency) * 0.95) - 1],
        "failure_fraction": sum(row.get("state") in ("failed", "rejected") for row in ordered) / len(ordered),
        "http_failure_rate": min(1, deltas["http_failure_count"] / max(1, deltas["http_request_count"])),
        "reconnects_per_minute": deltas["wifi_reconnect_attempts"] * 60 / duration,
        "offline_fraction": min(1, deltas["wifi_offline_ms"] / (duration * 1000)),
        "unexpected_reset_fraction": sum(row.get("reset_reason") in unexpected for row in ordered) / len(ordered),
    }
    return values, {"samples": len(ordered), "duration_seconds": duration,
                    "reboot_in_window": rebooted}


def fit_tree(samples, labels, depth=3, min_leaf=4):
    counts = {label: labels.count(label) for label in LABELS}
    prediction = max(LABELS, key=lambda label: counts[label])
    node = {"prediction": prediction, "counts": counts, "samples": len(labels)}
    if depth == 0 or sum(count > 0 for count in counts.values()) == 1:
        return node

    def impurity(indices):
        return len(indices) - sum(sum(labels[index] == label for index in indices) ** 2
                                  for label in LABELS) / len(indices)

    best = None
    parent_impurity = impurity(list(range(len(labels))))
    for feature in FEATURES:
        values = sorted({sample[feature] for sample in samples})
        for lower, upper in zip(values, values[1:]):
            threshold = (lower + upper) / 2
            left = [index for index, sample in enumerate(samples) if sample[feature] <= threshold]
            right = [index for index, sample in enumerate(samples) if sample[feature] > threshold]
            if min(len(left), len(right)) < min_leaf:
                continue
            score = impurity(left) + impurity(right)
            if score < parent_impurity and (best is None or score < best[0]):
                best = (score, feature, threshold, left, right)
    if best:
        _, feature, threshold, left, right = best
        node.update(feature=feature, threshold=threshold,
                    left=fit_tree([samples[index] for index in left], [labels[index] for index in left], depth - 1, min_leaf),
                    right=fit_tree([samples[index] for index in right], [labels[index] for index in right], depth - 1, min_leaf))
    return node


def predict_tree(tree, features):
    while "feature" in tree:
        tree = tree["left"] if features[tree["feature"]] <= tree["threshold"] else tree["right"]
    return tree["prediction"]


def rule_prediction(features):
    if features["failure_fraction"] > 0 or features["http_failure_rate"] > 0.05:
        return "service_unavailable"
    if features["http_latency_p95_ms"] >= 500:
        return "slow_service"
    return "nominal"


def readiness(features, quality, prediction):
    if quality["reboot_in_window"] or features["unexpected_reset_fraction"] > 0:
        return "investigate", "Recent restart or abnormal reset reason"
    if features["heap_min"] < 100000:
        return "investigate", "Free heap below the provisional 100 kB policy threshold"
    if features["rssi_min"] < -80 or features["offline_fraction"] > 0.1 or features["reconnects_per_minute"] > 2:
        return "defer", "Unstable connectivity under the provisional policy"
    if prediction != "nominal" or rule_prediction(features) != "nominal":
        return "defer", "Observed service degradation; retry after a healthy window"
    return "allow", "No degradation detected in the available pre-update window"


class TrustMonitor:
    def __init__(self, model_path):
        self.lock = threading.RLock()
        self.windows = {}
        self.latest_device = None
        self.enforce = False
        try:
            self.model = json.loads(Path(model_path).read_text(encoding="utf-8"))
            if self.model.get("features") != list(FEATURES) or self.model.get("schema_version") != 1:
                raise ValueError("Unsupported trust model schema")
            self.model_error = None
        except (OSError, ValueError) as error:
            self.model = None
            self.model_error = str(error)

    def observe(self, row):
        device = row.get("device_id")
        if not device:
            return
        with self.lock:
            self.latest_device = device
            window = self.windows.setdefault(device, deque(maxlen=180))
            window.append((time.monotonic(), dict(row)))

    def evaluate(self, policy="rules_model"):
        with self.lock:
            recent_devices = [device for device, samples in self.windows.items()
                              if samples and time.monotonic() - samples[-1][0] <= 65]
            if len(recent_devices) > 1:
                return {"decision": "defer", "reason": "Release gate supports one active device only"}
            window = self.windows.get(self.latest_device, [])
            if policy not in ("rules_only", "rules_model"):
                return {"decision": "defer", "reason": "Unknown readiness policy"}
            if policy == "rules_model" and self.model is None:
                return {"decision": "defer", "reason": "Model unavailable: " + str(self.model_error)}
            if not window or time.monotonic() - window[-1][0] > 5:
                return {"decision": "defer", "reason": "Fresh telemetry required"}
            rows = [row for received, row in window if time.monotonic() - received <= 60]
            if rows[-1].get("state") not in ("idle", "failed", "rejected"):
                return {"decision": "defer", "reason": "Device is already processing an update"}
            if any(row.get("state") not in ("idle", "failed", "rejected") for row in rows):
                return {"decision": "defer", "reason": "Waiting for a fresh pre-update window after OTA activity"}
            try:
                features, quality = extract_features(rows)
                if quality["duration_seconds"] < 50:
                    return {"decision": "defer", "reason": "Collecting approximately 60 seconds of pre-update telemetry"}
                prediction = (predict_tree(self.model["tree"], features)
                              if policy == "rules_model" else rule_prediction(features))
                decision, reason = readiness(features, quality, prediction)
                return dict(decision=decision, reason=reason, condition=prediction,
                            features=features, quality=quality, device_id=self.latest_device)
            except (ValueError, KeyError, TypeError) as error:
                return {"decision": "defer", "reason": str(error)}
