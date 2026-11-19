
# Support direct execution from any working directory.
import sys as _sys
from pathlib import Path as _Path
if __package__ in (None, ""):
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))

import hashlib
import itertools
import json
import platform
import random
import statistics
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from core.paths import experiment_directory


POLICIES = ("crypto_only", "rules_only", "rules_model")
EXPERIMENT_SCENARIOS = ("normal_update", "slow_server", "server_unavailable", "interrupted_download")
FROZEN_FILES = ("test/research_gui.py", "core/telemetry.py", 'core/trust_model.py', 'core/ota_conditions.py', 'core/ota_collection.py', 'core/ota_witness_bridge.py',
                'core/ota_experiment.py', "xmss_ota_gui.py", "xmss_signer_python.py",
                'test/train_trust_model.py', "trust_artifacts/model.json",
                "trust_artifacts/dataset.csv", "trust_artifacts/evaluation.json",
                'docs/EXPERIMENT_PROTOCOL.md')
SETTINGS = {"pre_seconds": 60, "post_seconds": 30, "timeout_seconds": 600,
            "fault_seconds": 90, "delay_ms_range": [300, 900],
            "chunk_pause_ms_range": [20, 80], "chunk_bytes": 16384,
            "truncate_fraction_range": [0.15, 0.4]}


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def write_json(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    temporary.replace(path)


def freeze_baseline(root):
    root = Path(root)
    directory = experiment_directory(root)
    pointer = directory / "FROZEN_BASELINE.json"
    if pointer.exists():
        manifest = json.loads(pointer.read_text())
        verify_baseline(root, manifest)
        return manifest
    hashes = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in FROZEN_FILES}
    identity = {"files": hashes, "settings": SETTINGS, "policies": POLICIES}
    baseline_id = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    snapshot = directory / "baselines" / baseline_id
    snapshot.mkdir(parents=True, exist_ok=True)
    for name in FROZEN_FILES:
        target = snapshot / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((root / name).read_bytes())
    manifest = dict(identity, baseline_id=baseline_id, frozen_at=utc_now())
    write_json(snapshot / "manifest.json", manifest)
    write_json(pointer, manifest)
    return manifest


def verify_baseline(root, manifest):
    root = Path(root)
    if manifest["settings"] != SETTINGS or tuple(manifest["policies"]) != POLICIES:
        raise ValueError("Experiment configuration differs from the frozen baseline")
    identity = {key: manifest[key] for key in ("files", "settings", "policies")}
    expected_id = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    if expected_id != manifest["baseline_id"] or set(manifest["files"]) != set(FROZEN_FILES):
        raise ValueError("Invalid frozen-baseline manifest")
    snapshot = experiment_directory(root) / "baselines" / manifest["baseline_id"]
    for name, expected in manifest["files"].items():
        for path in (root / name, snapshot / name):
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ValueError(f"Frozen baseline changed: {name}. Keep this study separate from revised code/models.")


class ExperimentRecorder:
    def __init__(self, root):
        self.root = Path(root)
        self.lock = threading.RLock()
        self.session = None
        self.trial = None
        self.result = None

    def begin_block(self, context, scenario, device_id, firmware_hash,
                    firmware_bytes=None, device_metadata=None):
        if not context.strip() or scenario not in EXPERIMENT_SCENARIOS:
            raise ValueError("Enter a physical-session label/context and select an automated scenario")
        with self.lock:
            if self.session is not None:
                raise ValueError("An experimental block is already running")
            baseline = freeze_baseline(self.root)
            prior = []
            for path in (experiment_directory(self.root) / "sessions").glob("*/session.json"):
                item = json.loads(path.read_text())
                if item["scenario"] == scenario:
                    prior.append(item)
            orders = list(itertools.permutations(POLICIES))
            random.Random(baseline["baseline_id"] + scenario).shuffle(orders)
            order = list(orders[len(prior) % len(orders)])
            seed = int.from_bytes(uuid.uuid4().bytes[:4], "big")
            generator = random.Random(seed)
            parameters = dict(duration_seconds=SETTINGS["fault_seconds"],
                              delay_ms=generator.randint(*SETTINGS["delay_ms_range"]),
                              chunk_pause_ms=generator.randint(*SETTINGS["chunk_pause_ms_range"]),
                              chunk_bytes=SETTINGS["chunk_bytes"],
                              truncate_fraction=round(generator.uniform(*SETTINGS["truncate_fraction_range"]), 3))
            self.session = dict(schema_version=1, block_id=uuid.uuid4().hex,
                                physical_session=context.strip(), scenario=scenario,
                                device_id=device_id, firmware_sha256=firmware_hash,
                                firmware_bytes=firmware_bytes, device_metadata=device_metadata or {},
                                baseline_id=baseline["baseline_id"], baseline=baseline,
                                host_runtime=dict(python=platform.python_version(), platform=platform.platform(),
                                                  thread_clock_resolution_seconds=time.get_clock_info("thread_time").resolution,
                                                  wall_clock_resolution_seconds=time.get_clock_info("perf_counter").resolution),
                                policy_order=order, fault_parameters=parameters, seed=seed,
                                started_at=utc_now(), outcome="running", trial_ids=[])
            self.directory = experiment_directory(self.root) / "sessions" / self.session["block_id"]
            self.directory.mkdir(parents=True)
            self._save_session()
            return order

    def _save_session(self):
        write_json(self.directory / "session.json", self.session)

    def begin_trial(self, policy, version):
        with self.lock:
            verify_baseline(self.root, self.session["baseline"])
            if self.trial is not None or policy not in POLICIES:
                raise ValueError("Invalid trial state")
            self.trial = dict(trial_id=uuid.uuid4().hex, block_id=self.session["block_id"],
                              physical_session=self.session["physical_session"], policy=policy,
                              scenario=self.session["scenario"], device_id=self.session["device_id"],
                              baseline_id=self.session["baseline_id"], target_version=version,
                              started_at=utc_now(), phase="pre_update", outcome="running",
                              pre_samples=0, post_samples=0, observed_failures=0,
                              pre_duration_seconds=0,
                              injection_counts={}, manifest_decisions=0, deferred_requests=0,
                              gate_cpu_us=[], gate_wall_us=[], installed_at=None,
                              healthy_confirmed_at=None, first_release_at=None,
                              first_release_delay_seconds=None, installed_delay_seconds=None,
                              completion_delay_seconds=None, min_heap=None)
            self.deadline = time.monotonic() + SETTINGS["timeout_seconds"]
            self.installed_uptime = None
            self.post_started = None
            self.last_post_uptime = None
            self.result = None
            self.update_ids = set()
            self.pre_first_received = None
            self.session["trial_ids"].append(self.trial["trial_id"])
            self._save_session()
            self._save_trial()

    def _save_trial(self):
        write_json(self.directory / (self.trial["trial_id"] + ".json"), self.trial)

    def _event(self, kind, **values):
        if self.trial:
            event = dict(kind=kind, at=utc_now(), trial_id=self.trial["trial_id"],
                         phase=self.trial["phase"], **values)
            with (self.directory / (self.trial["trial_id"] + ".jsonl")).open("a", encoding="utf-8") as output:
                output.write(json.dumps(event, separators=(",", ":")) + "\n")

    def arm(self):
        with self.lock:
            self.trial.update(phase="waiting_for_device", published_at=utc_now())
            self.published_monotonic = time.monotonic()
            self.deadline = time.monotonic() + SETTINGS["timeout_seconds"]
            self._save_trial()

    def policy(self):
        with self.lock:
            return self.trial["policy"] if self.trial else None

    def note_injection(self, detail):
        with self.lock:
            if self.trial:
                kind = detail["kind"]
                counts = self.trial["injection_counts"]
                counts[kind] = counts.get(kind, 0) + 1
                self._event("injection", detail=detail)

    def decision(self, result, enforced, cpu_us, wall_us):
        with self.lock:
            if self.trial is None:
                return
            pending = self.trial["phase"] == "waiting_for_device" and self.installed_uptime is None
            self._event("decision", result=result, enforced=enforced, candidate_pending=pending,
                        cpu_us=cpu_us, wall_us=wall_us)
            if pending:
                self.trial["manifest_decisions"] += 1
                self.trial["gate_cpu_us"].append(cpu_us)
                self.trial["gate_wall_us"].append(wall_us)
                if enforced and result["decision"] != "allow":
                    self.trial["deferred_requests"] += 1
                elif self.trial["first_release_at"] is None:
                    self.trial["first_release_at"] = utc_now()
                    self.trial["first_release_delay_seconds"] = time.monotonic() - self.published_monotonic

    def observe(self, status):
        with self.lock:
            trial = self.trial
            if trial is None:
                return
            self._event("telemetry", status=status)
            if status.get("device_id") != trial["device_id"]:
                self.finish_trial("invalid", "Telemetry from another device contaminated the block")
                return
            heap = status.get("heap")
            if isinstance(heap, (int, float)):
                trial["min_heap"] = min(trial["min_heap"], heap) if trial["min_heap"] is not None else heap
            if status.get("state") in ("failed", "rejected"):
                trial["observed_failures"] += 1
            if trial["phase"] == "pre_update":
                trial["pre_samples"] += 1
                if self.pre_first_received is None:
                    self.pre_first_received = time.monotonic()
                trial["pre_duration_seconds"] = time.monotonic() - self.pre_first_received
                return
            if trial["phase"] == "publishing":
                return
            if status.get("version") != trial["target_version"]:
                return
            if status.get("update_id"):
                self.update_ids.add(status["update_id"])
                trial["ota_attempt_count"] = len(self.update_ids)
            if status.get("state") == "rejected":
                self.finish_trial("rejected", status.get("reason", "Cryptographic rejection"))
                return
            if status.get("state") == "installed":
                self.installed_uptime = status["uptime_ms"]
                trial["installed_at"] = utc_now()
                trial["installed_delay_seconds"] = time.monotonic() - self.published_monotonic
                trial["ota_total_ms"] = status.get("ota_total_ms")
                trial["verification_us"] = status.get("verification_us")
                self._save_trial()
            if trial["phase"] == "post_update":
                if (status.get("state") != "idle" or status.get("reason") != "no_update"
                        or status.get("uptime_ms", 0) < self.last_post_uptime):
                    self.finish_trial("unstable", "Post-update health observation failed")
                    return
                self.last_post_uptime = status["uptime_ms"]
                trial["post_samples"] += 1
                if time.monotonic() - self.post_started >= SETTINGS["post_seconds"] and trial["post_samples"] >= 10:
                    trial["healthy_confirmed_at"] = utc_now()
                    trial["completion_delay_seconds"] = time.monotonic() - self.published_monotonic
                    self.finish_trial("completed", "Installed, rebooted, and completed healthy observation")
            elif (self.installed_uptime is not None and status.get("state") == "idle"
                  and status.get("reason") == "no_update" and status.get("uptime_ms", float("inf")) < self.installed_uptime):
                self.post_started = time.monotonic()
                self.last_post_uptime = status["uptime_ms"]
                trial["phase"] = "post_update"
                self._save_trial()

    def finish_trial(self, outcome, reason):
        with self.lock:
            if self.trial:
                expected_injection = {"slow_server": "server_delay", "server_unavailable": "manifest_http_503",
                                      "interrupted_download": "truncate_download"}.get(self.trial["scenario"])
                if outcome == "completed" and expected_injection and not self.trial["injection_counts"].get(expected_injection):
                    outcome, reason = "invalid", "Intended fault was not observed; exclude from matched comparison"
                self.trial.update(outcome=outcome, reason=reason, finished_at=utc_now())
                self._save_trial()
                self.result = dict(self.trial)
                self.trial = None
            return self.result

    def poll(self):
        with self.lock:
            if self.trial and time.monotonic() >= self.deadline:
                self.finish_trial("timeout", "Completion deadline exceeded; delay is censored")
            return self.result

    def finish_block(self, outcome, reason):
        with self.lock:
            if self.session:
                self.finish_trial("aborted", reason)
                self.session.update(outcome=outcome, reason=reason, finished_at=utc_now())
                self._save_session()
                self.session = None


def summarize(root):
    root = Path(root)
    sessions = []
    trials = []
    errors = []
    for path in sorted((experiment_directory(root) / "sessions").glob("*/session.json")):
        try:
            session = json.loads(path.read_text())
            sessions.append(session)
            for identity in session["trial_ids"]:
                trial = json.loads((path.parent / (identity + ".json")).read_text())
                trial["session_outcome"] = session["outcome"]
                trials.append(trial)
        except (OSError, ValueError, KeyError) as error:
            errors.append(dict(path=str(path), error=str(error)))

    baseline_ids = sorted({session["baseline_id"] for session in sessions})
    if len(baseline_ids) > 1:
        raise ValueError("Multiple frozen baselines found; analyze separate studies instead of pooling them")

    def bootstrap(rows, field):
        clusters = {}
        for row in rows:
            value = int(row["outcome"] == "completed") if field == "completion" else row.get(field)
            if value is not None:
                clusters.setdefault(row["physical_session"], []).append(value)
        if len(clusters) < 2:
            return None
        generator = random.Random(20261017)
        names = sorted(clusters)
        estimates = []
        for _ in range(2000):
            values = [value for name in generator.choices(names, k=len(names)) for value in clusters[name]]
            estimates.append(statistics.mean(values))
        estimates.sort()
        return [estimates[49], estimates[1949]]

    groups = []
    for scenario, policy in itertools.product(EXPERIMENT_SCENARIOS, POLICIES):
        selected = [trial for trial in trials if trial["scenario"] == scenario and trial["policy"] == policy]
        finished = [trial for trial in selected if trial["outcome"] != "running"]
        complete = [trial for trial in finished if trial["outcome"] == "completed"]
        delays = [trial["completion_delay_seconds"] for trial in complete]
        cpu = [value for trial in finished for value in trial.get("gate_cpu_us", [])]
        groups.append(dict(scenario=scenario, policy=policy, trials=len(selected), finished=len(finished),
                           completed=len(complete), incomplete=len(selected) - len(finished),
                           invalid=sum(trial["outcome"] == "invalid" for trial in finished),
                           physical_sessions=len({trial["physical_session"] for trial in finished}),
                           observed_failures=sum(trial["observed_failures"] for trial in finished),
                           deferred_requests=sum(trial["deferred_requests"] for trial in finished),
                           completion_rate=len(complete) / len(finished) if finished else None,
                           completion_rate_cluster_ci95=bootstrap(finished, "completion"),
                           median_completion_seconds=statistics.median(delays) if delays else None,
                           mean_completed_delay_cluster_ci95=bootstrap(complete, "completion_delay_seconds"),
                           mean_gate_cpu_us=statistics.mean(cpu) if cpu else None))
    paired_blocks = []
    for session in sessions:
        block_trials = [trial for trial in trials if trial["block_id"] == session["block_id"]]
        if (len(block_trials) != 3 or {trial["policy"] for trial in block_trials} != set(POLICIES)
                or any(trial["outcome"] in ("running", "invalid", "aborted", "error") for trial in block_trials)):
            continue
        reference = next(trial for trial in block_trials if trial["policy"] == "crypto_only")
        for trial in block_trials:
            if trial["policy"] == "crypto_only":
                continue
            both_completed = trial["outcome"] == reference["outcome"] == "completed"
            paired_blocks.append(dict(block_id=session["block_id"], physical_session=session["physical_session"],
                                      scenario=session["scenario"], policy=trial["policy"],
                                      completed_difference=int(trial["outcome"] == "completed") - int(reference["outcome"] == "completed"),
                                      completion_delay_difference_seconds=(trial["completion_delay_seconds"] - reference["completion_delay_seconds"]) if both_completed else None,
                                      observed_failure_difference=trial["observed_failures"] - reference["observed_failures"]))
    report = dict(generated_at=utc_now(), blocks=len(sessions), trials=len(trials), groups=groups, errors=errors,
                  baseline_ids=baseline_ids,
                  paired_against_crypto_only=paired_blocks,
                  notes=["Incomplete trials are not counted as successes.",
                         "Intervals use percentile bootstrap clustered by user-supplied physical-session label; at least two clusters required.",
                         "Session labels do not establish independence; experimenters must arrange independent sessions.",
                         "No intervals with fewer than two physical sessions; pilot bootstrap intervals with few sessions are unstable.",
                         "Groups are descriptive and include failed/invalid/aborted finished trials; paired comparisons exclude invalid/incomplete blocks.",
                         "Completed-only delay omits timeouts; report timeout counts and do not interpret it as unconditional latency.",
                         "Fault injection can directly prevent HTTP access regardless of policy; readiness is a host release gate.",
                         "CPU timing covers policy evaluation on the host, not full-process overhead or MCU inference.",
                         "Observed failures include manifest polling failures, not solely failed installations.",
                         "Invalid, aborted, and missing records require review; no research claim is generated automatically."])
    directory = experiment_directory(root)
    directory.mkdir(parents=True, exist_ok=True)
    write_json(directory / "results.json", report)
    lines = ["# OTA policy experiment results", "", f"Recorded blocks: {len(sessions)}. Trials: {len(trials)}.", "",
             "| Condition | Policy | Completed / finished | Unfinished | Deferrals | Median completion (s) |",
             "| --- | --- | ---: | ---: | ---: | ---: |"]
    for group in groups:
        if group["trials"]:
            delay = group["median_completion_seconds"]
            lines.append(f"| {group['scenario']} | {group['policy']} | {group['completed']}/{group['finished']} | {group['incomplete']} | {group['deferred_requests']} | {delay:.1f} |" if delay is not None else
                         f"| {group['scenario']} | {group['policy']} | {group['completed']}/{group['finished']} | {group['incomplete']} | {group['deferred_requests']} | n/a |")
    lines.extend(["", *["- " + note for note in report["notes"]]])
    if errors:
        lines.extend(["", "Read errors (do not interpret this report as complete):", json.dumps(errors, indent=2)])
    (directory / "RESULTS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    baseline = freeze_baseline(root)
    report = summarize(root)
    print(json.dumps(dict(baseline_id=baseline["baseline_id"], blocks=report["blocks"], trials=report["trials"])))
