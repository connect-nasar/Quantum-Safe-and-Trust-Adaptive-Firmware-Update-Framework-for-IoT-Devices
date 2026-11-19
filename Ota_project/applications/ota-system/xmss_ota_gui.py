"""Normal OTA publishing, live telemetry and an operational log feed."""
from collections import deque
from datetime import datetime, timezone
import json
import queue
import subprocess
import sys
import threading
import tkinter as tk
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from core.ota_witness_bridge import invoke, package_generation
from core.telemetry import TelemetryStore, atomic_write
from core.trust_model import TrustMonitor

ROOT = Path(__file__).resolve().parent
PORT = 8000
PACKAGE_LOCK = threading.RLock()
PACKAGE_PINS = {}
TELEMETRY = TelemetryStore(ROOT)
TRUST = TrustMonitor(ROOT / "trust_artifacts/model.json")
LOGS = queue.Queue(maxsize=500)


def log_event(message):
    line = datetime.now(timezone.utc).strftime("%H:%M:%S UTC") + "  " + str(message)
    try:
        LOGS.put_nowait(line)
    except queue.Full:
        try:
            LOGS.get_nowait()
        except queue.Empty:
            pass
        try:
            LOGS.put_nowait(line)
        except queue.Full:
            pass


def latest_version(root=ROOT, status=None):
    values = [0]
    if status and type(status.get("version")) is int:
        values.append(status["version"])
    # The immutable generation is authoritative; keep the compatibility mirror
    # as an additional lower bound, never as permission to roll back.
    directories = [Path(root), package_generation(root)]
    for directory in directories:
        path = directory / "manifest.json"
        if path.exists():
            manifest = json.loads(path.read_bytes())
            version = manifest.get("version")
            if type(version) is not int or not 0 <= version < 2**32:
                raise ValueError("Published manifest contains an invalid version")
            values.append(version)
    return max(values)


def validate_update(path, version, root=ROOT, status=None):
    path = Path(path)
    if path.name.lower() != "firmware.bin" or not path.is_file():
        raise ValueError("Choose an ESP32 application firmware.bin.")
    if path.resolve() == (Path(root) / "firmware.bin").resolve():
        raise ValueError("The server firmware.bin is encrypted. Choose the application build instead.")
    image = path.read_bytes()
    if not image or image[0] != 0xE9 or len(image) > 0x1E0000:
        raise ValueError("Select an ESP32 application image within the OTA partition size.")
    if type(version) is not int or not 1 <= version < 2**32:
        raise ValueError("Version must be an integer from 1 to 4294967295.")
    previous = latest_version(root, status)
    if version <= previous:
        raise ValueError(f"Version must exceed device/published version {previous}. Use {previous + 1} or higher.")
    return image


class UpdateHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        names = {"/" + name: name for name in (
            "manifest.json", "firmware.witness.json", "firmware.bin", "firmware.sig",
            "firmware.pub", "firmware.kem", "firmware.nonce", "firmware.tag")}
        name = names.get(self.path)
        if name is None:
            self.send_error(404)
            return
        try:
            with PACKAGE_LOCK:
                client = (str(ROOT.resolve()), self.client_address[0])
                if name == "manifest.json":
                    directory = package_generation(ROOT)
                    PACKAGE_PINS[client] = directory
                    if len(PACKAGE_PINS) > 128:
                        PACKAGE_PINS.pop(next(iter(PACKAGE_PINS)))
                else:
                    directory = PACKAGE_PINS.get(client) or package_generation(ROOT)
                path = directory / name
                if not path.is_file():
                    self.send_error(404)
                    return
                data = path.read_bytes()
                if name == "manifest.json":
                    manifest = json.loads(data)
                    values = {key: manifest[key] for key in ("version", "size", "encrypted_size")}
                    if any(type(value) is not int or not 0 <= value < 2**32 for value in values.values()):
                        raise ValueError("Invalid manifest integers")
                    data = json.dumps(values, separators=(",", ":")).encode()
        except (OSError, ValueError, RuntimeError, KeyError) as error:
            log_event(f"Publication unavailable: {error}")
            self.send_error(503, "Witness publication is unavailable")
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
        try:
            self.wfile.write(data)
            if name != "manifest.json":
                log_event(f"Served {name}: {len(data)} bytes to {self.client_address[0]}")
        except (ConnectionError, OSError) as error:
            self.close_connection = True
            log_event(f"Transfer interrupted for {name}: {error}")

    def do_POST(self):
        if self.path != "/status":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 65536:
                raise ValueError("Invalid status length")
            status = json.loads(self.rfile.read(length))
            if not isinstance(status, dict) or not isinstance(status.get("device_id"), str):
                raise ValueError("Expected a device status object")
            for field in ("version", "uptime_ms"):
                if type(status.get(field)) is not int or status[field] < 0:
                    raise ValueError(f"Invalid {field}")
        except (ValueError, UnicodeError):
            self.send_error(400, "Invalid JSON status payload")
            return
        previous, _, _ = TELEMETRY.snapshot()
        status, error = TELEMETRY.observe(status)
        try:
            TRUST.observe(status)
        except (ValueError, KeyError, TypeError) as model_error:
            log_event(f"Readiness advisory unavailable: {model_error}")
        if error:
            log_event(error)
            self.send_error(503, "Telemetry received in memory but persistence failed")
            return
        if any(previous.get(key) != status.get(key) for key in ("state", "reason", "version", "device_id")):
            log_event(f"Device {status['device_id']}: {status.get('state', '?')} "
                      f"v{status.get('version', '?')} - {status.get('reason', '')}")
        self.send_response(204)
        self.end_headers()

    def log_message(self, format, *args):
        return


class OtaGui:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure OTA Control Center")
        self.root.geometry("1000x720")
        self.root.minsize(820, 620)
        self.selected = tk.StringVar()
        self.version = tk.StringVar()
        self.status = tk.StringVar(value="Ready to choose firmware")
        self.signer_status = tk.StringVar(value="Signer: checking witness availability...")
        self.device_summary = tk.StringVar(value="Waiting for device telemetry")
        self.telemetry_age = tk.StringVar()
        self.model_status = tk.StringVar()
        self.messages = queue.Queue()
        self.busy = False
        self.checking = False
        self.closed = False
        self.suggested_version = ""
        self.log_lines = deque(maxlen=200)
        self.server = ThreadingHTTPServer(("0.0.0.0", PORT), UpdateHandler)
        self.server.daemon_threads = True
        self.build_ui()
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        log_event(f"Server listening on port {PORT}; normal publishing mode")
        log_event("Model is advisory; experimental release gating and collection are not active")
        self.refresh_status()
        self.check_signer()
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def build_ui(self):
        frame = ttk.Frame(self.root, padding=18)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(3, weight=1)
        ttk.Label(frame, text="Secure OTA Control Center", font=("Segoe UI", 20, "bold")).grid(row=0, column=0, sticky="w")
        ttk.Label(frame, text="5/7 witness authorization | ML-KEM + AES-GCM | XMSS authenticity").grid(row=1, column=0, sticky="w", pady=(4, 14))
        publish = ttk.LabelFrame(frame, text="Publish firmware update", padding=12)
        publish.grid(row=2, column=0, sticky="ew")
        publish.columnconfigure(1, weight=1)
        ttk.Button(publish, text="Choose firmware.bin", command=self.choose_file).grid(row=0, column=0, sticky="w")
        ttk.Label(publish, textvariable=self.selected, wraplength=620).grid(row=0, column=1, columnspan=2, sticky="w", padx=12)
        ttk.Label(publish, text="New version").grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.version_entry = ttk.Entry(publish, textvariable=self.version, width=14)
        self.version_entry.grid(row=1, column=1, sticky="w", padx=12, pady=(10, 0))
        self.publish_button = ttk.Button(publish, text="Sign and publish", command=self.publish)
        self.publish_button.grid(row=1, column=2, pady=(10, 0))
        ttk.Label(publish, textvariable=self.status, wraplength=850).grid(row=2, column=0, columnspan=3, sticky="w", pady=(8, 0))
        ttk.Label(publish, textvariable=self.signer_status, wraplength=700).grid(row=3, column=0, columnspan=2, sticky="w", pady=(6, 0))
        self.check_button = ttk.Button(publish, text="Check signer", command=self.check_signer)
        self.check_button.grid(row=3, column=2, pady=(6, 0))
        telemetry = ttk.LabelFrame(frame, text="Device telemetry and activity", padding=12)
        telemetry.grid(row=3, column=0, sticky="nsew", pady=(14, 0))
        telemetry.columnconfigure(0, weight=1)
        telemetry.rowconfigure(3, weight=1)
        ttk.Label(telemetry, textvariable=self.device_summary, justify="left").grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Label(telemetry, textvariable=self.telemetry_age).grid(row=1, column=0, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Label(telemetry, textvariable=self.model_status, wraplength=850).grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 8))
        self.events = tk.Text(telemetry, height=10, state="disabled", wrap="word", background="#f4f6f8", relief="flat")
        self.events.grid(row=3, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(telemetry, command=self.events.yview)
        scrollbar.grid(row=3, column=1, sticky="ns")
        self.events.configure(yscrollcommand=scrollbar.set)

    def choose_file(self):
        path = filedialog.askopenfilename(filetypes=[("ESP32 application image", "*.bin")])
        if path:
            self.selected.set(path)

    def check_signer(self):
        if self.busy or self.checking:
            return
        self.checking = True
        self.check_button.configure(state="disabled")
        self.publish_button.configure(state="disabled")
        self.signer_status.set("Signer: checking witnesses (no signature is created)...")
        threading.Thread(target=self.signer_check_worker, daemon=True).start()

    def signer_check_worker(self):
        try:
            result = json.loads(invoke(ROOT, "preflight"))
            self.messages.put(("signer", f"Signer ready: {result['reachable']}/7 witnesses reachable; 5 required"))
        except Exception as error:
            self.messages.put(("signer", "Signer unavailable: " + str(error)))
            log_event("Start the existing witnesses using ../../../witness-quorum/scripts/start.ps1, then click Check signer")
        finally:
            self.messages.put(("checked", ""))

    def publish(self):
        if self.busy or self.checking:
            return
        try:
            version = int(self.version.get())
            status, _, _ = TELEMETRY.snapshot()
            image = validate_update(self.selected.get(), version, ROOT, status)
        except (ValueError, OSError, RuntimeError) as error:
            messagebox.showerror("Cannot publish", str(error))
            return
        self.busy = True
        self.publish_button.configure(state="disabled")
        self.version_entry.configure(state="disabled")
        self.check_button.configure(state="disabled")
        self.status.set(f"Checking witnesses before signing version {version}...")
        threading.Thread(target=self.publish_worker, args=(image, version), daemon=True).start()

    def publish_worker(self, image, version):
        try:
            invoke(ROOT, "preflight")
            with PACKAGE_LOCK:
                status, _, _ = TELEMETRY.snapshot()
                if version <= latest_version(ROOT, status):
                    raise ValueError("Version is no longer newer than the published/device version; choose the next version")
                atomic_write(ROOT / "input_firmware.bin", image)
            # Immutable generations keep existing downloads consistent while the
            # signer works; do not block HTTP readers on a long witness request.
            self.messages.put(("status", f"Signing version {version} with witness authorization..."))
            result = subprocess.run([sys.executable, "-B", str(ROOT / "xmss_signer_python.py"), str(version)],
                                    cwd=ROOT, capture_output=True, text=True, timeout=180)
            if result.returncode:
                raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Signing failed")
            self.messages.put(("published", (result.stdout.strip() or f"Published version {version}") + "; waiting for ESP32 installation"))
        except subprocess.TimeoutExpired:
            self.messages.put(("error", "Signing timed out. The outcome is uncertain; check the signer journal before trying again."))
        except Exception as error:
            self.messages.put(("error", str(error)))
        finally:
            self.messages.put(("done", ""))

    def refresh_status(self):
        if self.closed:
            return
        while True:
            try:
                kind, text = self.messages.get_nowait()
            except queue.Empty:
                break
            if kind == "signer":
                self.signer_status.set(text)
                log_event(text)
            elif kind == "checked":
                self.checking = False
                if not self.busy:
                    self.check_button.configure(state="normal")
                    self.publish_button.configure(state="normal")
            elif kind == "done":
                self.busy = False
                self.publish_button.configure(state="normal")
                self.version_entry.configure(state="normal")
                self.check_button.configure(state="normal")
            else:
                self.status.set(("Signing failed: " if kind == "error" else "") + text)
                log_event(self.status.get())
        data, age, error = TELEMETRY.snapshot()
        if data:
            self.device_summary.set(
                f"Device: {data.get('device_id', '?')}    State: {data.get('state', '?')}    Version/build: {data.get('version', '?')}/{data.get('build', '?')}\n"
                f"Chip/reset: {data.get('chip_model', '?')} / {data.get('reset_reason', '?')}    Seen UTC: {data.get('server_received_at', '?')}\n"
                f"Heap: {data.get('heap', '?')} B (min {data.get('min_heap', '?')} B)    Free sketch: {data.get('free_sketch_space', '?')} B\n"
                f"Uptime: {data.get('uptime_ms', '?')} ms    Wi-Fi: {data.get('rssi', '?')} dBm    Reconnects: {data.get('wifi_reconnect_attempts', '?')}\n"
                f"HTTP failures/requests: {data.get('http_failure_count', '?')}/{data.get('http_request_count', '?')}    Last HTTP: {data.get('last_http_status', '?')}\n"
                f"OTA: {data.get('ota_download_bytes', '?')} bytes    Verify: {data.get('verification_us', '?')} us    Total: {data.get('ota_total_ms', '?')} ms\n"
                f"Reason: {data.get('reason', '')}")
        self.telemetry_age.set("Saved telemetry only - waiting for live device" if age is None else
                               f"Last live telemetry: {int(age)}s ago" + (" - STALE" if age > 5 else ""))
        if error:
            self.telemetry_age.set(self.telemetry_age.get() + " | Disk persistence error; see log")
        try:
            decision = TRUST.evaluate()
            self.model_status.set(f"Model readiness (advisory): {decision['decision'].upper()} - {decision['reason']}")
        except (ValueError, KeyError, TypeError):
            self.model_status.set("Model readiness: unavailable (advisory only)")
        if not self.busy:
            try:
                suggestion = str(latest_version(ROOT, data) + 1)
                if not self.version.get() or self.version.get() == self.suggested_version:
                    self.version.set(suggestion)
                self.suggested_version = suggestion
            except (OSError, ValueError, RuntimeError):
                pass
        changed = False
        while True:
            try:
                self.log_lines.append(LOGS.get_nowait())
                changed = True
            except queue.Empty:
                break
        if changed:
            self.events.configure(state="normal")
            self.events.delete("1.0", "end")
            self.events.insert("end", "\n".join(self.log_lines))
            self.events.see("end")
            self.events.configure(state="disabled")
        self.root.after(500, self.refresh_status)

    def close(self):
        if self.busy:
            messagebox.showinfo("Signing in progress", "Wait for the signing outcome before closing. Do not retry an uncertain operation.")
            return
        self.closed = True
        self.server.shutdown()
        self.server.server_close()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    try:
        OtaGui(root)
    except OSError as error:
        messagebox.showerror("Server could not start", f"Port {PORT} may already be in use. Close the other OTA server.\n{error}")
        root.destroy()
    else:
        root.mainloop()
