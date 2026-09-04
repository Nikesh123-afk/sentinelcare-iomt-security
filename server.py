"""Local SentinelCare event bridge for an authorized lab environment.

This service does not capture packets or control devices. A separate, approved
sensor can POST summarized detection events to /api/events, or raw N-BaIoT-style
feature vectors to /api/classify for live model inference (used by attacker.py
in a two-machine attacker/defender demo). If a trained model is present under
ml/artifacts (see ml/train_model.py), a background thread also replays held-out
N-BaIoT test traffic through the real classifier and streams its actual
predictions to connected dashboards.
"""
import os
import random
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from queue import Queue
from json import dumps, loads
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).parent
ARTIFACTS = ROOT / "ml" / "artifacts"
subscribers = []
incidents = deque(maxlen=20)
incidents_lock = threading.Lock()
QUARANTINE_SECONDS = 60
quarantined_ips = {}
quarantine_lock = threading.Lock()

ATTACK_TITLES = {
    "benign": "Benign traffic verified",
    "gafgyt_combo": "Gafgyt combo flood detected",
    "gafgyt_junk": "Gafgyt junk traffic detected",
    "gafgyt_scan": "Gafgyt scan detected",
    "gafgyt_tcp": "Gafgyt TCP flood detected",
    "gafgyt_udp": "Gafgyt UDP flood detected",
    "mirai_ack": "Mirai ACK flood detected",
    "mirai_scan": "Mirai scan detected",
    "mirai_syn": "Mirai SYN flood detected",
    "mirai_udp": "Mirai UDP flood detected",
    "mirai_udpplain": "Mirai UDP-plain flood detected",
}


def load_model_state():
    """Load the trained model + held-out test rows, if train_model.py has been run."""
    metrics_path = ARTIFACTS / "metrics.json"
    sample_path = ARTIFACTS / "test_sample.csv"
    model_path = ARTIFACTS / "model.joblib"
    columns_path = ARTIFACTS / "feature_columns.json"
    if not (metrics_path.is_file() and sample_path.is_file()):
        return None
    import csv as csv_module

    with open(metrics_path, "r", encoding="utf-8") as f:
        metrics = loads(f.read())
    with open(sample_path, "r", encoding="utf-8", newline="") as f:
        rows = list(csv_module.DictReader(f))
    random.shuffle(rows)

    model = None
    feature_columns = []
    if model_path.is_file() and columns_path.is_file():
        import joblib
        model = joblib.load(model_path)
        with open(columns_path, "r", encoding="utf-8") as f:
            feature_columns = loads(f.read())

    return {"metrics": metrics, "rows": rows, "model": model, "feature_columns": feature_columns}


MODEL_STATE = load_model_state()


def log_incident(device, signal, confidence, severity, status):
    with incidents_lock:
        incidents.appendleft({
            "device": device,
            "signal": signal,
            "confidence": confidence,
            "severity": severity,
            "status": status,
            "time": time.strftime("%H:%M:%S"),
        })


def quarantine_ip(client_ip):
    """Temporarily reject live classification requests from a detected source."""
    with quarantine_lock:
        quarantined_ips[client_ip] = time.time() + QUARANTINE_SECONDS


def quarantine_remaining(client_ip):
    with quarantine_lock:
        expires_at = quarantined_ips.get(client_ip)
        if expires_at is None:
            return 0
        if expires_at <= time.time():
            del quarantined_ips[client_ip]
            return 0
        return int(expires_at - time.time()) + 1


def classify_features(features):
    """Run the real trained model on a raw feature vector. Returns (is_attack, confidence_pct)."""
    model = MODEL_STATE["model"]
    columns = MODEL_STATE["feature_columns"]
    row = [[float(features.get(col, 0.0)) for col in columns]]
    proba = float(model.predict_proba(row)[0][1])
    is_attack = bool(proba >= 0.5)
    confidence = (proba if is_attack else 1 - proba) * 100
    return is_attack, confidence


def replay_predictions():
    """Continuously stream real model predictions from the held-out test set."""
    rows = MODEL_STATE["rows"]
    i = 0
    while True:
        time.sleep(4)
        if not subscribers:
            continue
        row = rows[i % len(rows)]
        i += 1
        predicted_attack = row["pred_is_attack"] == "1"
        true_attack = row["true_is_attack"] == "1"
        confidence = float(row["pred_confidence"]) * 100
        label = row["true_label"] if predicted_attack else "benign"
        title = ATTACK_TITLES.get(label, "Anomalous pattern detected")
        severity = "HIGH" if confidence >= 90 else "MEDIUM" if confidence >= 75 else "LOW"
        event = {
            "title": title,
            "device": f"{row['device_name']} / {confidence:.1f}% confidence",
            "severity": severity if predicted_attack else "LOW",
            "source": "model",
        }
        for queue in list(subscribers):
            queue.put(event)
        if predicted_attack:
            status = "Contained" if true_attack else "False alarm (model false-positive)"
            log_incident(row["device_name"], title, round(confidence, 1), severity, status)


class Handler(BaseHTTPRequestHandler):
    def _headers(self, content_type):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/api/stream":
            self._headers("text/event-stream")
            queue = Queue()
            subscribers.append(queue)
            try:
                self.wfile.write(b": connected\n\n")
                self.wfile.flush()
                while True:
                    event = queue.get()
                    self.wfile.write(("data: " + dumps(event) + "\n\n").encode())
                    self.wfile.flush()
            except (ConnectionAbortedError, BrokenPipeError):
                pass
            finally:
                if queue in subscribers:
                    subscribers.remove(queue)
            return
        if path == "/api/health":
            self._headers("application/json")
            self.wfile.write(b'{"status":"online","mode":"lab-bridge"}')
            return
        if path == "/api/metrics":
            self._headers("application/json")
            if MODEL_STATE:
                self.wfile.write(dumps({"trained": True, **MODEL_STATE["metrics"]}).encode())
            else:
                self.wfile.write(dumps({"trained": False}).encode())
            return
        if path == "/api/incidents":
            self._headers("application/json")
            with incidents_lock:
                self.wfile.write(dumps(list(incidents)).encode())
            return
        if path == "/api/devices":
            self._headers("application/json")
            devices = MODEL_STATE["metrics"].get("devices", []) if MODEL_STATE else []
            self.wfile.write(dumps(devices).encode())
            return
        if path == "/api/sample-traffic":
            self._headers("application/json")
            if not (MODEL_STATE and MODEL_STATE["feature_columns"]):
                self.wfile.write(b"[]")
                return
            n = min(int(parse_qs(parsed.query).get("n", ["15"])[0]), 50)
            columns = MODEL_STATE["feature_columns"]
            sample = random.sample(MODEL_STATE["rows"], min(n, len(MODEL_STATE["rows"])))
            payload = [{
                "features": {col: float(row[col]) for col in columns},
                "true_label": row["true_label"],
                "true_is_attack": row["true_is_attack"] == "1",
                "device_name": row["device_name"],
            } for row in sample]
            self.wfile.write(dumps(payload).encode())
            return
        file_path = ROOT / ("index.html" if path in ("/", "") else path.lstrip("/"))
        if file_path.is_file() and file_path.suffix == ".html":
            self._headers("text/html; charset=utf-8")
            self.wfile.write(file_path.read_bytes())
            return
        self.send_error(404)

    def _classify(self):
        if not (MODEL_STATE and MODEL_STATE["model"]):
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b'{"error":"No trained model loaded on this server"}')
            return
        client_ip = self.client_address[0]
        remaining = quarantine_remaining(client_ip)
        if remaining:
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(dumps({
                "blocked": True,
                "reason": "Source IP is temporarily quarantined",
                "retry_after": remaining,
            }).encode())
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = loads(self.rfile.read(length))
            features = payload["features"]
        except (ValueError, TypeError, KeyError):
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b'{"error":"Expected a JSON body with a features object"}')
            return

        source_name = payload.get("device_name") or "External sensor"
        device = f"{source_name} ({client_ip})"

        is_attack, confidence = classify_features(features)
        severity = "HIGH" if confidence >= 90 else "MEDIUM" if confidence >= 75 else "LOW"
        title = "Anomalous traffic detected (live classify)" if is_attack else "Benign traffic verified (live classify)"
        event = {
            "title": title,
            "device": f"{device} / {confidence:.1f}% confidence",
            "severity": severity if is_attack else "LOW",
            "source": "attacker-demo",
        }
        for queue in list(subscribers):
            queue.put(event)
        if is_attack:
            quarantine_ip(client_ip)
            log_incident(device, title, round(confidence, 1), severity, "Quarantined (60s)")

        self._headers("application/json")
        self.wfile.write(dumps({
            "predicted_attack": is_attack,
            "confidence": round(confidence, 1),
            "severity": severity,
            "title": title,
            "blocked": is_attack,
            "response": "Source IP quarantined for 60 seconds" if is_attack else "No action taken",
        }).encode())

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/classify":
            self._classify()
            return
        if path != "/api/events":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            event = loads(self.rfile.read(length))
            required = {"title", "device", "severity"}
            if not required.issubset(event):
                raise ValueError("title, device, and severity are required")
        except (ValueError, TypeError):
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b'{"error":"Expected title, device, and severity"}')
            return
        for queue in list(subscribers):
            queue.put(event)
        if event["severity"] in ("HIGH", "MEDIUM"):
            log_incident(event["device"], event["title"], None, event["severity"], "Reported")
        self._headers("application/json")
        self.wfile.write(b'{"accepted":true}')


if __name__ == "__main__":
    lan_mode = "--lan" in sys.argv or os.environ.get("SENTINELCARE_LAN") == "1"
    host = "0.0.0.0" if lan_mode else "localhost"

    print(f"SentinelCare bridge: http://localhost:8000")
    if lan_mode:
        import socket
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.connect(("8.8.8.8", 80))  # no packet actually sent; just picks the real outbound interface
            lan_ip = probe.getsockname()[0]
            probe.close()
        except OSError:
            lan_ip = "<run ipconfig / ifconfig to find your Wi-Fi/Ethernet adapter's IPv4>"
        print(f"LAN mode: also reachable at http://{lan_ip}:8000 from other machines on this network")
        print("WARNING: no authentication is implemented - only run this on a trusted lab network.")
    print("POST authorized lab events to http://localhost:8000/api/events")
    print("POST raw feature vectors to http://localhost:8000/api/classify for live model inference")
    if MODEL_STATE:
        print(f"Model loaded: {MODEL_STATE['metrics']['model']} "
              f"(accuracy {MODEL_STATE['metrics']['accuracy']:.2%}) - streaming live predictions")
        threading.Thread(target=replay_predictions, daemon=True).start()
    else:
        print("No trained model found under ml/artifacts - run ml/train_model.py first "
              "to stream real predictions instead of dashboard placeholders.")
    sys.stdout.flush()
    ThreadingHTTPServer((host, 8000), Handler).serve_forever()
