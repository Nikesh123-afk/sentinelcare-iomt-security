"""Local SentinelCare event bridge for an authorized lab environment.

This service does not capture packets or control devices. A separate, approved
sensor can POST summarized detection events to /api/events. If a trained model
is present under ml/artifacts (see ml/train_model.py), a background thread also
replays held-out N-BaIoT test traffic through the real classifier and streams
its actual predictions to connected dashboards.
"""
import random
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from queue import Queue
from json import dumps, loads
from urllib.parse import urlparse

ROOT = Path(__file__).parent
ARTIFACTS = ROOT / "ml" / "artifacts"
subscribers = []

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
    if not (metrics_path.is_file() and sample_path.is_file()):
        return None
    import csv as csv_module

    with open(metrics_path, "r", encoding="utf-8") as f:
        metrics = loads(f.read())
    with open(sample_path, "r", encoding="utf-8", newline="") as f:
        rows = list(csv_module.DictReader(f))
    random.shuffle(rows)
    return {"metrics": metrics, "rows": rows}


MODEL_STATE = load_model_state()


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
        path = urlparse(self.path).path
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
        file_path = ROOT / ("index.html" if path in ("/", "") else path.lstrip("/"))
        if file_path.is_file() and file_path.suffix == ".html":
            self._headers("text/html; charset=utf-8")
            self.wfile.write(file_path.read_bytes())
            return
        self.send_error(404)

    def do_POST(self):
        if urlparse(self.path).path != "/api/events":
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
        self._headers("application/json")
        self.wfile.write(b'{"accepted":true}')


if __name__ == "__main__":
    print("SentinelCare bridge: http://localhost:8000")
    print("POST authorized lab events to http://localhost:8000/api/events")
    if MODEL_STATE:
        print(f"Model loaded: {MODEL_STATE['metrics']['model']} "
              f"(accuracy {MODEL_STATE['metrics']['accuracy']:.2%}) - streaming live predictions")
        threading.Thread(target=replay_predictions, daemon=True).start()
    else:
        print("No trained model found under ml/artifacts - run ml/train_model.py first "
              "to stream real predictions instead of dashboard placeholders.")
    ThreadingHTTPServer(("localhost", 8000), Handler).serve_forever()
