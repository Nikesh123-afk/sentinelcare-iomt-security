"""SentinelCare attacker-role demo script.

Run this on a SECOND machine to simulate an attacker sending real N-BaIoT
traffic feature vectors to a SentinelCare dashboard running on a first
machine (the "defender"). The dashboard's live-loaded RandomForest model
classifies each vector for real and streams the verdict to its dashboard.

Usage (on the attacker machine):
    python attacker.py --host 192.168.1.23

Requires only the Python standard library - nothing else to install.
The dashboard machine must be started with:
    python server.py --lan
and both machines must be on the same local network, with port 8000
allowed through the dashboard machine's firewall.
"""
import argparse
import json
import socket
import time
import urllib.request
import urllib.error

ATTACKER_NAME = socket.gethostname()


def fetch_sample_traffic(base_url, count):
    url = f"{base_url}/api/sample-traffic?n={count}"
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read())


def classify(base_url, features, device_name):
    body = json.dumps({"features": features, "device_name": device_name}).encode()
    req = urllib.request.Request(
        f"{base_url}/api/classify",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def main():
    parser = argparse.ArgumentParser(description="SentinelCare attacker-role demo client")
    parser.add_argument("--host", required=True, help="Dashboard machine's LAN IP, e.g. 192.168.1.23")
    parser.add_argument("--port", default=8000, type=int)
    parser.add_argument("--count", default=20, type=int, help="How many traffic samples to send")
    parser.add_argument("--interval", default=3.0, type=float, help="Seconds between sends")
    args = parser.parse_args()

    base_url = f"http://{args.host}:{args.port}"
    print(f"SentinelCare attacker-role demo -> target dashboard: {base_url}")

    try:
        sample = fetch_sample_traffic(base_url, args.count)
    except urllib.error.URLError as exc:
        print(f"Could not reach the dashboard at {base_url}: {exc}")
        print("Check: same network, dashboard started with 'python server.py --lan', "
              "firewall allows inbound TCP 8000.")
        return

    if not sample:
        print("Dashboard has no trained model loaded (ml/artifacts missing). "
              "Run ml/train_model.py on the dashboard machine first.")
        return

    print(f"Loaded {len(sample)} real N-BaIoT traffic samples to replay.\n")
    correct = 0
    for i, row in enumerate(sample, 1):
        try:
            result = classify(base_url, row["features"], f"Attacker-rig ({ATTACKER_NAME})")
        except urllib.error.URLError as exc:
            print(f"[{i}] send failed: {exc}")
            time.sleep(args.interval)
            continue

        truth = "ATTACK" if row["true_is_attack"] else "BENIGN"
        verdict = "ATTACK" if result["predicted_attack"] else "BENIGN"
        match = "MATCH" if (truth == "ATTACK") == result["predicted_attack"] else "MISS "
        correct += match == "MATCH"
        print(f"[{i:02d}/{len(sample)}] sent: {row['device_name']:<38} "
              f"true={truth:<6} model={verdict:<6} conf={result['confidence']:5.1f}%  {match}")
        time.sleep(args.interval)

    print(f"\nDone. Dashboard's live model matched ground truth on {correct}/{len(sample)} sent samples.")
    print("Check the dashboard's Overview and Incidents tabs on the defender machine now.")


if __name__ == "__main__":
    main()
