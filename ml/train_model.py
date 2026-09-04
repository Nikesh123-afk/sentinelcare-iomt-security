"""Train a real IoT intrusion-detection model on the N-BaIoT dataset (UCI).

Dataset: Meidan et al., "N-BaIoT: Network-based Detection of IoT Botnet
Attacks Using Deep Autoencoders", 2018. https://archive.ics.uci.edu/dataset/442
Each of 9 real IoT devices contributes a benign traffic file and several
attack traffic files (Gafgyt / Mirai botnet variants), all sharing the same
115 statistical traffic features.

Run once after extracting the dataset:
    python train_model.py --data-dir <path to extracted N-BaIoT folder>

Writes artifacts/ with: model.joblib, metrics.json, feature_columns.json,
test_sample.csv (held-out rows used by server.py to replay live predictions).
"""
import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

ARTIFACTS = Path(__file__).parent / "artifacts"
BENIGN_ROWS_PER_DEVICE = 4000
ATTACK_ROWS_PER_FILE = 500


def pretty_device_name(folder_name: str) -> str:
    return folder_name.replace("_", " ")


def load_dataset(data_dir: Path) -> pd.DataFrame:
    """Walk N-BaIoT's per-device folder layout, e.g.:
    <device>/benign_traffic.csv
    <device>/gafgyt_attacks/{combo,junk,scan,tcp,udp}.csv
    <device>/mirai_attacks/{ack,scan,syn,udp,udpplain}.csv   (2 of 9 devices lack this)
    """
    frames = []
    device_dirs = sorted(d for d in data_dir.iterdir() if d.is_dir())
    for device_dir in device_dirs:
        device_name = pretty_device_name(device_dir.name)

        def add(csv_path: Path, attack_type: str, is_benign: bool):
            nrows = BENIGN_ROWS_PER_DEVICE if is_benign else ATTACK_ROWS_PER_FILE
            df = pd.read_csv(csv_path, nrows=nrows * 3)
            if len(df) > nrows:
                df = df.sample(n=nrows, random_state=42)
            df["device_name"] = device_name
            df["attack_type"] = attack_type
            df["is_attack"] = 0 if is_benign else 1
            frames.append(df)
            print(f"  loaded {csv_path.relative_to(data_dir)}: {len(df)} rows")

        benign_csv = device_dir / "benign_traffic.csv"
        if benign_csv.is_file():
            add(benign_csv, "benign", is_benign=True)

        for family in ("gafgyt_attacks", "mirai_attacks"):
            family_dir = device_dir / family
            if not family_dir.is_dir():
                continue
            for csv_path in sorted(family_dir.glob("*.csv")):
                attack_type = f"{family.split('_')[0]}_{csv_path.stem}"
                add(csv_path, attack_type, is_benign=False)

    if not frames:
        raise SystemExit(f"No N-BaIoT device folders found under {data_dir}")
    return pd.concat(frames, ignore_index=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True, type=Path)
    args = parser.parse_args()

    print(f"Loading N-BaIoT csv files from {args.data_dir} ...")
    data = load_dataset(args.data_dir)
    print(f"Total rows: {len(data)} | attack ratio: {data['is_attack'].mean():.2%}")

    meta_cols = ["device_name", "attack_type", "is_attack"]
    feature_columns = [c for c in data.columns if c not in meta_cols]

    X = data[feature_columns]
    y = data["is_attack"]

    X_train, X_test, y_train, y_test, meta_train, meta_test = train_test_split(
        X, y, data[meta_cols], test_size=0.25, random_state=42, stratify=y
    )

    print("Training RandomForestClassifier ...")
    model = RandomForestClassifier(
        n_estimators=200, max_depth=14, n_jobs=-1, random_state=42, class_weight="balanced"
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    metrics = {
        "dataset": "N-BaIoT (UCI ML Repository, Meidan et al. 2018)",
        "model": "RandomForestClassifier(n_estimators=200, max_depth=14)",
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "n_features": len(feature_columns),
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred), 4),
        "recall": round(recall_score(y_test, y_pred), 4),
        "f1": round(f1_score(y_test, y_pred), 4),
        "false_positive_rate": round(fp / (fp + tn), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }
    print(json.dumps(metrics, indent=2))

    ARTIFACTS.mkdir(exist_ok=True)
    joblib.dump(model, ARTIFACTS / "model.joblib")
    (ARTIFACTS / "metrics.json").write_text(json.dumps(metrics, indent=2))
    (ARTIFACTS / "feature_columns.json").write_text(json.dumps(feature_columns))

    proba = model.predict_proba(X_test)[:, 1]
    sample = X_test.copy()
    sample["device_name"] = meta_test["device_name"].values
    sample["true_label"] = meta_test["attack_type"].values
    sample["true_is_attack"] = meta_test["is_attack"].values
    sample["pred_is_attack"] = y_pred
    sample["pred_confidence"] = np.where(y_pred == 1, proba, 1 - proba)
    sample = sample.sample(n=min(400, len(sample)), random_state=7).reset_index(drop=True)
    sample.to_csv(ARTIFACTS / "test_sample.csv", index=False)

    print(f"\nSaved artifacts to {ARTIFACTS}")


if __name__ == "__main__":
    main()
