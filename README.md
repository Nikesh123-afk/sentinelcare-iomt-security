# SentinelCare IoMT Security

SentinelCare is a research prototype for monitoring and detecting threats in connected healthcare devices. It combines a live security dashboard, a Python event-streaming server, and a machine-learning intrusion-detection pipeline trained on the N-BaIoT dataset.

> **Research project:** This software is intended for authorized laboratory and educational use. It does not capture real patient data, control medical devices, or replace a certified healthcare security system.

## Dashboard Preview

<!-- Add your dashboard screenshot at docs/dashboard.png, then replace this placeholder. -->

> **Screenshot placeholder**
> Add the SentinelCare dashboard image here.

## Features

- Live security operations dashboard for connected healthcare devices
- Incident feed with severity, device, and confidence information
- Device fleet and model-health views
- Server-sent event stream for real-time detection updates
- Temporary application-layer quarantine for a source IP after a live attack prediction
- REST endpoints for health checks, metrics, and authorized lab events
- Random Forest intrusion-detection model for benign and botnet traffic
- Evaluation metrics calculated on a held-out test split
- Adversarial test-bench interface for demonstration purposes

## Technology

- **Frontend:** HTML, CSS, and JavaScript
- **Backend:** Python standard-library HTTP server
- **Machine learning:** Python, pandas, NumPy, scikit-learn, and joblib
- **Dataset:** N-BaIoT from the UCI Machine Learning Repository

## Project Structure

```text
sentinelcare-iomt-security/
|-- index.html                  # Dashboard interface
|-- server.py                   # Local API and event stream server
|-- ml/
|   |-- train_model.py          # Model training and evaluation script
|   `-- artifacts/              # Generated model outputs
|-- Research Report.pdf         # Project research report
`-- CET140-SpecialistProject-Presentation..pdf
```

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/Nikesh123-afk/sentinelcare-iomt-security.git
cd sentinelcare-iomt-security
```

### 2. Install machine-learning dependencies

```bash
python -m pip install numpy pandas scikit-learn joblib
```

### 3. Start the dashboard

```bash
python server.py
```

Open [http://localhost:8000](http://localhost:8000) in a browser.

The dashboard can run with demonstration values. To display metrics from a trained model, generate the files in `ml/artifacts/` first.

## Training the Model

Download and extract the [N-BaIoT dataset](https://archive.ics.uci.edu/dataset/442) into a local directory. The directory should contain one folder per device, with benign traffic and attack-traffic CSV files.

Run:

```bash
python ml/train_model.py --data-dir path/to/N-BaIoT
```

The script creates these files in `ml/artifacts/`:

- `model.joblib`
- `metrics.json`
- `feature_columns.json`
- `test_sample.csv`

The server reads `metrics.json` and `test_sample.csv` to display model metrics and stream held-out predictions.

## Automated Response

When `/api/classify` receives a live feature vector and the model predicts an attack, the server records the event and temporarily quarantines the source IP for 60 seconds. Further live classification requests from that IP receive an HTTP `403` response until the quarantine expires. This is an application-layer lab response; it does not change the Windows firewall or disconnect a physical device.

## API Endpoints

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Check whether the local service is online |
| `GET` | `/api/metrics` | Return trained-model metrics, when available |
| `GET` | `/api/devices` | Return per-device evaluation results (test rows, accuracy, attack families) from the held-out split |
| `GET` | `/api/incidents` | Return the rolling log of recent model-flagged and reported incidents |
| `GET` | `/api/stream` | Subscribe to server-sent detection events |
| `POST` | `/api/events` | Submit an authorized lab detection event |

Example event:

```json
{
	"title": "Unusual telemetry burst",
	"device": "Patient Monitor 12",
	"severity": "MEDIUM"
}
```

## Current Limitations

- The federated-learning workflow is currently conceptual and is not implemented.
- The adversarial test bench returns simulated results and does not run real perturbation attacks.
- The quarantine response is in-memory and resets when the server restarts; the server does not include production authentication, HTTPS, or persistent storage.
- Model results depend on the dataset split and should not be interpreted as production clinical-security guarantees.

## Research Materials

The project reports and presentation are included in the repository for additional background and methodology.

## License

No license has been selected yet. Add a license before accepting contributions or allowing reuse of the code.