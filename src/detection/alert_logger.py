import csv
from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

LOG_DIR = PROJECT_ROOT / "logs"
ALERT_FILE = LOG_DIR / "snids_alerts.csv"


FIELDS = [
    "timestamp",
    "prediction",
    "severity",
    "source_ip",
    "destination_ip",
    "packets",
]


def log_alert(
    prediction,
    source_ip="",
    destination_ip="",
    packets=0,
):
    LOG_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    severity = (
        "LOW"
        if prediction == "Benign"
        else "HIGH"
    )

    file_exists = ALERT_FILE.exists()

    with open(
        ALERT_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=FIELDS
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow({
            "timestamp": datetime.now().isoformat(
                timespec="seconds"
            ),
            "prediction": prediction,
            "severity": severity,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "packets": packets,
        })

    return ALERT_FILE


if __name__ == "__main__":
    path = log_alert(
        prediction="Benign",
        source_ip="127.0.0.1",
        destination_ip="127.0.0.1",
        packets=5,
    )

    print("Alert logger initialized successfully.")
    print(f"Log file: {path}")
