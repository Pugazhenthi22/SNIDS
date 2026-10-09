"""
SNIDS Dashboard backend.

Reads logs/snids_alerts.csv (written by src/detection/live_inference.py)
and exposes it as JSON for the dashboard frontend to poll. Serves the
static dashboard files (index.html, script.js, styles.css) from the same
folder.

Run from the project root:
    python3 dashboard/app.py

Then open:
    http://<your-ip>:5000
"""

import csv
import os
from collections import Counter, OrderedDict
from pathlib import Path

from flask import Flask, jsonify, send_from_directory

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOG_FILE = Path(os.environ.get("SNIDS_LOG", PROJECT_ROOT / "logs" / "snids_alerts.csv"))
DASHBOARD_DIR = Path(__file__).resolve().parent

# Adjust these to match alert_logger.py's actual column order if different.
COLUMNS = ["timestamp", "prediction", "severity", "source_ip", "destination_ip", "packets"]

TIMELINE_BUCKETS = 20    # how many minute-buckets to show on the chart
TOP_SOURCES_LIMIT = 5

app = Flask(__name__, static_folder=str(DASHBOARD_DIR), static_url_path="")


def read_alerts():
    if not LOG_FILE.exists():
        return []

    rows = []
    with open(LOG_FILE, "r", newline="") as f:
        reader = csv.reader(f)
        for parts in reader:
            if not parts:
                continue
            row = dict(zip(COLUMNS, parts))
            rows.append(row)
    return rows


def build_timeline(rows, buckets=TIMELINE_BUCKETS):
    """
    Group alerts into per-minute buckets of benign vs attack counts.

    Rows are sorted by timestamp first, since the CSV can contain data
    from multiple test sessions appended out of chronological order
    (different days, restarted capture sessions, etc). Sorting here
    guarantees the timeline always reads left-to-right in real time,
    regardless of file order.
    """
    sorted_rows = sorted(rows, key=lambda r: r.get("timestamp", ""))

    grouped = OrderedDict()

    for r in sorted_rows:
        ts = r.get("timestamp", "")
        minute_key = ts[:16] if len(ts) >= 16 else ts  # YYYY-MM-DDTHH:MM

        if minute_key not in grouped:
            grouped[minute_key] = {"benign": 0, "attack": 0}

        if r.get("prediction") == "Benign":
            grouped[minute_key]["benign"] += 1
        else:
            grouped[minute_key]["attack"] += 1

    # Keys are ISO-formatted (YYYY-MM-DDTHH:MM), so a plain sort is
    # also chronological — belt-and-braces against any insertion-order
    # edge cases.
    ordered_keys = sorted(grouped.keys())[-buckets:]
    return [
        {"time": k, "benign": grouped[k]["benign"], "attack": grouped[k]["attack"]}
        for k in ordered_keys
    ]


def build_top_sources(rows, limit=TOP_SOURCES_LIMIT):
    counter = Counter(r.get("source_ip", "unknown") for r in rows)
    return [{"ip": ip, "count": count} for ip, count in counter.most_common(limit)]


@app.route("/")
def index():
    return send_from_directory(DASHBOARD_DIR, "index.html")


@app.route("/api/alerts")
def api_alerts():
    rows = read_alerts()

    total = len(rows)
    benign = sum(1 for r in rows if r.get("prediction") == "Benign")
    attacks = total - benign
    attack_rate = round((attacks / total) * 100, 2) if total else 0.0

    severity_counts = {"LOW": 0, "HIGH": 0}
    for r in rows:
        sev = r.get("severity", "LOW")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    attack_type_counts = {}
    for r in rows:
        pred = r.get("prediction", "Unknown")
        if pred != "Benign":
            attack_type_counts[pred] = attack_type_counts.get(pred, 0) + 1

    recent = list(reversed(rows))[:50]  # most recent 50, newest first

    return jsonify({
        "total": total,
        "benign": benign,
        "attacks": attacks,
        "attack_rate": attack_rate,
        "severity_counts": severity_counts,
        "attack_type_counts": attack_type_counts,
        "recent_alerts": recent,
        "timeline": build_timeline(rows),
        "top_sources": build_top_sources(rows),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
