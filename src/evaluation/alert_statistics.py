import csv
from pathlib import Path
from collections import Counter


PROJECT_ROOT = Path(__file__).resolve().parents[2]

LOG_FILE = (
    PROJECT_ROOT
    / "logs"
    / "snids_alerts.csv"
)


def load_alerts():
    """Load SNIDS alert records from CSV."""

    if not LOG_FILE.exists():
        print("Alert log file not found.")
        return []

    with open(
        LOG_FILE,
        "r",
        newline="",
        encoding="utf-8"
    ) as file:

        reader = csv.DictReader(file)

        return list(reader)


def main():

    print("=" * 70)
    print("SNIDS ALERT STATISTICS")
    print("=" * 70)

    alerts = load_alerts()

    if not alerts:
        print("\nNo alerts found.")
        return

    total = len(alerts)

    predictions = Counter(
        alert["prediction"]
        for alert in alerts
    )

    severities = Counter(
        alert["severity"]
        for alert in alerts
    )

    benign_count = predictions.get(
        "Benign",
        0
    )

    attack_count = total - benign_count

    attack_rate = (
        attack_count / total
    ) * 100

    print(
        f"\nTotal alerts     : {total}"
    )

    print(
        f"Benign           : {benign_count}"
    )

    print(
        f"Attacks          : {attack_count}"
    )

    print(
        f"Attack rate      : {attack_rate:.2f}%"
    )

    print("\n" + "-" * 70)
    print("SEVERITY SUMMARY")
    print("-" * 70)

    print(
        f"LOW severity     : "
        f"{severities.get('LOW', 0)}"
    )

    print(
        f"HIGH severity    : "
        f"{severities.get('HIGH', 0)}"
    )

    print("\n" + "-" * 70)
    print("PREDICTION DISTRIBUTION")
    print("-" * 70)

    for prediction, count in predictions.most_common():

        percentage = (
            count / total
        ) * 100

        print(
            f"{prediction:<30} "
            f"{count:>6} "
            f"({percentage:>6.2f}%)"
        )

    print("\n" + "-" * 70)
    print("RECENT ALERTS")
    print("-" * 70)

    for alert in alerts[-5:]:

        print(
            f"{alert['timestamp']} | "
            f"{alert['prediction']} | "
            f"{alert['severity']} | "
            f"{alert['source_ip']} -> "
            f"{alert['destination_ip']} | "
            f"Packets: {alert['packets']}"
        )

    print("\n" + "=" * 70)
    print("Alert statistics completed.")
    print("=" * 70)


if __name__ == "__main__":
    main()
