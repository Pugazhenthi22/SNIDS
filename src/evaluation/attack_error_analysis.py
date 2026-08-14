import pandas as pd
import joblib

from pathlib import Path
from collections import Counter


PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_FILE = PROJECT_ROOT / "models" / "balanced_random_forest.joblib"
X_TEST_FILE = PROJECT_ROOT / "data" / "processed" / "X_test.parquet"
Y_TEST_FILE = PROJECT_ROOT / "data" / "processed" / "y_test.parquet"

ATTACK_IDS = {
    2: "DDoS",
    3: "DoS GoldenEye",
    4: "DoS Hulk",
    5: "DoS Slowhttptest",
    6: "DoS slowloris",
    10: "PortScan",
}


def main():

    print("=" * 70)
    print("SNIDS EXPERIMENT 5 - ATTACK ERROR ANALYSIS")
    print("=" * 70)

    model = joblib.load(MODEL_FILE)

    X_test = pd.read_parquet(X_TEST_FILE)
    y_test = pd.read_parquet(Y_TEST_FILE)

    mask = y_test["Label_ID"].isin(ATTACK_IDS.keys())

    X_attack = X_test.loc[mask]
    y_attack = y_test.loc[mask]

    print(f"\nAttack samples: {len(X_attack):,}")
    print("Generating predictions...")

    predictions = model.predict(X_attack)

    actual = y_attack["Label_ID"].to_numpy()

    errors = actual != predictions

    print("\n" + "=" * 70)
    print("ERROR SUMMARY")
    print("=" * 70)

    print(f"Total attack samples : {len(actual):,}")
    print(f"Correct              : {(~errors).sum():,}")
    print(f"Incorrect            : {errors.sum():,}")

    if errors.sum() == 0:
        print("\nNo misclassifications found.")
        return

    print("\n" + "=" * 70)
    print("MISCLASSIFICATION PAIRS")
    print("=" * 70)

    pairs = Counter(
        (int(a), int(p))
        for a, p in zip(actual[errors], predictions[errors])
    )

    for (actual_id, predicted_id), count in pairs.most_common():

        actual_name = ATTACK_IDS.get(
            actual_id,
            f"Unknown ({actual_id})"
        )

        predicted_name = ATTACK_IDS.get(
            predicted_id,
            f"Class {predicted_id}"
        )

        print(
            f"{actual_name:<25} -> "
            f"{predicted_name:<25} : "
            f"{count}"
        )

    print("\n" + "=" * 70)
    print("ERRORS BY ATTACK")
    print("=" * 70)

    for attack_id, attack_name in ATTACK_IDS.items():

        class_mask = actual == attack_id

        class_total = class_mask.sum()

        class_errors = (
            predictions[class_mask] != attack_id
        ).sum()

        error_rate = (
            class_errors / class_total
        ) * 100

        print(
            f"{attack_name:<25} "
            f"Total: {class_total:>6,} | "
            f"Errors: {class_errors:>4,} | "
            f"Error rate: {error_rate:>6.2f}%"
        )

    print("\n" + "=" * 70)
    print("EXPERIMENT 5 COMPLETED")
    print("=" * 70)


if __name__ == "__main__":
    main()
