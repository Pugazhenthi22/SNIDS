import pandas as pd
import joblib

from pathlib import Path
from sklearn.metrics import classification_report


PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_FILE = (
    PROJECT_ROOT
    / "models"
    / "balanced_random_forest.joblib"
)

X_TEST_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "X_test.parquet"
)

Y_TEST_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "y_test.parquet"
)

LABEL_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "label_mapping.csv"
)


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
    print("SNIDS EXPERIMENT 4 - ATTACK VALIDATION")
    print("=" * 70)

    print("\nLoading model...")

    model = joblib.load(MODEL_FILE)

    print("Model loaded successfully.")

    print("\nLoading test data...")

    X_test = pd.read_parquet(X_TEST_FILE)
    y_test = pd.read_parquet(Y_TEST_FILE)

    print(
        f"Test samples: {len(X_test):,}"
    )

    print(
        f"Features: {len(X_test.columns)}"
    )

    # ---------------------------------------------------------
    # Select attack samples
    # ---------------------------------------------------------

    mask = y_test["Label_ID"].isin(
        ATTACK_IDS.keys()
    )

    X_attack = X_test.loc[mask]
    y_attack = y_test.loc[mask]

    print(
        f"Attack samples selected: "
        f"{len(X_attack):,}"
    )

    # ---------------------------------------------------------
    # Predictions
    # ---------------------------------------------------------

    print("\nGenerating attack predictions...")

    predictions = model.predict(
        X_attack
    )

    probabilities = model.predict_proba(
        X_attack
    )

    confidence = probabilities.max(
        axis=1
    )

    # ---------------------------------------------------------
    # Overall attack validation
    # ---------------------------------------------------------

    correct = (
        predictions
        == y_attack["Label_ID"].values
    )

    print("\n" + "=" * 70)
    print("ATTACK VALIDATION SUMMARY")
    print("=" * 70)

    print(
        f"Correct predictions   : "
        f"{correct.sum():,}"
    )

    print(
        f"Incorrect predictions : "
        f"{(~correct).sum():,}"
    )

    print(
        f"Accuracy              : "
        f"{correct.mean() * 100:.2f}%"
    )

    # ---------------------------------------------------------
    # Per-class results
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("PER-ATTACK RESULTS")
    print("=" * 70)

    for label_id, label_name in ATTACK_IDS.items():

        class_mask = (
            y_attack["Label_ID"].values
            == label_id
        )

        class_predictions = predictions[
            class_mask
        ]

        class_correct = (
            class_predictions
            == label_id
        )

        class_confidence = confidence[
            class_mask
        ]

        count = class_mask.sum()

        print(
            f"\n{label_name}"
        )

        print(
            f"  Samples        : {count:,}"
        )

        print(
            f"  Correct        : "
            f"{class_correct.sum():,}"
        )

        print(
            f"  Incorrect      : "
            f"{(~class_correct).sum():,}"
        )

        print(
            f"  Accuracy       : "
            f"{class_correct.mean() * 100:.2f}%"
        )

        print(
            f"  Avg confidence : "
            f"{class_confidence.mean() * 100:.2f}%"
        )

    # ---------------------------------------------------------
    # Classification report
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("ATTACK CLASSIFICATION REPORT")
    print("=" * 70)

    print(
        classification_report(
            y_attack["Label_ID"],
            predictions,
            labels=list(ATTACK_IDS.keys()),
            target_names=list(ATTACK_IDS.values()),
            zero_division=0,
        )
    )

    # ---------------------------------------------------------
    # Save results
    # ---------------------------------------------------------

    report_dir = (
        PROJECT_ROOT
        / "reports"
        / "experiment_4"
    )

    report_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    report_file = (
        report_dir
        / "attack_validation.txt"
    )

    with open(
        report_file,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "SNIDS EXPERIMENT 4 - ATTACK VALIDATION\n"
        )

        file.write(
            "=" * 70
            + "\n\n"
        )

        file.write(
            f"Total attack samples: "
            f"{len(X_attack):,}\n"
        )

        file.write(
            f"Correct predictions: "
            f"{correct.sum():,}\n"
        )

        file.write(
            f"Incorrect predictions: "
            f"{(~correct).sum():,}\n"
        )

        file.write(
            f"Overall accuracy: "
            f"{correct.mean() * 100:.2f}%\n\n"
        )

        file.write(
            classification_report(
                y_attack["Label_ID"],
                predictions,
                labels=list(ATTACK_IDS.keys()),
                target_names=list(ATTACK_IDS.values()),
                zero_division=0,
            )
        )

    print(
        f"\nReport saved to:\n{report_file}"
    )

    print(
        "\nExperiment 4 attack validation completed."
    )


if __name__ == "__main__":
    main()
