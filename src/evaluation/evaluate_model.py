import pandas as pd
import joblib
import matplotlib.pyplot as plt

from pathlib import Path
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    ConfusionMatrixDisplay,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data" / "processed"
MODEL_FILE = PROJECT_ROOT / "models" / "random_forest_baseline.joblib"
MAPPING_FILE = DATA_DIR / "label_mapping.csv"

OUTPUT_DIR = PROJECT_ROOT / "reports"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def main():

    print("Loading model and test data...")

    model = joblib.load(MODEL_FILE)

    X_test = pd.read_parquet(DATA_DIR / "X_test.parquet")
    y_test = pd.read_parquet(DATA_DIR / "y_test.parquet")["Label_ID"]

    label_mapping = pd.read_csv(MAPPING_FILE)

    label_names = dict(
        zip(
            label_mapping["Label_ID"],
            label_mapping["Label"]
        )
    )

    print(f"Test samples: {len(X_test):,}")
    print(f"Features: {X_test.shape[1]}")

    # --------------------------------------------------
    # Generate predictions
    # --------------------------------------------------

    print("\nGenerating predictions...")

    y_pred = model.predict(X_test)

    # --------------------------------------------------
    # Overall metrics
    # --------------------------------------------------

    accuracy = accuracy_score(y_test, y_pred)

    macro_precision = precision_score(
        y_test,
        y_pred,
        average="macro",
        zero_division=0
    )

    macro_recall = recall_score(
        y_test,
        y_pred,
        average="macro",
        zero_division=0
    )

    macro_f1 = f1_score(
        y_test,
        y_pred,
        average="macro",
        zero_division=0
    )

    weighted_f1 = f1_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0
    )

    print("\n" + "=" * 70)
    print("OVERALL MODEL METRICS")
    print("=" * 70)

    print(f"Accuracy          : {accuracy:.4f}")
    print(f"Macro Precision   : {macro_precision:.4f}")
    print(f"Macro Recall      : {macro_recall:.4f}")
    print(f"Macro F1          : {macro_f1:.4f}")
    print(f"Weighted F1       : {weighted_f1:.4f}")

    # --------------------------------------------------
    # Classification report
    # --------------------------------------------------

    report = classification_report(
        y_test,
        y_pred,
        labels=sorted(label_names.keys()),
        target_names=[
            label_names[i]
            for i in sorted(label_names.keys())
        ],
        zero_division=0
    )

    print("\n" + "=" * 70)
    print("DETAILED CLASSIFICATION REPORT")
    print("=" * 70)

    print(report)

    # Save classification report
    report_file = OUTPUT_DIR / "classification_report.txt"

    with open(report_file, "w", encoding="utf-8") as f:
        f.write("SNIDS Random Forest Evaluation\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"Accuracy        : {accuracy:.4f}\n")
        f.write(f"Macro Precision : {macro_precision:.4f}\n")
        f.write(f"Macro Recall    : {macro_recall:.4f}\n")
        f.write(f"Macro F1        : {macro_f1:.4f}\n")
        f.write(f"Weighted F1     : {weighted_f1:.4f}\n\n")
        f.write(report)

    # --------------------------------------------------
    # Confusion matrix
    # --------------------------------------------------

    print("\nGenerating confusion matrix...")

    labels = sorted(label_names.keys())

    cm = confusion_matrix(
        y_test,
        y_pred,
        labels=labels
    )

    fig, ax = plt.subplots(figsize=(14, 12))

    display = ConfusionMatrixDisplay(
        confusion_matrix=cm,
        display_labels=[
            label_names[i]
            for i in labels
        ]
    )

    display.plot(
        ax=ax,
        xticks_rotation=90,
        cmap="Blues",
        values_format="d"
    )

    plt.title("SNIDS Random Forest Confusion Matrix")
    plt.tight_layout()

    matrix_file = OUTPUT_DIR / "confusion_matrix.png"

    plt.savefig(
        matrix_file,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print(f"Confusion matrix saved to:")
    print(matrix_file)

    print(f"\nClassification report saved to:")
    print(report_file)

    print("\nModel evaluation completed successfully.")


if __name__ == "__main__":
    main()