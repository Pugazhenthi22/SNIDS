import pandas as pd
import joblib

from pathlib import Path
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data" / "processed"
MODEL_DIR = PROJECT_ROOT / "models"
REPORT_DIR = PROJECT_ROOT / "reports"

REPORT_DIR.mkdir(parents=True, exist_ok=True)


def evaluate_model(model_name, model_file, X_test, y_test):
    print(f"\nEvaluating {model_name}...")

    model = joblib.load(model_file)

    y_pred = model.predict(X_test)

    metrics = {
        "Model": model_name,
        "Accuracy": accuracy_score(y_test, y_pred),
        "Macro Precision": precision_score(
            y_test,
            y_pred,
            average="macro",
            zero_division=0,
        ),
        "Macro Recall": recall_score(
            y_test,
            y_pred,
            average="macro",
            zero_division=0,
        ),
        "Macro F1": f1_score(
            y_test,
            y_pred,
            average="macro",
            zero_division=0,
        ),
        "Weighted F1": f1_score(
            y_test,
            y_pred,
            average="weighted",
            zero_division=0,
        ),
        "Incorrect Predictions": int((y_test != y_pred).sum()),
    }

    return metrics


def main():

    print("Loading test data...")

    X_test = pd.read_parquet(
        DATA_DIR / "X_test.parquet"
    )

    y_test = pd.read_parquet(
        DATA_DIR / "y_test.parquet"
    )["Label_ID"]

    print(f"Test samples: {len(X_test):,}")
    print(f"Features: {X_test.shape[1]}")

    baseline_metrics = evaluate_model(
        "Experiment 1 - Random Forest",
        MODEL_DIR / "random_forest_baseline.joblib",
        X_test,
        y_test,
    )

    balanced_metrics = evaluate_model(
        "Experiment 2 - Balanced Random Forest",
        MODEL_DIR / "balanced_random_forest.joblib",
        X_test,
        y_test,
    )

    results = pd.DataFrame([
        baseline_metrics,
        balanced_metrics,
    ])

    print("\n" + "=" * 80)
    print("MODEL COMPARISON")
    print("=" * 80)

    print(
        results.to_string(
            index=False,
            float_format=lambda x: f"{x:.4f}"
        )
    )

    # Calculate improvements
    baseline = results.iloc[0]
    balanced = results.iloc[1]

    print("\n" + "=" * 80)
    print("EXPERIMENT 2 IMPROVEMENT")
    print("=" * 80)

    print(
        f"Accuracy improvement: "
        f"{(balanced['Accuracy'] - baseline['Accuracy']) * 100:.2f} percentage points"
    )

    print(
        f"Macro F1 improvement: "
        f"{(balanced['Macro F1'] - baseline['Macro F1']) * 100:.2f} percentage points"
    )

    print(
        f"Fewer incorrect predictions: "
        f"{int(baseline['Incorrect Predictions'] - balanced['Incorrect Predictions']):,}"
    )

    # Save comparison
    output_file = REPORT_DIR / "model_comparison.csv"

    results.to_csv(
        output_file,
        index=False
    )

    print("\nComparison saved to:")
    print(output_file)

    print("\nModel comparison completed successfully.")


if __name__ == "__main__":
    main()