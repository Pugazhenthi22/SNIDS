import pandas as pd
import joblib

from pathlib import Path
from sklearn.metrics import confusion_matrix


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data" / "processed"
MODEL_FILE = PROJECT_ROOT / "models" / "balanced_random_forest.joblib"


def main():
    print("Loading Experiment 2 model and test data...")

    model = joblib.load(MODEL_FILE)

    X_test = pd.read_parquet(DATA_DIR / "X_test.parquet")
    y_test = pd.read_parquet(DATA_DIR / "y_test.parquet")["Label_ID"]

    mapping = pd.read_csv(DATA_DIR / "label_mapping.csv")

    label_names = dict(
        zip(
            mapping["Label_ID"],
            mapping["Label"]
        )
    )

    print(f"Test samples: {len(X_test):,}")
    print(f"Features: {X_test.shape[1]}")

    print("\nGenerating predictions...")

    y_pred = model.predict(X_test)

    labels = sorted(label_names.keys())

    cm = confusion_matrix(
        y_test,
        y_pred,
        labels=labels
    )

    print("\n" + "=" * 70)
    print("EXPERIMENT 2 - MAJOR CLASS CONFUSIONS")
    print("=" * 70)

    errors = []

    for i, actual in enumerate(labels):
        for j, predicted in enumerate(labels):

            if i != j and cm[i][j] > 0:
                errors.append(
                    (
                        cm[i][j],
                        label_names[actual],
                        label_names[predicted]
                    )
                )

    errors.sort(reverse=True)

    for count, actual, predicted in errors[:20]:
        print(
            f"{actual:30} -> "
            f"{predicted:30} : {count}"
        )

    print("\n" + "=" * 70)
    print("TOTAL INCORRECT PREDICTIONS")
    print("=" * 70)

    incorrect = (y_test != y_pred).sum()
    correct = (y_test == y_pred).sum()

    print(f"Incorrect predictions: {incorrect:,}")
    print(f"Correct predictions  : {correct:,}")

    print("\nExperiment 2 error analysis completed.")


if __name__ == "__main__":
    main()