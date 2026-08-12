import pandas as pd
import joblib

from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data" / "processed"
MODEL_DIR = PROJECT_ROOT / "models"

MODEL_DIR.mkdir(parents=True, exist_ok=True)


def main():
    print("Loading training and testing data...")

    X_train = pd.read_parquet(DATA_DIR / "X_train.parquet")
    X_test = pd.read_parquet(DATA_DIR / "X_test.parquet")

    y_train = pd.read_parquet(DATA_DIR / "y_train.parquet")["Label_ID"]
    y_test = pd.read_parquet(DATA_DIR / "y_test.parquet")["Label_ID"]

    print(f"Training samples: {len(X_train):,}")
    print(f"Testing samples : {len(X_test):,}")
    print(f"Features        : {X_train.shape[1]}")

    print("\nTraining Experiment 2: Balanced Random Forest...")

    model = RandomForestClassifier(
        n_estimators=100,
        max_features="sqrt",
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
    )

    model.fit(X_train, y_train)

    print("Training completed!")

    print("\nGenerating predictions...")

    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)

    macro_f1 = f1_score(
        y_test,
        y_pred,
        average="macro",
        zero_division=0,
    )

    weighted_f1 = f1_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0,
    )

    print("\n" + "=" * 70)
    print("EXPERIMENT 2 RESULTS")
    print("=" * 70)

    print(f"Accuracy   : {accuracy:.4f}")
    print(f"Macro F1   : {macro_f1:.4f}")
    print(f"Weighted F1: {weighted_f1:.4f}")

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            y_pred,
            zero_division=0,
        )
    )

    model_file = MODEL_DIR / "balanced_random_forest.joblib"

    joblib.dump(model, model_file)

    print("\nModel saved to:")
    print(model_file)

    print("\nExperiment 2 completed successfully.")


if __name__ == "__main__":
    main()