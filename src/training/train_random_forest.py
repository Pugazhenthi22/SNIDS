import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib


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

    print("\nTraining Random Forest...")

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced"
    )

    model.fit(X_train, y_train)

    print("Training completed!")

    print("\nGenerating predictions...")

    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)

    print("\n" + "=" * 60)
    print("MODEL RESULTS")
    print("=" * 60)

    print(f"Accuracy: {accuracy:.4f}")

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            y_pred,
            zero_division=0
        )
    )

    # Save model
    model_file = MODEL_DIR / "random_forest_baseline.joblib"

    joblib.dump(model, model_file)

    print("\nModel saved to:")
    print(model_file)

    print("\nRandom Forest baseline completed successfully.")


if __name__ == "__main__":
    main()