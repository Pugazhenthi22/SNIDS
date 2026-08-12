import pandas as pd
import joblib

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data" / "processed"
MODEL_FILE = PROJECT_ROOT / "models" / "balanced_random_forest.joblib"


def main():

    print("=" * 70)
    print("SNIDS MULTI-CLASS INFERENCE TEST")
    print("=" * 70)

    print("\nLoading SNIDS model...")

    model = joblib.load(MODEL_FILE)

    print("Model loaded successfully.")

    # Load test data
    X_test = pd.read_parquet(
        DATA_DIR / "X_test.parquet"
    )

    y_test = pd.read_parquet(
        DATA_DIR / "y_test.parquet"
    )["Label_ID"]

    # Load label mapping
    mapping = pd.read_csv(
        DATA_DIR / "label_mapping.csv"
    )

    label_mapping = dict(
        zip(
            mapping["Label_ID"],
            mapping["Label"]
        )
    )

    print(f"\nTest samples available: {len(X_test):,}")
    print(f"Features available: {X_test.shape[1]}")

    # Choose one sample from each available class
    selected_samples = []

    for label_id in sorted(label_mapping.keys()):

        matching_indices = y_test[
            y_test == label_id
        ].index

        if len(matching_indices) > 0:

            # Take the first available sample
            selected_samples.append(
                matching_indices[0]
            )

    X_samples = X_test.loc[selected_samples]
    y_actual = y_test.loc[selected_samples]

    # Generate predictions
    print("\nGenerating predictions...")

    predictions = model.predict(X_samples)

    print("\n" + "=" * 70)
    print("MULTI-CLASS PREDICTIONS")
    print("=" * 70)

    correct = 0

    for actual, predicted in zip(
        y_actual,
        predictions
    ):

        actual = int(actual)
        predicted = int(predicted)

        actual_name = label_mapping[actual]
        predicted_name = label_mapping[predicted]

        if actual == predicted:
            result = "CORRECT"
            correct += 1
        else:
            result = "INCORRECT"

        print(
            f"\nActual    : {actual_name}"
            f"\nPredicted : {predicted_name}"
            f"\nResult    : {result}"
        )

    total = len(predictions)

    print("\n" + "=" * 70)
    print("INFERENCE SUMMARY")
    print("=" * 70)

    print(f"Classes tested : {total}")
    print(f"Correct        : {correct}")
    print(f"Incorrect      : {total - correct}")

    print(
        f"Sample accuracy: "
        f"{correct / total:.2%}"
    )

    print("\nMulti-class inference test completed.")


if __name__ == "__main__":
    main()