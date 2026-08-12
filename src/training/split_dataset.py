import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split


PROJECT_ROOT = Path(__file__).resolve().parents[2]

INPUT_FILE = PROJECT_ROOT / "data" / "processed" / "labeled_dataset.parquet"
OUTPUT_DIR = PROJECT_ROOT / "data" / "processed"


def main():
    print("Loading labeled dataset...")

    df = pd.read_parquet(INPUT_FILE)

    print(f"Dataset shape: {df.shape}")

    # Features and target
    X = df.drop(columns=["Label", "Label_ID"])
    y = df["Label_ID"]

    print(f"Features: {X.shape[1]}")
    print(f"Classes : {y.nunique()}")

    # Stratified 80/20 split
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print("\n" + "=" * 60)
    print("TRAIN / TEST SPLIT")
    print("=" * 60)

    print(f"Training samples: {len(X_train):,}")
    print(f"Testing samples : {len(X_test):,}")

    print("\nTraining class distribution:")
    print(y_train.value_counts().sort_index())

    print("\nTesting class distribution:")
    print(y_test.value_counts().sort_index())

    # Save the split datasets
    X_train.to_parquet(OUTPUT_DIR / "X_train.parquet", index=False)
    X_test.to_parquet(OUTPUT_DIR / "X_test.parquet", index=False)

    y_train.to_frame("Label_ID").to_parquet(
        OUTPUT_DIR / "y_train.parquet",
        index=False
    )

    y_test.to_frame("Label_ID").to_parquet(
        OUTPUT_DIR / "y_test.parquet",
        index=False
    )

    print("\nSaved:")
    print("X_train.parquet")
    print("X_test.parquet")
    print("y_train.parquet")
    print("y_test.parquet")

    print("\nTrain/test split completed successfully.")


if __name__ == "__main__":
    main()