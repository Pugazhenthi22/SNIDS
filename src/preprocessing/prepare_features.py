import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

INPUT_FILE = PROJECT_ROOT / "data" / "processed" / "cleaned.parquet"


def main():
    print("Loading cleaned dataset...")

    df = pd.read_parquet(INPUT_FILE)

    print("\nDataset loaded successfully!")
    print(f"Rows    : {len(df):,}")
    print(f"Columns : {df.shape[1]}")

    # Separate features and target
    X = df.drop(columns=["Label"])
    y = df["Label"]

    print("\n" + "=" * 60)
    print("FEATURE INFORMATION")
    print("=" * 60)

    print(f"Number of features: {X.shape[1]}")

    print("\nNumeric features:")
    numeric_features = X.select_dtypes(include="number").columns
    print(f"Count: {len(numeric_features)}")

    print("\nNon-numeric features:")
    non_numeric_features = X.select_dtypes(exclude="number").columns
    print(f"Count: {len(non_numeric_features)}")

    if len(non_numeric_features) > 0:
        print(non_numeric_features.tolist())

    print("\n" + "=" * 60)
    print("DATA TYPES")
    print("=" * 60)

    print(X.dtypes.value_counts())

    print("\n" + "=" * 60)
    print("TARGET LABELS")
    print("=" * 60)

    print(f"Number of classes: {y.nunique()}")
    print(y.value_counts())

    print("\nFeature inspection completed.")


if __name__ == "__main__":
    main()