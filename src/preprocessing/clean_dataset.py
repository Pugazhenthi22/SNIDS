import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

INPUT_FILE = PROJECT_ROOT / "data" / "processed" / "combined.parquet"
OUTPUT_FILE = PROJECT_ROOT / "data" / "processed" / "cleaned.parquet"


def main():
    print("Loading combined dataset...")

    df = pd.read_parquet(INPUT_FILE)

    print(f"Original rows: {len(df):,}")
    print(f"Original columns: {df.shape[1]}")

    # Remove duplicate rows
    duplicate_count = df.duplicated().sum()

    print(f"Duplicate rows found: {duplicate_count:,}")

    df = df.drop_duplicates().reset_index(drop=True)

    print(f"Rows after removing duplicates: {len(df):,}")

    # Save cleaned dataset
    df.to_parquet(OUTPUT_FILE, index=False)

    print("\nCleaned dataset saved successfully!")
    print(f"Location: {OUTPUT_FILE}")

    print("\nFinal dataset:")
    print(f"Rows    : {len(df):,}")
    print(f"Columns : {df.shape[1]}")

    print("\nDuplicates remaining:", df.duplicated().sum())


if __name__ == "__main__":
    main()