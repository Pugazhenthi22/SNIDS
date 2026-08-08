"""Explore SNIDS network flow datasets stored as Parquet files."""

from pathlib import Path

import pandas as pd

DATA_DIR = Path("data/raw")


def list_datasets() -> list[Path]:
    """Return all Parquet files in the raw data directory."""
    return sorted(DATA_DIR.glob("*.parquet"))


def explore_dataset(path: Path) -> None:
    """Print summary statistics for a single dataset."""
    print(f"\n{'=' * 60}")
    print(f"Dataset: {path.name}")
    print(f"{'=' * 60}")

    df = pd.read_parquet(path)

    print(f"\nShape: {df.shape[0]:,} rows x {df.shape[1]} columns")

    print("\nColumn dtypes:")
    print(df.dtypes.to_string())

    missing = df.isna().sum()
    if missing.any():
        print("\nMissing values:")
        print(missing[missing > 0].to_string())
    else:
        print("\nMissing values: none")

    if "Label" in df.columns:
        print("\nLabel distribution:")
        print(df["Label"].value_counts().to_string())

    print("\nNumeric summary (first 10 columns):")
    numeric_cols = df.select_dtypes(include="number").columns[:10]
    print(df[numeric_cols].describe().T.to_string())


def main() -> None:
    datasets = list_datasets()

    if not datasets:
        print(f"No Parquet files found in {DATA_DIR}")
        return

    print(f"Found {len(datasets)} dataset(s) in {DATA_DIR}:")
    for path in datasets:
        print(f"  - {path.name}")

    for path in datasets:
        explore_dataset(path)


if __name__ == "__main__":
    main()
