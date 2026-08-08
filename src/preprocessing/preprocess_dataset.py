"""Load, clean, and combine SNIDS network flow datasets."""

from pathlib import Path

import numpy as np
import pandas as pd

RAW_DATA_DIR = Path("data/raw")
PROCESSED_DATA_DIR = Path("data/processed")
OUTPUT_FILE = PROCESSED_DATA_DIR / "combined.parquet"


def list_raw_datasets() -> list[Path]:
    """Return all Parquet files in the raw data directory."""
    return sorted(RAW_DATA_DIR.glob("*.parquet"))


def load_raw_datasets() -> pd.DataFrame:
    """Load and combine all raw Parquet datasets."""
    datasets = list_raw_datasets()
    if not datasets:
        raise FileNotFoundError(f"No Parquet files found in {RAW_DATA_DIR}")

    frames = [pd.read_parquet(path) for path in datasets]
    return pd.concat(frames, ignore_index=True)


def clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """Replace inf values and drop rows with missing feature values."""
    df = df.copy()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    feature_cols = [col for col in df.columns if col != "Label"]
    df.dropna(subset=feature_cols, inplace=True)
    df.reset_index(drop=True, inplace=True)

    return df


def preprocess_dataset() -> pd.DataFrame:
    """Load, clean, and return the combined dataset."""
    df = load_raw_datasets()
    return clean_dataset(df)


def save_dataset(df: pd.DataFrame, path: Path = OUTPUT_FILE) -> Path:
    """Save the processed dataset to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(path, index=False)
    return path


def main() -> None:
    df = preprocess_dataset()
    output_path = save_dataset(df)

    print(f"Processed shape: {df.shape[0]:,} rows x {df.shape[1]} columns")
    print(f"Saved to: {output_path}")

    if "Label" in df.columns:
        print("\nLabel distribution:")
        for label, count in df["Label"].value_counts().items():
            print(f"  {ascii(label)}: {count:,}")


if __name__ == "__main__":
    main()
