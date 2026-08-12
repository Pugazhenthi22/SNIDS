import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

INPUT_FILE = PROJECT_ROOT / "data" / "processed" / "features_cleaned.parquet"
OUTPUT_FILE = PROJECT_ROOT / "data" / "processed" / "labeled_dataset.parquet"
MAPPING_FILE = PROJECT_ROOT / "data" / "processed" / "label_mapping.csv"


def main():
    print("Loading feature-cleaned dataset...")

    df = pd.read_parquet(INPUT_FILE)

    print(f"Original shape: {df.shape}")

    # Normalize corrupted Web Attack labels
    label_fixes = {
        "Web Attack � Brute Force": "Web Attack - Brute Force",
        "Web Attack � XSS": "Web Attack - XSS",
        "Web Attack � Sql Injection": "Web Attack - Sql Injection",
    }

    df["Label"] = df["Label"].replace(label_fixes)

    # Create numerical label mapping
    labels = sorted(df["Label"].unique())

    label_to_id = {label: idx for idx, label in enumerate(labels)}

    df["Label_ID"] = df["Label"].map(label_to_id)

    # Save mapping
    mapping_df = pd.DataFrame(
        list(label_to_id.items()),
        columns=["Label", "Label_ID"]
    )

    mapping_df.to_csv(MAPPING_FILE, index=False)

    # Save labeled dataset
    df.to_parquet(OUTPUT_FILE, index=False)

    print("\n" + "=" * 60)
    print("LABEL MAPPING")
    print("=" * 60)

    print(mapping_df.to_string(index=False))

    print("\n" + "=" * 60)
    print("FINAL DATASET")
    print("=" * 60)

    print(f"Rows    : {len(df):,}")
    print(f"Columns : {df.shape[1]}")
    print(f"Classes : {df['Label'].nunique()}")

    print("\nLabel_ID distribution:")
    print(df["Label_ID"].value_counts().sort_index())

    print("\nSaved dataset:")
    print(OUTPUT_FILE)

    print("\nSaved label mapping:")
    print(MAPPING_FILE)

    print("\nLabel preparation completed successfully.")


if __name__ == "__main__":
    main()