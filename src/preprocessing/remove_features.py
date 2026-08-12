import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

INPUT_FILE = PROJECT_ROOT / "data" / "processed" / "cleaned.parquet"
OUTPUT_FILE = PROJECT_ROOT / "data" / "processed" / "features_cleaned.parquet"

CONSTANT_FEATURES = [
    "Bwd PSH Flags",
    "Bwd URG Flags",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
]


def main():
    print("Loading cleaned dataset...")

    df = pd.read_parquet(INPUT_FILE)

    print(f"Original shape: {df.shape}")

    # Remove constant features
    df = df.drop(columns=CONSTANT_FEATURES)

    print(f"New shape: {df.shape}")

    # Verify removed features
    remaining = [col for col in CONSTANT_FEATURES if col in df.columns]

    if remaining:
        print("Warning: Some constant features were not removed:")
        print(remaining)
    else:
        print("All 8 constant features removed successfully.")

    # Save feature-cleaned dataset
    df.to_parquet(OUTPUT_FILE, index=False)

    print("\nFeature-cleaned dataset saved to:")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    main()