import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

INPUT_FILE = PROJECT_ROOT / "data" / "processed" / "cleaned.parquet"


def main():
    print("Loading cleaned dataset...")

    df = pd.read_parquet(INPUT_FILE)

    X = df.drop(columns=["Label"])

    print("\nDataset loaded successfully!")
    print(f"Rows    : {len(df):,}")
    print(f"Features: {X.shape[1]}")

    # --------------------------------------------------
    # 1. Check constant features
    # --------------------------------------------------
    print("\n" + "=" * 60)
    print("CONSTANT FEATURES")
    print("=" * 60)

    constant_features = X.columns[X.nunique() <= 1]

    if len(constant_features) == 0:
        print("No constant features found.")
    else:
        print(f"Found {len(constant_features)} constant features:")
        print(constant_features.tolist())

    # --------------------------------------------------
    # 2. Check zero variance features
    # --------------------------------------------------
    print("\n" + "=" * 60)
    print("ZERO VARIANCE FEATURES")
    print("=" * 60)

    variance = X.var()
    zero_variance = variance[variance == 0]

    if zero_variance.empty:
        print("No zero-variance features found.")
    else:
        print(zero_variance)

    # --------------------------------------------------
    # 3. Check infinite values
    # --------------------------------------------------
    print("\n" + "=" * 60)
    print("INFINITE VALUES")
    print("=" * 60)

    infinite_counts = X.isin([float("inf"), float("-inf")]).sum()
    infinite_counts = infinite_counts[infinite_counts > 0]

    if infinite_counts.empty:
        print("No infinite values found.")
    else:
        print(infinite_counts)

    # --------------------------------------------------
    # 4. Feature statistics
    # --------------------------------------------------
    print("\n" + "=" * 60)
    print("FEATURE STATISTICS")
    print("=" * 60)

    stats = X.describe().T

    print(stats[["mean", "std", "min", "max"]])

    # --------------------------------------------------
    # 5. Save feature quality report
    # --------------------------------------------------
    REPORT_DIR = PROJECT_ROOT / "data" / "processed"
    REPORT_FILE = REPORT_DIR / "feature_quality_report.csv"

    stats.to_csv(REPORT_FILE)

    print("\nFeature quality report saved to:")
    print(REPORT_FILE)

    print("\nFeature quality inspection completed.")


if __name__ == "__main__":
    main()