import pandas as pd
import numpy as np

from pathlib import Path

from flow_features import FlowFeatureExtractor


PROJECT_ROOT = Path(__file__).resolve().parents[2]

TRAIN_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "X_train.parquet"
)


def main():

    print("=" * 70)
    print("SNIDS LIVE FEATURE VALIDATION")
    print("=" * 70)

    # ---------------------------------------------------------
    # Load training feature schema
    # ---------------------------------------------------------

    print("\nLoading training feature schema...")

    X_train = pd.read_parquet(TRAIN_FILE)

    expected_features = list(X_train.columns)

    print(
        f"Training features: "
        f"{len(expected_features)}"
    )

    # ---------------------------------------------------------
    # Create a test flow
    # ---------------------------------------------------------

    print("\nCreating test flow...")

    extractor = FlowFeatureExtractor()

    # Simulate a small TCP flow
    extractor.add_packet(
        timestamp=1.000000,
        packet_length=66,
        direction="fwd",
        tcp_flags=0x02,
        header_length=20,
        payload_length=0,
        protocol=6,
        window_size=64240,
    )

    extractor.add_packet(
        timestamp=1.001000,
        packet_length=66,
        direction="bwd",
        tcp_flags=0x12,
        header_length=20,
        payload_length=0,
        protocol=6,
        window_size=64240,
    )

    extractor.add_packet(
        timestamp=1.002000,
        packet_length=100,
        direction="fwd",
        tcp_flags=0x18,
        header_length=20,
        payload_length=34,
        protocol=6,
        window_size=64240,
    )

    features = extractor.extract()

    # ---------------------------------------------------------
    # Convert to DataFrame
    # ---------------------------------------------------------

    live_df = pd.DataFrame(
        [features]
    )

    # ---------------------------------------------------------
    # Validation 1: Feature count
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("VALIDATION")
    print("=" * 70)

    print(
        f"\nExpected feature count : "
        f"{len(expected_features)}"
    )

    print(
        f"Generated feature count: "
        f"{len(live_df.columns)}"
    )

    if len(live_df.columns) == len(expected_features):
        print("Feature count: PASS")
    else:
        print("Feature count: FAIL")

    # ---------------------------------------------------------
    # Validation 2: Feature names
    # ---------------------------------------------------------

    generated_features = list(
        live_df.columns
    )

    missing_features = [
        feature
        for feature in expected_features
        if feature not in generated_features
    ]

    extra_features = [
        feature
        for feature in generated_features
        if feature not in expected_features
    ]

    print(
        f"\nMissing features: "
        f"{len(missing_features)}"
    )

    if missing_features:
        print(missing_features)

    print(
        f"Extra features: "
        f"{len(extra_features)}"
    )

    if extra_features:
        print(extra_features)

    if not missing_features and not extra_features:
        print("Feature names: PASS")
    else:
        print("Feature names: FAIL")

    # ---------------------------------------------------------
    # Validation 3: Feature order
    # ---------------------------------------------------------

    if generated_features == expected_features:
        print("Feature order: PASS")
    else:
        print("Feature order: FAIL")

    # ---------------------------------------------------------
    # Reorder exactly like training
    # ---------------------------------------------------------

    live_df = live_df[
        expected_features
    ]

    # ---------------------------------------------------------
    # Validation 4: Numeric values
    # ---------------------------------------------------------

    numeric_check = all(
        pd.api.types.is_numeric_dtype(
            live_df[column]
        )
        for column in live_df.columns
    )

    if numeric_check:
        print("Numeric features: PASS")
    else:
        print("Numeric features: FAIL")

    # ---------------------------------------------------------
    # Validation 5: NaN values
    # ---------------------------------------------------------

    nan_count = int(
        live_df.isna().sum().sum()
    )

    print(
        f"NaN values: {nan_count}"
    )

    if nan_count == 0:
        print("NaN check: PASS")
    else:
        print("NaN check: FAIL")

    # ---------------------------------------------------------
    # Validation 6: Infinite values
    # ---------------------------------------------------------

    numeric_values = live_df.select_dtypes(
        include=[np.number]
    )

    infinite_count = int(
        np.isinf(
            numeric_values.to_numpy()
        ).sum()
    )

    print(
        f"Infinite values: "
        f"{infinite_count}"
    )

    if infinite_count == 0:
        print("Infinite value check: PASS")
    else:
        print("Infinite value check: FAIL")

    # ---------------------------------------------------------
    # Display sample
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("SAMPLE GENERATED FEATURES")
    print("=" * 70)

    print(
        live_df.T.to_string(
            header=False
        )
    )

    # ---------------------------------------------------------
    # Final result
    # ---------------------------------------------------------

    all_passed = (
        len(expected_features)
        == len(live_df.columns)
        and not missing_features
        and not extra_features
        and generated_features == expected_features
        and numeric_check
        and nan_count == 0
        and infinite_count == 0
    )

    print("\n" + "=" * 70)

    if all_passed:
        print(
            "RESULT: LIVE FEATURE VALIDATION PASSED"
        )
    else:
        print(
            "RESULT: LIVE FEATURE VALIDATION FAILED"
        )

    print("=" * 70)


if __name__ == "__main__":
    main()

