import pandas as pd
import joblib
import matplotlib.pyplot as plt

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data" / "processed"
MODEL_FILE = PROJECT_ROOT / "models" / "balanced_random_forest.joblib"

OUTPUT_DIR = PROJECT_ROOT / "reports"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def main():
    print("Loading Experiment 2 model...")

    model = joblib.load(MODEL_FILE)

    # Load feature names
    X_train = pd.read_parquet(
        DATA_DIR / "X_train.parquet"
    )

    feature_names = X_train.columns

    print(f"Number of features: {len(feature_names)}")

    # Get feature importance
    importances = model.feature_importances_

    importance_df = pd.DataFrame({
        "Feature": feature_names,
        "Importance": importances
    })

    # Sort from most important to least important
    importance_df = importance_df.sort_values(
        by="Importance",
        ascending=False
    ).reset_index(drop=True)

    # Add ranking
    importance_df.insert(
        0,
        "Rank",
        range(1, len(importance_df) + 1)
    )

    print("\n" + "=" * 70)
    print("FEATURE IMPORTANCE RANKING")
    print("=" * 70)

    print(
        importance_df.head(20).to_string(index=False)
    )

    # Save complete ranking
    csv_file = OUTPUT_DIR / "feature_importance.csv"

    importance_df.to_csv(
        csv_file,
        index=False
    )

    # Plot top 20
    top_features = importance_df.head(20).sort_values(
        by="Importance"
    )

    plt.figure(figsize=(12, 8))

    plt.barh(
        top_features["Feature"],
        top_features["Importance"]
    )

    plt.xlabel("Importance")
    plt.ylabel("Feature")
    plt.title(
        "Top 20 Network Features - Balanced Random Forest"
    )

    plt.tight_layout()

    plot_file = OUTPUT_DIR / "feature_importance_top20.png"

    plt.savefig(
        plot_file,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print("\n" + "=" * 70)
    print("FILES SAVED")
    print("=" * 70)

    print(f"Full ranking:")
    print(csv_file)

    print(f"\nTop 20 plot:")
    print(plot_file)

    print("\nFeature importance analysis completed successfully.")


if __name__ == "__main__":
    main()