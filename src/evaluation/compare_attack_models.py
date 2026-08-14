import pandas as pd
import joblib

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

X_TEST_FILE = PROJECT_ROOT / "data" / "processed" / "X_test.parquet"
Y_TEST_FILE = PROJECT_ROOT / "data" / "processed" / "y_test.parquet"

MODELS = {
    "Balanced RF": PROJECT_ROOT / "models" / "balanced_random_forest.joblib",
    "Recall RF": PROJECT_ROOT / "models" / "recall_focused_random_forest.joblib",
}

ATTACK_IDS = {
    2: "DDoS",
    3: "DoS GoldenEye",
    4: "DoS Hulk",
    5: "DoS Slowhttptest",
    6: "DoS slowloris",
    10: "PortScan",
}


def evaluate_model(model_name, model, X, y):

    predictions = model.predict(X)

    actual = y.to_numpy()

    correct = predictions == actual
    total = len(actual)

    attack_to_benign = (
        (actual != 0)
        & (predictions == 0)
    ).sum()

    print("\n" + "=" * 70)
    print(model_name)
    print("=" * 70)

    print(f"Overall attack accuracy : {correct.mean() * 100:.2f}%")
    print(f"Correct predictions     : {correct.sum():,}")
    print(f"Incorrect predictions   : {(~correct).sum():,}")
    print(f"Attack -> Benign        : {attack_to_benign:,}")

    print("\nPer-attack recall:")

    for attack_id, attack_name in ATTACK_IDS.items():

        mask = actual == attack_id

        if mask.sum() == 0:
            continue

        recall = (
            predictions[mask] == attack_id
        ).mean() * 100

        false_benign = (
            predictions[mask] == 0
        ).sum()

        print(
            f"{attack_name:<25} "
            f"Recall: {recall:>6.2f}% | "
            f"-> Benign: {false_benign:>4,}"
        )


def main():

    print("=" * 70)
    print("SNIDS EXPERIMENT 6 - ATTACK MODEL COMPARISON")
    print("=" * 70)

    X_test = pd.read_parquet(X_TEST_FILE)
    y_test = pd.read_parquet(Y_TEST_FILE)

    mask = y_test["Label_ID"].isin(
        ATTACK_IDS.keys()
    )

    X_attack = X_test.loc[mask]
    y_attack = y_test.loc[mask, "Label_ID"]

    print(
        f"\nAttack samples: {len(X_attack):,}"
    )

    for model_name, model_file in MODELS.items():

        print(
            f"\nLoading {model_name}..."
        )

        model = joblib.load(model_file)

        evaluate_model(
            model_name,
            model,
            X_attack,
            y_attack
        )

    print("\n" + "=" * 70)
    print("EXPERIMENT 6 COMPLETED")
    print("=" * 70)


if __name__ == "__main__":
    main()
