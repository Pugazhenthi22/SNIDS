import pandas as pd
import joblib

from pathlib import Path

from flow_builder import FlowBuilder


PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_FILE = (
    PROJECT_ROOT
    / "models"
    / "balanced_random_forest.joblib"
)

TRAIN_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "X_train.parquet"
)

LABEL_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "label_mapping.csv"
)

LOCAL_IP = "10.74.75.244"


def main():

    print("=" * 70)
    print("SNIDS LIVE ML INFERENCE")
    print("=" * 70)

    # ---------------------------------------------------------
    # Load model
    # ---------------------------------------------------------

    print("\nLoading Balanced Random Forest...")

    model = joblib.load(MODEL_FILE)

    print("Model loaded successfully.")

    # ---------------------------------------------------------
    # Load training feature schema
    # ---------------------------------------------------------

    X_train = pd.read_parquet(TRAIN_FILE)

    feature_names = list(X_train.columns)

    print(
        f"Expected features: {len(feature_names)}"
    )

    # ---------------------------------------------------------
    # Load label mapping
    # ---------------------------------------------------------

    label_mapping_df = pd.read_csv(
        LABEL_FILE
    )

    label_mapping = dict(
        zip(
            label_mapping_df["Label_ID"],
            label_mapping_df["Label"]
        )
    )

    # ---------------------------------------------------------
    # Create flow builder
    # ---------------------------------------------------------

    builder = FlowBuilder(LOCAL_IP)

    print(
        f"Local IP: {LOCAL_IP}"
    )

    print("\nStarting live packet capture...")
    print("A prediction will be generated when a flow reaches 5 packets.")
    print("Press CTRL+C to stop.\n")

    processed_flows = set()

    def process_packet(packet):

        flow_key = builder.process_packet(packet)

        if flow_key is None:
            return

        flow = builder.flows[flow_key]

        # Wait until the flow has enough packets
        if len(flow.packets) < 5:
            return

        # Predict each flow only once
        if flow_key in processed_flows:
            return

        processed_flows.add(flow_key)

        # -----------------------------------------------------
        # Extract features
        # -----------------------------------------------------

        features = builder.get_features(flow_key)

        if features is None:
            return

        # Convert to DataFrame
        live_df = pd.DataFrame(
            [features]
        )

        # -----------------------------------------------------
        # Verify feature schema
        # -----------------------------------------------------

        if len(live_df.columns) != len(feature_names):

            print(
                "\nERROR: Incorrect feature count."
            )

            print(
                f"Expected: {len(feature_names)}"
            )

            print(
                f"Received: {len(live_df.columns)}"
            )

            return

        # Reorder exactly like training
        live_df = live_df[
            feature_names
        ]

        # -----------------------------------------------------
        # Generate prediction
        # -----------------------------------------------------

        prediction = model.predict(
            live_df
        )[0]

        prediction_id = int(prediction)

        prediction_label = label_mapping.get(
            prediction_id,
            f"Unknown ({prediction_id})"
        )

        # -----------------------------------------------------
        # Display result
        # -----------------------------------------------------

        print("\n" + "=" * 70)
        print("SNIDS PREDICTION")
        print("=" * 70)

        print(
            f"Flow packets : "
            f"{len(flow.packets)}"
        )

        print(
            f"Features     : "
            f"{len(live_df.columns)}"
        )

        print(
            f"Prediction ID: "
            f"{prediction_id}"
        )

        print(
            f"Prediction   : "
            f"{prediction_label}"
        )

        if prediction_label == "Benign":

            print(
                "\nSTATUS       : NORMAL TRAFFIC"
            )

        else:

            print(
                "\nSTATUS       : 🚨 ATTACK DETECTED"
            )

        print("=" * 70)

    try:

        from scapy.all import sniff

        sniff(
            prn=process_packet,
            store=False
        )

    except KeyboardInterrupt:

        print("\n")
        print("=" * 70)
        print("SNIDS LIVE INFERENCE STOPPED")
        print("=" * 70)

        print(
            f"Flows analyzed: "
            f"{len(processed_flows)}"
        )


if __name__ == "__main__":
    main()
