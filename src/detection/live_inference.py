import pandas as pd
import joblib

from pathlib import Path

from flow_builder import FlowBuilder
from alert_logger import log_alert


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

    print("\nLoading Balanced Random Forest...")

    model = joblib.load(MODEL_FILE)

    print("Model loaded successfully.")

    X_train = pd.read_parquet(TRAIN_FILE)

    feature_names = list(X_train.columns)

    print(
        f"Expected features: {len(feature_names)}"
    )

    label_mapping_df = pd.read_csv(
        LABEL_FILE
    )

    label_mapping = dict(
        zip(
            label_mapping_df["Label_ID"],
            label_mapping_df["Label"]
        )
    )

    builder = FlowBuilder(LOCAL_IP)

    print(
        f"Local IP: {LOCAL_IP}"
    )

    print("\nStarting live packet capture...")
    print(
        "A prediction will be generated "
        "when a flow reaches 5 packets."
    )
    print("Press CTRL+C to stop.\n")

    processed_flows = set()

    def process_packet(packet):

        flow_key = builder.process_packet(packet)

        if flow_key is None:
            return

        flow = builder.flows[flow_key]

        if len(flow.packets) < 5:
            return

        if flow_key in processed_flows:
            return

        processed_flows.add(flow_key)

        features = builder.get_features(flow_key)

        if features is None:
            return

        live_df = pd.DataFrame(
            [features]
        )

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

        live_df = live_df[
            feature_names
        ]

        # -------------------------------------------------
        # Prediction + confidence
        # -------------------------------------------------

        prediction_probabilities = model.predict_proba(
            live_df
        )[0]

        best_index = prediction_probabilities.argmax()

        prediction_id = int(
            model.classes_[best_index]
        )

        confidence = float(
            prediction_probabilities[best_index]
        )

        prediction_label = label_mapping.get(
            prediction_id,
            f"Unknown ({prediction_id})"
        )

        # -------------------------------------------------
        # Flow endpoints
        # -------------------------------------------------

        endpoint_a = flow_key[0]
        endpoint_b = flow_key[1]

        endpoint_a_ip = endpoint_a[0]
        endpoint_a_port = endpoint_a[1]

        endpoint_b_ip = endpoint_b[0]
        endpoint_b_port = endpoint_b[1]

        # -------------------------------------------------
        # Severity
        # -------------------------------------------------

        if prediction_label == "Benign":
            severity = "LOW"
        else:
            severity = "HIGH"

        # -------------------------------------------------
        # Log prediction
        # -------------------------------------------------

        log_alert(
            prediction=prediction_label,
            source_ip=endpoint_a_ip,
            destination_ip=endpoint_b_ip,
            packets=len(flow.packets),
        )

        # -------------------------------------------------
        # Display result
        # -------------------------------------------------

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

        print(
            f"Confidence   : "
            f"{confidence * 100:.2f}%"
        )

        print(
            f"Endpoint A   : "
            f"{endpoint_a_ip}:{endpoint_a_port}"
        )

        print(
            f"Endpoint B   : "
            f"{endpoint_b_ip}:{endpoint_b_port}"
        )

        if prediction_label == "Benign":

            print(
                "\nSTATUS       : NORMAL TRAFFIC"
            )

        else:

            print(
                "\nSTATUS       : 🚨 ATTACK DETECTED"
            )

        print(
            f"Severity     : {severity}"
        )

        print(
            "Alert logged to: logs/snids_alerts.csv"
        )

    # -----------------------------------------------------
    # Start packet capture
    # -----------------------------------------------------

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
