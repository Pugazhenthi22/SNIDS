import sys
import time
import subprocess
from pathlib import Path
from collections import defaultdict, deque

import pandas as pd
import joblib

from flow_builder import FlowBuilder
from alert_logger import log_alert


# ================================================================
# Paths / constants
# ================================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_NAME = sys.argv[2] if len(sys.argv) > 2 else "balanced"

MODEL_FILES = {
    "balanced": PROJECT_ROOT / "models" / "balanced_random_forest.joblib",
    "experiment": PROJECT_ROOT / "models" / "balanced_random_forest_experiment.joblib",
}

if MODEL_NAME not in MODEL_FILES:
    raise ValueError("Choose model: balanced or experiment")

MODEL_FILE = MODEL_FILES[MODEL_NAME]
LABEL_FILE = PROJECT_ROOT / "data" / "processed" / "label_mapping.csv"

# Flow-based ML classification fires once a flow reaches this many packets.
FLOW_PACKET_THRESHOLD = 5

# Behavioral PortScan detection: N unique destination ports within WINDOW seconds.
PORTSCAN_WINDOW = 10
PORTSCAN_THRESHOLD = 10
CONN_RATE_WINDOW = 10
CONN_RATE_THRESHOLD = 20
HIGH_TRAFFIC_WINDOW = 5
HIGH_TRAFFIC_THRESHOLD = 200

# ================================================================
# Interface / local IP resolution
# ================================================================

def get_local_ip(interface):
    """Return the IPv4 address assigned to the given network interface."""
    if interface == "lo":
        return "127.0.0.1"

    try:
        result = subprocess.check_output(
            ["ip", "-4", "addr", "show", interface],
            text=True,
        )
        for line in result.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1].split("/")[0]
    except Exception as error:
        raise RuntimeError(f"Unable to determine IP address for {interface}: {error}")

    raise RuntimeError(f"No IPv4 address found on {interface}.")


CAPTURE_INTERFACE = sys.argv[1] if len(sys.argv) > 1 else "eth0"
LOCAL_IP = get_local_ip(CAPTURE_INTERFACE)


# ================================================================
# PortScan behavioral detector
# ================================================================

class PortScanDetector:
    """
    Tracks outbound TCP SYN packets per source IP. If a single source
    touches PORTSCAN_THRESHOLD or more unique destination ports within
    PORTSCAN_WINDOW seconds, it's flagged as a PortScan and logged once.

    Only pure SYN packets (flags == "S") count towards the port total.
    Replies such as SYN-ACK, RST, and RST-ACK are intentionally ignored,
    since counting them corrupts the unique-port count and causes false
    positives/negatives.
    """

    def __init__(self, window=PORTSCAN_WINDOW, threshold=PORTSCAN_THRESHOLD):
        self.window = window
        self.threshold = threshold
        self.tracker = defaultdict(deque)   # src_ip -> deque[(timestamp, dst_ip, dst_port)]
        self.alerted = set()

    def process(self, packet):
        if not packet.haslayer("IP") or not packet.haslayer("TCP"):
            return

        tcp_layer = packet["TCP"]

        # Pure SYN only — excludes SYN-ACK, RST, RST-ACK, ACK, etc.
        if tcp_layer.flags != "S":
            return

        ip_layer = packet["IP"]
        source_ip = ip_layer.src
        destination_ip = ip_layer.dst
        destination_port = int(tcp_layer.dport)
        now = time.time()

        events = self.tracker[source_ip]
        events.append((now, destination_ip, destination_port))

        while events and now - events[0][0] > self.window:
            events.popleft()

        unique_ports = {port for (_, _, port) in events}

        if len(unique_ports) >= self.threshold:
            if source_ip not in self.alerted:
                self.alerted.add(source_ip)
                self._raise_alert(source_ip, destination_ip, unique_ports)
        elif source_ip in self.alerted:
            # Activity dropped back below threshold; allow re-alerting later.
            self.alerted.discard(source_ip)

    def _raise_alert(self, source_ip, destination_ip, unique_ports):
        print("\n" + "=" * 70)
        print("SNIDS BEHAVIORAL DETECTION")
        print("=" * 70)
        print("Detection    : PortScan")
        print(f"Source IP    : {source_ip}")
        print(f"Target IP    : {destination_ip}")
        print(f"Unique Ports : {len(unique_ports)}")
        print(f"Window       : {self.window} seconds")
        print("STATUS       : \U0001f6a8 ATTACK DETECTED")
        print("Severity     : HIGH")

        log_alert(
            prediction="PortScan",
            source_ip=source_ip,
            destination_ip=destination_ip,
            packets=len(unique_ports),
        )

        print("Alert logged to: logs/snids_alerts.csv")

class ConnectionRateDetector:
    """Detect a burst of new TCP connection attempts from one source."""

    def __init__(self, window=CONN_RATE_WINDOW,
                 threshold=CONN_RATE_THRESHOLD):
        self.window = window
        self.threshold = threshold
        self.tracker = defaultdict(deque)
        self.alerted = set()

    def process(self, packet):
        if not packet.haslayer("IP") or not packet.haslayer("TCP"):
            return

        tcp = packet["TCP"]
        flags = int(tcp.flags)

        # Count new connection attempts: SYN set, ACK not set.
        if not (flags & 0x02) or (flags & 0x10):
            return

        ip = packet["IP"]
        source_ip = ip.src
        destination_ip = ip.dst
        now = time.time()

        events = self.tracker[source_ip]
        events.append((now, destination_ip, int(tcp.dport)))

        while events and now - events[0][0] > self.window:
            events.popleft()

        if len(events) >= self.threshold:
            if source_ip not in self.alerted:
                self.alerted.add(source_ip)

                print("\n" + "=" * 60)
                print("SNIDS BEHAVIORAL DETECTION")
                print("Detection    : HighConnectionRate")
                print(f"Source IP    : {source_ip}")
                print(f"Attempts     : {len(events)}")
                print(f"Window       : {self.window} seconds")
                print("Severity     : HIGH")
                print("=" * 60)

                log_alert(
                    prediction="HighConnectionRate",
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    packets=len(events),
                )
        elif source_ip in self.alerted:
            self.alerted.discard(source_ip)

class HighTrafficDetector:
    """Detect unusually high IP packet rates from a single source."""

    def __init__(
        self,
        window=HIGH_TRAFFIC_WINDOW,
        threshold=HIGH_TRAFFIC_THRESHOLD,
    ):
        self.window = window
        self.threshold = threshold
        self.tracker = defaultdict(deque)
        self.alerted = set()

    def process(self, packet):
        if not packet.haslayer("IP"):
            return

        ip = packet["IP"]
        source_ip = ip.src
        destination_ip = ip.dst
        now = time.time()

        events = self.tracker[source_ip]
        events.append(now)

        while events and now - events[0] > self.window:
            events.popleft()

        if len(events) >= self.threshold:
            if source_ip not in self.alerted:
                self.alerted.add(source_ip)

                print("\n" + "=" * 60)
                print("SNIDS BEHAVIORAL DETECTION")
                print("Detection    : HighTraffic")
                print(f"Source IP    : {source_ip}")
                print(f"Packets      : {len(events)}")
                print(f"Window       : {self.window} seconds")
                print("Severity     : HIGH")
                print("=" * 60)

                log_alert(
                    prediction="HighTraffic",
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    packets=len(events),
                )
        elif source_ip in self.alerted:
            self.alerted.discard(source_ip)

# ================================================================
# Main
# ================================================================

def main():
    print("=" * 70)
    print("SNIDS LIVE ML INFERENCE")
    print("=" * 70)

    print("\nLoading Balanced Random Forest...")
    model = joblib.load(MODEL_FILE)
    print("Model loaded successfully.")

    feature_names = list(model.feature_names_in_)
    print(f"Selected model: {MODEL_NAME}")
    print(f"Expected features: {len(feature_names)}")

    label_mapping_df = pd.read_csv(LABEL_FILE)
    label_mapping = dict(zip(label_mapping_df["Label_ID"], label_mapping_df["Label"]))

    builder = FlowBuilder(LOCAL_IP)
    scanner = PortScanDetector()
    connection_detector = ConnectionRateDetector()
    high_traffic_detector = HighTrafficDetector()

    print(f"Local IP: {LOCAL_IP}")
    print(f"Capture interface: {CAPTURE_INTERFACE}")
    print("\nStarting live packet capture...")
    print(f"A prediction will be generated when a flow reaches {FLOW_PACKET_THRESHOLD} packets.")
    print("Press CTRL+C to stop.\n")

    processed_flows = set()

    def process_packet(packet):
        # ---- Behavioral PortScan detection (runs on every packet) ----
        try:
            scanner.process(packet)
        except Exception as error:
            print(f"\nPortScan detection error: {error}")

        try:
            connection_detector.process(packet)
        except Exception as error:
            print(f"\nConnection-rate detection error: {error}")


        try:
            high_traffic_detector.process(packet)
        except Exception as error:
            print(f"\nHigh-traffic detection error: {error}")


        # ---- ML flow-based classification ----
        flow_key = builder.process_packet(packet)
        if flow_key is None:
            return

        flow = builder.flows[flow_key]

        if len(flow.packets) < FLOW_PACKET_THRESHOLD:
            return

        if flow_key in processed_flows:
            return
        processed_flows.add(flow_key)

        features = builder.get_features(flow_key)
        if features is None:
            return

        live_df = pd.DataFrame([features])

        if len(live_df.columns) != len(feature_names):
            print("\nERROR: Incorrect feature count.")
            print(f"Expected: {len(feature_names)}")
            print(f"Received: {len(live_df.columns)}")
            return

        try:
            live_df = live_df[feature_names]
        except KeyError as error:
            print("\nERROR: Feature mismatch.")
            print(error)
            return

        prediction_probabilities = model.predict_proba(live_df)[0]
        best_index = prediction_probabilities.argmax()
        prediction_id = int(model.classes_[best_index])
        confidence = float(prediction_probabilities[best_index])
        prediction_label = label_mapping.get(prediction_id, f"Unknown ({prediction_id})")

        endpoint_a_ip, endpoint_a_port = flow_key[0]
        endpoint_b_ip, endpoint_b_port = flow_key[1]

        severity = "LOW" if prediction_label == "Benign" else "HIGH"

        log_alert(
            prediction=prediction_label,
            source_ip=endpoint_a_ip,
            destination_ip=endpoint_b_ip,
            packets=len(flow.packets),
        )

        print("\n" + "=" * 70)
        print("SNIDS PREDICTION")
        print("=" * 70)
        print(f"Flow packets : {len(flow.packets)}")
        print(f"Features     : {len(live_df.columns)}")
        print(f"Prediction ID: {prediction_id}")
        print(f"Prediction   : {prediction_label}")
        print(f"Confidence   : {confidence * 100:.2f}%")
        print(f"Endpoint A   : {endpoint_a_ip}:{endpoint_a_port}")
        print(f"Endpoint B   : {endpoint_b_ip}:{endpoint_b_port}")

        if prediction_label == "Benign":
            print("\nSTATUS       : NORMAL TRAFFIC")
        else:
            print("\nSTATUS       : \U0001f6a8 ATTACK DETECTED")

        print(f"Severity     : {severity}")
        print("Alert logged to: logs/snids_alerts.csv")

    try:
        from scapy.all import sniff
        sniff(iface=CAPTURE_INTERFACE, prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n" + "=" * 70)
        print("SNIDS LIVE INFERENCE STOPPED")
        print("=" * 70)
        print(f"Flows analyzed: {len(processed_flows)}")


if __name__ == "__main__":
    main()
