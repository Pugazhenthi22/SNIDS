from collections import defaultdict
from statistics import mean, pstdev


class FlowFeatureExtractor:
    """
    Collect packets belonging to a network flow and
    generate the 69 features expected by the SNIDS model.
    """

    FEATURE_NAMES = [
        "Protocol",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Fwd Packets Length Total",
        "Bwd Packets Length Total",
        "Fwd Packet Length Max",
        "Fwd Packet Length Min",
        "Fwd Packet Length Mean",
        "Fwd Packet Length Std",
        "Bwd Packet Length Max",
        "Bwd Packet Length Min",
        "Bwd Packet Length Mean",
        "Bwd Packet Length Std",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Flow IAT Mean",
        "Flow IAT Std",
        "Flow IAT Max",
        "Flow IAT Min",
        "Fwd IAT Total",
        "Fwd IAT Mean",
        "Fwd IAT Std",
        "Fwd IAT Max",
        "Fwd IAT Min",
        "Bwd IAT Total",
        "Bwd IAT Mean",
        "Bwd IAT Std",
        "Bwd IAT Max",
        "Bwd IAT Min",
        "Fwd PSH Flags",
        "Fwd URG Flags",
        "Fwd Header Length",
        "Bwd Header Length",
        "Fwd Packets/s",
        "Bwd Packets/s",
        "Packet Length Min",
        "Packet Length Max",
        "Packet Length Mean",
        "Packet Length Std",
        "Packet Length Variance",
        "FIN Flag Count",
        "SYN Flag Count",
        "RST Flag Count",
        "PSH Flag Count",
        "ACK Flag Count",
        "URG Flag Count",
        "CWE Flag Count",
        "ECE Flag Count",
        "Down/Up Ratio",
        "Avg Packet Size",
        "Avg Fwd Segment Size",
        "Avg Bwd Segment Size",
        "Subflow Fwd Packets",
        "Subflow Fwd Bytes",
        "Subflow Bwd Packets",
        "Subflow Bwd Bytes",
        "Init Fwd Win Bytes",
        "Init Bwd Win Bytes",
        "Fwd Act Data Packets",
        "Fwd Seg Size Min",
        "Active Mean",
        "Active Std",
        "Active Max",
        "Active Min",
        "Idle Mean",
        "Idle Std",
        "Idle Max",
        "Idle Min",
    ]

    def __init__(self):
        self.reset()

    def reset(self):
        self.packets = []

    def add_packet(
        self,
        timestamp,
        packet_length,
        direction="fwd",
        tcp_flags=0,
        header_length=0,
        payload_length=0,
        protocol=6,
        window_size=0,
    ):
        self.packets.append({
            "timestamp": float(timestamp),
            "length": float(packet_length),
            "direction": direction,
            "flags": int(tcp_flags),
            "header_length": float(header_length),
            "payload_length": float(payload_length),
            "protocol": int(protocol),
            "window_size": int(window_size),
        })

    @staticmethod
    def _safe_mean(values):
        return mean(values) if values else 0.0

    @staticmethod
    def _safe_std(values):
        return pstdev(values) if len(values) > 1 else 0.0

    @staticmethod
    def _safe_min(values):
        return min(values) if values else 0.0

    @staticmethod
    def _safe_max(values):
        return max(values) if values else 0.0

    @staticmethod
    def _iat(timestamps):
        if len(timestamps) < 2:
            return []

        timestamps = sorted(timestamps)

        return [
            timestamps[i] - timestamps[i - 1]
            for i in range(1, len(timestamps))
        ]

    def extract(self):
        if not self.packets:
            return {name: 0.0 for name in self.FEATURE_NAMES}

        packets = sorted(
            self.packets,
            key=lambda x: x["timestamp"]
        )

        fwd = [
            p for p in packets
            if p["direction"] == "fwd"
        ]

        bwd = [
            p for p in packets
            if p["direction"] == "bwd"
        ]

        all_lengths = [
            p["length"] for p in packets
        ]

        fwd_lengths = [
            p["length"] for p in fwd
        ]

        bwd_lengths = [
            p["length"] for p in bwd
        ]

        timestamps = [
            p["timestamp"] for p in packets
        ]

        fwd_times = [
            p["timestamp"] for p in fwd
        ]

        bwd_times = [
            p["timestamp"] for p in bwd
        ]

        flow_iat = self._iat(timestamps)
        fwd_iat = self._iat(fwd_times)
        bwd_iat = self._iat(bwd_times)

        duration = (
            timestamps[-1] - timestamps[0]
            if len(timestamps) > 1
            else 0.0
        )

        flow_seconds = max(duration, 1e-9)

        def flag_count(mask):
            return sum(
                1 for p in packets
                if p["flags"] & mask
            )

        features = {
            "Protocol": packets[0]["protocol"],

            "Flow Duration": duration * 1_000_000,

            "Total Fwd Packets": len(fwd),
            "Total Backward Packets": len(bwd),

            "Fwd Packets Length Total": sum(fwd_lengths),
            "Bwd Packets Length Total": sum(bwd_lengths),

            "Fwd Packet Length Max": self._safe_max(fwd_lengths),
            "Fwd Packet Length Min": self._safe_min(fwd_lengths),
            "Fwd Packet Length Mean": self._safe_mean(fwd_lengths),
            "Fwd Packet Length Std": self._safe_std(fwd_lengths),

            "Bwd Packet Length Max": self._safe_max(bwd_lengths),
            "Bwd Packet Length Min": self._safe_min(bwd_lengths),
            "Bwd Packet Length Mean": self._safe_mean(bwd_lengths),
            "Bwd Packet Length Std": self._safe_std(bwd_lengths),

            "Flow Bytes/s": sum(all_lengths) / flow_seconds,
            "Flow Packets/s": len(packets) / flow_seconds,

            "Flow IAT Mean": self._safe_mean(flow_iat) * 1_000_000,
            "Flow IAT Std": self._safe_std(flow_iat) * 1_000_000,
            "Flow IAT Max": self._safe_max(flow_iat) * 1_000_000,
            "Flow IAT Min": self._safe_min(flow_iat) * 1_000_000,

            "Fwd IAT Total": sum(fwd_iat) * 1_000_000,
            "Fwd IAT Mean": self._safe_mean(fwd_iat) * 1_000_000,
            "Fwd IAT Std": self._safe_std(fwd_iat) * 1_000_000,
            "Fwd IAT Max": self._safe_max(fwd_iat) * 1_000_000,
            "Fwd IAT Min": self._safe_min(fwd_iat) * 1_000_000,

            "Bwd IAT Total": sum(bwd_iat) * 1_000_000,
            "Bwd IAT Mean": self._safe_mean(bwd_iat) * 1_000_000,
            "Bwd IAT Std": self._safe_std(bwd_iat) * 1_000_000,
            "Bwd IAT Max": self._safe_max(bwd_iat) * 1_000_000,
            "Bwd IAT Min": self._safe_min(bwd_iat) * 1_000_000,

            "Fwd PSH Flags": sum(
                1 for p in fwd if p["flags"] & 0x08
            ),

            "Fwd URG Flags": sum(
                1 for p in fwd if p["flags"] & 0x20
            ),

            "Fwd Header Length": sum(
                p["header_length"] for p in fwd
            ),

            "Bwd Header Length": sum(
                p["header_length"] for p in bwd
            ),

            "Fwd Packets/s": len(fwd) / flow_seconds,
            "Bwd Packets/s": len(bwd) / flow_seconds,

            "Packet Length Min": self._safe_min(all_lengths),
            "Packet Length Max": self._safe_max(all_lengths),
            "Packet Length Mean": self._safe_mean(all_lengths),
            "Packet Length Std": self._safe_std(all_lengths),

            "Packet Length Variance": (
                self._safe_std(all_lengths) ** 2
            ),

            "FIN Flag Count": flag_count(0x01),
            "SYN Flag Count": flag_count(0x02),
            "RST Flag Count": flag_count(0x04),
            "PSH Flag Count": flag_count(0x08),
            "ACK Flag Count": flag_count(0x10),
            "URG Flag Count": flag_count(0x20),
            "CWE Flag Count": flag_count(0x80),
            "ECE Flag Count": flag_count(0x40),

            "Down/Up Ratio": (
                len(bwd) / len(fwd)
                if len(fwd) > 0
                else 0.0
            ),

            "Avg Packet Size": self._safe_mean(all_lengths),

            "Avg Fwd Segment Size": self._safe_mean(
                [
                    p["payload_length"]
                    for p in fwd
                ]
            ),

            "Avg Bwd Segment Size": self._safe_mean(
                [
                    p["payload_length"]
                    for p in bwd
                ]
            ),

            "Subflow Fwd Packets": len(fwd),
            "Subflow Fwd Bytes": sum(fwd_lengths),

            "Subflow Bwd Packets": len(bwd),
            "Subflow Bwd Bytes": sum(bwd_lengths),

            "Init Fwd Win Bytes": (
                fwd[0]["window_size"]
                if fwd else 0
            ),

            "Init Bwd Win Bytes": (
                bwd[0]["window_size"]
                if bwd else 0
            ),

            "Fwd Act Data Packets": sum(
                1 for p in fwd
                if p["payload_length"] > 0
            ),

            "Fwd Seg Size Min": self._safe_min(
                [
                    p["payload_length"]
                    for p in fwd
                    if p["payload_length"] > 0
                ]
            ),

            # Active / Idle are initialized to zero
            # until we implement the full CICIDS active-idle algorithm.
            "Active Mean": 0.0,
            "Active Std": 0.0,
            "Active Max": 0.0,
            "Active Min": 0.0,

            "Idle Mean": 0.0,
            "Idle Std": 0.0,
            "Idle Max": 0.0,
            "Idle Min": 0.0,
        }

        return features


if __name__ == "__main__":
    extractor = FlowFeatureExtractor()

    print("Flow feature extractor loaded successfully.")
    print(f"Expected features: {len(extractor.FEATURE_NAMES)}")