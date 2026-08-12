from collections import defaultdict
from scapy.all import IP, TCP, UDP
from flow_features import FlowFeatureExtractor


class FlowBuilder:

    def __init__(self, local_ip):
        self.local_ip = local_ip
        self.flows = defaultdict(FlowFeatureExtractor)

    def get_flow_key(self, src_ip, src_port, dst_ip, dst_port, protocol):
        """
        Create a bidirectional flow key.

        Traffic in both directions belongs to the same flow.
        """

        endpoint_a = (src_ip, src_port)
        endpoint_b = (dst_ip, dst_port)

        if endpoint_a <= endpoint_b:
            return (
                endpoint_a,
                endpoint_b,
                protocol
            )

        return (
            endpoint_b,
            endpoint_a,
            protocol
        )

    def process_packet(self, packet):

        if not packet.haslayer(IP):
            return None

        ip = packet[IP]

        src_ip = ip.src
        dst_ip = ip.dst
        protocol = ip.proto

        src_port = 0
        dst_port = 0
        tcp_flags = 0
        window_size = 0
        header_length = 0

        if packet.haslayer(TCP):

            tcp = packet[TCP]

            src_port = tcp.sport
            dst_port = tcp.dport

            tcp_flags = int(tcp.flags)
            window_size = int(tcp.window)

            header_length = int(tcp.dataofs or 5) * 4

        elif packet.haslayer(UDP):

            udp = packet[UDP]

            src_port = udp.sport
            dst_port = udp.dport

            header_length = 8

        else:
            return None

        packet_length = len(packet)

        payload_length = len(
            packet.payload.payload
        )

        direction = (
            "fwd"
            if src_ip == self.local_ip
            else "bwd"
        )

        flow_key = self.get_flow_key(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol
        )

        extractor = self.flows[flow_key]

        extractor.add_packet(
            timestamp=float(packet.time),
            packet_length=packet_length,
            direction=direction,
            tcp_flags=tcp_flags,
            header_length=header_length,
            payload_length=payload_length,
            protocol=protocol,
            window_size=window_size
        )

        return flow_key

    def get_features(self, flow_key):

        if flow_key not in self.flows:
            return None

        features = self.flows[flow_key].extract()

        return features

    def flow_count(self):
        return len(self.flows)


if __name__ == "__main__":

    local_ip = "10.74.75.244"

    builder = FlowBuilder(local_ip)

    print("=" * 70)
    print("SNIDS FLOW BUILDER")
    print("=" * 70)

    print(f"\nLocal IP: {local_ip}")

    print(
        f"Expected features: "
        f"{len(FlowFeatureExtractor.FEATURE_NAMES)}"
    )

    print("\nFlow builder initialized successfully.")