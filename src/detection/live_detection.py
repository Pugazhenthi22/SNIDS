import time

from scapy.all import sniff

from flow_builder import FlowBuilder


LOCAL_IP = "10.74.75.244"


def main():

    print("=" * 70)
    print("SNIDS LIVE FLOW DETECTION")
    print("=" * 70)

    builder = FlowBuilder(LOCAL_IP)

    print(f"\nLocal IP: {LOCAL_IP}")
    print("Starting packet capture...")
    print("Press CTRL+C to stop.\n")

    packet_count = 0

    def process_packet(packet):

        nonlocal packet_count

        flow_key = builder.process_packet(packet)

        if flow_key is None:
            return

        packet_count += 1

        if packet_count % 20 == 0:

            features = builder.get_features(flow_key)

            if features:

                print("\n" + "-" * 70)
                print("FLOW DETECTED")
                print("-" * 70)

                print(f"Flow packets : {len(builder.flows[flow_key].packets)}")
                print(f"Features     : {len(features)}")

                print(
                    f"Protocol     : "
                    f"{features['Protocol']}"
                )

                print(
                    f"Flow Duration: "
                    f"{features['Flow Duration']}"
                )

                print(
                    f"Fwd Packets  : "
                    f"{features['Total Fwd Packets']}"
                )

                print(
                    f"Bwd Packets  : "
                    f"{features['Total Backward Packets']}"
                )

                print(
                    f"Packet Mean  : "
                    f"{features['Packet Length Mean']:.2f}"
                )

                print(
                    f"Flow Bytes/s : "
                    f"{features['Flow Bytes/s']:.2f}"
                )

                print("-" * 70)

    try:

        sniff(
            prn=process_packet,
            store=False
        )

    except KeyboardInterrupt:

        print("\n")
        print("=" * 70)
        print("SNIDS CAPTURE STOPPED")
        print("=" * 70)

        print(
            f"Packets processed: {packet_count}"
        )

        print(
            f"Flows created: {builder.flow_count()}"
        )


if __name__ == "__main__":
    main()