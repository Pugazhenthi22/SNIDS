from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
from datetime import datetime


flows = defaultdict(list)


def process_packet(packet):

    if not packet.haslayer(IP):
        return

    ip = packet[IP]

    src_ip = ip.src
    dst_ip = ip.dst
    protocol = ip.proto

    src_port = 0
    dst_port = 0

    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    flow_key = (
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol
    )

    flows[flow_key].append(packet)

    print(
        f"[{datetime.now().strftime('%H:%M:%S')}] "
        f"{src_ip}:{src_port} -> "
        f"{dst_ip}:{dst_port} "
        f"Protocol={protocol} "
        f"Length={len(packet)}"
    )


def main():

    print("=" * 70)
    print("SNIDS PACKET CAPTURE")
    print("=" * 70)

    print("\nStarting packet capture...")
    print("Press CTRL+C to stop.\n")

    try:

        sniff(
            prn=process_packet,
            store=False
        )

    except KeyboardInterrupt:

        print("\n" + "=" * 70)
        print("CAPTURE STOPPED")
        print("=" * 70)

        print(
            f"\nUnique flows captured: {len(flows)}"
        )

        for flow, packets in list(flows.items())[:10]:

            print("\nFlow:")
            print(
                f"  {flow[0]}:{flow[1]} -> "
                f"{flow[2]}:{flow[3]}"
            )

            print(
                f"  Protocol : {flow[4]}"
            )

            print(
                f"  Packets  : {len(packets)}"
            )


if __name__ == "__main__":
    main()