from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS
from collections import Counter
from pathlib import Path
import json


def analyze_packets(pcap_file):
    """
    Analyze an authorized PCAP capture and return
    structured network statistics.
    """

    path = Path(pcap_file)

    if not path.exists():
        raise FileNotFoundError(
            f"PCAP file not found: {pcap_file}"
        )

    packets = rdpcap(str(path))

    protocol_counts = Counter()
    source_counts = Counter()
    destination_counts = Counter()

    tcp_count = 0
    udp_count = 0
    icmp_count = 0
    dns_count = 0

    for packet in packets:

        if IP not in packet:
            continue

        source = packet[IP].src
        destination = packet[IP].dst

        source_counts[source] += 1
        destination_counts[destination] += 1

        if TCP in packet:
            protocol_counts["TCP"] += 1
            tcp_count += 1

        elif UDP in packet:
            protocol_counts["UDP"] += 1
            udp_count += 1

        elif ICMP in packet:
            protocol_counts["ICMP"] += 1
            icmp_count += 1

        else:
            protocol_counts["Other"] += 1

        if DNS in packet:
            dns_count += 1

    result = {
        "total_packets": len(packets),
        "protocols": dict(protocol_counts),
        "top_sources": dict(source_counts.most_common(10)),
        "top_destinations": dict(
            destination_counts.most_common(10)
        ),
        "tcp_packets": tcp_count,
        "udp_packets": udp_count,
        "icmp_packets": icmp_count,
        "dns_packets": dns_count
    }

    return result


def display_results(results):

    print("\n" + "=" * 60)
    print("NETWORK PACKET ANALYSIS")
    print("=" * 60)

    print(
        f"\nTotal packets : "
        f"{results['total_packets']}"
    )

    print("\nProtocol distribution:")

    for protocol, count in results["protocols"].items():
        print(f"  {protocol:<10} {count}")

    print("\nTop source IPs:")

    for ip, count in results["top_sources"].items():
        print(f"  {ip:<18} {count}")

    print("\nTop destination IPs:")

    for ip, count in results["top_destinations"].items():
        print(f"  {ip:<18} {count}")

    print("\nProtocol details:")

    print(f"  TCP  : {results['tcp_packets']}")
    print(f"  UDP  : {results['udp_packets']}")
    print(f"  ICMP : {results['icmp_packets']}")
    print(f"  DNS  : {results['dns_packets']}")


def save_results(results):

    output = Path("reports/packet_analysis.json")

    with open(
        output,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            results,
            file,
            indent=4
        )

    print(
        f"\n[+] Packet analysis saved to: {output}"
    )


def main():

    pcap_file = "captures/network_capture.pcapng"

    try:

        results = analyze_packets(pcap_file)

        display_results(results)

        save_results(results)

    except FileNotFoundError as error:

        print(f"[!] {error}")

    except Exception as error:

        print(f"[!] Analysis failed: {error}")


if __name__ == "__main__":
    main()