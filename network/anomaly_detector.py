from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict, Counter
from pathlib import Path
import json


PCAP_FILE = "captures/network_capture.pcapng"
OUTPUT_FILE = "reports/anomalies.json"


def analyze_traffic(pcap_file):

    packets = rdpcap(pcap_file)

    source_packets = Counter()
    source_destinations = defaultdict(set)
    source_ports = defaultdict(set)
    source_connections = Counter()

    for packet in packets:

        if IP not in packet:
            continue

        src = packet[IP].src
        dst = packet[IP].dst

        source_packets[src] += 1
        source_destinations[src].add(dst)

        if TCP in packet:

            source_ports[src].add(
                packet[TCP].dport
            )

            if packet[TCP].flags.S:
                source_connections[(src, dst)] += 1

        elif UDP in packet:

            source_ports[src].add(
                packet[UDP].dport
            )

    anomalies = []

    # High packet-volume sources
    for source, count in source_packets.items():

        if count > 10000:

            anomalies.append({
                "type": "High Packet Volume",
                "source": source,
                "evidence": f"{count} packets observed",
                "severity": "Medium",
                "confidence": "Low",
                "recommendation": (
                    "Review the destination and application "
                    "associated with this traffic."
                )
            })

    # Sources communicating with many destinations
    for source, destinations in source_destinations.items():

        if len(destinations) > 50:

            anomalies.append({
                "type": "High Destination Diversity",
                "source": source,
                "evidence": (
                    f"{len(destinations)} unique destinations"
                ),
                "severity": "Medium",
                "confidence": "Low",
                "recommendation": (
                    "Review whether the host normally "
                    "communicates with this many destinations."
                )
            })

    # Sources contacting many ports
    for source, ports in source_ports.items():

        if len(ports) > 30:

            anomalies.append({
                "type": "High Port Diversity",
                "source": source,
                "evidence": (
                    f"{len(ports)} destination ports contacted"
                ),
                "severity": "Medium",
                "confidence": "Low",
                "recommendation": (
                    "Investigate whether this represents "
                    "normal application activity or scanning."
                )
            })

    return anomalies


def display_anomalies(anomalies):

    print("\n" + "=" * 60)
    print("TRAFFIC ANOMALY ANALYSIS")
    print("=" * 60)

    if not anomalies:

        print("\n[+] No potential anomalies detected.")

        return

    for anomaly in anomalies:

        print(
            f"\n[{anomaly['severity']}] "
            f"{anomaly['type']}"
        )

        print(
            f"Source       : "
            f"{anomaly['source']}"
        )

        print(
            f"Evidence     : "
            f"{anomaly['evidence']}"
        )

        print(
            f"Confidence   : "
            f"{anomaly['confidence']}"
        )

        print(
            f"Recommendation: "
            f"{anomaly['recommendation']}"
        )


def save_anomalies(anomalies):

    output = Path(OUTPUT_FILE)

    with open(
        output,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            anomalies,
            file,
            indent=4
        )

    print(
        f"\n[+] Anomaly results saved to: "
        f"{output}"
    )


def main():

    try:

        anomalies = analyze_traffic(PCAP_FILE)

        display_anomalies(anomalies)

        save_anomalies(anomalies)

    except FileNotFoundError:

        print(
            f"[!] PCAP file not found: "
            f"{PCAP_FILE}"
        )

    except Exception as error:

        print(
            f"[!] Analysis failed: {error}"
        )


if __name__ == "__main__":
    main()