import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def run(command, description):
    print("\n" + "=" * 70)
    print(description)
    print("=" * 70)

    result = subprocess.run(
        command,
        cwd=ROOT
    )

    if result.returncode != 0:
        print(
            f"\n[!] Step failed: {description}"
        )
        return False

    print(
        f"\n[+] Completed: {description}"
    )

    return True


def check_project():

    required_files = [
        "scanner/nmap_scanner.py",
        "scanner/nmap_parser.py",
        "analyzer/assessment.py",
        "analyzer/correlation_engine.py",
        "risk/risk_engine.py",
        "reports/report_generator.py",
        "network/packet_analyzer.py",
        "network/anomaly_detector.py",
    ]

    missing = []

    for file in required_files:

        if not (ROOT / file).exists():
            missing.append(file)

    if missing:

        print("\n[!] Missing project files:")

        for file in missing:
            print(f"    {file}")

        return False

    return True


def run_nmap(target):

    print("\n" + "=" * 70)
    print("STEP 1 — NETWORK DISCOVERY")
    print("=" * 70)

    print(
        f"\n[*] Target: {target}"
    )

    command = [
        "nmap",
        "-Pn",
        "-sV",
        "-oX",
        "scans/nmap_scan.xml",
        target
    ]

    result = subprocess.run(
        command,
        cwd=ROOT
    )

    if result.returncode != 0:

        print("\n[!] Nmap scan failed.")

        return False

    print(
        "\n[+] Nmap scan completed."
    )

    print(
        "[+] XML saved to:"
        " scans/nmap_scan.xml"
    )

    return True


def run_assessment():

    return run(
        [
            sys.executable,
            "-m",
            "analyzer.assessment"
        ],
        "STEP 2 — SECURITY RISK ASSESSMENT"
    )


def run_report():

    return run(
        [
            sys.executable,
            "reports/report_generator.py"
        ],
        "STEP 3 — REPORT GENERATION"
    )


def run_correlation():

    return run(
        [
            sys.executable,
            "-m",
            "analyzer.correlation_engine"
        ],
        "STEP 4 — SECURITY CORRELATION"
    )


def run_packet_analysis():

    pcap = (
        ROOT
        / "captures"
        / "network_capture.pcapng"
    )

    if not pcap.exists():

        print(
            "\n[i] No PCAP file found."
        )

        print(
            "[i] Skipping packet analysis."
        )

        return True

    print("\n" + "=" * 70)
    print("STEP 5 — NETWORK TRAFFIC ANALYSIS")
    print("=" * 70)

    if not run(
        [
            sys.executable,
            "network/packet_analyzer.py"
        ],
        "Packet Analysis"
    ):

        return False

    if not run(
        [
            sys.executable,
            "network/anomaly_detector.py"
        ],
        "Traffic Anomaly Detection"
    ):

        return False

    return True


def full_assessment():

    print("\n")
    print("=" * 70)
    print("       FULL NETWORK SECURITY ASSESSMENT")
    print("=" * 70)

    target = input(
        "\nEnter authorized target IP/hostname: "
    ).strip()

    if not target:

        print(
            "\n[!] Target cannot be empty."
        )

        return

    print(
        f"\n[*] Assessment target: {target}"
    )

    # 1. Nmap
    if not run_nmap(target):
        return

    # 2. Risk assessment
    if not run_assessment():
        return

    # 3. HTML report
    if not run_report():
        return

    # 4. PCAP analysis
    if not run_packet_analysis():
        return

    # 5. Correlation
    if not run_correlation():
        return

    print("\n")
    print("=" * 70)
    print("             ASSESSMENT COMPLETE")
    print("=" * 70)

    print(
        "\nTarget:"
        f" {target}"
    )

    print("\nGenerated results:")

    print(
        "  [✓] scans/nmap_scan.xml"
    )

    print(
        "  [✓] reports/findings.json"
    )

    print(
        "  [✓] reports/security_assessment_report.html"
    )

    print(
        "  [✓] reports/security_summary.json"
    )

    if (
        ROOT
        / "reports"
        / "packet_analysis.json"
    ).exists():

        print(
            "  [✓] reports/packet_analysis.json"
        )

    if (
        ROOT
        / "reports"
        / "anomalies.json"
    ).exists():

        print(
            "  [✓] reports/anomalies.json"
        )

    print(
        "\n[+] Security assessment pipeline finished."
    )


def start_dashboard():

    print(
        "\n[*] Starting dashboard..."
    )

    subprocess.Popen(
        [
            sys.executable,
            "dashboard/app.py"
        ],
        cwd=ROOT
    )

    print(
        "\n[+] Dashboard available at:"
    )

    print(
        "    http://127.0.0.1:5000"
    )


def main():

    print("\n")
    print("=" * 70)
    print("       NETWORK SECURITY ASSESSMENT FRAMEWORK")
    print("=" * 70)

    print(
        "\nAutomated network discovery, "
        "risk assessment, traffic analysis "
        "and reporting."
    )

    if not check_project():

        print(
            "\n[!] Project setup is incomplete."
        )

        return

    while True:

        print("\n")
        print("=" * 70)
        print("MAIN MENU")
        print("=" * 70)

        print("""
1. Full Security Assessment
2. Nmap Scan Only
3. Packet Analysis Only
4. Open Dashboard
5. Exit
""")

        choice = input(
            "Select an option: "
        ).strip()

        if choice == "1":

            full_assessment()

        elif choice == "2":

            target = input(
                "\nEnter authorized target IP/hostname: "
            ).strip()

            if target:
                run_nmap(target)

        elif choice == "3":

            run_packet_analysis()

        elif choice == "4":

            start_dashboard()

        elif choice == "5":

            print(
                "\nExiting framework..."
            )

            break

        else:

            print(
                "\n[!] Invalid option."
            )


if __name__ == "__main__":
    main()