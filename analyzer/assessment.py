import json

from scanner.nmap_parser import parse_nmap_xml
from risk.risk_engine import analyze


def main():

    xml_file = "scans/nmap_scan.xml"

    print("=" * 70)
    print("NETWORK SECURITY ASSESSMENT FRAMEWORK")
    print("=" * 70)

    print(f"\n[*] Reading scan data: {xml_file}")

    try:
        hosts = parse_nmap_xml(xml_file)
    except FileNotFoundError:
        print("[!] Nmap XML file not found.")
        return
    except Exception as error:
        print(f"[!] Failed to parse XML: {error}")
        return

    findings = analyze(hosts)

    print("\n" + "=" * 70)
    print("SECURITY FINDINGS")
    print("=" * 70)

    if not findings:
        print("\n[+] No findings generated.")
        return

    for item in findings:

        print(
            f"\n[{item['severity']}] "
            f"{item['host']}:{item['port']}"
        )

        print(f"Protocol : {item['protocol']}")
        print(f"Service  : {item['service']}")
        print(
            f"Product  : "
            f"{item['product']} {item['version']}"
        )

        if item.get("cpe"):
            print(f"CPE      : {item['cpe']}")

        print(f"Risk     : {item['score']}")
        print(f"Finding  : {item['finding']}")
        print(f"Mitigate : {item['mitigation']}")

    # Save findings as JSON
    output_file = "reports/findings.json"

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(findings, file, indent=4)

    print("\n" + "=" * 70)
    print(f"[+] Findings saved to: {output_file}")
    print("=" * 70)


if __name__ == "__main__":
    main()