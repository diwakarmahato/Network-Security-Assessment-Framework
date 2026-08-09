import json
from pathlib import Path
from datetime import datetime


FINDINGS_FILE = Path("reports/findings.json")
STATUS_FILE = Path("reports/mitigation_status.json")


VALID_STATUSES = {
    "Open",
    "In Progress",
    "Resolved"
}


def load_findings():

    if not FINDINGS_FILE.exists():
        return []

    with open(
        FINDINGS_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


def load_status():

    if not STATUS_FILE.exists():
        return {}

    with open(
        STATUS_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


def save_status(status):

    with open(
        STATUS_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            status,
            file,
            indent=4
        )


def create_finding_id(finding):

    return (
        f"{finding.get('host', 'unknown')}:"
        f"{finding.get('port', 'unknown')}/"
        f"{finding.get('protocol', 'unknown')}"
    )


def initialize_findings(findings, status):

    changed = False

    for finding in findings:

        finding_id = create_finding_id(
            finding
        )

        if finding_id not in status:

            status[finding_id] = {
                "status": "Open",
                "updated_at": datetime.now().isoformat(
                    timespec="seconds"
                ),
                "finding": finding.get(
                    "finding",
                    ""
                ),
                "mitigation": finding.get(
                    "mitigation",
                    ""
                )
            }

            changed = True

    return changed


def display_findings(findings, status):

    print("\n" + "=" * 70)
    print("MITIGATION TRACKING")
    print("=" * 70)

    if not findings:

        print("\n[!] No findings available.")

        return

    for index, finding in enumerate(
        findings,
        start=1
    ):

        finding_id = create_finding_id(
            finding
        )

        current = status.get(
            finding_id,
            {}
        )

        print(
            f"\n[{index}] "
            f"{finding.get('severity', 'Unknown')} "
            f"- "
            f"{finding.get('service', 'Unknown')}"
        )

        print(
            f"    Target : "
            f"{finding.get('host', 'Unknown')}"
        )

        print(
            f"    Port   : "
            f"{finding.get('port', 'Unknown')}"
        )

        print(
            f"    Finding: "
            f"{finding.get('finding', '')}"
        )

        print(
            f"    Status : "
            f"{current.get('status', 'Open')}"
        )

        print(
            f"    Updated: "
            f"{current.get('updated_at', 'N/A')}"
        )


def update_status(findings, status):

    if not findings:

        print("\n[!] No findings available.")

        return

    display_findings(
        findings,
        status
    )

    try:

        choice = int(
            input(
                "\nEnter finding number to update: "
            )
        )

    except ValueError:

        print(
            "\n[!] Please enter a valid number."
        )

        return

    if choice < 1 or choice > len(findings):

        print(
            "\n[!] Invalid finding number."
        )

        return

    finding = findings[choice - 1]

    finding_id = create_finding_id(
        finding
    )

    print("\nAvailable statuses:")

    print("1. Open")
    print("2. In Progress")
    print("3. Resolved")

    new_status_choice = input(
        "\nSelect status: "
    ).strip()

    status_map = {
        "1": "Open",
        "2": "In Progress",
        "3": "Resolved"
    }

    new_status = status_map.get(
        new_status_choice
    )

    if not new_status:

        print(
            "\n[!] Invalid status."
        )

        return

    status[finding_id][
        "status"
    ] = new_status

    status[finding_id][
        "updated_at"
    ] = datetime.now().isoformat(
        timespec="seconds"
    )

    save_status(status)

    print(
        f"\n[+] Finding status updated to: "
        f"{new_status}"
    )


def main():

    findings = load_findings()

    status = load_status()

    if initialize_findings(
        findings,
        status
    ):

        save_status(status)

    while True:

        print("\n" + "=" * 70)
        print("MITIGATION TRACKER")
        print("=" * 70)

        print("""
1. View findings
2. Update mitigation status
3. Exit
""")

        choice = input(
            "Select an option: "
        ).strip()

        if choice == "1":

            display_findings(
                findings,
                status
            )

        elif choice == "2":

            update_status(
                findings,
                status
            )

        elif choice == "3":

            break

        else:

            print(
                "\n[!] Invalid option."
            )


if __name__ == "__main__":
    main()