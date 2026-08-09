import subprocess
from pathlib import Path


OUTPUT_FILE = Path("scans/nmap_scan.xml")


def run_nmap_scan(target):

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    command = [
        "nmap",
        "-Pn",
        "-sV",
        "-oX",
        str(OUTPUT_FILE),
        target
    ]

    print(f"\n[*] Starting Nmap scan against {target}")
    print("[*] Please wait...\n")

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    print(result.stdout)

    if result.returncode != 0:

        print("[!] Nmap scan failed.")

        if result.stderr:
            print(result.stderr)

        return None

    print(
        f"\n[+] Scan completed."
        f"\n[+] XML saved to: {OUTPUT_FILE}"
    )

    return OUTPUT_FILE


def main():

    print("=" * 60)
    print("NETWORK SECURITY ASSESSMENT - NMAP SCANNER")
    print("=" * 60)

    target = input(
        "\nEnter authorized target IP/hostname: "
    ).strip()

    if not target:

        print("[!] Target cannot be empty.")
        return

    run_nmap_scan(target)


if __name__ == "__main__":
    main()