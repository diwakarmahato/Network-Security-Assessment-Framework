import xml.etree.ElementTree as ET
from pathlib import Path


def parse_nmap_xml(xml_file):
    path = Path(xml_file)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    tree = ET.parse(path)
    root = tree.getroot()

    hosts = []

    for host in root.findall("host"):

        address = host.find("address")

        if address is None:
            continue

        host_data = {
            "ip": address.get("addr"),
            "ports": []
        }

        ports = host.find("ports")

        if ports is None:
            hosts.append(host_data)
            continue

        for port in ports.findall("port"):

            state = port.find("state")

            if state is None or state.get("state") != "open":
                continue

            service = port.find("service")

            data = {
                "port": int(port.get("portid")),
                "protocol": port.get("protocol", "tcp"),
                "service": "unknown",
                "product": "",
                "version": "",
                "extrainfo": "",
                "cpe": ""
            }

            if service is not None:

                data["service"] = service.get("name", "unknown")
                data["product"] = service.get("product", "")
                data["version"] = service.get("version", "")
                data["extrainfo"] = service.get("extrainfo", "")

                cpe = service.find("cpe")

                if cpe is not None:
                    data["cpe"] = cpe.text or ""

            host_data["ports"].append(data)

        hosts.append(host_data)

    return hosts


def display_results(hosts):

    print("\n" + "=" * 60)
    print("NMAP ASSESSMENT DATA")
    print("=" * 60)

    for host in hosts:

        print(f"\nHost: {host['ip']}")

        for port in host["ports"]:

            print(
                f"{port['port']}/{port['protocol']} | "
                f"{port['service']} | "
                f"{port['product']} | "
                f"{port['version']}"
            )

            if port["extrainfo"]:
                print(f"  Extra: {port['extrainfo']}")

            if port["cpe"]:
                print(f"  CPE: {port['cpe']}")


if __name__ == "__main__":

    try:
        results = parse_nmap_xml("scans/nmap_scan.xml")
        display_results(results)

    except Exception as error:
        print(f"[!] Error: {error}")