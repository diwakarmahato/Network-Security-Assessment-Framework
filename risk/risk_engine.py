RISK_RULES = {

    "telnet": {
        "severity": "Critical",
        "score": 9.0,
        "finding": (
            "Telnet provides remote administration "
            "without strong transport encryption."
        ),
        "mitigation": (
            "Disable Telnet and use SSH for secure "
            "remote administration."
        )
    },

    "microsoft-ds": {
        "severity": "High",
        "score": 8.0,
        "finding": (
            "SMB service is exposed to the network."
        ),
        "mitigation": (
            "Restrict SMB access to trusted hosts and "
            "disable unnecessary SMB services."
        )
    },

    "mysql": {
        "severity": "High",
        "score": 8.0,
        "finding": (
            "MySQL database service is network accessible."
        ),
        "mitigation": (
            "Restrict database access to authorized "
            "application and administration hosts."
        )
    },

    "ftp": {
        "severity": "Medium",
        "score": 6.0,
        "finding": (
            "FTP service may transmit credentials "
            "without encryption."
        ),
        "mitigation": (
            "Use SFTP/FTPS and restrict FTP access."
        )
    },

    "ssh": {
        "severity": "Medium",
        "score": 5.0,
        "finding": (
            "SSH remote administration is exposed."
        ),
        "mitigation": (
            "Use key-based authentication, disable "
            "unnecessary root login, and restrict "
            "administrative access."
        )
    },

    "http": {
        "severity": "Low",
        "score": 3.0,
        "finding": (
            "HTTP web management service is exposed."
        ),
        "mitigation": (
            "Prefer HTTPS for administrative interfaces "
            "and review authentication configuration."
        )
    },

    "domain": {
        "severity": "Low",
        "score": 3.0,
        "finding": (
            "DNS service is network accessible."
        ),
        "mitigation": (
            "Restrict DNS access to trusted clients and "
            "disable unnecessary external DNS exposure."
        )
    },

    "upnp": {
        "severity": "Medium",
        "score": 5.0,
        "finding": (
            "UPnP service is exposed and may allow "
            "automatic network service discovery."
        ),
        "mitigation": (
            "Disable UPnP if it is not required and "
            "restrict access to trusted network segments."
        )
    }
}


def analyze(hosts):
    """
    Analyze parsed Nmap hosts and generate
    security findings.
    """

    findings = []

    for host in hosts:

        for port in host["ports"]:

            service = port["service"].lower()

            rule = RISK_RULES.get(service)

            if rule:

                finding = {
                    "host": host["ip"],
                    "port": port["port"],
                    "protocol": port["protocol"],
                    "service": service,
                    "product": port["product"],
                    "version": port["version"],
                    "cpe": port.get("cpe", ""),
                    "severity": rule["severity"],
                    "score": rule["score"],
                    "finding": rule["finding"],
                    "mitigation": rule["mitigation"]
                }

            else:

                finding = {
                    "host": host["ip"],
                    "port": port["port"],
                    "protocol": port["protocol"],
                    "service": service,
                    "product": port["product"],
                    "version": port["version"],
                    "cpe": port.get("cpe", ""),
                    "severity": "Informational",
                    "score": 1.0,
                    "finding": (
                        f"Open {service} service detected."
                    ),
                    "mitigation": (
                        "Confirm that the service is required "
                        "and restrict access where possible."
                    )
                }

            findings.append(finding)

    return findings