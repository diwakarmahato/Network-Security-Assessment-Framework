# 🛡 Network Security Assessment Framework

A Python-based network security assessment framework that combines network discovery, service enumeration, risk assessment, packet analysis, traffic anomaly detection, security correlation, mitigation tracking, and web-based reporting into a single workflow.

---

## 📌 Project Overview

The Network Security Assessment Framework is designed to automate the initial security assessment of an authorized network host.

Instead of manually running multiple security tools and analyzing their results separately, the framework combines several assessment stages into one automated pipeline.

The framework can:

- Discover exposed network services using Nmap
- Parse Nmap XML results
- Perform preliminary security risk assessment
- Analyze captured network traffic
- Detect potential traffic anomalies
- Correlate security findings and traffic observations
- Generate a preliminary security score
- Track mitigation status
- Generate an HTML security assessment report
- Display assessment results through a Flask dashboard
- Allow the generated report to be downloaded

> ⚠️ This project is intended for authorized security testing, cybersecurity education, labs, and controlled environments only.

---

# 🚀 Features

## 1. Network Discovery

Uses Nmap to identify:

- Open TCP ports
- Network services
- Service versions
- Product information
- CPE information

Example:

```text
Target: 192.168.1.104

135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
2869/tcp open http