import json
from pathlib import Path
from collections import Counter


FINDINGS_FILE = Path("reports/findings.json")
ANOMALIES_FILE = Path("reports/anomalies.json")
OUTPUT_FILE = Path("reports/security_summary.json")


def load_json(path):
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def calculate_security_score(findings, anomalies):
    """
    Calculate an overall preliminary security score.

    This is a project-level risk indicator, not a CVSS score.
    """

    score = 100.0

    severity_penalty = {
        "Critical": 25,
        "High": 18,
        "Medium": 10,
        "Low": 4,
        "Informational": 1
    }

    for finding in findings:
        severity = finding.get("severity", "Informational")
        score -= severity_penalty.get(severity, 1)

    for anomaly in anomalies:
        severity = anomaly.get("severity", "Low")

        if severity == "High":
            score -= 10
        elif severity == "Medium":
            score -= 5
        elif severity == "Low":
            score -= 2

    return max(0, round(score, 2))


def create_summary(findings, anomalies):

    severity_counts = Counter(
        finding.get("severity", "Informational")
        for finding in findings
    )

    anomaly_counts = Counter(
        anomaly.get("severity", "Low")
        for anomaly in anomalies
    )

    score = calculate_security_score(
        findings,
        anomalies
    )

    if score >= 80:
        overall_rating = "Good"
    elif score >= 60:
        overall_rating = "Moderate"
    elif score >= 40:
        overall_rating = "Needs Improvement"
    else:
        overall_rating = "High Risk"

    target = "Unknown"

    if findings:
        target = findings[0].get(
            "host",
            "Unknown"
        )

    summary = {
        "target": target,

        "security_score": score,

        "overall_rating": overall_rating,

        "total_findings": len(findings),

        "total_anomalies": len(anomalies),

        "severity_summary": dict(
            severity_counts
        ),

        "anomaly_summary": dict(
            anomaly_counts
        ),

        "critical_findings": [
            finding
            for finding in findings
            if finding.get("severity") == "Critical"
        ],

        "high_findings": [
            finding
            for finding in findings
            if finding.get("severity") == "High"
        ],

        "anomalies": anomalies
    }

    return summary


def display_summary(summary):

    print("\n" + "=" * 70)
    print("SECURITY CORRELATION SUMMARY")
    print("=" * 70)

    print(
        f"\nTarget          : "
        f"{summary['target']}"
    )

    print(
        f"Security Score  : "
        f"{summary['security_score']}/100"
    )

    print(
        f"Overall Rating  : "
        f"{summary['overall_rating']}"
    )

    print(
        f"Total Findings  : "
        f"{summary['total_findings']}"
    )

    print(
        f"Total Anomalies : "
        f"{summary['total_anomalies']}"
    )

    print("\nSeverity Summary:")

    for severity, count in summary[
        "severity_summary"
    ].items():

        print(
            f"  {severity:<15} {count}"
        )

    print("\nAnomaly Summary:")

    for severity, count in summary[
        "anomaly_summary"
    ].items():

        print(
            f"  {severity:<15} {count}"
        )


def save_summary(summary):

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            summary,
            file,
            indent=4
        )

    print(
        f"\n[+] Security summary saved to:"
        f" {OUTPUT_FILE}"
    )


def main():

    try:

        findings = load_json(
            FINDINGS_FILE
        )

        anomalies = load_json(
            ANOMALIES_FILE
        )

        summary = create_summary(
            findings,
            anomalies
        )

        display_summary(summary)

        save_summary(summary)

    except FileNotFoundError as error:

        print(f"[!] {error}")

    except Exception as error:

        print(
            f"[!] Correlation failed: "
            f"{error}"
        )


if __name__ == "__main__":
    main()