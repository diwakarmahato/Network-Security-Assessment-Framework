from datetime import datetime
import json
from pathlib import Path


def load_findings():
    path = Path("reports/findings.json")

    if not path.exists():
        raise FileNotFoundError(
            "reports/findings.json was not found."
        )

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def severity_class(severity):
    return severity.lower()


def generate_report(findings):

    target = findings[0]["host"] if findings else "Unknown"

    counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0
    }

    for finding in findings:
        severity = finding["severity"]

        if severity in counts:
            counts[severity] += 1

    total_risk = sum(
        finding["score"]
        for finding in findings
    )

    generated_time = datetime.now().strftime(
        "%d-%m-%Y %H:%M:%S"
    )

    rows = ""

    for finding in findings:

        rows += f"""
        <tr>
            <td>{finding['port']}</td>
            <td>{finding['protocol']}</td>
            <td>{finding['service']}</td>
            <td>{finding['product']} {finding['version']}</td>
            <td>
                <span class="severity {severity_class(finding['severity'])}">
                    {finding['severity']}
                </span>
            </td>
            <td>{finding['score']}</td>
            <td>{finding['finding']}</td>
            <td>{finding['mitigation']}</td>
        </tr>
        """

    html = f"""
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>Network Security Assessment Report</title>

<style>

body {{
    font-family: Arial, sans-serif;
    background: #f4f6f8;
    margin: 0;
    padding: 30px;
    color: #222;
}}

.container {{
    max-width: 1400px;
    margin: auto;
}}

header {{
    background: #111827;
    color: white;
    padding: 30px;
    border-radius: 12px;
    margin-bottom: 25px;
}}

h1 {{
    margin: 0 0 10px 0;
}}

.cards {{
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(180px, 1fr));
    gap: 15px;
    margin-bottom: 25px;
}}

.card {{
    background: white;
    padding: 20px;
    border-radius: 10px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.08);
}}

.card h2 {{
    margin: 0;
    font-size: 30px;
}}

.card p {{
    margin-bottom: 0;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    background: white;
    border-radius: 10px;
    overflow: hidden;
}}

th {{
    background: #111827;
    color: white;
    padding: 12px;
    text-align: left;
}}

td {{
    padding: 12px;
    border-bottom: 1px solid #ddd;
    vertical-align: top;
}}

.severity {{
    padding: 5px 10px;
    border-radius: 20px;
    font-weight: bold;
}}

.critical {{
    background: #fee2e2;
    color: #991b1b;
}}

.high {{
    background: #ffedd5;
    color: #9a3412;
}}

.medium {{
    background: #fef3c7;
    color: #92400e;
}}

.low {{
    background: #dcfce7;
    color: #166534;
}}

.informational {{
    background: #e0f2fe;
    color: #075985;
}}

.summary {{
    background: white;
    padding: 25px;
    border-radius: 10px;
    margin-bottom: 25px;
}}

</style>

</head>

<body>

<div class="container">

<header>

<h1>Network Security Assessment Report</h1>

<p><strong>Target:</strong> {target}</p>

<p>
<strong>Generated:</strong>
{generated_time}
</p>

</header>


<div class="cards">

<div class="card">
<h2>{counts['Critical']}</h2>
<p>Critical</p>
</div>

<div class="card">
<h2>{counts['High']}</h2>
<p>High</p>
</div>

<div class="card">
<h2>{counts['Medium']}</h2>
<p>Medium</p>
</div>

<div class="card">
<h2>{counts['Low']}</h2>
<p>Low</p>
</div>

<div class="card">
<h2>{total_risk:.1f}</h2>
<p>Total Risk Score</p>
</div>

</div>


<div class="summary">

<h2>Executive Summary</h2>

<p>
The security assessment identified
<strong>{len(findings)}</strong>
network-exposed services on
<strong>{target}</strong>.
</p>

<p>
The assessment detected
<strong>{counts['Critical']}</strong>
critical,
<strong>{counts['High']}</strong>
high,
<strong>{counts['Medium']}</strong>
medium and
<strong>{counts['Low']}</strong>
low severity findings.
</p>

</div>


<h2>Detailed Findings</h2>

<table>

<thead>

<tr>
<th>Port</th>
<th>Protocol</th>
<th>Service</th>
<th>Product / Version</th>
<th>Severity</th>
<th>Score</th>
<th>Finding</th>
<th>Mitigation</th>
</tr>

</thead>

<tbody>

{rows}

</tbody>

</table>

</div>

</body>

</html>
"""

    output = Path("reports/security_assessment_report.html")

    with open(output, "w", encoding="utf-8") as file:
        file.write(html)

    return output


def main():

    try:

        findings = load_findings()

        report = generate_report(findings)

        print("\n" + "=" * 60)
        print("REPORT GENERATION COMPLETE")
        print("=" * 60)

        print(f"\n[+] Report created:")
        print(f"    {report}")

    except Exception as error:

        print(f"[!] Error: {error}")


if __name__ == "__main__":
    main()