from flask import Flask, render_template, send_file
from pathlib import Path
import json


app = Flask(__name__)


def load_json(path):
    file_path = Path(path)

    if not file_path.exists():
        return {}

    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


@app.route("/")
def dashboard():

    summary = load_json(
        "reports/security_summary.json"
    )

    findings = load_json(
        "reports/findings.json"
    )

    packet_data = load_json(
        "reports/packet_analysis.json"
    )

    mitigation_status = load_json(
        "reports/mitigation_status.json"
    )

    return render_template(
        "dashboard.html",
        summary=summary,
        findings=findings,
        packet_data=packet_data,
        mitigation_status=mitigation_status
    )


@app.route("/download-report")
def download_report():

    report_path = Path(
        "reports/security_assessment_report.html"
    )

    if not report_path.exists():

        return (
            "Security assessment report not found.",
            404
        )

    return send_file(
        report_path,
        as_attachment=True,
        download_name="security_assessment_report.html"
    )


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )