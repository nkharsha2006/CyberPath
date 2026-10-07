from html import escape
from pathlib import Path
from datetime import datetime


class HTMLReportGenerator:
    """Generate HTML security assessment reports."""

    def __init__(self, output_directory="reports"):
        self.output_directory = Path(output_directory)

    def generate(
        self,
        assessment_data,
        filename="cyberpath_report.html",
    ):
        """Generate and save an HTML assessment report."""

        self.output_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        html = self.build_html(assessment_data)

        output_file = self.output_directory / filename

        output_file.write_text(
            html,
            encoding="utf-8",
        )

        return output_file

    def build_html(self, assessment_data):
        """Build the HTML report."""

        target = escape(
            str(assessment_data.get("target", "Unknown"))
        )

        status = escape(
            str(assessment_data.get("status", "Unknown"))
        )

        findings = assessment_data.get(
            "findings",
            [],
        )

        generated_at = datetime.now().astimezone().isoformat()

        finding_rows = ""

        for number, finding in enumerate(
            findings,
            start=1,
        ):

            title = escape(
                str(finding.get("title", "Unknown"))
            )

            finding_status = escape(
                str(finding.get("status", "Unknown"))
            )

            severity = escape(
                str(finding.get("severity", "INFO"))
            )

            confidence = escape(
                str(finding.get("confidence", "LOW"))
            )

            risk_score = escape(
                str(finding.get("risk_score", 0))
            )

            priority = escape(
                str(finding.get("priority", "INFO"))
            )

            owasp = escape(
                str(finding.get("owasp", "Not mapped"))
            )

            cwe = escape(
                str(finding.get("cwe", "Not mapped"))
            )

            description = escape(
                str(finding.get("description", ""))
            )

            remediation = escape(
                str(finding.get("remediation", ""))
            )

            evidence = finding.get(
                "evidence",
                {},
            )

            evidence_text = escape(
                str(evidence)
            )

            finding_rows += f"""
            <tr>
                <td>{number}</td>
                <td>{title}</td>
                <td>{finding_status}</td>
                <td>{severity}</td>
                <td>{confidence}</td>
                <td>{risk_score}</td>
                <td>{priority}</td>
                <td>{owasp}</td>
                <td>{cwe}</td>
            </tr>

            <tr>
                <td colspan="9">
                    <strong>Description:</strong>
                    {description}<br><br>

                    <strong>Evidence:</strong>
                    {evidence_text}<br><br>

                    <strong>Remediation:</strong>
                    {remediation}
                </td>
            </tr>
            """

        if not finding_rows:

            finding_rows = """
            <tr>
                <td colspan="9">
                    No findings were generated.
                </td>
            </tr>
            """

        return f"""<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>CyberPath Security Assessment</title>

<style>

body {{
    font-family: Arial, sans-serif;
    margin: 40px;
    background: #f4f6f8;
    color: #222;
}}

.container {{
    max-width: 1400px;
    margin: auto;
    background: white;
    padding: 30px;
    border-radius: 8px;
}}

h1 {{
    margin-bottom: 5px;
}}

.subtitle {{
    color: #666;
}}

.info {{
    margin-top: 25px;
    margin-bottom: 25px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 20px;
}}

th,
td {{
    border: 1px solid #ddd;
    padding: 10px;
    text-align: left;
    vertical-align: top;
}}

th {{
    background: #f0f0f0;
}}

tr:nth-child(even) {{
    background: #fafafa;
}}

.footer {{
    margin-top: 30px;
    color: #777;
    font-size: 13px;
}}

</style>

</head>

<body>

<div class="container">

<h1>CyberPath 2.0</h1>

<div class="subtitle">
Context-Aware Ethical Security Assessment Platform
</div>

<div class="info">

<p>
<strong>Target:</strong>
{target}
</p>

<p>
<strong>Assessment Status:</strong>
{status}
</p>

<p>
<strong>Generated:</strong>
{escape(generated_at)}
</p>

</div>

<h2>Security Findings</h2>

<table>

<thead>

<tr>
<th>#</th>
<th>Finding</th>
<th>Status</th>
<th>Severity</th>
<th>Confidence</th>
<th>Risk Score</th>
<th>Priority</th>
<th>OWASP</th>
<th>CWE</th>
</tr>

</thead>

<tbody>

{finding_rows}

</tbody>

</table>

<div class="footer">

Generated by CyberPath 2.0

</div>

</div>

</body>

</html>
"""