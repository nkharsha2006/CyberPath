from cyberpath.reports.html_report import HTMLReportGenerator


assessment = {
    "target": "http://127.0.0.1:8000",

    "status": "COMPLETED",

    "findings": [
        {
            "title": (
                "Missing Content-Security-Policy "
                "security header"
            ),

            "status": "POTENTIAL",

            "severity": "MEDIUM",

            "confidence": "MEDIUM",

            "risk_score": 3.75,

            "priority": "MEDIUM",

            "owasp": (
                "A05:2025 - Security Misconfiguration"
            ),

            "cwe": (
                "CWE-693 - Protection Mechanism Failure"
            ),

            "description": (
                "A Content-Security-Policy header "
                "was not observed."
            ),

            "evidence": {
                "header": "Content-Security-Policy",
                "observed": "MISSING",
            },

            "remediation": (
                "Define and deploy an appropriate "
                "Content-Security-Policy."
            ),
        }
    ],
}


generator = HTMLReportGenerator()

output_file = generator.generate(
    assessment,
    "test_report.html",
)


print("\n" + "=" * 60)
print("CYBERPATH HTML REPORT TEST")
print("=" * 60)

print("\nHTML report generated successfully.")

print(f"\nLocation:")
print(f"  {output_file}")

print("\n" + "=" * 60)
print("HTML REPORT TEST COMPLETE")
print("=" * 60)