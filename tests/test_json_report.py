from cyberpath.reports.json_report import JSONReportGenerator


assessment = {
    "target": "http://127.0.0.1:8000",

    "scanner": "CyberPath",

    "status": "COMPLETED",

    "findings": [
        {
            "title": "Missing Content-Security-Policy security header",
            "status": "POTENTIAL",
            "severity": "MEDIUM",
            "confidence": "MEDIUM",
            "risk_score": 3.75,
            "priority": "MEDIUM",
            "owasp": "A05:2025 - Security Misconfiguration",
            "cwe": "CWE-693 - Protection Mechanism Failure",
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


generator = JSONReportGenerator()

output_file = generator.generate(
    assessment,
    "test_report.json",
)


print("\n" + "=" * 60)
print("CYBERPATH JSON REPORT TEST")
print("=" * 60)

print(f"\nReport generated successfully.")

print(f"Location:")
print(f"  {output_file}")

print("\n" + "=" * 60)
print("JSON REPORT TEST COMPLETE")
print("=" * 60)