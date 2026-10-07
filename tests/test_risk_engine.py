from cyberpath.checks.http_headers import HTTPSecurityHeadersCheck
from cyberpath.analyzer.finding_analyzer import FindingAnalyzer
from cyberpath.analyzer.risk_engine import RiskEngine

url = "http://127.0.0.1:8000"
checker = HTTPSecurityHeadersCheck()

check_result = checker.check(url)

analyzer = FindingAnalyzer(check_result)

analysis = analyzer.analyze()

risk_engine = RiskEngine(analysis)

risk_result = risk_engine.analyze()


print("\n" + "=" * 60)
print("CYBERPATH SECURITY ANALYSIS TEST")
print("=" * 60)

print(f"\nTarget : {risk_result['target']}")
print(f"Rule   : {risk_result['rule']}")
print(f"Status : {risk_result['status']}")

print("\nFindings")
print("-" * 40)

for number, finding in enumerate(
    risk_result["findings"],
    start=1,
):

    print(f"\nFinding #{number}")

    print(f"Title      : {finding['title']}")
    print(f"Status     : {finding['status']}")
    print(f"Severity   : {finding['severity']}")
    print(f"Confidence : {finding['confidence']}")
    print(f"Risk Score : {finding['risk_score']}")
    print(f"Priority   : {finding['priority']}")

    print(f"OWASP      : {finding['owasp']}")
    print(f"CWE        : {finding['cwe']}")

    print(f"Evidence   : {finding['evidence']}")
    print(f"Remediation: {finding['remediation']}")

print("\n" + "=" * 60)
print("SECURITY ANALYSIS TEST COMPLETE")
print("=" * 60)